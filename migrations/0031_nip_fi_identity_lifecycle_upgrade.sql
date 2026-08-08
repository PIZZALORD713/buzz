-- Additive provider-free NIP-FI identity, lifecycle, and audit foundation.
--
-- Migrations 0029 and 0030 are independently deployable and checksum-frozen.
-- This migration projects their populated uid-era catalog into the canonical
-- immutable-generation model. Every synthetic identifier and digest is derived
-- from authoritative legacy coordinates; ambiguous authority fails before any
-- legacy table is renamed.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM identity_bindings
        GROUP BY community_id, issuer, uid, pubkey, source, created_at
        HAVING count(*) <> 1
    ) THEN
        RAISE EXCEPTION 'NIP-FI 0031 blocked: duplicate binding birth coordinates'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'nip_fi_0031_unique_binding_birth';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM identity_bindings
        GROUP BY community_id, issuer, uid, pubkey
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'NIP-FI 0031 blocked: a principal/key pair was reused'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'nip_fi_0031_unique_principal_key';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM identity_bindings binding
        WHERE binding.revoked_at IS NOT NULL
          AND binding.revoked_at < binding.created_at
    ) OR EXISTS (
        SELECT 1
        FROM identity_bindings binding
        WHERE binding.rotation_completed_at IS NOT NULL
          AND (binding.rotation_completed_at <= binding.created_at
               OR binding.revoked_at IS NULL
               OR binding.revocation_scope NOT IN ('key', 'rotation')
               OR (binding.revocation_scope = 'rotation'
                   AND binding.revoked_at <> binding.rotation_completed_at)
               OR (binding.revocation_scope = 'key'
                   AND binding.revoked_at >= binding.rotation_completed_at))
    ) THEN
        RAISE EXCEPTION 'NIP-FI 0031 blocked: invalid lifecycle timestamp order'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'nip_fi_0031_timestamp_order';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM identity_bindings predecessor
        WHERE predecessor.rotation_completed_at IS NOT NULL
          AND 1 <> (
              SELECT count(*)
              FROM identity_bindings successor
              WHERE successor.community_id = predecessor.community_id
                AND successor.issuer = predecessor.issuer
                AND successor.uid = predecessor.uid
                AND successor.pubkey = predecessor.rotated_to_pubkey
                AND successor.created_at = predecessor.rotation_completed_at
          )
    ) OR EXISTS (
        SELECT successor.community_id, successor.issuer, successor.uid,
               successor.pubkey, successor.created_at
        FROM identity_bindings successor
        JOIN identity_bindings predecessor
          ON predecessor.community_id = successor.community_id
         AND predecessor.issuer = successor.issuer
         AND predecessor.uid = successor.uid
         AND predecessor.rotated_to_pubkey = successor.pubkey
         AND predecessor.rotation_completed_at = successor.created_at
        GROUP BY successor.community_id, successor.issuer, successor.uid,
                 successor.pubkey, successor.created_at
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'NIP-FI 0031 blocked: ambiguous rotation lineage'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'nip_fi_0031_rotation_lineage';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM identity_bindings binding
        WHERE binding.revoked_at IS NOT NULL
          AND NOT EXISTS (
              SELECT 1
              FROM identity_revoked_keys revoked
              WHERE revoked.community_id = binding.community_id
                AND revoked.pubkey = binding.pubkey
                AND revoked.revoked_at = binding.revoked_at
                AND revoked.revoked_by IS NOT DISTINCT FROM binding.revoked_by
                AND revoked.reason = COALESCE(NULLIF(binding.revoked_reason, ''),
                                              'legacy key revocation')
          )
    ) THEN
        RAISE EXCEPTION 'NIP-FI 0031 blocked: key tombstone does not match its binding'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'nip_fi_0031_key_tombstone_match';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM identity_bindings binding
        WHERE binding.revoked_at IS NOT NULL
          AND binding.revocation_scope = 'principal'
          AND NOT EXISTS (
              SELECT 1
              FROM identity_principals principal
              WHERE principal.community_id = binding.community_id
                AND principal.issuer = binding.issuer
                AND principal.uid = binding.uid
                AND principal.disabled_at = binding.revoked_at
                AND principal.disabled_by IS NOT DISTINCT FROM binding.revoked_by
                AND principal.disabled_reason = COALESCE(
                    NULLIF(binding.revoked_reason, ''),
                    'legacy principal revocation'
                )
          )
    ) THEN
        RAISE EXCEPTION 'NIP-FI 0031 blocked: principal disable does not match its binding'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'nip_fi_0031_principal_disable_match';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM identity_bindings active
        JOIN identity_principals principal
          ON principal.community_id = active.community_id
         AND principal.issuer = active.issuer
         AND principal.uid = active.uid
         AND principal.disabled_at IS NOT NULL
        WHERE active.revoked_at IS NULL
    ) OR EXISTS (
        SELECT 1
        FROM identity_bindings active
        JOIN identity_revoked_keys revoked
          ON revoked.community_id = active.community_id
         AND revoked.pubkey = active.pubkey
        WHERE active.revoked_at IS NULL
    ) THEN
        RAISE EXCEPTION 'NIP-FI 0031 blocked: active binding conflicts with a denial fact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'nip_fi_0031_active_denial_conflict';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM identity_bindings binding
        WHERE binding.revocation_scope = 'rotation'
          AND binding.rotation_completed_at IS NOT NULL
          AND (binding.rotation_by IS DISTINCT FROM binding.revoked_by
               OR binding.rotation_reason IS DISTINCT FROM binding.revoked_reason)
    ) THEN
        RAISE EXCEPTION 'NIP-FI 0031 blocked: rotation authority does not match retirement'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'nip_fi_0031_rotation_authority_match';
    END IF;

    IF EXISTS (
        SELECT community_id, issuer, uid
        FROM identity_bindings
        WHERE revoked_at IS NOT NULL
          AND NOT (revocation_scope = 'key' AND rotation_completed_at IS NOT NULL)
        GROUP BY community_id, issuer, uid
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'NIP-FI 0031 blocked: multiple open pending replacements'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'nip_fi_0031_one_open_pending_replacement';
    END IF;
END;
$$;

ALTER TABLE identity_bindings RENAME TO identity_bindings_legacy_0031;
ALTER TABLE identity_principals RENAME TO identity_principals_legacy_0031;
ALTER TABLE identity_revoked_keys RENAME TO identity_revoked_keys_legacy_0031;

CREATE FUNCTION nip_fi_upgrade_frame_v1(value BYTEA) RETURNS BYTEA AS $$
    SELECT int8send(octet_length(value)::BIGINT) || value;
$$ LANGUAGE SQL IMMUTABLE STRICT;

CREATE FUNCTION nip_fi_upgrade_hash_v1(domain_name TEXT, VARIADIC fields BYTEA[])
RETURNS BYTEA AS $$
DECLARE
    framed BYTEA := nip_fi_upgrade_frame_v1(convert_to(domain_name, 'UTF8'));
    field BYTEA;
BEGIN
    FOREACH field IN ARRAY fields LOOP
        framed := framed || nip_fi_upgrade_frame_v1(field);
    END LOOP;
    RETURN digest(framed, 'sha256');
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

CREATE FUNCTION nip_fi_upgrade_nullable_v1(value BYTEA) RETURNS BYTEA AS $$
    SELECT CASE WHEN value IS NULL THEN decode('00', 'hex')
                ELSE decode('01', 'hex') || value END;
$$ LANGUAGE SQL IMMUTABLE;

CREATE FUNCTION nip_fi_upgrade_timestamp_v1(value TIMESTAMPTZ) RETURNS BYTEA AS $$
    SELECT int8send((extract(epoch FROM value) * 1000000)::BIGINT);
$$ LANGUAGE SQL IMMUTABLE STRICT;

CREATE FUNCTION nip_fi_upgrade_uuid_v5_v1(namespace_id UUID, name TEXT) RETURNS UUID AS $$
DECLARE
    value BYTEA := substring(digest(uuid_send(namespace_id) || convert_to(name, 'UTF8'), 'sha1') FROM 1 FOR 16);
    encoded TEXT;
BEGIN
    value := set_byte(value, 6, (get_byte(value, 6) & 15) | 80);
    value := set_byte(value, 8, (get_byte(value, 8) & 63) | 128);
    encoded := encode(value, 'hex');
    RETURN (substring(encoded FROM 1 FOR 8) || '-' ||
            substring(encoded FROM 9 FOR 4) || '-' ||
            substring(encoded FROM 13 FOR 4) || '-' ||
            substring(encoded FROM 17 FOR 4) || '-' ||
            substring(encoded FROM 21 FOR 12))::UUID;
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

CREATE FUNCTION nip_fi_upgrade_id_v1(label TEXT, value BYTEA) RETURNS UUID AS $$
    SELECT nip_fi_upgrade_uuid_v5_v1(
        'e6216f85-c129-52a5-b8fe-4a0d71b0d886'::UUID,
        label || ':' || encode(value, 'hex')
    );
$$ LANGUAGE SQL IMMUTABLE STRICT;

-- The sole idempotency/result root shared by identity lifecycle, operator
-- lifecycle, protected operations, invalidation, and status publication.
-- Pre-authentication denials never write this table. ExactReplay and
-- IntentConflict are read-time observations, not persisted outcomes.
CREATE TABLE authorization_operation_receipts (
    community_id UUID NOT NULL REFERENCES communities(id),
    operation_id UUID NOT NULL,
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    -- 1 enroll, 2 provision, 3 retire, 4 disable, 5 revoke, 6 rotate,
    -- 7 recover, 8 enable, 9 admission loss, 10 operator,
    -- 11 protected mutation, 12 invalidation, 13 status revision.
    operation_kind SMALLINT NOT NULL CHECK (
        operation_kind IN (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
    ),
    actor_fingerprint BYTEA NOT NULL CHECK (octet_length(actor_fingerprint) = 32),
    -- 1 applied, 2 denied, 3 no-op.
    outcome_code SMALLINT NOT NULL CHECK (outcome_code IN (1, 2, 3)),
    result_digest BYTEA NOT NULL CHECK (octet_length(result_digest) = 32),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (community_id, operation_id),
    UNIQUE (community_id, operation_id, request_fingerprint),
    UNIQUE (
        community_id,
        operation_id,
        request_fingerprint,
        operation_kind,
        outcome_code
    ),
    CHECK (operation_id <> '00000000-0000-0000-0000-000000000000'::uuid)
);

-- A configured row is the immutable capacity policy required by Enforce mode.
-- A migration-bootstrap row has configuration_state=1, NULL limits, and exact
-- retained counters for imported events. It blocks all further event writes
-- until the explicit policy installer adopts limits large enough for the
-- retained corpus. No production capacity is fabricated by this migration.
CREATE TABLE authorization_event_capacity (
    community_id UUID NOT NULL PRIMARY KEY REFERENCES communities(id),
    -- 1 migration bootstrap/unconfigured, 2 explicitly configured.
    configuration_state SMALLINT NOT NULL DEFAULT 2 CHECK (configuration_state IN (1, 2)),
    max_events_per_domain BIGINT CONSTRAINT authorization_event_capacity_max_events CHECK (
        max_events_per_domain IS NULL
        OR max_events_per_domain BETWEEN 1 AND 1000000
    ),
    max_bytes_per_domain BIGINT CONSTRAINT authorization_event_capacity_max_bytes CHECK (
        max_bytes_per_domain IS NULL
        OR max_bytes_per_domain BETWEEN 1 AND 4294967296
    ),
    max_envelope_bytes INTEGER CONSTRAINT authorization_event_capacity_max_envelope CHECK (
        max_envelope_bytes IS NULL
        OR max_envelope_bytes BETWEEN 1 AND 65536
    ),
    retained_event_count BIGINT NOT NULL CHECK (retained_event_count >= 0),
    retained_envelope_bytes BIGINT NOT NULL CHECK (retained_envelope_bytes >= 0),
    retained_largest_envelope_bytes INTEGER NOT NULL CHECK (
        retained_largest_envelope_bytes BETWEEN 0 AND 65536
    ),
    -- 1 healthy, 2 audit unavailable/exhausted.
    health_state SMALLINT NOT NULL DEFAULT 1 CHECK (health_state IN (1, 2)),
    failure_code SMALLINT CHECK (failure_code IS NULL OR failure_code IN (1, 2, 3)),
    failure_observed_at TIMESTAMPTZ,
    configured_at TIMESTAMPTZ DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK (
        (configuration_state = 1
            AND max_events_per_domain IS NULL
            AND max_bytes_per_domain IS NULL
            AND max_envelope_bytes IS NULL
            AND configured_at IS NULL)
        OR (configuration_state = 2
            AND max_events_per_domain IS NOT NULL
            AND max_bytes_per_domain IS NOT NULL
            AND max_envelope_bytes IS NOT NULL
            AND configured_at IS NOT NULL
            AND max_envelope_bytes <= max_bytes_per_domain
            AND retained_event_count <= max_events_per_domain
            AND retained_envelope_bytes <= max_bytes_per_domain
            AND retained_largest_envelope_bytes <= max_envelope_bytes)
    ),
    CHECK (
        (health_state = 1 AND failure_code IS NULL AND failure_observed_at IS NULL)
        OR (health_state = 2 AND failure_code IS NOT NULL AND failure_observed_at IS NOT NULL)
    )
);

-- Durable versioned pseudonymous authorization envelope. event_kind:
-- 1 enrolled, 2 revoked, 3 rotated, 4 recovered, 5 principal enabled,
-- 6 retired, 7 principal disabled, 8 admission lost, 9 operator denied,
-- 10 protected allowed, 11 protected denied, 12 status published,
-- 13 status withdrawn, 14 invalidation advanced.
CREATE TABLE authorization_events (
    community_id UUID NOT NULL REFERENCES communities(id),
    event_id UUID NOT NULL,
    schema_version SMALLINT NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    event_kind SMALLINT NOT NULL CHECK (
        event_kind IN (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)
    ),
    outcome_code SMALLINT NOT NULL CHECK (outcome_code IN (1, 2, 3, 4, 5)),
    reason_code SMALLINT NOT NULL CHECK (
        reason_code IN (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
    ),
    actor_kind SMALLINT NOT NULL CHECK (actor_kind IN (1, 2, 3, 4)),
    actor_fingerprint BYTEA CHECK (
        actor_fingerprint IS NULL OR octet_length(actor_fingerprint) = 32
    ),
    subject_fingerprint BYTEA CHECK (
        subject_fingerprint IS NULL OR octet_length(subject_fingerprint) = 32
    ),
    operation_id UUID NOT NULL,
    request_fingerprint BYTEA CHECK (
        request_fingerprint IS NULL OR octet_length(request_fingerprint) = 32
    ),
    correlation_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    canonical_envelope BYTEA NOT NULL CONSTRAINT authorization_events_envelope_size CHECK (
        octet_length(canonical_envelope) BETWEEN 1 AND 65536
    ),
    envelope_digest BYTEA NOT NULL CHECK (octet_length(envelope_digest) = 32),
    PRIMARY KEY (community_id, event_id),
    UNIQUE (community_id, event_id, operation_id),
    UNIQUE (community_id, event_id, event_kind, operation_id),
    UNIQUE (community_id, operation_id, event_kind, attempt_id),
    FOREIGN KEY (community_id, operation_id, request_fingerprint)
        REFERENCES authorization_operation_receipts
            (community_id, operation_id, request_fingerprint)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (event_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (operation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (correlation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (
        (actor_kind = 4 AND event_kind = 9 AND request_fingerprint IS NULL)
        OR (actor_kind IN (1, 2, 3) AND request_fingerprint IS NOT NULL)
    ),
    CHECK (
        (actor_kind = 4 AND actor_fingerprint IS NULL AND subject_fingerprint IS NULL)
        OR (actor_kind IN (1, 2, 3) AND actor_fingerprint IS NOT NULL)
    )
);

-- Immutable monotonic local policy revisions. Enrollment modes are the closed
-- provider-free V1 set: 1 attested-key, 2 provisioned, 3 risk-labelled TOFU.
CREATE TABLE identity_enrollment_policies (
    community_id UUID NOT NULL REFERENCES communities(id),
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    enrollment_mode SMALLINT NOT NULL CHECK (enrollment_mode IN (1, 2, 3)),
    policy_digest BYTEA NOT NULL CHECK (octet_length(policy_digest) = 32),
    effective_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (community_id, policy_revision),
    CHECK (expires_at IS NULL OR effective_at < expires_at)
);

-- One row is one immutable binding generation. binding_version is allocated
-- from one non-cycling PostgreSQL identity sequence and is never changed or
-- reused. Explicit lifecycle may only retire the generation; X/Y denial
-- semantics live in immutable selector facts below, not alternate row states.
CREATE TABLE identity_bindings (
    community_id UUID NOT NULL REFERENCES communities(id),
    binding_id UUID NOT NULL,
    binding_version BIGINT GENERATED ALWAYS AS IDENTITY (
        START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1 NO CYCLE
    ),
    issuer TEXT COLLATE "C" NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    subject TEXT COLLATE "C" NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 2048),
    principal_fingerprint BYTEA NOT NULL CHECK (octet_length(principal_fingerprint) = 32),
    event_author_pubkey BYTEA NOT NULL CHECK (octet_length(event_author_pubkey) = 32),
    -- 1 active, 2 retired.
    binding_state SMALLINT NOT NULL CHECK (binding_state IN (1, 2)),
    lifecycle_revision BIGINT NOT NULL CHECK (lifecycle_revision IN (1, 2)),
    -- 1 attested-key, 2 provisioned, 3 risk-labelled TOFU.
    binding_provenance SMALLINT NOT NULL CHECK (binding_provenance IN (1, 2, 3)),
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    -- Canonical evidence for the selected provenance. This is an assertion
    -- digest for attested/TOFU admission and a provisioning receipt digest for
    -- separately provisioned admission; it never stores credential bytes.
    enrollment_evidence_digest BYTEA NOT NULL CHECK (
        octet_length(enrollment_evidence_digest) = 32
    ),
    expires_at TIMESTAMPTZ,
    birth_history_id UUID NOT NULL,
    creation_operation_id UUID NOT NULL,
    creation_request_fingerprint BYTEA NOT NULL CHECK (
        octet_length(creation_request_fingerprint) = 32
    ),
    retirement_history_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (community_id, binding_id),
    UNIQUE (community_id, binding_version),
    UNIQUE (community_id, binding_id, binding_version),
    FOREIGN KEY (community_id, policy_revision)
        REFERENCES identity_enrollment_policies (community_id, policy_revision),
    CHECK (binding_version > 0),
    CHECK (binding_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (birth_history_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (creation_operation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (expires_at IS NULL OR created_at < expires_at),
    CHECK (
        (binding_state = 1 AND lifecycle_revision = 1 AND retirement_history_id IS NULL)
        OR (binding_state = 2 AND lifecycle_revision = 2 AND retirement_history_id IS NOT NULL)
    )
);

-- State 1 is Active. Expiry is evaluated with authoritative PostgreSQL time
-- at read/finalization and is exclusive; it cannot appear in an index predicate.
CREATE UNIQUE INDEX identity_bindings_active_principal
    ON identity_bindings (community_id, issuer, subject)
    WHERE binding_state = 1;
CREATE INDEX identity_bindings_principal_fingerprint_lookup
    ON identity_bindings (community_id, principal_fingerprint)
    WHERE binding_state = 1;
CREATE UNIQUE INDEX identity_bindings_active_event_author
    ON identity_bindings (community_id, event_author_pubkey)
    WHERE binding_state = 1;
CREATE INDEX identity_bindings_current_lookup
    ON identity_bindings (community_id, event_author_pubkey, binding_state, expires_at);

-- The one canonical immutable lifecycle transition row for a successful or
-- no-op lifecycle operation. A transition can name an old generation, a new
-- successor generation, both (Rotate), or neither (a semantic no-op or an
-- inactive-principal selector transition). It is not a second result/effect
-- engine: the shared receipt remains the sole persisted operation outcome.
CREATE TABLE identity_lifecycle_history (
    community_id UUID NOT NULL REFERENCES communities(id),
    history_id UUID NOT NULL,
    -- 1 enroll, 2 provision, 3 retire, 4 disable, 5 revoke, 6 rotate,
    -- 7 recover, 8 enable, 9 admission loss.
    transition_kind SMALLINT NOT NULL CHECK (
        transition_kind IN (1, 2, 3, 4, 5, 6, 7, 8, 9)
    ),
    -- Matches the shared receipt: 1 applied, 3 no-op.
    outcome_code SMALLINT NOT NULL CHECK (outcome_code IN (1, 3)),
    old_binding_id UUID,
    old_binding_version BIGINT CHECK (old_binding_version IS NULL OR old_binding_version > 0),
    old_prior_lifecycle_revision BIGINT CHECK (
        old_prior_lifecycle_revision IS NULL OR old_prior_lifecycle_revision IN (1, 2)
    ),
    old_prior_state SMALLINT CHECK (old_prior_state IS NULL OR old_prior_state IN (1, 2)),
    old_resulting_lifecycle_revision BIGINT CHECK (
        old_resulting_lifecycle_revision IS NULL OR old_resulting_lifecycle_revision IN (1, 2)
    ),
    old_resulting_state SMALLINT CHECK (
        old_resulting_state IS NULL OR old_resulting_state IN (1, 2)
    ),
    successor_binding_id UUID,
    successor_binding_version BIGINT CHECK (
        successor_binding_version IS NULL OR successor_binding_version > 0
    ),
    successor_lifecycle_revision BIGINT CHECK (
        successor_lifecycle_revision IS NULL OR successor_lifecycle_revision = 1
    ),
    successor_state SMALLINT CHECK (successor_state IS NULL OR successor_state = 1),
    operation_id UUID NOT NULL,
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    transition_digest BYTEA NOT NULL CHECK (octet_length(transition_digest) = 32),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (community_id, history_id),
    UNIQUE (community_id, operation_id),
    UNIQUE (community_id, history_id, operation_id, request_fingerprint),
    UNIQUE (
        community_id,
        history_id,
        successor_binding_id,
        successor_binding_version,
        operation_id,
        request_fingerprint
    ),
    UNIQUE (
        community_id,
        history_id,
        old_binding_id,
        old_binding_version,
        old_resulting_lifecycle_revision,
        old_resulting_state
    ),
    FOREIGN KEY (
        community_id,
        operation_id,
        request_fingerprint,
        transition_kind,
        outcome_code
    ) REFERENCES authorization_operation_receipts (
        community_id,
        operation_id,
        request_fingerprint,
        operation_kind,
        outcome_code
    ) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (community_id, old_binding_id, old_binding_version)
        REFERENCES identity_bindings (community_id, binding_id, binding_version)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (community_id, successor_binding_id, successor_binding_version)
        REFERENCES identity_bindings (community_id, binding_id, binding_version)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (history_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (operation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (
        (old_binding_id IS NULL
            AND old_binding_version IS NULL
            AND old_prior_lifecycle_revision IS NULL
            AND old_prior_state IS NULL
            AND old_resulting_lifecycle_revision IS NULL
            AND old_resulting_state IS NULL)
        OR (old_binding_id IS NOT NULL
            AND old_binding_version IS NOT NULL
            AND old_prior_lifecycle_revision IS NOT NULL
            AND old_prior_state IS NOT NULL
            AND old_resulting_lifecycle_revision IS NOT NULL
            AND old_resulting_state IS NOT NULL)
    ),
    CHECK (
        (successor_binding_id IS NULL
            AND successor_binding_version IS NULL
            AND successor_lifecycle_revision IS NULL
            AND successor_state IS NULL)
        OR (successor_binding_id IS NOT NULL
            AND successor_binding_version IS NOT NULL
            AND successor_lifecycle_revision = 1
            AND successor_state = 1)
    ),
    CHECK (
        old_binding_id IS NULL
        OR successor_binding_id IS NULL
        OR old_binding_id <> successor_binding_id
    ),
    CHECK (
        old_binding_version IS NULL
        OR successor_binding_version IS NULL
        OR old_binding_version <> successor_binding_version
    ),
    CHECK (
        old_binding_id IS NULL
        OR (old_prior_lifecycle_revision = 1
            AND old_prior_state = 1
            AND old_resulting_lifecycle_revision = 2
            AND old_resulting_state = 2)
        OR (transition_kind IN (7, 8)
            AND old_prior_lifecycle_revision = 2
            AND old_prior_state = 2
            AND old_resulting_lifecycle_revision = 2
            AND old_resulting_state = 2)
    ),
    CHECK (
        (outcome_code = 3
            AND old_binding_id IS NULL
            AND successor_binding_id IS NULL)
        OR (outcome_code = 1 AND (
            (transition_kind IN (1, 2)
                AND old_binding_id IS NULL
                AND successor_binding_id IS NOT NULL)
            OR (transition_kind = 3
                AND old_binding_id IS NOT NULL
                AND successor_binding_id IS NULL)
            OR (transition_kind IN (4, 5)
                AND successor_binding_id IS NULL)
            OR (transition_kind = 6
                AND old_binding_id IS NOT NULL
                AND successor_binding_id IS NOT NULL)
            OR (transition_kind = 7
                AND old_binding_id IS NOT NULL
                AND successor_binding_id IS NOT NULL)
            OR (transition_kind = 8
                AND successor_binding_id IS NOT NULL)
            OR (transition_kind = 9
                AND old_binding_id IS NOT NULL
                AND successor_binding_id IS NULL)
        ))
    )
);

CREATE INDEX identity_lifecycle_history_old_binding
    ON identity_lifecycle_history (community_id, old_binding_id, old_binding_version, recorded_at);
CREATE INDEX identity_lifecycle_history_successor_binding
    ON identity_lifecycle_history (
        community_id,
        successor_binding_id,
        successor_binding_version,
        recorded_at
    );

-- Circular birth/transition ordering is deliberate and fully deferred. Every
-- generation must commit with its exact birth transition, and a retired row
-- must commit with the exact transition that changed Active/r1 to Retired/r2.
ALTER TABLE identity_bindings
    ADD CONSTRAINT identity_bindings_exact_birth_history_fk
    FOREIGN KEY (
        community_id,
        birth_history_id,
        binding_id,
        binding_version,
        creation_operation_id,
        creation_request_fingerprint
    ) REFERENCES identity_lifecycle_history (
        community_id,
        history_id,
        successor_binding_id,
        successor_binding_version,
        operation_id,
        request_fingerprint
    ) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE identity_bindings
    ADD CONSTRAINT identity_bindings_exact_retirement_history_fk
    FOREIGN KEY (
        community_id,
        retirement_history_id,
        binding_id,
        binding_version,
        lifecycle_revision,
        binding_state
    ) REFERENCES identity_lifecycle_history (
        community_id,
        history_id,
        old_binding_id,
        old_binding_version,
        old_resulting_lifecycle_revision,
        old_resulting_state
    ) DEFERRABLE INITIALLY DEFERRED;

-- One immutable closed-scope fact table. selector_kind is:
-- 1 retired pair (P), 2 disabled identity (X), 3 revoked key (Y),
-- 4 pending replacement (Q_D). P/Y are permanent. X/Q are semantically open
-- exactly while they have no immutable consumption row.
CREATE TABLE identity_lifecycle_selectors (
    community_id UUID NOT NULL REFERENCES communities(id),
    selector_id UUID NOT NULL,
    selector_kind SMALLINT NOT NULL CHECK (selector_kind IN (1, 2, 3, 4)),
    selector_fingerprint BYTEA NOT NULL CHECK (octet_length(selector_fingerprint) = 32),
    fact_generation BIGINT NOT NULL CHECK (fact_generation > 0),
    principal_fingerprint BYTEA CHECK (
        principal_fingerprint IS NULL OR octet_length(principal_fingerprint) = 32
    ),
    event_author_pubkey BYTEA CHECK (
        event_author_pubkey IS NULL OR octet_length(event_author_pubkey) = 32
    ),
    binding_id UUID,
    binding_version BIGINT CHECK (binding_version IS NULL OR binding_version > 0),
    asserted_history_id UUID NOT NULL,
    selected_by_operation_id UUID NOT NULL,
    selected_by_request_fingerprint BYTEA NOT NULL CHECK (
        octet_length(selected_by_request_fingerprint) = 32
    ),
    selected_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (community_id, selector_id),
    UNIQUE (community_id, selector_id, selector_kind),
    UNIQUE (community_id, selector_kind, selector_fingerprint, fact_generation),
    FOREIGN KEY (
        community_id,
        asserted_history_id,
        selected_by_operation_id,
        selected_by_request_fingerprint
    ) REFERENCES identity_lifecycle_history (
        community_id,
        history_id,
        operation_id,
        request_fingerprint
    ) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (
        community_id,
        selected_by_operation_id,
        selected_by_request_fingerprint
    ) REFERENCES authorization_operation_receipts (
        community_id,
        operation_id,
        request_fingerprint
    ) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (community_id, binding_id, binding_version)
        REFERENCES identity_bindings (community_id, binding_id, binding_version)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (selector_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (
        (selector_kind = 1
            AND fact_generation = 1
            AND principal_fingerprint IS NOT NULL
            AND event_author_pubkey IS NOT NULL
            AND binding_id IS NOT NULL
            AND binding_version IS NOT NULL)
        OR (selector_kind = 2
            AND principal_fingerprint IS NOT NULL
            AND event_author_pubkey IS NULL
            AND binding_id IS NULL
            AND binding_version IS NULL)
        OR (selector_kind = 3
            AND fact_generation = 1
            AND principal_fingerprint IS NULL
            AND event_author_pubkey IS NOT NULL
            AND binding_id IS NULL
            AND binding_version IS NULL)
        OR (selector_kind = 4
            AND principal_fingerprint IS NOT NULL
            AND event_author_pubkey IS NOT NULL
            AND binding_id IS NOT NULL
            AND binding_version IS NOT NULL)
    )
);

CREATE UNIQUE INDEX identity_lifecycle_selectors_permanent_pair
    ON identity_lifecycle_selectors (community_id, binding_id, binding_version)
    WHERE selector_kind = 1;
CREATE UNIQUE INDEX identity_lifecycle_selectors_permanent_principal_key
    ON identity_lifecycle_selectors (
        community_id,
        principal_fingerprint,
        event_author_pubkey
    ) WHERE selector_kind = 1;
CREATE UNIQUE INDEX identity_lifecycle_selectors_permanent_key
    ON identity_lifecycle_selectors (community_id, event_author_pubkey)
    WHERE selector_kind = 3;
CREATE UNIQUE INDEX identity_lifecycle_selectors_fact_generation
    ON identity_lifecycle_selectors (
        community_id,
        selector_kind,
        principal_fingerprint,
        fact_generation
    ) WHERE selector_kind IN (2, 4);
CREATE INDEX identity_lifecycle_selectors_principal_lookup
    ON identity_lifecycle_selectors
        (community_id, selector_kind, principal_fingerprint, fact_generation);
CREATE INDEX identity_lifecycle_selectors_key_lookup
    ON identity_lifecycle_selectors
        (community_id, selector_kind, event_author_pubkey, fact_generation);
CREATE INDEX identity_lifecycle_selectors_binding_lookup
    ON identity_lifecycle_selectors
        (community_id, selector_kind, binding_id, binding_version, fact_generation);
CREATE INDEX identity_lifecycle_selectors_asserted_history
    ON identity_lifecycle_selectors
        (community_id, asserted_history_id, selector_kind);

-- One-winner immutable X/Q consumption. The same Enable transition and
-- successor may consume both facts; only the selector identity is unique.
CREATE TABLE identity_lifecycle_selector_consumptions (
    community_id UUID NOT NULL REFERENCES communities(id),
    selector_id UUID NOT NULL,
    selector_kind SMALLINT NOT NULL CHECK (selector_kind IN (2, 4)),
    history_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    successor_binding_id UUID NOT NULL,
    successor_binding_version BIGINT NOT NULL CHECK (successor_binding_version > 0),
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (community_id, selector_id),
    FOREIGN KEY (community_id, selector_id, selector_kind)
        REFERENCES identity_lifecycle_selectors
            (community_id, selector_id, selector_kind)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (community_id, operation_id, request_fingerprint)
        REFERENCES authorization_operation_receipts
            (community_id, operation_id, request_fingerprint)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (
        community_id,
        history_id,
        successor_binding_id,
        successor_binding_version,
        operation_id,
        request_fingerprint
    ) REFERENCES identity_lifecycle_history (
        community_id,
        history_id,
        successor_binding_id,
        successor_binding_version,
        operation_id,
        request_fingerprint
    ) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX identity_lifecycle_consumptions_history
    ON identity_lifecycle_selector_consumptions
        (community_id, history_id, selector_kind);

-- Derive the complete legacy projection before installing mutation guards.
-- The ordering is global: one PostgreSQL identity sequence backs every domain.
CREATE TEMPORARY TABLE nip_fi_upgrade_binding_map_0031 ON COMMIT DROP AS
WITH derived AS (
    SELECT
        legacy.*,
        nip_fi_upgrade_hash_v1(
            'buzz:identity-principal:v1',
            uuid_send(legacy.community_id),
            convert_to(legacy.issuer, 'UTF8'),
            convert_to(legacy.uid, 'UTF8')
        ) AS principal_fingerprint,
        nip_fi_upgrade_id_v1(
            'binding',
            nip_fi_upgrade_hash_v1(
                'buzz:nip-fi-upgrade:binding-birth:v1',
                uuid_send(legacy.community_id),
                convert_to(legacy.issuer, 'UTF8'),
                convert_to(legacy.uid, 'UTF8'),
                legacy.pubkey,
                convert_to(legacy.source, 'UTF8'),
                nip_fi_upgrade_timestamp_v1(legacy.created_at)
            )
        ) AS binding_id,
        CASE legacy.source WHEN 'jwt_npub' THEN 1::SMALLINT ELSE 3::SMALLINT END
            AS binding_provenance,
        CASE legacy.source WHEN 'jwt_npub' THEN 1::BIGINT ELSE 3::BIGINT END
            AS policy_revision,
        nip_fi_upgrade_hash_v1(
            'buzz:nip-fi-upgrade:enrollment-evidence:v1',
            uuid_send(legacy.community_id),
            convert_to(legacy.issuer, 'UTF8'),
            convert_to(legacy.uid, 'UTF8'),
            legacy.pubkey,
            convert_to(legacy.source, 'UTF8'),
            nip_fi_upgrade_timestamp_v1(legacy.created_at)
        ) AS enrollment_evidence_digest
    FROM identity_bindings_legacy_0031 legacy
), numbered AS (
    SELECT
        derived.*,
        row_number() OVER (
            ORDER BY community_id, created_at, binding_id
        )::BIGINT AS binding_version
    FROM derived
)
SELECT
    current_binding.*,
    predecessor.binding_id AS predecessor_binding_id,
    predecessor.binding_version AS predecessor_binding_version,
    predecessor.revocation_scope AS predecessor_revocation_scope
FROM numbered current_binding
LEFT JOIN numbered predecessor
  ON predecessor.community_id = current_binding.community_id
 AND predecessor.issuer = current_binding.issuer
 AND predecessor.uid = current_binding.uid
 AND predecessor.rotated_to_pubkey = current_binding.pubkey
 AND predecessor.rotation_completed_at = current_binding.created_at;

CREATE UNIQUE INDEX nip_fi_upgrade_binding_map_id_0031
    ON nip_fi_upgrade_binding_map_0031 (community_id, binding_id);

INSERT INTO identity_enrollment_policies (
    community_id,
    policy_revision,
    enrollment_mode,
    policy_digest,
    effective_at,
    expires_at,
    recorded_at
)
SELECT
    community_id,
    policy_revision,
    binding_provenance,
    nip_fi_upgrade_hash_v1(
        'buzz:nip-fi-upgrade:enrollment-policy:v1',
        uuid_send(community_id),
        int8send(policy_revision),
        int2send(binding_provenance)
    ),
    min(created_at),
    NULL,
    min(created_at)
FROM nip_fi_upgrade_binding_map_0031
GROUP BY community_id, policy_revision, binding_provenance;

CREATE TEMPORARY TABLE nip_fi_upgrade_operations_0031 ON COMMIT DROP AS
WITH operation_inputs AS (
    -- Root births. A rotation successor is born by Rotate or Recover below.
    SELECT
        binding.community_id,
        CASE binding.source WHEN 'jwt_npub' THEN 'enroll' ELSE 'provision' END AS label,
        CASE binding.source WHEN 'jwt_npub' THEN 1::SMALLINT ELSE 2::SMALLINT END
            AS transition_kind,
        1::SMALLINT AS event_kind,
        NULL::UUID AS old_binding_id,
        NULL::BIGINT AS old_binding_version,
        NULL::BIGINT AS old_prior_lifecycle_revision,
        NULL::SMALLINT AS old_prior_state,
        NULL::BIGINT AS old_resulting_lifecycle_revision,
        NULL::SMALLINT AS old_resulting_state,
        binding.binding_id AS successor_binding_id,
        binding.binding_version AS successor_binding_version,
        binding.principal_fingerprint,
        binding.pubkey AS event_author_pubkey,
        binding.created_at AS occurred_at,
        NULL::BYTEA AS raw_actor,
        binding.source::TEXT AS raw_reason
    FROM nip_fi_upgrade_binding_map_0031 binding
    WHERE binding.predecessor_binding_id IS NULL

    UNION ALL

    -- The operation that first retires one legacy generation.
    SELECT
        binding.community_id,
        CASE binding.revocation_scope
            WHEN 'principal' THEN 'disable'
            WHEN 'key' THEN 'revoke'
            ELSE 'rotate'
        END,
        CASE binding.revocation_scope
            WHEN 'principal' THEN 4::SMALLINT
            WHEN 'key' THEN 5::SMALLINT
            ELSE 6::SMALLINT
        END,
        CASE binding.revocation_scope
            WHEN 'principal' THEN 7::SMALLINT
            WHEN 'key' THEN 2::SMALLINT
            ELSE 3::SMALLINT
        END,
        binding.binding_id,
        binding.binding_version,
        1::BIGINT,
        1::SMALLINT,
        2::BIGINT,
        2::SMALLINT,
        CASE WHEN binding.revocation_scope = 'rotation'
             THEN successor.binding_id END,
        CASE WHEN binding.revocation_scope = 'rotation'
             THEN successor.binding_version END,
        binding.principal_fingerprint,
        binding.pubkey,
        CASE WHEN binding.revocation_scope = 'rotation'
             THEN binding.rotation_completed_at ELSE binding.revoked_at END,
        CASE WHEN binding.revocation_scope = 'rotation'
             THEN binding.rotation_by ELSE binding.revoked_by END,
        CASE WHEN binding.revocation_scope = 'rotation'
             THEN binding.rotation_reason ELSE binding.revoked_reason END
    FROM nip_fi_upgrade_binding_map_0031 binding
    LEFT JOIN nip_fi_upgrade_binding_map_0031 successor
      ON successor.predecessor_binding_id = binding.binding_id
     AND successor.predecessor_binding_version = binding.binding_version
    WHERE binding.revoked_at IS NOT NULL

    UNION ALL

    -- A previously key-revoked generation can only create its successor by
    -- consuming the exact pending-replacement fact in Recover.
    SELECT
        binding.community_id,
        'recover',
        7::SMALLINT,
        4::SMALLINT,
        binding.binding_id,
        binding.binding_version,
        2::BIGINT,
        2::SMALLINT,
        2::BIGINT,
        2::SMALLINT,
        successor.binding_id,
        successor.binding_version,
        binding.principal_fingerprint,
        successor.pubkey,
        binding.rotation_completed_at,
        binding.rotation_by,
        binding.rotation_reason
    FROM nip_fi_upgrade_binding_map_0031 binding
    JOIN nip_fi_upgrade_binding_map_0031 successor
      ON successor.predecessor_binding_id = binding.binding_id
     AND successor.predecessor_binding_version = binding.binding_version
    WHERE binding.revocation_scope = 'key'
      AND binding.rotation_completed_at IS NOT NULL

    UNION ALL

    -- A disabled principal with no exact retired binding remains an immutable,
    -- open X fact; no authenticated denial receipt is invented.
    SELECT
        principal.community_id,
        'inactive-disable',
        4::SMALLINT,
        7::SMALLINT,
        NULL::UUID,
        NULL::BIGINT,
        NULL::BIGINT,
        NULL::SMALLINT,
        NULL::BIGINT,
        NULL::SMALLINT,
        NULL::UUID,
        NULL::BIGINT,
        nip_fi_upgrade_hash_v1(
            'buzz:identity-principal:v1',
            uuid_send(principal.community_id),
            convert_to(principal.issuer, 'UTF8'),
            convert_to(principal.uid, 'UTF8')
        ),
        NULL::BYTEA,
        principal.disabled_at,
        principal.disabled_by,
        principal.disabled_reason
    FROM identity_principals_legacy_0031 principal
    WHERE principal.disabled_at IS NOT NULL
      AND NOT EXISTS (
          SELECT 1
          FROM nip_fi_upgrade_binding_map_0031 binding
          WHERE binding.community_id = principal.community_id
            AND binding.issuer = principal.issuer
            AND binding.uid = principal.uid
            AND binding.revocation_scope = 'principal'
            AND binding.revoked_at = principal.disabled_at
            AND binding.revoked_by IS NOT DISTINCT FROM principal.disabled_by
            AND COALESCE(NULLIF(binding.revoked_reason, ''),
                         'legacy principal revocation') = principal.disabled_reason
      )

    UNION ALL

    -- Every key tombstone not already represented by a key-scope Revoke is a
    -- separate inactive Revoke/Y fact. This preserves the old global denial.
    SELECT
        revoked.community_id,
        'inactive-revoke',
        5::SMALLINT,
        2::SMALLINT,
        NULL::UUID,
        NULL::BIGINT,
        NULL::BIGINT,
        NULL::SMALLINT,
        NULL::BIGINT,
        NULL::SMALLINT,
        NULL::UUID,
        NULL::BIGINT,
        NULL::BYTEA,
        revoked.pubkey,
        revoked.revoked_at,
        revoked.revoked_by,
        revoked.reason
    FROM identity_revoked_keys_legacy_0031 revoked
    WHERE NOT EXISTS (
        SELECT 1
        FROM nip_fi_upgrade_binding_map_0031 binding
        WHERE binding.community_id = revoked.community_id
          AND binding.pubkey = revoked.pubkey
          AND binding.revocation_scope = 'key'
          AND binding.revoked_at = revoked.revoked_at
          AND binding.revoked_by IS NOT DISTINCT FROM revoked.revoked_by
          AND COALESCE(NULLIF(binding.revoked_reason, ''),
                       'legacy key revocation') = revoked.reason
    )
), seeded AS (
    SELECT
        operation_inputs.*,
        nip_fi_upgrade_hash_v1(
            'buzz:nip-fi-upgrade:operation:v1',
            uuid_send(community_id),
            convert_to(label, 'UTF8'),
            nip_fi_upgrade_nullable_v1(
                CASE WHEN old_binding_id IS NULL THEN NULL ELSE uuid_send(old_binding_id) END
            ),
            nip_fi_upgrade_nullable_v1(
                CASE WHEN successor_binding_id IS NULL THEN NULL
                     ELSE uuid_send(successor_binding_id) END
            ),
            nip_fi_upgrade_timestamp_v1(occurred_at),
            nip_fi_upgrade_nullable_v1(raw_actor),
            nip_fi_upgrade_nullable_v1(
                CASE WHEN raw_reason IS NULL THEN NULL ELSE convert_to(raw_reason, 'UTF8') END
            )
        ) AS operation_seed
    FROM operation_inputs
), identified AS (
    SELECT
        seeded.*,
        nip_fi_upgrade_id_v1('operation', operation_seed) AS operation_id,
        nip_fi_upgrade_hash_v1(
            'buzz:nip-fi-upgrade:request:v1',
            operation_seed,
            int2send(transition_kind)
        ) AS request_fingerprint,
        nip_fi_upgrade_hash_v1(
            'buzz:nip-fi-upgrade:result:v1',
            operation_seed,
            int2send(1::SMALLINT)
        ) AS result_digest,
        nip_fi_upgrade_id_v1('history', operation_seed) AS history_id,
        nip_fi_upgrade_hash_v1(
            'buzz:nip-fi-upgrade:transition:v1',
            operation_seed,
            int2send(transition_kind)
        ) AS transition_digest,
        nip_fi_upgrade_hash_v1(
            'buzz:nip-fi-upgrade:local-authority-actor:v1',
            uuid_send(community_id),
            int2send(transition_kind),
            nip_fi_upgrade_nullable_v1(raw_actor),
            nip_fi_upgrade_nullable_v1(
                CASE WHEN raw_reason IS NULL THEN NULL ELSE convert_to(raw_reason, 'UTF8') END
            )
        ) AS actor_fingerprint
    FROM seeded
)
SELECT
    identified.*,
    nip_fi_upgrade_id_v1('event', operation_seed) AS event_id,
    nip_fi_upgrade_id_v1('correlation', operation_seed) AS correlation_id,
    nip_fi_upgrade_id_v1('attempt', operation_seed) AS attempt_id
FROM identified;

CREATE UNIQUE INDEX nip_fi_upgrade_operations_id_0031
    ON nip_fi_upgrade_operations_0031 (community_id, operation_id);

INSERT INTO authorization_operation_receipts (
    community_id,
    operation_id,
    request_fingerprint,
    operation_kind,
    actor_fingerprint,
    outcome_code,
    result_digest,
    recorded_at
)
SELECT
    community_id,
    operation_id,
    request_fingerprint,
    transition_kind,
    actor_fingerprint,
    1,
    result_digest,
    occurred_at
FROM nip_fi_upgrade_operations_0031;

INSERT INTO identity_lifecycle_history (
    community_id,
    history_id,
    transition_kind,
    outcome_code,
    old_binding_id,
    old_binding_version,
    old_prior_lifecycle_revision,
    old_prior_state,
    old_resulting_lifecycle_revision,
    old_resulting_state,
    successor_binding_id,
    successor_binding_version,
    successor_lifecycle_revision,
    successor_state,
    operation_id,
    request_fingerprint,
    transition_digest,
    recorded_at
)
SELECT
    community_id,
    history_id,
    transition_kind,
    1,
    old_binding_id,
    old_binding_version,
    old_prior_lifecycle_revision,
    old_prior_state,
    old_resulting_lifecycle_revision,
    old_resulting_state,
    successor_binding_id,
    successor_binding_version,
    CASE WHEN successor_binding_id IS NULL THEN NULL ELSE 1::BIGINT END,
    CASE WHEN successor_binding_id IS NULL THEN NULL ELSE 1::SMALLINT END,
    operation_id,
    request_fingerprint,
    transition_digest,
    occurred_at
FROM nip_fi_upgrade_operations_0031;

INSERT INTO identity_bindings (
    community_id,
    binding_id,
    binding_version,
    issuer,
    subject,
    principal_fingerprint,
    event_author_pubkey,
    binding_state,
    lifecycle_revision,
    binding_provenance,
    policy_revision,
    enrollment_evidence_digest,
    expires_at,
    birth_history_id,
    creation_operation_id,
    creation_request_fingerprint,
    retirement_history_id,
    created_at,
    updated_at
) OVERRIDING SYSTEM VALUE
SELECT
    binding.community_id,
    binding.binding_id,
    binding.binding_version,
    binding.issuer,
    binding.uid,
    binding.principal_fingerprint,
    binding.pubkey,
    CASE WHEN binding.revoked_at IS NULL THEN 1::SMALLINT ELSE 2::SMALLINT END,
    CASE WHEN binding.revoked_at IS NULL THEN 1::BIGINT ELSE 2::BIGINT END,
    binding.binding_provenance,
    binding.policy_revision,
    binding.enrollment_evidence_digest,
    NULL,
    birth.history_id,
    birth.operation_id,
    birth.request_fingerprint,
    retirement.history_id,
    binding.created_at,
    CASE WHEN binding.revoked_at IS NULL THEN binding.created_at
         WHEN binding.revocation_scope = 'rotation' THEN binding.rotation_completed_at
         ELSE binding.revoked_at END
FROM nip_fi_upgrade_binding_map_0031 binding
JOIN nip_fi_upgrade_operations_0031 birth
  ON birth.community_id = binding.community_id
 AND birth.successor_binding_id = binding.binding_id
 AND birth.successor_binding_version = binding.binding_version
 AND (
     (binding.predecessor_binding_id IS NULL AND birth.transition_kind IN (1, 2))
     OR (binding.predecessor_revocation_scope = 'rotation' AND birth.transition_kind = 6)
     OR (binding.predecessor_revocation_scope = 'key' AND birth.transition_kind = 7)
 )
LEFT JOIN nip_fi_upgrade_operations_0031 retirement
  ON retirement.community_id = binding.community_id
 AND retirement.old_binding_id = binding.binding_id
 AND retirement.old_binding_version = binding.binding_version
 AND retirement.old_prior_lifecycle_revision = 1
 AND retirement.old_resulting_lifecycle_revision = 2;

SELECT setval(
    pg_get_serial_sequence('identity_bindings', 'binding_version'),
    COALESCE((SELECT max(binding_version) FROM identity_bindings), 0) + 1,
    false
);

CREATE TEMPORARY TABLE nip_fi_upgrade_selectors_0031 ON COMMIT DROP AS
WITH selector_inputs AS (
    SELECT operation.*, 1::SMALLINT AS selector_kind,
           operation.principal_fingerprint AS selector_principal,
           operation.event_author_pubkey AS selector_key,
           operation.old_binding_id AS selector_binding_id,
           operation.old_binding_version AS selector_binding_version
    FROM nip_fi_upgrade_operations_0031 operation
    WHERE operation.old_binding_id IS NOT NULL
      AND operation.transition_kind IN (3, 4, 5, 6, 9)

    UNION ALL

    SELECT operation.*, 2::SMALLINT,
           operation.principal_fingerprint, NULL::BYTEA, NULL::UUID, NULL::BIGINT
    FROM nip_fi_upgrade_operations_0031 operation
    WHERE operation.transition_kind = 4

    UNION ALL

    SELECT operation.*, 3::SMALLINT,
           NULL::BYTEA, operation.event_author_pubkey, NULL::UUID, NULL::BIGINT
    FROM nip_fi_upgrade_operations_0031 operation
    WHERE operation.transition_kind = 5

    UNION ALL

    SELECT operation.*, 4::SMALLINT,
           operation.principal_fingerprint, operation.event_author_pubkey,
           operation.old_binding_id, operation.old_binding_version
    FROM nip_fi_upgrade_operations_0031 operation
    WHERE operation.old_binding_id IS NOT NULL
      AND operation.transition_kind IN (3, 4, 5, 9)
), fingerprinted AS (
    SELECT
        selector_inputs.*,
        nip_fi_upgrade_hash_v1(
            CASE selector_kind
                WHEN 1 THEN 'buzz:identity-selector:retired-pair:v1'
                WHEN 2 THEN 'buzz:identity-selector:disabled-principal:v1'
                WHEN 3 THEN 'buzz:identity-selector:revoked-key:v1'
                ELSE 'buzz:identity-selector:pending-replacement:v1'
            END,
            uuid_send(community_id),
            int2send(selector_kind),
            nip_fi_upgrade_nullable_v1(selector_principal),
            nip_fi_upgrade_nullable_v1(selector_key),
            nip_fi_upgrade_nullable_v1(
                CASE WHEN selector_binding_id IS NULL THEN NULL
                     ELSE uuid_send(selector_binding_id) END
            ),
            nip_fi_upgrade_nullable_v1(
                CASE WHEN selector_binding_version IS NULL THEN NULL
                     ELSE int8send(selector_binding_version) END
            ),
            int8send(1::BIGINT)
        ) AS selector_fingerprint
    FROM selector_inputs
)
SELECT
    fingerprinted.*,
    nip_fi_upgrade_id_v1(
        CASE selector_kind WHEN 1 THEN 'selector-p' WHEN 2 THEN 'selector-x'
             WHEN 3 THEN 'selector-y' ELSE 'selector-q' END,
        selector_fingerprint
    ) AS selector_id
FROM fingerprinted;

INSERT INTO identity_lifecycle_selectors (
    community_id,
    selector_id,
    selector_kind,
    selector_fingerprint,
    fact_generation,
    principal_fingerprint,
    event_author_pubkey,
    binding_id,
    binding_version,
    asserted_history_id,
    selected_by_operation_id,
    selected_by_request_fingerprint,
    selected_at
)
SELECT
    community_id,
    selector_id,
    selector_kind,
    selector_fingerprint,
    1,
    selector_principal,
    selector_key,
    selector_binding_id,
    selector_binding_version,
    history_id,
    operation_id,
    request_fingerprint,
    occurred_at
FROM nip_fi_upgrade_selectors_0031;

INSERT INTO identity_lifecycle_selector_consumptions (
    community_id,
    selector_id,
    selector_kind,
    history_id,
    operation_id,
    request_fingerprint,
    successor_binding_id,
    successor_binding_version,
    consumed_at
)
SELECT
    recover.community_id,
    pending.selector_id,
    4,
    recover.history_id,
    recover.operation_id,
    recover.request_fingerprint,
    recover.successor_binding_id,
    recover.successor_binding_version,
    recover.occurred_at
FROM nip_fi_upgrade_operations_0031 recover
JOIN nip_fi_upgrade_selectors_0031 pending
  ON pending.community_id = recover.community_id
 AND pending.selector_kind = 4
 AND pending.selector_binding_id = recover.old_binding_id
 AND pending.selector_binding_version = recover.old_binding_version
WHERE recover.transition_kind = 7;

INSERT INTO authorization_events (
    community_id,
    event_id,
    schema_version,
    event_kind,
    outcome_code,
    reason_code,
    actor_kind,
    actor_fingerprint,
    subject_fingerprint,
    operation_id,
    request_fingerprint,
    correlation_id,
    attempt_id,
    occurred_at,
    accepted_at,
    canonical_envelope,
    envelope_digest
)
SELECT
    operation.community_id,
    operation.event_id,
    1,
    operation.event_kind,
    1,
    16,
    1,
    operation.actor_fingerprint,
    operation.principal_fingerprint,
    operation.operation_id,
    operation.request_fingerprint,
    operation.correlation_id,
    operation.attempt_id,
    operation.occurred_at,
    operation.occurred_at,
    envelope.canonical_envelope,
    digest(envelope.canonical_envelope, 'sha256')
FROM nip_fi_upgrade_operations_0031 operation
CROSS JOIN LATERAL (
    SELECT convert_to(
        jsonb_build_object(
            'schema_version', 1,
            'event_id', operation.event_id,
            'event_kind', operation.event_kind,
            'outcome_code', 1,
            'reason_code', 16,
            'actor_kind', 1,
            'actor_fingerprint', encode(operation.actor_fingerprint, 'hex'),
            'subject_fingerprint', CASE
                WHEN operation.principal_fingerprint IS NULL THEN NULL
                ELSE encode(operation.principal_fingerprint, 'hex')
            END,
            'operation_id', operation.operation_id,
            'request_fingerprint', encode(operation.request_fingerprint, 'hex'),
            'correlation_id', operation.correlation_id,
            'attempt_id', operation.attempt_id,
            'occurred_at_micros',
                (extract(epoch FROM operation.occurred_at) * 1000000)::BIGINT
        )::TEXT,
        'UTF8'
    ) AS canonical_envelope
) envelope;

DO $$
DECLARE
    projected_events BIGINT;
    projected_bytes BIGINT;
    projected_largest INTEGER;
BEGIN
    SELECT count(*),
           COALESCE(sum(octet_length(canonical_envelope)), 0),
           COALESCE(max(octet_length(canonical_envelope)), 0)
    INTO projected_events, projected_bytes, projected_largest
    FROM authorization_events;
    IF projected_events > 1000000
        OR projected_bytes > 4294967296
        OR projected_largest > 65536
    THEN
        RAISE EXCEPTION 'NIP-FI 0031 blocked: imported audit corpus exceeds V1 hard ceilings'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'nip_fi_0031_imported_event_capacity';
    END IF;
END;
$$;

INSERT INTO authorization_event_capacity (
    community_id,
    configuration_state,
    max_events_per_domain,
    max_bytes_per_domain,
    max_envelope_bytes,
    retained_event_count,
    retained_envelope_bytes,
    retained_largest_envelope_bytes,
    health_state,
    failure_code,
    failure_observed_at,
    configured_at,
    updated_at
)
SELECT
    community_id,
    1,
    NULL,
    NULL,
    NULL,
    count(*),
    sum(octet_length(canonical_envelope)),
    max(octet_length(canonical_envelope)),
    1,
    NULL,
    NULL,
    NULL,
    max(accepted_at)
FROM authorization_events
GROUP BY community_id;

SET CONSTRAINTS ALL IMMEDIATE;

DO $$
BEGIN
    IF (SELECT count(*) FROM identity_bindings)
        <> (SELECT count(*) FROM nip_fi_upgrade_binding_map_0031)
       OR (SELECT count(*) FROM authorization_operation_receipts)
        <> (SELECT count(*) FROM nip_fi_upgrade_operations_0031)
       OR (SELECT count(*) FROM identity_lifecycle_history)
        <> (SELECT count(*) FROM nip_fi_upgrade_operations_0031)
       OR (SELECT count(*) FROM authorization_events)
        <> (SELECT count(*) FROM nip_fi_upgrade_operations_0031)
       OR EXISTS (
           SELECT 1
           FROM authorization_event_capacity capacity
           CROSS JOIN LATERAL (
               SELECT count(*) AS event_count,
                      COALESCE(sum(octet_length(event.canonical_envelope)), 0) AS event_bytes,
                      COALESCE(max(octet_length(event.canonical_envelope)), 0) AS largest
               FROM authorization_events event
               WHERE event.community_id = capacity.community_id
           ) actual
           WHERE capacity.configuration_state <> 1
              OR capacity.retained_event_count <> actual.event_count
              OR capacity.retained_envelope_bytes <> actual.event_bytes
              OR capacity.retained_largest_envelope_bytes <> actual.largest
       )
    THEN
        RAISE EXCEPTION 'NIP-FI 0031 blocked: projected authority is incomplete'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'nip_fi_0031_projection_completeness';
    END IF;
END;
$$;

DROP TABLE identity_bindings_legacy_0031;
DROP TABLE identity_principals_legacy_0031;
DROP TABLE identity_revoked_keys_legacy_0031;

CREATE FUNCTION nip_fi_reject_row_mutation_v1() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION '% is immutable', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION nip_fi_reject_truncate_v1() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION '% cannot be truncated', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END;
$$ LANGUAGE plpgsql;

-- Every binding/selector path derives the same domain-scoped coordinates and
-- takes their signed BIGINT advisory keys in numeric order. Typed transaction
-- APIs take these locks before row mutation; the triggers are the fail-closed
-- backstop for direct SQL.
CREATE FUNCTION identity_lifecycle_lock_coordinates_v1(
    locked_community_id UUID,
    locked_principal_fingerprint BYTEA,
    locked_event_author_pubkey BYTEA
) RETURNS VOID AS $$
DECLARE
    principal_lock_key BIGINT;
    event_author_lock_key BIGINT;
BEGIN
    IF locked_principal_fingerprint IS NOT NULL THEN
        principal_lock_key := hashtextextended(
            'buzz:identity-lifecycle-coordinate:v1:principal:'
                || locked_community_id::text || ':'
                || encode(locked_principal_fingerprint, 'hex'),
            0
        );
    END IF;
    IF locked_event_author_pubkey IS NOT NULL THEN
        event_author_lock_key := hashtextextended(
            'buzz:identity-lifecycle-coordinate:v1:key:'
                || locked_community_id::text || ':'
                || encode(locked_event_author_pubkey, 'hex'),
            0
        );
    END IF;

    IF principal_lock_key IS NOT NULL AND event_author_lock_key IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(LEAST(principal_lock_key, event_author_lock_key));
        IF principal_lock_key <> event_author_lock_key THEN
            PERFORM pg_advisory_xact_lock(GREATEST(principal_lock_key, event_author_lock_key));
        END IF;
    ELSIF principal_lock_key IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(principal_lock_key);
    ELSIF event_author_lock_key IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(event_author_lock_key);
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION identity_bindings_insert_guard_v1() RETURNS TRIGGER AS $$
BEGIN
    PERFORM identity_lifecycle_lock_coordinates_v1(
        NEW.community_id,
        NEW.principal_fingerprint,
        NEW.event_author_pubkey
    );
    IF NEW.binding_state <> 1
        OR NEW.lifecycle_revision <> 1
        OR NEW.retirement_history_id IS NOT NULL
    THEN
        RAISE EXCEPTION 'identity binding birth must be Active at lifecycle revision 1'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'identity_bindings_birth_state';
    END IF;
    NEW.created_at := transaction_timestamp();
    NEW.updated_at := transaction_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION identity_bindings_transition_guard_v1() RETURNS TRIGGER AS $$
BEGIN
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    PERFORM identity_lifecycle_lock_coordinates_v1(
        OLD.community_id,
        OLD.principal_fingerprint,
        OLD.event_author_pubkey
    );
    IF NEW.community_id IS DISTINCT FROM OLD.community_id
        OR NEW.binding_id IS DISTINCT FROM OLD.binding_id
        OR NEW.binding_version IS DISTINCT FROM OLD.binding_version
        OR NEW.issuer IS DISTINCT FROM OLD.issuer
        OR NEW.subject IS DISTINCT FROM OLD.subject
        OR NEW.principal_fingerprint IS DISTINCT FROM OLD.principal_fingerprint
        OR NEW.event_author_pubkey IS DISTINCT FROM OLD.event_author_pubkey
        OR NEW.binding_provenance IS DISTINCT FROM OLD.binding_provenance
        OR NEW.policy_revision IS DISTINCT FROM OLD.policy_revision
        OR NEW.enrollment_evidence_digest IS DISTINCT FROM OLD.enrollment_evidence_digest
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
        OR NEW.birth_history_id IS DISTINCT FROM OLD.birth_history_id
        OR NEW.creation_operation_id IS DISTINCT FROM OLD.creation_operation_id
        OR NEW.creation_request_fingerprint IS DISTINCT FROM OLD.creation_request_fingerprint
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'identity binding generation coordinates are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'identity_bindings_immutable_generation';
    END IF;
    IF OLD.binding_state <> 1
        OR OLD.lifecycle_revision <> 1
        OR OLD.retirement_history_id IS NOT NULL
        OR NEW.binding_state <> 2
        OR NEW.lifecycle_revision <> 2
        OR NEW.retirement_history_id IS NULL
        OR NEW.retirement_history_id = OLD.birth_history_id
    THEN
        RAISE EXCEPTION 'identity binding permits only Active/r1 to Retired/r2'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'identity_bindings_active_to_retired';
    END IF;
    NEW.updated_at := transaction_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION identity_lifecycle_history_insert_guard_v1() RETURNS TRIGGER AS $$
BEGIN
    NEW.recorded_at := transaction_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION identity_binding_history_semantics_guard_v1() RETURNS TRIGGER AS $$
DECLARE
    retirement identity_lifecycle_history%ROWTYPE;
BEGIN
    IF NEW.binding_state = 2 THEN
        SELECT * INTO STRICT retirement
        FROM identity_lifecycle_history
        WHERE community_id = NEW.community_id
          AND history_id = NEW.retirement_history_id
          AND old_binding_id = NEW.binding_id
          AND old_binding_version = NEW.binding_version;
        IF retirement.outcome_code <> 1
            OR retirement.old_prior_lifecycle_revision <> 1
            OR retirement.old_prior_state <> 1
            OR retirement.old_resulting_lifecycle_revision <> 2
            OR retirement.old_resulting_state <> 2
        THEN
            RAISE EXCEPTION 'retired binding must reference its exact Active-to-Retired transition'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'identity_bindings_retirement_history_semantics';
        END IF;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION identity_binding_birth_eligibility_guard_v1() RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM identity_lifecycle_selectors selector
        LEFT JOIN identity_lifecycle_selector_consumptions consumption
          ON consumption.community_id = selector.community_id
         AND consumption.selector_id = selector.selector_id
        WHERE selector.community_id = NEW.community_id
          AND (
            (selector.selector_kind = 1
                AND selector.principal_fingerprint = NEW.principal_fingerprint
                AND selector.event_author_pubkey = NEW.event_author_pubkey)
            OR (selector.selector_kind = 3
                AND selector.event_author_pubkey = NEW.event_author_pubkey)
            OR (selector.selector_kind IN (2, 4)
                AND selector.principal_fingerprint = NEW.principal_fingerprint
                AND consumption.selector_id IS NULL)
          )
    ) THEN
        RAISE EXCEPTION 'binding birth conflicts with an effective lifecycle selector'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'identity_bindings_birth_eligibility';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION authorization_operation_receipt_history_guard_v1() RETURNS TRIGGER AS $$
DECLARE
    history_count BIGINT;
    expected_count BIGINT;
BEGIN
    SELECT count(*) INTO history_count
    FROM identity_lifecycle_history history
    WHERE history.community_id = NEW.community_id
      AND history.operation_id = NEW.operation_id;

    expected_count := CASE
        WHEN NEW.operation_kind BETWEEN 1 AND 9 AND NEW.outcome_code IN (1, 3) THEN 1
        ELSE 0
    END;
    IF history_count <> expected_count THEN
        RAISE EXCEPTION 'operation receipt requires % lifecycle history row, found %',
            expected_count, history_count
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_operation_receipt_history_cardinality';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION identity_lifecycle_selector_insert_guard_v1() RETURNS TRIGGER AS $$
DECLARE
    prior_generation BIGINT;
BEGIN
    NEW.selected_at := transaction_timestamp();
    PERFORM identity_lifecycle_lock_coordinates_v1(
        NEW.community_id,
        CASE WHEN NEW.selector_kind IN (1, 2, 4) THEN NEW.principal_fingerprint END,
        CASE WHEN NEW.selector_kind IN (1, 3) THEN NEW.event_author_pubkey END
    );
    IF NEW.selector_kind NOT IN (2, 4) THEN
        RETURN NEW;
    END IF;
    SELECT max(selector.fact_generation) INTO prior_generation
    FROM identity_lifecycle_selectors selector
    WHERE selector.community_id = NEW.community_id
      AND selector.selector_kind = NEW.selector_kind
      AND selector.principal_fingerprint = NEW.principal_fingerprint;
    IF prior_generation IS NOT NULL AND NEW.fact_generation <= prior_generation THEN
        RAISE EXCEPTION 'selector fact generation must advance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'identity_lifecycle_selector_fact_generation';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM identity_lifecycle_selectors selector
        LEFT JOIN identity_lifecycle_selector_consumptions consumption
          ON consumption.community_id = selector.community_id
         AND consumption.selector_id = selector.selector_id
        WHERE selector.community_id = NEW.community_id
          AND selector.selector_kind = NEW.selector_kind
          AND selector.principal_fingerprint = NEW.principal_fingerprint
          AND consumption.selector_id IS NULL
    ) THEN
        RAISE EXCEPTION 'an unconsumed selector fact already exists'
            USING ERRCODE = 'unique_violation',
                  CONSTRAINT = 'identity_lifecycle_selector_one_open_fact';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION identity_lifecycle_selector_history_guard_v1() RETURNS TRIGGER AS $$
DECLARE
    history identity_lifecycle_history%ROWTYPE;
    old_binding identity_bindings%ROWTYPE;
BEGIN
    SELECT * INTO STRICT history
    FROM identity_lifecycle_history
    WHERE community_id = NEW.community_id
      AND history_id = NEW.asserted_history_id
      AND operation_id = NEW.selected_by_operation_id
      AND request_fingerprint = NEW.selected_by_request_fingerprint;

    IF history.old_binding_id IS NOT NULL THEN
        SELECT * INTO STRICT old_binding
        FROM identity_bindings
        WHERE community_id = history.community_id
          AND binding_id = history.old_binding_id
          AND binding_version = history.old_binding_version;
    END IF;

    IF history.outcome_code <> 1
        OR (NEW.selector_kind = 1 AND (
            history.transition_kind NOT IN (3, 4, 5, 6, 9)
            OR history.old_binding_id IS DISTINCT FROM NEW.binding_id
            OR history.old_binding_version IS DISTINCT FROM NEW.binding_version
            OR old_binding.principal_fingerprint IS DISTINCT FROM NEW.principal_fingerprint
            OR old_binding.event_author_pubkey IS DISTINCT FROM NEW.event_author_pubkey
        ))
        OR (NEW.selector_kind = 2 AND (
            history.transition_kind <> 4
            OR (history.old_binding_id IS NOT NULL
                AND old_binding.principal_fingerprint
                    IS DISTINCT FROM NEW.principal_fingerprint)
        ))
        OR (NEW.selector_kind = 3 AND (
            history.transition_kind <> 5
            OR (history.old_binding_id IS NOT NULL
                AND old_binding.event_author_pubkey
                    IS DISTINCT FROM NEW.event_author_pubkey)
        ))
        OR (NEW.selector_kind = 4 AND (
            history.transition_kind NOT IN (3, 4, 5, 9)
            OR history.old_binding_id IS DISTINCT FROM NEW.binding_id
            OR history.old_binding_version IS DISTINCT FROM NEW.binding_version
            OR old_binding.principal_fingerprint IS DISTINCT FROM NEW.principal_fingerprint
            OR old_binding.event_author_pubkey IS DISTINCT FROM NEW.event_author_pubkey
        ))
    THEN
        RAISE EXCEPTION 'selector does not match its lifecycle transition'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'identity_lifecycle_selector_history_semantics';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION identity_lifecycle_transition_integrity_guard_v1() RETURNS TRIGGER AS $$
DECLARE
    transition identity_lifecycle_history%ROWTYPE;
    old_binding_state SMALLINT;
    asserted_p BIGINT;
    asserted_x BIGINT;
    asserted_y BIGINT;
    asserted_q BIGINT;
    consumed_x BIGINT;
    consumed_q BIGINT;
BEGIN
    IF TG_TABLE_NAME = 'identity_lifecycle_history' THEN
        transition := NEW;
    ELSIF TG_TABLE_NAME = 'identity_lifecycle_selectors' THEN
        SELECT * INTO STRICT transition
        FROM identity_lifecycle_history
        WHERE community_id = NEW.community_id
          AND history_id = NEW.asserted_history_id;
    ELSIF TG_TABLE_NAME = 'identity_lifecycle_selector_consumptions' THEN
        SELECT * INTO STRICT transition
        FROM identity_lifecycle_history
        WHERE community_id = NEW.community_id
          AND history_id = NEW.history_id;
    ELSE
        SELECT * INTO STRICT transition
        FROM identity_lifecycle_history
        WHERE community_id = NEW.community_id
          AND history_id = CASE
              WHEN NEW.binding_state = 2 THEN NEW.retirement_history_id
              ELSE NEW.birth_history_id
          END;
    END IF;

    SELECT
        count(*) FILTER (WHERE selector_kind = 1),
        count(*) FILTER (WHERE selector_kind = 2),
        count(*) FILTER (WHERE selector_kind = 3),
        count(*) FILTER (WHERE selector_kind = 4)
    INTO asserted_p, asserted_x, asserted_y, asserted_q
    FROM identity_lifecycle_selectors
    WHERE community_id = transition.community_id
      AND asserted_history_id = transition.history_id;

    SELECT
        count(*) FILTER (WHERE selector_kind = 2),
        count(*) FILTER (WHERE selector_kind = 4)
    INTO consumed_x, consumed_q
    FROM identity_lifecycle_selector_consumptions
    WHERE community_id = transition.community_id
      AND history_id = transition.history_id;

    IF transition.old_binding_id IS NOT NULL THEN
        SELECT binding_state INTO STRICT old_binding_state
        FROM identity_bindings
        WHERE community_id = transition.community_id
          AND binding_id = transition.old_binding_id
          AND binding_version = transition.old_binding_version;
        IF old_binding_state <> 2 THEN
            RAISE EXCEPTION 'lifecycle transition old binding must be retired at commit'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'identity_lifecycle_transition_integrity';
        END IF;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM identity_lifecycle_selectors selector
        LEFT JOIN identity_lifecycle_selector_consumptions consumption
          ON consumption.community_id = selector.community_id
         AND consumption.selector_id = selector.selector_id
        JOIN identity_bindings active
          ON active.community_id = selector.community_id
         AND active.binding_state = 1
         AND (
            (selector.selector_kind = 1
                AND active.principal_fingerprint = selector.principal_fingerprint
                AND active.event_author_pubkey = selector.event_author_pubkey)
            OR (selector.selector_kind IN (2, 4)
                AND consumption.selector_id IS NULL
                AND active.principal_fingerprint = selector.principal_fingerprint)
            OR (selector.selector_kind = 3
                AND active.event_author_pubkey = selector.event_author_pubkey)
         )
        WHERE selector.community_id = transition.community_id
    ) THEN
        RAISE EXCEPTION 'effective lifecycle selector conflicts with an active binding'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'identity_lifecycle_transition_integrity';
    END IF;

    IF transition.outcome_code = 3 THEN
        IF asserted_p + asserted_x + asserted_y + asserted_q + consumed_x + consumed_q <> 0 THEN
            RAISE EXCEPTION 'no-op lifecycle transition cannot create or consume selector facts'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'identity_lifecycle_transition_integrity';
        END IF;
        RETURN NULL;
    END IF;

    IF (transition.transition_kind IN (1, 2)
            AND (asserted_p, asserted_x, asserted_y, asserted_q, consumed_x, consumed_q)
                <> (0, 0, 0, 0, 0, 0))
        OR (transition.transition_kind = 3
            AND (asserted_p, asserted_x, asserted_y, asserted_q, consumed_x, consumed_q)
                <> (1, 0, 0, 1, 0, 0))
        OR (transition.transition_kind = 4 AND (
            (transition.old_binding_id IS NOT NULL
                AND (asserted_p, asserted_x, asserted_y, asserted_q, consumed_x, consumed_q)
                    <> (1, 1, 0, 1, 0, 0))
            OR (transition.old_binding_id IS NULL
                AND (asserted_p, asserted_x, asserted_y, asserted_q, consumed_x, consumed_q)
                    <> (0, 1, 0, 0, 0, 0))
        ))
        OR (transition.transition_kind = 5 AND (
            (transition.old_binding_id IS NOT NULL
                AND (asserted_p, asserted_x, asserted_y, asserted_q, consumed_x, consumed_q)
                    <> (1, 0, 1, 1, 0, 0))
            OR (transition.old_binding_id IS NULL
                AND (asserted_p, asserted_x, asserted_y, asserted_q, consumed_x, consumed_q)
                    <> (0, 0, 1, 0, 0, 0))
        ))
        OR (transition.transition_kind = 6
            AND (asserted_p, asserted_x, asserted_y, asserted_q, consumed_x, consumed_q)
                <> (1, 0, 0, 0, 0, 0))
        OR (transition.transition_kind = 7
            AND (asserted_p, asserted_x, asserted_y, asserted_q, consumed_x, consumed_q)
                <> (0, 0, 0, 0, 0, 1))
        OR (transition.transition_kind = 8 AND (
            (asserted_p, asserted_x, asserted_y, asserted_q, consumed_x)
                <> (0, 0, 0, 0, 1)
            OR consumed_q NOT IN (0, 1)
            OR (transition.old_binding_id IS NULL AND consumed_q <> 0)
            OR (transition.old_binding_id IS NOT NULL AND consumed_q <> 1)
        ))
        OR (transition.transition_kind = 9
            AND (asserted_p, asserted_x, asserted_y, asserted_q, consumed_x, consumed_q)
                <> (1, 0, 0, 1, 0, 0))
    THEN
        RAISE EXCEPTION 'lifecycle transition has incomplete or forbidden selector companions'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'identity_lifecycle_transition_integrity';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION identity_lifecycle_consumption_lock_v1() RETURNS TRIGGER AS $$
DECLARE
    selector identity_lifecycle_selectors%ROWTYPE;
BEGIN
    SELECT * INTO STRICT selector
    FROM identity_lifecycle_selectors
    WHERE community_id = NEW.community_id
      AND selector_id = NEW.selector_id;
    PERFORM identity_lifecycle_lock_coordinates_v1(
        selector.community_id,
        selector.principal_fingerprint,
        NULL
    );
    NEW.consumed_at := transaction_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION identity_lifecycle_consumption_history_guard_v1() RETURNS TRIGGER AS $$
DECLARE
    selector identity_lifecycle_selectors%ROWTYPE;
    successor identity_bindings%ROWTYPE;
    history identity_lifecycle_history%ROWTYPE;
BEGIN
    SELECT * INTO STRICT selector
    FROM identity_lifecycle_selectors
    WHERE community_id = NEW.community_id
      AND selector_id = NEW.selector_id
      AND selector_kind = NEW.selector_kind;
    SELECT * INTO STRICT successor
    FROM identity_bindings
    WHERE community_id = NEW.community_id
      AND binding_id = NEW.successor_binding_id
      AND binding_version = NEW.successor_binding_version;
    SELECT * INTO STRICT history
    FROM identity_lifecycle_history
    WHERE community_id = NEW.community_id
      AND history_id = NEW.history_id
      AND operation_id = NEW.operation_id
      AND request_fingerprint = NEW.request_fingerprint
      AND successor_binding_id = NEW.successor_binding_id
      AND successor_binding_version = NEW.successor_binding_version;

    IF successor.principal_fingerprint IS DISTINCT FROM selector.principal_fingerprint
        OR (NEW.selector_kind = 2 AND history.transition_kind <> 8)
        OR (NEW.selector_kind = 4 AND history.transition_kind NOT IN (7, 8))
        OR (NEW.selector_kind = 4 AND (
            history.old_binding_id IS DISTINCT FROM selector.binding_id
            OR history.old_binding_version IS DISTINCT FROM selector.binding_version
        ))
    THEN
        RAISE EXCEPTION 'selector consumption does not match its successor transition'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'identity_lifecycle_consumption_history_semantics';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER identity_bindings_insert_guard
    BEFORE INSERT ON identity_bindings
    FOR EACH ROW EXECUTE FUNCTION identity_bindings_insert_guard_v1();
CREATE TRIGGER identity_bindings_transition_guard
    BEFORE UPDATE ON identity_bindings
    FOR EACH ROW EXECUTE FUNCTION identity_bindings_transition_guard_v1();
CREATE CONSTRAINT TRIGGER identity_bindings_history_semantics
    AFTER INSERT OR UPDATE ON identity_bindings
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION identity_binding_history_semantics_guard_v1();
CREATE CONSTRAINT TRIGGER identity_bindings_birth_eligibility
    AFTER INSERT ON identity_bindings
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION identity_binding_birth_eligibility_guard_v1();
CREATE CONSTRAINT TRIGGER identity_bindings_transition_integrity
    AFTER INSERT OR UPDATE ON identity_bindings
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION identity_lifecycle_transition_integrity_guard_v1();
CREATE TRIGGER identity_bindings_no_delete
    BEFORE DELETE ON identity_bindings
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER identity_bindings_no_truncate
    BEFORE TRUNCATE ON identity_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE TRIGGER identity_lifecycle_history_insert_guard
    BEFORE INSERT ON identity_lifecycle_history
    FOR EACH ROW EXECUTE FUNCTION identity_lifecycle_history_insert_guard_v1();
CREATE CONSTRAINT TRIGGER authorization_operation_receipt_history_cardinality
    AFTER INSERT ON authorization_operation_receipts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION authorization_operation_receipt_history_guard_v1();
CREATE CONSTRAINT TRIGGER identity_lifecycle_transition_integrity
    AFTER INSERT ON identity_lifecycle_history
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION identity_lifecycle_transition_integrity_guard_v1();

CREATE TRIGGER identity_lifecycle_selector_insert_guard
    BEFORE INSERT ON identity_lifecycle_selectors
    FOR EACH ROW EXECUTE FUNCTION identity_lifecycle_selector_insert_guard_v1();
CREATE CONSTRAINT TRIGGER identity_lifecycle_selector_history_semantics
    AFTER INSERT ON identity_lifecycle_selectors
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION identity_lifecycle_selector_history_guard_v1();
CREATE CONSTRAINT TRIGGER identity_lifecycle_selector_transition_integrity
    AFTER INSERT ON identity_lifecycle_selectors
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION identity_lifecycle_transition_integrity_guard_v1();

CREATE TRIGGER identity_lifecycle_consumption_lock
    BEFORE INSERT ON identity_lifecycle_selector_consumptions
    FOR EACH ROW EXECUTE FUNCTION identity_lifecycle_consumption_lock_v1();
CREATE CONSTRAINT TRIGGER identity_lifecycle_consumption_history_semantics
    AFTER INSERT ON identity_lifecycle_selector_consumptions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION identity_lifecycle_consumption_history_guard_v1();
CREATE CONSTRAINT TRIGGER identity_lifecycle_consumption_transition_integrity
    AFTER INSERT ON identity_lifecycle_selector_consumptions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION identity_lifecycle_transition_integrity_guard_v1();

CREATE TRIGGER authorization_operation_receipts_immutable
    BEFORE UPDATE OR DELETE ON authorization_operation_receipts
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER authorization_operation_receipts_no_truncate
    BEFORE TRUNCATE ON authorization_operation_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE TRIGGER identity_enrollment_policies_immutable
    BEFORE UPDATE OR DELETE ON identity_enrollment_policies
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER identity_enrollment_policies_no_truncate
    BEFORE TRUNCATE ON identity_enrollment_policies
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE TRIGGER identity_lifecycle_history_immutable
    BEFORE UPDATE OR DELETE ON identity_lifecycle_history
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER identity_lifecycle_history_no_truncate
    BEFORE TRUNCATE ON identity_lifecycle_history
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE TRIGGER identity_lifecycle_selectors_immutable
    BEFORE UPDATE OR DELETE ON identity_lifecycle_selectors
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER identity_lifecycle_selectors_no_truncate
    BEFORE TRUNCATE ON identity_lifecycle_selectors
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE TRIGGER identity_lifecycle_selector_consumptions_immutable
    BEFORE UPDATE OR DELETE ON identity_lifecycle_selector_consumptions
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER identity_lifecycle_selector_consumptions_no_truncate
    BEFORE TRUNCATE ON identity_lifecycle_selector_consumptions
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE FUNCTION authorization_event_capacity_policy_insert_v1() RETURNS TRIGGER AS $$
DECLARE
    actual_count BIGINT;
    actual_bytes BIGINT;
    actual_largest INTEGER;
BEGIN
    IF NEW.configuration_state <> 2 THEN
        RAISE EXCEPTION 'only migration 0031 may create an unconfigured capacity row'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_event_capacity_configuration_required';
    END IF;

    SELECT count(*),
           COALESCE(sum(octet_length(canonical_envelope)), 0),
           COALESCE(max(octet_length(canonical_envelope)), 0)
    INTO actual_count, actual_bytes, actual_largest
    FROM authorization_events
    WHERE community_id = NEW.community_id;

    IF NEW.max_events_per_domain < actual_count
        OR NEW.max_bytes_per_domain < actual_bytes
        OR NEW.max_envelope_bytes < actual_largest
    THEN
        RAISE EXCEPTION 'authorization event capacity is below retained audit data'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_event_capacity_retained_data';
    END IF;

    NEW.retained_event_count := actual_count;
    NEW.retained_envelope_bytes := actual_bytes;
    NEW.retained_largest_envelope_bytes := actual_largest;
    NEW.configured_at := transaction_timestamp();
    NEW.updated_at := transaction_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION authorization_event_capacity_guard_v1() RETURNS TRIGGER AS $$
BEGIN
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;

    IF OLD.configuration_state = 1 THEN
        IF NEW.community_id IS DISTINCT FROM OLD.community_id
            OR NEW.configuration_state <> 2
            OR NEW.max_events_per_domain IS NULL
            OR NEW.max_bytes_per_domain IS NULL
            OR NEW.max_envelope_bytes IS NULL
            OR NEW.max_events_per_domain < OLD.retained_event_count
            OR NEW.max_bytes_per_domain < OLD.retained_envelope_bytes
            OR NEW.max_envelope_bytes < OLD.retained_largest_envelope_bytes
            OR NEW.retained_event_count <> OLD.retained_event_count
            OR NEW.retained_envelope_bytes <> OLD.retained_envelope_bytes
            OR NEW.retained_largest_envelope_bytes <> OLD.retained_largest_envelope_bytes
            OR NEW.health_state <> OLD.health_state
            OR NEW.failure_code IS DISTINCT FROM OLD.failure_code
            OR NEW.failure_observed_at IS DISTINCT FROM OLD.failure_observed_at
            OR NEW.configured_at IS NULL
            OR NEW.updated_at < OLD.updated_at
        THEN
            RAISE EXCEPTION 'authorization event capacity bootstrap adoption is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'authorization_event_capacity_bootstrap_adoption';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.community_id IS DISTINCT FROM OLD.community_id
        OR NEW.configuration_state <> 2
        OR NEW.max_events_per_domain IS DISTINCT FROM OLD.max_events_per_domain
        OR NEW.max_bytes_per_domain IS DISTINCT FROM OLD.max_bytes_per_domain
        OR NEW.max_envelope_bytes IS DISTINCT FROM OLD.max_envelope_bytes
        OR NEW.configured_at IS DISTINCT FROM OLD.configured_at
        OR NEW.retained_event_count < OLD.retained_event_count
        OR NEW.retained_envelope_bytes < OLD.retained_envelope_bytes
        OR NEW.retained_largest_envelope_bytes < OLD.retained_largest_envelope_bytes
        OR NEW.updated_at < OLD.updated_at
        OR (OLD.health_state = 2 AND (
            NEW.health_state <> 2
            OR NEW.failure_code IS DISTINCT FROM OLD.failure_code
            OR NEW.failure_observed_at IS DISTINCT FROM OLD.failure_observed_at
        ))
        OR (OLD.health_state = 1 AND NEW.health_state = 1 AND (
            NEW.failure_code IS NOT NULL OR NEW.failure_observed_at IS NOT NULL
        ))
    THEN
        RAISE EXCEPTION 'authorization event capacity cannot be reset online'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_event_capacity_immutable_policy';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION authorization_event_capacity_install_v1(
    target_community_id UUID,
    configured_max_events BIGINT,
    configured_max_bytes BIGINT,
    configured_max_envelope INTEGER
) RETURNS VOID AS $$
DECLARE
    capacity authorization_event_capacity%ROWTYPE;
    actual_count BIGINT;
    actual_bytes BIGINT;
    actual_largest INTEGER;
BEGIN
    IF target_community_id IS NULL
        OR target_community_id = '00000000-0000-0000-0000-000000000000'::UUID
        OR configured_max_events <= 0
        OR configured_max_events > 1000000
        OR configured_max_bytes <= 0
        OR configured_max_bytes > 4294967296
        OR configured_max_envelope <= 0
        OR configured_max_envelope > 65536
        OR configured_max_envelope > configured_max_bytes
    THEN
        RAISE EXCEPTION 'authorization event capacity policy is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_event_capacity_policy_bounds';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'buzz:authorization-event-capacity:v1:' || target_community_id::TEXT,
        0
    ));

    SELECT count(*),
           COALESCE(sum(octet_length(canonical_envelope)), 0),
           COALESCE(max(octet_length(canonical_envelope)), 0)
    INTO actual_count, actual_bytes, actual_largest
    FROM authorization_events
    WHERE community_id = target_community_id;

    SELECT * INTO capacity
    FROM authorization_event_capacity
    WHERE community_id = target_community_id
    FOR UPDATE;

    IF NOT FOUND THEN
        INSERT INTO authorization_event_capacity (
            community_id,
            configuration_state,
            max_events_per_domain,
            max_bytes_per_domain,
            max_envelope_bytes,
            retained_event_count,
            retained_envelope_bytes,
            retained_largest_envelope_bytes
        ) VALUES (
            target_community_id,
            2,
            configured_max_events,
            configured_max_bytes,
            configured_max_envelope,
            actual_count,
            actual_bytes,
            actual_largest
        );
        RETURN;
    END IF;

    IF capacity.retained_event_count <> actual_count
        OR capacity.retained_envelope_bytes <> actual_bytes
        OR capacity.retained_largest_envelope_bytes <> actual_largest
    THEN
        RAISE EXCEPTION 'authorization event capacity counters do not match retained audit data'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_event_capacity_counter_integrity';
    END IF;

    IF capacity.configuration_state = 2 THEN
        IF capacity.max_events_per_domain = configured_max_events
            AND capacity.max_bytes_per_domain = configured_max_bytes
            AND capacity.max_envelope_bytes = configured_max_envelope
        THEN
            RETURN;
        END IF;
        RAISE EXCEPTION 'authorization event capacity conflicts with installed policy'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_event_capacity_policy_conflict';
    END IF;

    UPDATE authorization_event_capacity
    SET configuration_state = 2,
        max_events_per_domain = configured_max_events,
        max_bytes_per_domain = configured_max_bytes,
        max_envelope_bytes = configured_max_envelope,
        configured_at = transaction_timestamp(),
        updated_at = transaction_timestamp()
    WHERE community_id = target_community_id;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION authorization_event_capacity_before_insert_v1() RETURNS TRIGGER AS $$
DECLARE
    policy authorization_event_capacity%ROWTYPE;
    envelope_bytes BIGINT;
BEGIN
    SELECT * INTO policy
    FROM authorization_event_capacity
    WHERE community_id = NEW.community_id
    FOR UPDATE;

    IF NOT FOUND OR policy.configuration_state <> 2 THEN
        RAISE EXCEPTION 'authorization event capacity policy missing'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_event_capacity_policy_required';
    END IF;
    IF policy.health_state <> 1 THEN
        RAISE EXCEPTION 'authorization audit is unavailable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_event_capacity_health';
    END IF;

    envelope_bytes := octet_length(NEW.canonical_envelope);
    IF envelope_bytes > policy.max_envelope_bytes
        OR policy.retained_event_count >= policy.max_events_per_domain
        OR envelope_bytes > policy.max_bytes_per_domain - policy.retained_envelope_bytes
    THEN
        RAISE EXCEPTION 'authorization event capacity exhausted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_event_capacity_exhausted';
    END IF;

    UPDATE authorization_event_capacity
    SET retained_event_count = retained_event_count + 1,
        retained_envelope_bytes = retained_envelope_bytes + envelope_bytes,
        retained_largest_envelope_bytes = GREATEST(
            retained_largest_envelope_bytes,
            envelope_bytes
        ),
        updated_at = transaction_timestamp()
    WHERE community_id = NEW.community_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION authorization_operation_receipt_event_guard_v1() RETURNS TRIGGER AS $$
DECLARE
    receipt authorization_operation_receipts%ROWTYPE;
    event_count BIGINT;
    expected_event_count BIGINT;
    expected_event_kind SMALLINT;
BEGIN
    IF TG_TABLE_NAME = 'authorization_operation_receipts' THEN
        receipt := NEW;
    ELSE
        IF NEW.request_fingerprint IS NULL THEN
            RETURN NULL;
        END IF;
        SELECT * INTO STRICT receipt
        FROM authorization_operation_receipts
        WHERE community_id = NEW.community_id
          AND operation_id = NEW.operation_id;
    END IF;

    IF receipt.operation_kind NOT BETWEEN 1 AND 9 THEN
        RETURN NULL;
    END IF;
    expected_event_kind := CASE receipt.operation_kind
        WHEN 1 THEN 1 WHEN 2 THEN 1 WHEN 3 THEN 6 WHEN 4 THEN 7
        WHEN 5 THEN 2 WHEN 6 THEN 3 WHEN 7 THEN 4 WHEN 8 THEN 5
        WHEN 9 THEN 8
    END;
    SELECT count(*),
           count(*) FILTER (WHERE event.event_kind = expected_event_kind)
    INTO event_count, expected_event_count
    FROM authorization_events event
    WHERE event.community_id = receipt.community_id
      AND event.operation_id = receipt.operation_id
      AND event.request_fingerprint = receipt.request_fingerprint;
    IF event_count <> 1 OR expected_event_count <> 1 THEN
        RAISE EXCEPTION 'lifecycle receipt requires exactly one canonical event, found %',
            event_count
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_operation_receipt_event_cardinality';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER authorization_event_capacity_policy_prepare
    BEFORE INSERT ON authorization_event_capacity
    FOR EACH ROW EXECUTE FUNCTION authorization_event_capacity_policy_insert_v1();
CREATE TRIGGER authorization_event_capacity_monotonic
    BEFORE UPDATE ON authorization_event_capacity
    FOR EACH ROW EXECUTE FUNCTION authorization_event_capacity_guard_v1();
CREATE TRIGGER authorization_event_capacity_no_delete
    BEFORE DELETE ON authorization_event_capacity
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER authorization_event_capacity_no_truncate
    BEFORE TRUNCATE ON authorization_event_capacity
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE TRIGGER authorization_events_capacity
    BEFORE INSERT ON authorization_events
    FOR EACH ROW EXECUTE FUNCTION authorization_event_capacity_before_insert_v1();
CREATE CONSTRAINT TRIGGER authorization_events_lifecycle_cardinality
    AFTER INSERT ON authorization_events
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION authorization_operation_receipt_event_guard_v1();
CREATE CONSTRAINT TRIGGER authorization_operation_receipt_event_cardinality
    AFTER INSERT ON authorization_operation_receipts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION authorization_operation_receipt_event_guard_v1();
CREATE TRIGGER authorization_events_immutable
    BEFORE UPDATE OR DELETE ON authorization_events
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER authorization_events_no_truncate
    BEFORE TRUNCATE ON authorization_events
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

DROP FUNCTION nip_fi_upgrade_id_v1(TEXT, BYTEA);
DROP FUNCTION nip_fi_upgrade_uuid_v5_v1(UUID, TEXT);
DROP FUNCTION nip_fi_upgrade_timestamp_v1(TIMESTAMPTZ);
DROP FUNCTION nip_fi_upgrade_nullable_v1(BYTEA);
DROP FUNCTION nip_fi_upgrade_hash_v1(TEXT, BYTEA[]);
DROP FUNCTION nip_fi_upgrade_frame_v1(BYTEA);
