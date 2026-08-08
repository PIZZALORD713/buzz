-- Provider-free invalidation, restore attribution, and status prerequisites.
--
-- 0031 owns the canonical operation receipt/event foundation; 0032 owns
-- protected authority. This additive tranche installs only the remaining
-- generic invalidation floors, exact operation delta manifests, and the
-- epoch-free ClientStatusRevision coordinate consumed by the later #4790
-- code-only status implementation.

-- Closed selectors: 1 principal, 2 Nostr key, 3 binding, 4 session, 5 domain,
-- 6 configuration revision, 7 delegated relationship. Kind 7 is the
-- authoritative relationship identity/revision coordinate; it contains no
-- provider vocabulary.
CREATE TABLE authorization_invalidation_floors (
    community_id UUID NOT NULL REFERENCES communities(id),
    selector_kind SMALLINT NOT NULL CHECK (selector_kind IN (1, 2, 3, 4, 5, 6, 7)),
    selector_fingerprint BYTEA NOT NULL CHECK (octet_length(selector_fingerprint) = 32),
    floor_generation BIGINT NOT NULL CHECK (floor_generation > 0),
    binding_version_floor BIGINT CHECK (binding_version_floor IS NULL OR binding_version_floor > 0),
    relationship_revision_floor BIGINT CHECK (
        relationship_revision_floor IS NULL OR relationship_revision_floor > 0
    ),
    operation_id UUID NOT NULL,
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (community_id, selector_kind, selector_fingerprint),
    FOREIGN KEY (community_id, operation_id, request_fingerprint)
        REFERENCES authorization_operation_receipts
            (community_id, operation_id, request_fingerprint)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (selector_kind = 3
            AND binding_version_floor IS NOT NULL
            AND relationship_revision_floor IS NULL)
        OR (selector_kind = 7
            AND binding_version_floor IS NULL
            AND relationship_revision_floor IS NOT NULL)
        OR (selector_kind NOT IN (3, 7)
            AND binding_version_floor IS NULL
            AND relationship_revision_floor IS NULL)
    )
);

-- Epoch-free kind-24244 status revision history. There is deliberately no
-- 24245 ClientBindingEpoch/bootstrap/connection field here.
-- disposition: 1 current, 2 withdrawn.
CREATE TABLE client_status_revisions (
    community_id UUID NOT NULL REFERENCES communities(id),
    event_author_pubkey BYTEA NOT NULL CHECK (octet_length(event_author_pubkey) = 32),
    revision BIGINT NOT NULL CHECK (revision > 0),
    disposition SMALLINT NOT NULL CHECK (disposition IN (1, 2)),
    binding_id UUID,
    binding_version BIGINT CHECK (binding_version IS NULL OR binding_version > 0),
    policy_revision BIGINT CHECK (policy_revision IS NULL OR policy_revision > 0),
    invalidation_generation BIGINT CHECK (
        invalidation_generation IS NULL OR invalidation_generation >= 0
    ),
    authority_epoch BIGINT CHECK (authority_epoch IS NULL OR authority_epoch > 0),
    fence BYTEA CHECK (
        fence IS NULL
        OR (octet_length(fence) = 32 AND fence <> decode(repeat('00', 32), 'hex'))
    ),
    observed_at TIMESTAMPTZ,
    fresh_until TIMESTAMPTZ,
    supersedes_revision BIGINT CHECK (supersedes_revision IS NULL OR supersedes_revision > 0),
    receipt_digest BYTEA NOT NULL CHECK (octet_length(receipt_digest) = 32),
    operation_id UUID NOT NULL,
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (community_id, event_author_pubkey, revision),
    UNIQUE (community_id, operation_id),
    FOREIGN KEY (community_id, operation_id, request_fingerprint)
        REFERENCES authorization_operation_receipts
            (community_id, operation_id, request_fingerprint)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (community_id, binding_id, binding_version)
        REFERENCES identity_bindings (community_id, binding_id, binding_version)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (community_id, event_author_pubkey, supersedes_revision)
        REFERENCES client_status_revisions (community_id, event_author_pubkey, revision)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (disposition = 1
            AND binding_id IS NOT NULL
            AND binding_version IS NOT NULL
            AND policy_revision IS NOT NULL
            AND invalidation_generation IS NOT NULL
            AND authority_epoch IS NOT NULL
            AND fence IS NOT NULL
            AND observed_at IS NOT NULL
            AND fresh_until IS NOT NULL
            AND supersedes_revision IS NULL
            AND observed_at < fresh_until
            AND fresh_until <= observed_at + INTERVAL '300 seconds')
        OR (disposition = 2
            AND binding_id IS NULL
            AND binding_version IS NULL
            AND policy_revision IS NULL
            AND invalidation_generation IS NULL
            AND authority_epoch IS NULL
            AND fence IS NULL
            AND observed_at IS NULL
            AND fresh_until IS NULL
            AND supersedes_revision IS NOT NULL
            AND supersedes_revision < revision)
    )
);

CREATE INDEX client_status_revisions_current_lookup
    ON client_status_revisions (community_id, event_author_pubkey, revision DESC);

-- Exact per-operation authority-version attribution for restore. Empty
-- manifests are valid; every stored component must advance strictly.
CREATE TABLE authorization_operation_version_delta_manifests (
    community_id UUID NOT NULL REFERENCES communities(id),
    operation_id UUID NOT NULL,
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    component_count INTEGER NOT NULL CHECK (component_count BETWEEN 0 AND 1024),
    before_digest BYTEA NOT NULL CHECK (octet_length(before_digest) = 32),
    after_digest BYTEA NOT NULL CHECK (octet_length(after_digest) = 32),
    manifest_digest BYTEA NOT NULL CHECK (octet_length(manifest_digest) = 32),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (community_id, operation_id),
    UNIQUE (community_id, operation_id, request_fingerprint),
    FOREIGN KEY (community_id, operation_id, request_fingerprint)
        REFERENCES authorization_operation_receipts
            (community_id, operation_id, request_fingerprint)
        DEFERRABLE INITIALLY DEFERRED
);

-- component_kind: 1 binding version, 2 policy revision,
-- 3 invalidation generation, 4 authority epoch, 5 client-status revision,
-- 6 delegated-relationship revision, 7 lifecycle-selector generation.
CREATE TABLE authorization_operation_version_deltas (
    community_id UUID NOT NULL REFERENCES communities(id),
    operation_id UUID NOT NULL,
    component_kind SMALLINT NOT NULL CHECK (component_kind IN (1, 2, 3, 4, 5, 6, 7)),
    component_key BYTEA NOT NULL CHECK (octet_length(component_key) = 32),
    before_version BIGINT NOT NULL CHECK (before_version >= 0),
    after_version BIGINT NOT NULL,
    component_digest BYTEA NOT NULL CHECK (octet_length(component_digest) = 32),
    PRIMARY KEY (community_id, operation_id, component_kind, component_key),
    FOREIGN KEY (community_id, operation_id)
        REFERENCES authorization_operation_version_delta_manifests
            (community_id, operation_id),
    CHECK (after_version > before_version)
);

CREATE FUNCTION authorization_invalidation_floor_guard_v1() RETURNS TRIGGER AS $$
BEGIN
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF NEW.community_id IS DISTINCT FROM OLD.community_id
        OR NEW.selector_kind IS DISTINCT FROM OLD.selector_kind
        OR NEW.selector_fingerprint IS DISTINCT FROM OLD.selector_fingerprint
        OR NEW.floor_generation < OLD.floor_generation
        OR COALESCE(NEW.binding_version_floor, 0) < COALESCE(OLD.binding_version_floor, 0)
        OR COALESCE(NEW.relationship_revision_floor, 0)
            < COALESCE(OLD.relationship_revision_floor, 0)
        OR (
            NEW.floor_generation = OLD.floor_generation
            AND COALESCE(NEW.binding_version_floor, 0)
                = COALESCE(OLD.binding_version_floor, 0)
            AND COALESCE(NEW.relationship_revision_floor, 0)
                = COALESCE(OLD.relationship_revision_floor, 0)
        )
        OR NEW.operation_id IS NOT DISTINCT FROM OLD.operation_id
        OR NEW.updated_at <= OLD.updated_at
    THEN
        RAISE EXCEPTION 'authorization invalidation floor cannot move backward'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER authorization_invalidation_floors_monotonic
    BEFORE UPDATE ON authorization_invalidation_floors
    FOR EACH ROW EXECUTE FUNCTION authorization_invalidation_floor_guard_v1();
CREATE TRIGGER authorization_invalidation_floors_no_delete
    BEFORE DELETE ON authorization_invalidation_floors
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER authorization_invalidation_floors_no_truncate
    BEFORE TRUNCATE ON authorization_invalidation_floors
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE TRIGGER client_status_revisions_immutable
    BEFORE UPDATE OR DELETE ON client_status_revisions
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER client_status_revisions_no_truncate
    BEFORE TRUNCATE ON client_status_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE FUNCTION authorization_operation_version_delta_cardinality_guard_v1()
RETURNS TRIGGER AS $$
DECLARE
    manifest authorization_operation_version_delta_manifests%ROWTYPE;
    actual_component_count BIGINT;
BEGIN
    IF TG_TABLE_NAME = 'authorization_operation_version_delta_manifests' THEN
        manifest := NEW;
    ELSE
        SELECT * INTO STRICT manifest
        FROM authorization_operation_version_delta_manifests
        WHERE community_id = NEW.community_id
          AND operation_id = NEW.operation_id
        FOR NO KEY UPDATE;
    END IF;

    SELECT count(*) INTO actual_component_count
    FROM authorization_operation_version_deltas
    WHERE community_id = manifest.community_id
      AND operation_id = manifest.operation_id;

    IF actual_component_count <> manifest.component_count THEN
        RAISE EXCEPTION 'operation version manifest declares % components, found %',
            manifest.component_count, actual_component_count
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_operation_version_delta_cardinality';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER authorization_operation_version_delta_manifest_cardinality
    AFTER INSERT ON authorization_operation_version_delta_manifests
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION authorization_operation_version_delta_cardinality_guard_v1();
CREATE CONSTRAINT TRIGGER authorization_operation_version_delta_component_cardinality
    AFTER INSERT ON authorization_operation_version_deltas
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION authorization_operation_version_delta_cardinality_guard_v1();

CREATE TRIGGER authorization_operation_version_delta_manifests_immutable
    BEFORE UPDATE OR DELETE ON authorization_operation_version_delta_manifests
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER authorization_operation_version_delta_manifests_no_truncate
    BEFORE TRUNCATE ON authorization_operation_version_delta_manifests
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE TRIGGER authorization_operation_version_deltas_immutable
    BEFORE UPDATE OR DELETE ON authorization_operation_version_deltas
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER authorization_operation_version_deltas_no_truncate
    BEFORE TRUNCATE ON authorization_operation_version_deltas
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();
