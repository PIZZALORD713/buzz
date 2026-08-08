-- Provider-free protected-domain and per-object authority prerequisites.
--
-- The protected-domain marker is intentionally installed before the later
-- invalidation implementation. Protected mutations consume the sole
-- operation-receipt and authorization-event foundation created by 0031.
-- There are no publication, delivery, audio-ledger, restore, status, or
-- operator/pre-authentication tables in this migration.

-- Durable one-way protected-domain activation marker and current generation.
-- Later invalidation code advances the generation; removing the marker would
-- silently reclassify an Enforce domain as legacy and is always forbidden.
CREATE TABLE authorization_invalidation_domains (
    community_id UUID NOT NULL PRIMARY KEY REFERENCES communities(id),
    current_generation BIGINT NOT NULL CHECK (current_generation >= 0),
    activated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

-- Protected-object kinds: 1 domain, 2 channel, 3 repository, 4 media,
-- 5 moderation target, 6 audio session, 7 binding status. One current row is
-- the durable epoch/fence prerequisite for the exact protected authority row.
CREATE TABLE authorization_authority_epochs (
    community_id UUID NOT NULL REFERENCES communities(id),
    object_kind SMALLINT NOT NULL CHECK (object_kind IN (1, 2, 3, 4, 5, 6, 7)),
    object_key BYTEA NOT NULL CHECK (octet_length(object_key) = 32),
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    fence BYTEA NOT NULL CHECK (
        octet_length(fence) = 32 AND fence <> decode(repeat('00', 32), 'hex')
    ),
    operation_id UUID NOT NULL,
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (community_id, object_kind, object_key),
    UNIQUE (
        community_id,
        object_kind,
        object_key,
        authority_epoch,
        fence,
        operation_id,
        request_fingerprint
    ),
    FOREIGN KEY (community_id, operation_id, request_fingerprint)
        REFERENCES authorization_operation_receipts
            (community_id, operation_id, request_fingerprint)
        DEFERRABLE INITIALLY DEFERRED
);

-- Direct-final current authority for one protected object. The authorization
-- lease itself is sealed in memory and dies on restart; this row is the exact
-- durable state re-fenced before a protected mutation or emission.
CREATE TABLE protected_object_authority (
    community_id UUID NOT NULL REFERENCES communities(id),
    object_kind SMALLINT NOT NULL CHECK (object_kind IN (1, 2, 3, 4, 5, 6, 7)),
    object_key BYTEA NOT NULL CHECK (octet_length(object_key) = 32),
    capability SMALLINT NOT NULL CHECK (
        capability IN (
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27
        )
    ),
    actor_pubkey BYTEA NOT NULL CHECK (octet_length(actor_pubkey) = 32),
    owner_pubkey BYTEA CHECK (owner_pubkey IS NULL OR octet_length(owner_pubkey) = 32),
    binding_id UUID NOT NULL,
    binding_version BIGINT NOT NULL CHECK (binding_version > 0),
    delegated_relationship_id UUID,
    delegated_relationship_revision BIGINT CHECK (
        delegated_relationship_revision IS NULL OR delegated_relationship_revision > 0
    ),
    delegation_conditions_fingerprint BYTEA CHECK (
        delegation_conditions_fingerprint IS NULL
        OR octet_length(delegation_conditions_fingerprint) = 32
    ),
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    invalidation_generation BIGINT NOT NULL CHECK (invalidation_generation >= 0),
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    fence BYTEA NOT NULL CHECK (
        octet_length(fence) = 32 AND fence <> decode(repeat('00', 32), 'hex')
    ),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    operation_id UUID NOT NULL,
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    PRIMARY KEY (community_id, object_kind, object_key),
    CONSTRAINT protected_object_authority_delegated_relationship_non_nil CHECK (
        delegated_relationship_id IS NULL
        OR delegated_relationship_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    FOREIGN KEY (community_id, binding_id, binding_version)
        REFERENCES identity_bindings (community_id, binding_id, binding_version)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (community_id, operation_id, request_fingerprint)
        REFERENCES authorization_operation_receipts
            (community_id, operation_id, request_fingerprint)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (
        community_id,
        object_kind,
        object_key,
        authority_epoch,
        fence,
        operation_id,
        request_fingerprint
    ) REFERENCES authorization_authority_epochs (
        community_id,
        object_kind,
        object_key,
        authority_epoch,
        fence,
        operation_id,
        request_fingerprint
    ) DEFERRABLE INITIALLY DEFERRED,
    CHECK (issued_at < expires_at),
    CHECK (
        (owner_pubkey IS NULL
            AND delegated_relationship_id IS NULL
            AND delegated_relationship_revision IS NULL
            AND delegation_conditions_fingerprint IS NULL)
        OR (owner_pubkey IS NOT NULL
            AND delegated_relationship_id IS NOT NULL
            AND delegated_relationship_revision IS NOT NULL
            AND delegation_conditions_fingerprint IS NOT NULL)
    )
);

CREATE FUNCTION authorization_invalidation_domain_guard_v1() RETURNS TRIGGER AS $$
BEGIN
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF NEW.community_id IS DISTINCT FROM OLD.community_id
        OR NEW.activated_at IS DISTINCT FROM OLD.activated_at
        OR NEW.current_generation <= OLD.current_generation
        OR NEW.updated_at <= OLD.updated_at
    THEN
        RAISE EXCEPTION 'authorization invalidation activation/generation cannot move backward'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER authorization_invalidation_domains_monotonic
    BEFORE UPDATE ON authorization_invalidation_domains
    FOR EACH ROW EXECUTE FUNCTION authorization_invalidation_domain_guard_v1();
CREATE TRIGGER authorization_invalidation_domains_no_delete
    BEFORE DELETE ON authorization_invalidation_domains
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER authorization_invalidation_domains_no_truncate
    BEFORE TRUNCATE ON authorization_invalidation_domains
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE FUNCTION authorization_authority_epoch_guard_v1() RETURNS TRIGGER AS $$
BEGIN
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF NEW.community_id IS DISTINCT FROM OLD.community_id
        OR NEW.object_kind IS DISTINCT FROM OLD.object_kind
        OR NEW.object_key IS DISTINCT FROM OLD.object_key
        OR NEW.authority_epoch <= OLD.authority_epoch
        OR NEW.fence IS NOT DISTINCT FROM OLD.fence
        OR NEW.operation_id IS NOT DISTINCT FROM OLD.operation_id
        OR NEW.updated_at <= OLD.updated_at
    THEN
        RAISE EXCEPTION 'authorization authority epoch cannot move backward'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER authorization_authority_epochs_monotonic
    BEFORE UPDATE ON authorization_authority_epochs
    FOR EACH ROW EXECUTE FUNCTION authorization_authority_epoch_guard_v1();
CREATE TRIGGER authorization_authority_epochs_no_delete
    BEFORE DELETE ON authorization_authority_epochs
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER authorization_authority_epochs_no_truncate
    BEFORE TRUNCATE ON authorization_authority_epochs
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

CREATE FUNCTION protected_object_authority_guard_v1() RETURNS TRIGGER AS $$
BEGIN
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF NEW.community_id IS DISTINCT FROM OLD.community_id
        OR NEW.object_kind IS DISTINCT FROM OLD.object_kind
        OR NEW.object_key IS DISTINCT FROM OLD.object_key
        OR NEW.authority_epoch <= OLD.authority_epoch
        OR NEW.fence IS NOT DISTINCT FROM OLD.fence
        OR NEW.operation_id IS NOT DISTINCT FROM OLD.operation_id
        OR NEW.issued_at <= OLD.issued_at
    THEN
        RAISE EXCEPTION 'protected authority replacement requires a new operation and epoch'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER protected_object_authority_no_delete
    BEFORE DELETE ON protected_object_authority
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER protected_object_authority_no_truncate
    BEFORE TRUNCATE ON protected_object_authority
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();
CREATE TRIGGER protected_object_authority_strict_replacement
    BEFORE UPDATE ON protected_object_authority
    FOR EACH ROW EXECUTE FUNCTION protected_object_authority_guard_v1();
