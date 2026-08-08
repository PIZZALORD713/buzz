-- Dedicated bounded credential-free operator-denial audit.
--
-- This non-authoritative lane is deliberately independent from canonical
-- authorization receipts, events, capacity, and health. A saturated pre-auth
-- lane therefore cannot consume or poison canonical authorization audit.

CREATE TABLE authorization_operator_preauth_denial_capacity (
    community_id UUID NOT NULL PRIMARY KEY REFERENCES communities(id),
    max_events_per_domain BIGINT NOT NULL CHECK (
        max_events_per_domain BETWEEN 1 AND 1000000
    ),
    max_bytes_per_domain BIGINT NOT NULL CHECK (
        max_bytes_per_domain BETWEEN 1 AND 4294967296
    ),
    max_envelope_bytes INTEGER NOT NULL CHECK (
        max_envelope_bytes BETWEEN 1 AND 65536
    ),
    retained_event_count BIGINT NOT NULL DEFAULT 0 CHECK (retained_event_count >= 0),
    retained_envelope_bytes BIGINT NOT NULL DEFAULT 0 CHECK (retained_envelope_bytes >= 0),
    retained_largest_envelope_bytes INTEGER NOT NULL DEFAULT 0 CHECK (
        retained_largest_envelope_bytes >= 0
    ),
    configured_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    saturation_generation BIGINT NOT NULL DEFAULT 0,
    last_signaled_generation BIGINT NOT NULL DEFAULT 0,
    last_saturated_at TIMESTAMPTZ,
    last_recovered_at TIMESTAMPTZ,
    last_signal_at TIMESTAMPTZ,
    next_signal_at TIMESTAMPTZ,
    last_signal_xid XID8,
    CHECK (max_envelope_bytes <= max_bytes_per_domain),
    CHECK (retained_event_count <= max_events_per_domain),
    CHECK (retained_envelope_bytes <= max_bytes_per_domain),
    CHECK (retained_largest_envelope_bytes <= max_envelope_bytes),
    CONSTRAINT authorization_operator_preauth_saturation_generation_nonneg
        CHECK (saturation_generation >= 0),
    CONSTRAINT authorization_operator_preauth_signaled_generation_bounded
        CHECK (last_signaled_generation BETWEEN 0 AND saturation_generation),
    CONSTRAINT authorization_operator_preauth_saturation_state_consistent CHECK (
        (saturation_generation = 0
         AND last_signaled_generation = 0
         AND last_saturated_at IS NULL
         AND last_recovered_at IS NULL
         AND last_signal_at IS NULL
         AND next_signal_at IS NULL
         AND last_signal_xid IS NULL)
        OR
        (saturation_generation > 0
         AND last_saturated_at IS NOT NULL
         AND (
             (last_signaled_generation = 0
              AND last_signal_at IS NULL
              AND next_signal_at IS NULL
              AND last_signal_xid IS NULL)
             OR
             (last_signaled_generation > 0
              AND last_signal_at IS NOT NULL
              AND next_signal_at = last_signal_at + INTERVAL '60 seconds'
              AND last_signal_xid IS NOT NULL)
         ))
    )
);

CREATE TABLE authorization_operator_preauth_denial_events (
    community_id UUID NOT NULL REFERENCES communities(id),
    event_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    correlation_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    semantic_fingerprint BYTEA NOT NULL CHECK (octet_length(semantic_fingerprint) = 32),
    denial_reason SMALLINT NOT NULL CHECK (denial_reason IN (1, 2, 3)),
    expected_revision BIGINT NOT NULL CHECK (expected_revision > 0),
    action SMALLINT NOT NULL CHECK (action IN (1, 2, 3, 4, 5, 6, 7, 8)),
    reason_code SMALLINT NOT NULL CHECK (
        reason_code IN (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
    ),
    occurred_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    canonical_envelope BYTEA NOT NULL CHECK (
        octet_length(canonical_envelope) BETWEEN 1 AND 65536
    ),
    envelope_digest BYTEA NOT NULL CHECK (octet_length(envelope_digest) = 32),
    retain_until TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, event_id),
    UNIQUE (
        community_id,
        operation_id,
        correlation_id,
        semantic_fingerprint,
        denial_reason
    ),
    CHECK (event_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (operation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (correlation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT authorization_operator_preauth_retention_positive
        CHECK (retain_until > accepted_at)
);

CREATE INDEX authorization_operator_preauth_denial_retention
    ON authorization_operator_preauth_denial_events
       (community_id, retain_until, event_id);

CREATE FUNCTION authorization_operator_preauth_denial_capacity_before_insert_v1()
RETURNS TRIGGER AS $$
DECLARE
    policy authorization_operator_preauth_denial_capacity%ROWTYPE;
    existing authorization_operator_preauth_denial_events%ROWTYPE;
    envelope_bytes INTEGER;
    authoritative_now TIMESTAMPTZ;
    exact_count BIGINT;
    exact_bytes BIGINT;
    exact_largest INTEGER;
    new_episode BOOLEAN;
    claim_signal BOOLEAN;
    effective_generation BIGINT;
BEGIN
    SELECT * INTO policy
    FROM authorization_operator_preauth_denial_capacity
    WHERE community_id = NEW.community_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'operator pre-auth denial capacity policy missing'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_operator_preauth_capacity_required';
    END IF;
    -- Take authoritative time only after the per-domain serialization lock.
    -- Lock wait must not shorten retention or miss rows that expired while
    -- this writer was waiting.
    authoritative_now := clock_timestamp();

    SELECT * INTO existing
    FROM authorization_operator_preauth_denial_events
    WHERE community_id = NEW.community_id
      AND operation_id = NEW.operation_id
      AND correlation_id = NEW.correlation_id
      AND semantic_fingerprint = NEW.semantic_fingerprint
      AND denial_reason = NEW.denial_reason;
    IF FOUND THEN
        IF existing.event_id IS DISTINCT FROM NEW.event_id
            OR existing.attempt_id IS DISTINCT FROM NEW.attempt_id
            OR existing.expected_revision IS DISTINCT FROM NEW.expected_revision
            OR existing.action IS DISTINCT FROM NEW.action
            OR existing.reason_code IS DISTINCT FROM NEW.reason_code
            OR existing.occurred_at IS DISTINCT FROM NEW.occurred_at
            OR existing.canonical_envelope IS DISTINCT FROM NEW.canonical_envelope
            OR existing.envelope_digest IS DISTINCT FROM NEW.envelope_digest
        THEN
            RAISE EXCEPTION 'operator pre-auth denial replay payload conflicts'
                USING ERRCODE = 'unique_violation',
                      CONSTRAINT = 'authorization_operator_preauth_replay_conflict';
        END IF;
        -- Exact replay is idempotent, including when the retained row is
        -- already past its expiry but has not yet been reclaimed by another
        -- distinct attempt.
        RETURN NULL;
    END IF;

    SELECT count(*),
           COALESCE(sum(octet_length(canonical_envelope)), 0),
           COALESCE(max(octet_length(canonical_envelope)), 0)
    INTO exact_count, exact_bytes, exact_largest
    FROM authorization_operator_preauth_denial_events
    WHERE community_id = NEW.community_id;
    IF policy.retained_event_count <> exact_count
        OR policy.retained_envelope_bytes <> exact_bytes
        OR policy.retained_largest_envelope_bytes <> exact_largest
    THEN
        RAISE EXCEPTION 'operator pre-auth denial capacity counters are corrupt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'authorization_operator_preauth_counter_integrity';
    END IF;

    PERFORM set_config(
        'buzz.operator_preauth_capacity_transition',
        'reclaim:' || NEW.community_id::text,
        true
    );
    WITH candidates AS (
        SELECT community_id, event_id
        FROM authorization_operator_preauth_denial_events
        WHERE community_id = NEW.community_id
          AND retain_until <= authoritative_now
        ORDER BY retain_until, event_id
        LIMIT 256
        FOR UPDATE
    )
    DELETE FROM authorization_operator_preauth_denial_events events
    USING candidates
    WHERE events.community_id = candidates.community_id
      AND events.event_id = candidates.event_id;

    SELECT count(*),
           COALESCE(sum(octet_length(canonical_envelope)), 0),
           COALESCE(max(octet_length(canonical_envelope)), 0)
    INTO exact_count, exact_bytes, exact_largest
    FROM authorization_operator_preauth_denial_events
    WHERE community_id = NEW.community_id;
    UPDATE authorization_operator_preauth_denial_capacity
    SET retained_event_count = exact_count,
        retained_envelope_bytes = exact_bytes,
        retained_largest_envelope_bytes = exact_largest,
        updated_at = GREATEST(updated_at, authoritative_now)
    WHERE community_id = NEW.community_id
    RETURNING * INTO policy;
    PERFORM set_config('buzz.operator_preauth_capacity_transition', '', true);

    envelope_bytes := octet_length(NEW.canonical_envelope);
    IF envelope_bytes > policy.max_envelope_bytes
        OR policy.retained_event_count >= policy.max_events_per_domain
        OR envelope_bytes > policy.max_bytes_per_domain - policy.retained_envelope_bytes
    THEN
        new_episode := policy.saturation_generation = 0
            OR (policy.last_recovered_at IS NOT NULL
                AND policy.last_saturated_at IS NOT NULL
                AND policy.last_recovered_at >= policy.last_saturated_at);
        effective_generation := policy.saturation_generation
            + CASE WHEN new_episode THEN 1 ELSE 0 END;
        claim_signal := policy.last_signaled_generation < effective_generation
            AND (policy.next_signal_at IS NULL
                 OR authoritative_now >= policy.next_signal_at);
        PERFORM set_config(
            'buzz.operator_preauth_capacity_transition',
            'saturate:' || NEW.community_id::text,
            true
        );
        UPDATE authorization_operator_preauth_denial_capacity
        SET saturation_generation = CASE
                WHEN new_episode THEN saturation_generation + 1
                ELSE saturation_generation
            END,
            last_signaled_generation = CASE
                WHEN claim_signal THEN effective_generation
                ELSE last_signaled_generation
            END,
            last_saturated_at = CASE
                WHEN new_episode THEN authoritative_now
                ELSE last_saturated_at
            END,
            last_signal_at = CASE
                WHEN claim_signal THEN authoritative_now
                ELSE last_signal_at
            END,
            next_signal_at = CASE
                WHEN claim_signal THEN authoritative_now + INTERVAL '60 seconds'
                ELSE next_signal_at
            END,
            last_signal_xid = CASE
                WHEN claim_signal THEN pg_current_xact_id()
                ELSE last_signal_xid
            END,
            updated_at = GREATEST(updated_at, authoritative_now)
        WHERE community_id = NEW.community_id;
        PERFORM set_config('buzz.operator_preauth_capacity_transition', '', true);
        RETURN NULL;
    END IF;

    NEW.accepted_at := authoritative_now;
    NEW.retain_until := authoritative_now + INTERVAL '24 hours';
    PERFORM set_config(
        'buzz.operator_preauth_capacity_transition',
        'insert:' || NEW.community_id::text,
        true
    );
    PERFORM set_config(
        'buzz.operator_preauth_envelope_bytes',
        envelope_bytes::text,
        true
    );
    UPDATE authorization_operator_preauth_denial_capacity
    SET retained_event_count = retained_event_count + 1,
        retained_envelope_bytes = retained_envelope_bytes + envelope_bytes,
        retained_largest_envelope_bytes = GREATEST(
            retained_largest_envelope_bytes,
            envelope_bytes
        ),
        last_recovered_at = CASE
            WHEN last_saturated_at IS NOT NULL
                 AND (last_recovered_at IS NULL OR last_recovered_at < last_saturated_at)
            THEN authoritative_now
            ELSE last_recovered_at
        END,
        updated_at = GREATEST(updated_at, authoritative_now)
    WHERE community_id = NEW.community_id;
    PERFORM set_config('buzz.operator_preauth_envelope_bytes', '', true);
    PERFORM set_config('buzz.operator_preauth_capacity_transition', '', true);
    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('buzz.operator_preauth_envelope_bytes', '', true);
    PERFORM set_config('buzz.operator_preauth_capacity_transition', '', true);
    RAISE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE FUNCTION authorization_operator_preauth_denial_capacity_guard_v1()
RETURNS TRIGGER AS $$
DECLARE
    transition TEXT;
    exact_count BIGINT;
    exact_bytes BIGINT;
    exact_largest INTEGER;
    inserted_bytes INTEGER;
BEGIN
    transition := current_setting('buzz.operator_preauth_capacity_transition', true);
    IF TG_OP = 'INSERT' THEN
        SELECT count(*),
               COALESCE(sum(octet_length(canonical_envelope)), 0),
               COALESCE(max(octet_length(canonical_envelope)), 0)
        INTO exact_count, exact_bytes, exact_largest
        FROM authorization_operator_preauth_denial_events
        WHERE community_id = NEW.community_id;
        IF NEW.saturation_generation <> 0
            OR NEW.last_signaled_generation <> 0
            OR NEW.last_saturated_at IS NOT NULL
            OR NEW.last_recovered_at IS NOT NULL
            OR NEW.last_signal_at IS NOT NULL
            OR NEW.next_signal_at IS NOT NULL
            OR NEW.last_signal_xid IS NOT NULL
        THEN
            RAISE EXCEPTION 'operator pre-auth denial capacity must begin at exact empty state'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'authorization_operator_preauth_initial_state';
        END IF;
        -- Derivation keeps startup `INSERT ... ON CONFLICT DO NOTHING`
        -- idempotent after retained rows exist while preventing callers from
        -- fabricating aggregate counters on a genuinely new row.
        NEW.retained_event_count := exact_count;
        NEW.retained_envelope_bytes := exact_bytes;
        NEW.retained_largest_envelope_bytes := exact_largest;
        RETURN NEW;
    END IF;

    IF NEW.community_id IS DISTINCT FROM OLD.community_id
        OR NEW.max_events_per_domain IS DISTINCT FROM OLD.max_events_per_domain
        OR NEW.max_bytes_per_domain IS DISTINCT FROM OLD.max_bytes_per_domain
        OR NEW.max_envelope_bytes IS DISTINCT FROM OLD.max_envelope_bytes
        OR NEW.configured_at IS DISTINCT FROM OLD.configured_at
        OR NEW.updated_at < OLD.updated_at
    THEN
        RAISE EXCEPTION 'operator pre-auth denial capacity policy is immutable'
            USING ERRCODE = 'check_violation';
    END IF;

    IF pg_trigger_depth() <> 2 THEN
        RAISE EXCEPTION 'operator pre-auth denial capacity transition requires nested trigger ownership'
            USING ERRCODE = 'check_violation';
    END IF;

    IF transition = 'reclaim:' || OLD.community_id::text THEN
        SELECT count(*),
               COALESCE(sum(octet_length(canonical_envelope)), 0),
               COALESCE(max(octet_length(canonical_envelope)), 0)
        INTO exact_count, exact_bytes, exact_largest
        FROM authorization_operator_preauth_denial_events
        WHERE community_id = OLD.community_id;
        IF NEW.retained_event_count <> exact_count
            OR NEW.retained_envelope_bytes <> exact_bytes
            OR NEW.retained_largest_envelope_bytes <> exact_largest
            OR NEW.retained_event_count > OLD.retained_event_count
            OR NEW.retained_envelope_bytes > OLD.retained_envelope_bytes
            OR NEW.retained_largest_envelope_bytes > OLD.retained_largest_envelope_bytes
            OR NEW.saturation_generation IS DISTINCT FROM OLD.saturation_generation
            OR NEW.last_signaled_generation IS DISTINCT FROM OLD.last_signaled_generation
            OR NEW.last_saturated_at IS DISTINCT FROM OLD.last_saturated_at
            OR NEW.last_recovered_at IS DISTINCT FROM OLD.last_recovered_at
            OR NEW.last_signal_at IS DISTINCT FROM OLD.last_signal_at
            OR NEW.next_signal_at IS DISTINCT FROM OLD.next_signal_at
            OR NEW.last_signal_xid IS DISTINCT FROM OLD.last_signal_xid
        THEN
            RAISE EXCEPTION 'operator pre-auth denial reclamation counters are not exact'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    IF transition = 'saturate:' || OLD.community_id::text THEN
        IF NEW.retained_event_count IS DISTINCT FROM OLD.retained_event_count
            OR NEW.retained_envelope_bytes IS DISTINCT FROM OLD.retained_envelope_bytes
            OR NEW.retained_largest_envelope_bytes
               IS DISTINCT FROM OLD.retained_largest_envelope_bytes
            OR NEW.last_recovered_at IS DISTINCT FROM OLD.last_recovered_at
            OR NEW.saturation_generation NOT IN (
                OLD.saturation_generation,
                OLD.saturation_generation + 1
            )
            OR (NEW.saturation_generation = OLD.saturation_generation
                AND NEW.last_saturated_at IS DISTINCT FROM OLD.last_saturated_at)
            OR (NEW.saturation_generation = OLD.saturation_generation + 1
                AND (NEW.last_saturated_at IS NULL
                     OR (OLD.last_saturated_at IS NOT NULL
                         AND NEW.last_saturated_at < OLD.last_saturated_at)))
            OR NEW.last_signaled_generation NOT IN (
                OLD.last_signaled_generation,
                NEW.saturation_generation
            )
            OR (
                NEW.last_signaled_generation = OLD.last_signaled_generation
                AND (
                    NEW.last_signal_at IS DISTINCT FROM OLD.last_signal_at
                    OR NEW.next_signal_at IS DISTINCT FROM OLD.next_signal_at
                    OR NEW.last_signal_xid IS DISTINCT FROM OLD.last_signal_xid
                )
            )
            OR (
                NEW.last_signaled_generation > OLD.last_signaled_generation
                AND (
                    NEW.last_signaled_generation <> NEW.saturation_generation
                    OR NEW.last_signal_at IS NULL
                    OR NEW.next_signal_at <> NEW.last_signal_at + INTERVAL '60 seconds'
                    OR NEW.last_signal_xid IS DISTINCT FROM pg_current_xact_id()
                    OR (OLD.next_signal_at IS NOT NULL
                        AND NEW.last_signal_at < OLD.next_signal_at)
                )
            )
        THEN
            RAISE EXCEPTION 'operator pre-auth denial saturation transition is invalid'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    BEGIN
        inserted_bytes := current_setting('buzz.operator_preauth_envelope_bytes', true)::INTEGER;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'operator pre-auth denial insert is missing its exact envelope size'
            USING ERRCODE = 'check_violation';
    END;
    IF transition IS DISTINCT FROM 'insert:' || OLD.community_id::text
        OR inserted_bytes <= 0
        OR NEW.retained_event_count <> OLD.retained_event_count + 1
        OR NEW.retained_envelope_bytes <> OLD.retained_envelope_bytes + inserted_bytes
        OR NEW.retained_largest_envelope_bytes
           <> GREATEST(OLD.retained_largest_envelope_bytes, inserted_bytes)
        OR NEW.saturation_generation IS DISTINCT FROM OLD.saturation_generation
        OR NEW.last_signaled_generation IS DISTINCT FROM OLD.last_signaled_generation
        OR NEW.last_saturated_at IS DISTINCT FROM OLD.last_saturated_at
        OR NEW.last_signal_at IS DISTINCT FROM OLD.last_signal_at
        OR NEW.next_signal_at IS DISTINCT FROM OLD.next_signal_at
        OR NEW.last_signal_xid IS DISTINCT FROM OLD.last_signal_xid
        OR NOT (
            NEW.last_recovered_at IS NOT DISTINCT FROM OLD.last_recovered_at
            OR (
                OLD.last_saturated_at IS NOT NULL
                AND (OLD.last_recovered_at IS NULL
                     OR OLD.last_recovered_at < OLD.last_saturated_at)
                AND NEW.last_recovered_at >= OLD.last_saturated_at
            )
        )
    THEN
        RAISE EXCEPTION 'operator pre-auth denial capacity cannot be reset online'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE FUNCTION authorization_operator_preauth_denial_events_retention_guard_v1()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'operator pre-auth denial events are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF pg_trigger_depth() <> 2
        OR current_setting('buzz.operator_preauth_capacity_transition', true)
           IS DISTINCT FROM 'reclaim:' || OLD.community_id::text
        OR clock_timestamp() < OLD.retain_until
    THEN
        RAISE EXCEPTION 'operator pre-auth denial event is still retained'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION authorization_operator_preauth_denial_capacity_guard_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION authorization_operator_preauth_denial_events_retention_guard_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION authorization_operator_preauth_denial_capacity_before_insert_v1() FROM PUBLIC;

CREATE TRIGGER authorization_operator_preauth_denial_capacity_insert
    BEFORE INSERT ON authorization_operator_preauth_denial_events
    FOR EACH ROW EXECUTE FUNCTION authorization_operator_preauth_denial_capacity_before_insert_v1();
CREATE TRIGGER authorization_operator_preauth_denial_capacity_monotonic
    BEFORE INSERT OR UPDATE ON authorization_operator_preauth_denial_capacity
    FOR EACH ROW EXECUTE FUNCTION authorization_operator_preauth_denial_capacity_guard_v1();
CREATE TRIGGER authorization_operator_preauth_denial_capacity_no_delete
    BEFORE DELETE ON authorization_operator_preauth_denial_capacity
    FOR EACH ROW EXECUTE FUNCTION nip_fi_reject_row_mutation_v1();
CREATE TRIGGER authorization_operator_preauth_denial_capacity_no_truncate
    BEFORE TRUNCATE ON authorization_operator_preauth_denial_capacity
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();
CREATE TRIGGER authorization_operator_preauth_denial_events_immutable
    BEFORE UPDATE OR DELETE ON authorization_operator_preauth_denial_events
    FOR EACH ROW EXECUTE FUNCTION authorization_operator_preauth_denial_events_retention_guard_v1();
CREATE TRIGGER authorization_operator_preauth_denial_events_no_truncate
    BEFORE TRUNCATE ON authorization_operator_preauth_denial_events
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();
