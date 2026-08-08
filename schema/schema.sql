--
-- PostgreSQL database dump
--


-- Dumped from database version 17.10
-- Dumped by pg_dump version 17.10

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: approval_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.approval_status AS ENUM (
    'pending',
    'granted',
    'denied',
    'expired'
);


--
-- Name: channel_add_policy; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.channel_add_policy AS ENUM (
    'anyone',
    'owner_only',
    'nobody'
);


--
-- Name: channel_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.channel_type AS ENUM (
    'stream',
    'forum',
    'dm',
    'workflow'
);


--
-- Name: channel_visibility; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.channel_visibility AS ENUM (
    'open',
    'private'
);


--
-- Name: delivery_method; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.delivery_method AS ENUM (
    'webhook',
    'websocket'
);


--
-- Name: member_role; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.member_role AS ENUM (
    'owner',
    'admin',
    'member',
    'guest',
    'bot'
);


--
-- Name: pause_reason; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.pause_reason AS ENUM (
    'user',
    'system',
    'rate_limit'
);


--
-- Name: run_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.run_status AS ENUM (
    'pending',
    'running',
    'waiting_approval',
    'completed',
    'failed',
    'cancelled'
);


--
-- Name: subscription_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.subscription_status AS ENUM (
    'active',
    'paused',
    'deleted'
);


--
-- Name: workflow_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.workflow_status AS ENUM (
    'active',
    'disabled',
    'archived'
);


--
-- Name: authorization_authority_epoch_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_authority_epoch_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: authorization_event_capacity_before_insert_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_event_capacity_before_insert_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: authorization_event_capacity_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_event_capacity_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: authorization_event_capacity_install_v1(uuid, bigint, bigint, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_event_capacity_install_v1(target_community_id uuid, configured_max_events bigint, configured_max_bytes bigint, configured_max_envelope integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: authorization_event_capacity_policy_insert_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_event_capacity_policy_insert_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: authorization_invalidation_domain_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_invalidation_domain_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: authorization_invalidation_floor_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_invalidation_floor_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: authorization_operation_receipt_event_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_operation_receipt_event_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: authorization_operation_receipt_history_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_operation_receipt_history_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: authorization_operation_version_delta_cardinality_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_operation_version_delta_cardinality_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: authorization_operator_preauth_denial_capacity_before_insert_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_operator_preauth_denial_capacity_before_insert_v1() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
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
$$;


--
-- Name: authorization_operator_preauth_denial_capacity_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_operator_preauth_denial_capacity_guard_v1() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
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
$$;


--
-- Name: authorization_operator_preauth_denial_events_retention_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_operator_preauth_denial_events_retention_guard_v1() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
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
$$;


--
-- Name: channels_community_id_immutable(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.channels_community_id_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.community_id IS DISTINCT FROM OLD.community_id THEN
        RAISE EXCEPTION 'channels.community_id is immutable (channel % cannot be re-tenanted)', OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: enqueue_push_match_job(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enqueue_push_match_job() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Keep this allowlist identical to the relay's validated NIP-PL descriptor.
    IF NEW.kind IN (7, 9, 1059, 40007, 46010) THEN
        PERFORM pg_advisory_xact_lock_shared(
            hashtextextended('buzz_push_gate:' || NEW.community_id::text, 0));
        IF EXISTS (
            SELECT 1 FROM push_leases
            WHERE community_id = NEW.community_id
              AND active
              AND endpoint_enabled
              AND expires_at > EXTRACT(EPOCH FROM now())::bigint
        ) THEN
            INSERT INTO push_match_queue (community_id, event_id)
            VALUES (NEW.community_id, NEW.id)
            ON CONFLICT DO NOTHING;
        END IF;
    END IF;
    RETURN NEW;
END
$$;


--
-- Name: events_created_at_floor_guard(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.events_created_at_floor_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    floor_secs numeric := nullif(current_setting('buzz.created_at_floor', true), '')::numeric;
BEGIN
    IF floor_secs IS NOT NULL
       AND floor_secs > 0
       AND NEW.channel_id IS NOT NULL
       AND NEW.created_at < clock_timestamp() - make_interval(secs => floor_secs)
    THEN
        RAISE EXCEPTION
            'events.created_at % is more than % s before commit time %; below the replica-fence floor',
            NEW.created_at, floor_secs, clock_timestamp()
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NULL;
END
$$;


--
-- Name: guard_event_mention_live(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.guard_event_mention_live() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.event_kind IS DISTINCT FROM 30078 THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM events
    WHERE community_id = NEW.community_id
      AND id = NEW.event_id
      AND created_at = NEW.event_created_at
      AND deleted_at IS NULL
    FOR KEY SHARE;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: guard_nip_rs_hard_delete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.guard_nip_rs_hard_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF current_setting('buzz.nip_rs_hard_delete', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'NIP-RS hard delete requires corrected writer opt-in'
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN OLD;
END;
$$;


--
-- Name: guard_nip_rs_watermark(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.guard_nip_rs_watermark() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    advanced BOOLEAN;
BEGIN
    IF NEW.kind = 30078
       AND NEW.d_tag ~ '^read-state:[0-9a-f]{32}$'
       AND (
           SELECT count(*)
           FROM jsonb_array_elements(CASE WHEN jsonb_typeof(NEW.tags) = 'array' THEN NEW.tags ELSE '[]'::jsonb END) tag
           WHERE jsonb_typeof(tag) = 'array'
             AND tag->0 = '"d"'::jsonb
       ) = 1
       AND EXISTS (
           SELECT 1
           FROM jsonb_array_elements(CASE WHEN jsonb_typeof(NEW.tags) = 'array' THEN NEW.tags ELSE '[]'::jsonb END) tag
           WHERE jsonb_typeof(tag) = 'array'
             AND jsonb_array_length(tag) >= 2
             AND jsonb_typeof(tag->1) = 'string'
             AND tag->>0 = 'd'
             AND tag->>1 = NEW.d_tag
       )
       AND (
           SELECT count(*)
           FROM jsonb_array_elements(CASE WHEN jsonb_typeof(NEW.tags) = 'array' THEN NEW.tags ELSE '[]'::jsonb END) tag
           WHERE tag = '["t", "read-state"]'::jsonb
       ) = 1 THEN
        INSERT INTO parameterized_event_watermarks
            (community_id, kind, pubkey, d_tag, created_at, event_id)
        VALUES
            (NEW.community_id, NEW.kind, NEW.pubkey, NEW.d_tag, NEW.created_at, NEW.id)
        ON CONFLICT (community_id, kind, pubkey, d_tag) DO UPDATE SET
            created_at = EXCLUDED.created_at,
            event_id = EXCLUDED.event_id
        WHERE EXCLUDED.created_at > parameterized_event_watermarks.created_at
           OR (EXCLUDED.created_at = parameterized_event_watermarks.created_at
               AND EXCLUDED.event_id < parameterized_event_watermarks.event_id)
        RETURNING TRUE INTO advanced;

        IF NOT COALESCE(advanced, FALSE) THEN
            IF EXISTS (
                SELECT 1
                FROM parameterized_event_watermarks
                WHERE community_id = NEW.community_id
                  AND kind = NEW.kind
                  AND pubkey = NEW.pubkey
                  AND d_tag = NEW.d_tag
                  AND created_at = NEW.created_at
                  AND event_id = NEW.id
            ) THEN
                RETURN NULL;
            END IF;

            RAISE EXCEPTION 'stale NIP-RS event rejected by durable watermark'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    RETURN NEW;
END;
$_$;


--
-- Name: identity_binding_birth_eligibility_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.identity_binding_birth_eligibility_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: identity_binding_history_semantics_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.identity_binding_history_semantics_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: identity_bindings_insert_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.identity_bindings_insert_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: identity_bindings_transition_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.identity_bindings_transition_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: identity_lifecycle_consumption_history_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.identity_lifecycle_consumption_history_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: identity_lifecycle_consumption_lock_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.identity_lifecycle_consumption_lock_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: identity_lifecycle_history_insert_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.identity_lifecycle_history_insert_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.recorded_at := transaction_timestamp();
    RETURN NEW;
END;
$$;


--
-- Name: identity_lifecycle_lock_coordinates_v1(uuid, bytea, bytea); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.identity_lifecycle_lock_coordinates_v1(locked_community_id uuid, locked_principal_fingerprint bytea, locked_event_author_pubkey bytea) RETURNS void
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: identity_lifecycle_selector_history_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.identity_lifecycle_selector_history_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: identity_lifecycle_selector_insert_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.identity_lifecycle_selector_insert_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: identity_lifecycle_transition_integrity_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.identity_lifecycle_transition_integrity_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: nip_fi_reject_row_mutation_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.nip_fi_reject_row_mutation_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION '% is immutable', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END;
$$;


--
-- Name: nip_fi_reject_truncate_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.nip_fi_reject_truncate_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION '% cannot be truncated', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END;
$$;


--
-- Name: protected_object_authority_guard_v1(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.protected_object_authority_guard_v1() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: purge_soft_deleted_buzz_mesh_status(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.purge_soft_deleted_buzz_mesh_status() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.deleted_at IS NULL
       AND NEW.deleted_at IS NOT NULL
       AND NEW.kind = 30003
       AND NEW.d_tag LIKE 'buzz-mesh-member-status:%'
       AND NEW.tags @> '[["k", "buzz-mesh-status"]]'::jsonb THEN
        DELETE FROM events
        WHERE community_id = NEW.community_id
          AND created_at = NEW.created_at
          AND id = NEW.id;

        DELETE FROM event_mentions
        WHERE community_id = NEW.community_id AND event_id = NEW.id;
    END IF;

    RETURN NULL;
END;
$$;


--
-- Name: purge_soft_deleted_nip_rs(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.purge_soft_deleted_nip_rs() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
BEGIN
    IF OLD.deleted_at IS NULL
       AND NEW.deleted_at IS NOT NULL
       AND NEW.kind = 30078
       AND NEW.d_tag ~ '^read-state:[0-9a-f]{32}$'
       AND (
           SELECT count(*)
           FROM jsonb_array_elements(CASE WHEN jsonb_typeof(NEW.tags) = 'array' THEN NEW.tags ELSE '[]'::jsonb END) tag
           WHERE jsonb_typeof(tag) = 'array'
             AND tag->0 = '"d"'::jsonb
       ) = 1
       AND EXISTS (
           SELECT 1
           FROM jsonb_array_elements(CASE WHEN jsonb_typeof(NEW.tags) = 'array' THEN NEW.tags ELSE '[]'::jsonb END) tag
           WHERE jsonb_typeof(tag) = 'array'
             AND jsonb_array_length(tag) >= 2
             AND jsonb_typeof(tag->1) = 'string'
             AND tag->>0 = 'd'
             AND tag->>1 = NEW.d_tag
       )
       AND (
           SELECT count(*)
           FROM jsonb_array_elements(CASE WHEN jsonb_typeof(NEW.tags) = 'array' THEN NEW.tags ELSE '[]'::jsonb END) tag
           WHERE tag = '["t", "read-state"]'::jsonb
       ) = 1 THEN
        PERFORM set_config('buzz.nip_rs_hard_delete', 'on', true);

        DELETE FROM events
        WHERE community_id = NEW.community_id
          AND created_at = NEW.created_at
          AND id = NEW.id;

        DELETE FROM event_mentions
        WHERE community_id = NEW.community_id AND event_id = NEW.id;
    END IF;

    RETURN NULL;
END;
$_$;


--
-- Name: refresh_channel_ttl_after_event_insert(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.refresh_channel_ttl_after_event_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    channel_ttl INTEGER;
BEGIN
    -- Kind 9007 creates the channel and initializes its deadline itself.
    IF NEW.channel_id IS NOT NULL AND NEW.kind <> 9007 THEN
        BEGIN
            PERFORM pg_advisory_xact_lock_shared(hashtextextended(
                'buzz_channel_ttl:' || NEW.community_id::text || ':' || NEW.channel_id::text, 0));

            SELECT ttl_seconds INTO channel_ttl
            FROM channels
            WHERE community_id = NEW.community_id AND id = NEW.channel_id;

            IF channel_ttl IS NOT NULL THEN
                UPDATE channels
                SET ttl_deadline = clock_timestamp() + make_interval(secs => ttl_seconds)
                WHERE community_id = NEW.community_id
                  AND id = NEW.channel_id
                  AND ttl_seconds IS NOT NULL
                  AND archived_at IS NULL
                  AND deleted_at IS NULL;
            END IF;
        EXCEPTION WHEN OTHERS THEN
            -- Preserve the existing best-effort contract: a TTL refresh failure
            -- must not reject an otherwise valid durable event.
            RAISE WARNING 'channel TTL refresh failed for community %, channel %: %',
                NEW.community_id, NEW.channel_id, SQLERRM;
        END;
    END IF;
    RETURN NULL;
END
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: _operator_global_tables; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public._operator_global_tables (
    table_name text NOT NULL,
    reason text NOT NULL
);


--
-- Name: api_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_tokens (
    community_id uuid NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_hash bytea NOT NULL,
    owner_pubkey bytea NOT NULL,
    name character varying(255) NOT NULL,
    scopes jsonb NOT NULL,
    channel_ids jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_by bytea,
    created_by_self_mint boolean DEFAULT false NOT NULL,
    CONSTRAINT chk_api_tokens_hash_len CHECK ((length(token_hash) = 32))
);


--
-- Name: archived_identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.archived_identities (
    community_id uuid NOT NULL,
    pubkey text NOT NULL,
    consent_path text NOT NULL,
    actor text NOT NULL,
    reason text,
    replaced_by text,
    request_event_id text NOT NULL,
    archived_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT archived_identities_consent_path_check CHECK ((consent_path = ANY (ARRAY['self'::text, 'owner'::text, 'admin'::text])))
);


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    community_id uuid NOT NULL,
    seq bigint NOT NULL,
    hash bytea NOT NULL,
    prev_hash bytea,
    action character varying(64) NOT NULL,
    actor_pubkey bytea,
    object_id text,
    detail jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: authorization_authority_epochs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_authority_epochs (
    community_id uuid NOT NULL,
    object_kind smallint NOT NULL,
    object_key bytea NOT NULL,
    authority_epoch bigint NOT NULL,
    fence bytea NOT NULL,
    operation_id uuid NOT NULL,
    request_fingerprint bytea NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT authorization_authority_epochs_authority_epoch_check CHECK ((authority_epoch > 0)),
    CONSTRAINT authorization_authority_epochs_fence_check CHECK (((octet_length(fence) = 32) AND (fence <> decode(repeat('00'::text, 32), 'hex'::text)))),
    CONSTRAINT authorization_authority_epochs_object_key_check CHECK ((octet_length(object_key) = 32)),
    CONSTRAINT authorization_authority_epochs_object_kind_check CHECK ((object_kind = ANY (ARRAY[1, 2, 3, 4, 5, 6, 7]))),
    CONSTRAINT authorization_authority_epochs_request_fingerprint_check CHECK ((octet_length(request_fingerprint) = 32))
);


--
-- Name: authorization_event_capacity; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_event_capacity (
    community_id uuid NOT NULL,
    configuration_state smallint DEFAULT 2 NOT NULL,
    max_events_per_domain bigint,
    max_bytes_per_domain bigint,
    max_envelope_bytes integer,
    retained_event_count bigint NOT NULL,
    retained_envelope_bytes bigint NOT NULL,
    retained_largest_envelope_bytes integer NOT NULL,
    health_state smallint DEFAULT 1 NOT NULL,
    failure_code smallint,
    failure_observed_at timestamp with time zone,
    configured_at timestamp with time zone DEFAULT transaction_timestamp(),
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT authorization_event_capacity_check CHECK ((((configuration_state = 1) AND (max_events_per_domain IS NULL) AND (max_bytes_per_domain IS NULL) AND (max_envelope_bytes IS NULL) AND (configured_at IS NULL)) OR ((configuration_state = 2) AND (max_events_per_domain IS NOT NULL) AND (max_bytes_per_domain IS NOT NULL) AND (max_envelope_bytes IS NOT NULL) AND (configured_at IS NOT NULL) AND (max_envelope_bytes <= max_bytes_per_domain) AND (retained_event_count <= max_events_per_domain) AND (retained_envelope_bytes <= max_bytes_per_domain) AND (retained_largest_envelope_bytes <= max_envelope_bytes)))),
    CONSTRAINT authorization_event_capacity_check1 CHECK ((((health_state = 1) AND (failure_code IS NULL) AND (failure_observed_at IS NULL)) OR ((health_state = 2) AND (failure_code IS NOT NULL) AND (failure_observed_at IS NOT NULL)))),
    CONSTRAINT authorization_event_capacity_configuration_state_check CHECK ((configuration_state = ANY (ARRAY[1, 2]))),
    CONSTRAINT authorization_event_capacity_failure_code_check CHECK (((failure_code IS NULL) OR (failure_code = ANY (ARRAY[1, 2, 3])))),
    CONSTRAINT authorization_event_capacity_health_state_check CHECK ((health_state = ANY (ARRAY[1, 2]))),
    CONSTRAINT authorization_event_capacity_max_bytes CHECK (((max_bytes_per_domain IS NULL) OR ((max_bytes_per_domain >= 1) AND (max_bytes_per_domain <= '4294967296'::bigint)))),
    CONSTRAINT authorization_event_capacity_max_envelope CHECK (((max_envelope_bytes IS NULL) OR ((max_envelope_bytes >= 1) AND (max_envelope_bytes <= 65536)))),
    CONSTRAINT authorization_event_capacity_max_events CHECK (((max_events_per_domain IS NULL) OR ((max_events_per_domain >= 1) AND (max_events_per_domain <= 1000000)))),
    CONSTRAINT authorization_event_capacity_retained_envelope_bytes_check CHECK ((retained_envelope_bytes >= 0)),
    CONSTRAINT authorization_event_capacity_retained_event_count_check CHECK ((retained_event_count >= 0)),
    CONSTRAINT authorization_event_capacity_retained_largest_envelope_by_check CHECK (((retained_largest_envelope_bytes >= 0) AND (retained_largest_envelope_bytes <= 65536)))
);


--
-- Name: authorization_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_events (
    community_id uuid NOT NULL,
    event_id uuid NOT NULL,
    schema_version smallint DEFAULT 1 NOT NULL,
    event_kind smallint NOT NULL,
    outcome_code smallint NOT NULL,
    reason_code smallint NOT NULL,
    actor_kind smallint NOT NULL,
    actor_fingerprint bytea,
    subject_fingerprint bytea,
    operation_id uuid NOT NULL,
    request_fingerprint bytea,
    correlation_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    canonical_envelope bytea NOT NULL,
    envelope_digest bytea NOT NULL,
    CONSTRAINT authorization_events_actor_fingerprint_check CHECK (((actor_fingerprint IS NULL) OR (octet_length(actor_fingerprint) = 32))),
    CONSTRAINT authorization_events_actor_kind_check CHECK ((actor_kind = ANY (ARRAY[1, 2, 3, 4]))),
    CONSTRAINT authorization_events_attempt_id_check CHECK ((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT authorization_events_check CHECK ((((actor_kind = 4) AND (event_kind = 9) AND (request_fingerprint IS NULL)) OR ((actor_kind = ANY (ARRAY[1, 2, 3])) AND (request_fingerprint IS NOT NULL)))),
    CONSTRAINT authorization_events_check1 CHECK ((((actor_kind = 4) AND (actor_fingerprint IS NULL) AND (subject_fingerprint IS NULL)) OR ((actor_kind = ANY (ARRAY[1, 2, 3])) AND (actor_fingerprint IS NOT NULL)))),
    CONSTRAINT authorization_events_correlation_id_check CHECK ((correlation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT authorization_events_envelope_digest_check CHECK ((octet_length(envelope_digest) = 32)),
    CONSTRAINT authorization_events_envelope_size CHECK (((octet_length(canonical_envelope) >= 1) AND (octet_length(canonical_envelope) <= 65536))),
    CONSTRAINT authorization_events_event_id_check CHECK ((event_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT authorization_events_event_kind_check CHECK ((event_kind = ANY (ARRAY[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]))),
    CONSTRAINT authorization_events_operation_id_check CHECK ((operation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT authorization_events_outcome_code_check CHECK ((outcome_code = ANY (ARRAY[1, 2, 3, 4, 5]))),
    CONSTRAINT authorization_events_reason_code_check CHECK ((reason_code = ANY (ARRAY[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]))),
    CONSTRAINT authorization_events_request_fingerprint_check CHECK (((request_fingerprint IS NULL) OR (octet_length(request_fingerprint) = 32))),
    CONSTRAINT authorization_events_schema_version_check CHECK ((schema_version = 1)),
    CONSTRAINT authorization_events_subject_fingerprint_check CHECK (((subject_fingerprint IS NULL) OR (octet_length(subject_fingerprint) = 32)))
);


--
-- Name: authorization_invalidation_domains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_invalidation_domains (
    community_id uuid NOT NULL,
    current_generation bigint NOT NULL,
    activated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT authorization_invalidation_domains_current_generation_check CHECK ((current_generation >= 0))
);


--
-- Name: authorization_invalidation_floors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_invalidation_floors (
    community_id uuid NOT NULL,
    selector_kind smallint NOT NULL,
    selector_fingerprint bytea NOT NULL,
    floor_generation bigint NOT NULL,
    binding_version_floor bigint,
    relationship_revision_floor bigint,
    operation_id uuid NOT NULL,
    request_fingerprint bytea NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT authorization_invalidation_fl_relationship_revision_floor_check CHECK (((relationship_revision_floor IS NULL) OR (relationship_revision_floor > 0))),
    CONSTRAINT authorization_invalidation_floors_binding_version_floor_check CHECK (((binding_version_floor IS NULL) OR (binding_version_floor > 0))),
    CONSTRAINT authorization_invalidation_floors_check CHECK ((((selector_kind = 3) AND (binding_version_floor IS NOT NULL) AND (relationship_revision_floor IS NULL)) OR ((selector_kind = 7) AND (binding_version_floor IS NULL) AND (relationship_revision_floor IS NOT NULL)) OR ((selector_kind <> ALL (ARRAY[3, 7])) AND (binding_version_floor IS NULL) AND (relationship_revision_floor IS NULL)))),
    CONSTRAINT authorization_invalidation_floors_floor_generation_check CHECK ((floor_generation > 0)),
    CONSTRAINT authorization_invalidation_floors_request_fingerprint_check CHECK ((octet_length(request_fingerprint) = 32)),
    CONSTRAINT authorization_invalidation_floors_selector_fingerprint_check CHECK ((octet_length(selector_fingerprint) = 32)),
    CONSTRAINT authorization_invalidation_floors_selector_kind_check CHECK ((selector_kind = ANY (ARRAY[1, 2, 3, 4, 5, 6, 7])))
);


--
-- Name: authorization_operation_receipts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_operation_receipts (
    community_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    request_fingerprint bytea NOT NULL,
    operation_kind smallint NOT NULL,
    actor_fingerprint bytea NOT NULL,
    outcome_code smallint NOT NULL,
    result_digest bytea NOT NULL,
    recorded_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT authorization_operation_receipts_actor_fingerprint_check CHECK ((octet_length(actor_fingerprint) = 32)),
    CONSTRAINT authorization_operation_receipts_operation_id_check CHECK ((operation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT authorization_operation_receipts_operation_kind_check CHECK ((operation_kind = ANY (ARRAY[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]))),
    CONSTRAINT authorization_operation_receipts_outcome_code_check CHECK ((outcome_code = ANY (ARRAY[1, 2, 3]))),
    CONSTRAINT authorization_operation_receipts_request_fingerprint_check CHECK ((octet_length(request_fingerprint) = 32)),
    CONSTRAINT authorization_operation_receipts_result_digest_check CHECK ((octet_length(result_digest) = 32))
);


--
-- Name: authorization_operation_version_delta_manifests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_operation_version_delta_manifests (
    community_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    request_fingerprint bytea NOT NULL,
    component_count integer NOT NULL,
    before_digest bytea NOT NULL,
    after_digest bytea NOT NULL,
    manifest_digest bytea NOT NULL,
    recorded_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT authorization_operation_version_delta_man_component_count_check CHECK (((component_count >= 0) AND (component_count <= 1024))),
    CONSTRAINT authorization_operation_version_delta_man_manifest_digest_check CHECK ((octet_length(manifest_digest) = 32)),
    CONSTRAINT authorization_operation_version_delta_manif_before_digest_check CHECK ((octet_length(before_digest) = 32)),
    CONSTRAINT authorization_operation_version_delta_manife_after_digest_check CHECK ((octet_length(after_digest) = 32)),
    CONSTRAINT authorization_operation_version_delta_request_fingerprint_check CHECK ((octet_length(request_fingerprint) = 32))
);


--
-- Name: authorization_operation_version_deltas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_operation_version_deltas (
    community_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    component_kind smallint NOT NULL,
    component_key bytea NOT NULL,
    before_version bigint NOT NULL,
    after_version bigint NOT NULL,
    component_digest bytea NOT NULL,
    CONSTRAINT authorization_operation_version_deltas_before_version_check CHECK ((before_version >= 0)),
    CONSTRAINT authorization_operation_version_deltas_check CHECK ((after_version > before_version)),
    CONSTRAINT authorization_operation_version_deltas_component_digest_check CHECK ((octet_length(component_digest) = 32)),
    CONSTRAINT authorization_operation_version_deltas_component_key_check CHECK ((octet_length(component_key) = 32)),
    CONSTRAINT authorization_operation_version_deltas_component_kind_check CHECK ((component_kind = ANY (ARRAY[1, 2, 3, 4, 5, 6, 7])))
);


--
-- Name: authorization_operator_preauth_denial_capacity; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_operator_preauth_denial_capacity (
    community_id uuid NOT NULL,
    max_events_per_domain bigint NOT NULL,
    max_bytes_per_domain bigint NOT NULL,
    max_envelope_bytes integer NOT NULL,
    retained_event_count bigint DEFAULT 0 NOT NULL,
    retained_envelope_bytes bigint DEFAULT 0 NOT NULL,
    retained_largest_envelope_bytes integer DEFAULT 0 NOT NULL,
    configured_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    saturation_generation bigint DEFAULT 0 NOT NULL,
    last_signaled_generation bigint DEFAULT 0 NOT NULL,
    last_saturated_at timestamp with time zone,
    last_recovered_at timestamp with time zone,
    last_signal_at timestamp with time zone,
    next_signal_at timestamp with time zone,
    last_signal_xid xid8,
    CONSTRAINT authorization_operator_preau_retained_largest_envelope_by_check CHECK ((retained_largest_envelope_bytes >= 0)),
    CONSTRAINT authorization_operator_preauth_de_retained_envelope_bytes_check CHECK ((retained_envelope_bytes >= 0)),
    CONSTRAINT authorization_operator_preauth_deni_max_events_per_domain_check CHECK (((max_events_per_domain >= 1) AND (max_events_per_domain <= 1000000))),
    CONSTRAINT authorization_operator_preauth_denia_max_bytes_per_domain_check CHECK (((max_bytes_per_domain >= 1) AND (max_bytes_per_domain <= '4294967296'::bigint))),
    CONSTRAINT authorization_operator_preauth_denia_retained_event_count_check CHECK ((retained_event_count >= 0)),
    CONSTRAINT authorization_operator_preauth_denial__max_envelope_bytes_check CHECK (((max_envelope_bytes >= 1) AND (max_envelope_bytes <= 65536))),
    CONSTRAINT authorization_operator_preauth_denial_capacity_check CHECK ((max_envelope_bytes <= max_bytes_per_domain)),
    CONSTRAINT authorization_operator_preauth_denial_capacity_check1 CHECK ((retained_event_count <= max_events_per_domain)),
    CONSTRAINT authorization_operator_preauth_denial_capacity_check2 CHECK ((retained_envelope_bytes <= max_bytes_per_domain)),
    CONSTRAINT authorization_operator_preauth_denial_capacity_check3 CHECK ((retained_largest_envelope_bytes <= max_envelope_bytes)),
    CONSTRAINT authorization_operator_preauth_saturation_generation_nonneg CHECK ((saturation_generation >= 0)),
    CONSTRAINT authorization_operator_preauth_saturation_state_consistent CHECK ((((saturation_generation = 0) AND (last_signaled_generation = 0) AND (last_saturated_at IS NULL) AND (last_recovered_at IS NULL) AND (last_signal_at IS NULL) AND (next_signal_at IS NULL) AND (last_signal_xid IS NULL)) OR ((saturation_generation > 0) AND (last_saturated_at IS NOT NULL) AND (((last_signaled_generation = 0) AND (last_signal_at IS NULL) AND (next_signal_at IS NULL) AND (last_signal_xid IS NULL)) OR ((last_signaled_generation > 0) AND (last_signal_at IS NOT NULL) AND (next_signal_at = (last_signal_at + '00:01:00'::interval)) AND (last_signal_xid IS NOT NULL)))))),
    CONSTRAINT authorization_operator_preauth_signaled_generation_bounded CHECK (((last_signaled_generation >= 0) AND (last_signaled_generation <= saturation_generation)))
);


--
-- Name: authorization_operator_preauth_denial_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_operator_preauth_denial_events (
    community_id uuid NOT NULL,
    event_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    semantic_fingerprint bytea NOT NULL,
    denial_reason smallint NOT NULL,
    expected_revision bigint NOT NULL,
    action smallint NOT NULL,
    reason_code smallint NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    canonical_envelope bytea NOT NULL,
    envelope_digest bytea NOT NULL,
    retain_until timestamp with time zone NOT NULL,
    CONSTRAINT authorization_operator_preauth_denia_semantic_fingerprint_check CHECK ((octet_length(semantic_fingerprint) = 32)),
    CONSTRAINT authorization_operator_preauth_denial__canonical_envelope_check CHECK (((octet_length(canonical_envelope) >= 1) AND (octet_length(canonical_envelope) <= 65536))),
    CONSTRAINT authorization_operator_preauth_denial_e_expected_revision_check CHECK ((expected_revision > 0)),
    CONSTRAINT authorization_operator_preauth_denial_eve_envelope_digest_check CHECK ((octet_length(envelope_digest) = 32)),
    CONSTRAINT authorization_operator_preauth_denial_even_correlation_id_check CHECK ((correlation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT authorization_operator_preauth_denial_event_denial_reason_check CHECK ((denial_reason = ANY (ARRAY[1, 2, 3]))),
    CONSTRAINT authorization_operator_preauth_denial_events_action_check CHECK ((action = ANY (ARRAY[1, 2, 3, 4, 5, 6, 7, 8]))),
    CONSTRAINT authorization_operator_preauth_denial_events_attempt_id_check CHECK ((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT authorization_operator_preauth_denial_events_event_id_check CHECK ((event_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT authorization_operator_preauth_denial_events_operation_id_check CHECK ((operation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT authorization_operator_preauth_denial_events_reason_code_check CHECK ((reason_code = ANY (ARRAY[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]))),
    CONSTRAINT authorization_operator_preauth_retention_positive CHECK ((retain_until > accepted_at))
);


--
-- Name: channel_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.channel_members (
    community_id uuid NOT NULL,
    channel_id uuid NOT NULL,
    pubkey bytea NOT NULL,
    role public.member_role DEFAULT 'member'::public.member_role NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL,
    invited_by bytea,
    removed_at timestamp with time zone,
    removed_by bytea,
    hidden_at timestamp with time zone
);


--
-- Name: channels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.channels (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    community_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    channel_type public.channel_type DEFAULT 'stream'::public.channel_type NOT NULL,
    visibility public.channel_visibility DEFAULT 'open'::public.channel_visibility NOT NULL,
    description text,
    canvas text,
    created_by bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    archived_at timestamp with time zone,
    deleted_at timestamp with time zone,
    nip29_group_id character varying(255),
    topic_required boolean DEFAULT false NOT NULL,
    max_members integer,
    topic text,
    topic_set_by bytea,
    topic_set_at timestamp with time zone,
    purpose text,
    purpose_set_by bytea,
    purpose_set_at timestamp with time zone,
    participant_hash bytea,
    ttl_seconds integer,
    ttl_deadline timestamp with time zone,
    CONSTRAINT chk_channels_id_not_nil CHECK ((id <> '00000000-0000-0000-0000-000000000000'::uuid))
);


--
-- Name: client_status_revisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_status_revisions (
    community_id uuid NOT NULL,
    event_author_pubkey bytea NOT NULL,
    revision bigint NOT NULL,
    disposition smallint NOT NULL,
    binding_id uuid,
    binding_version bigint,
    policy_revision bigint,
    invalidation_generation bigint,
    authority_epoch bigint,
    fence bytea,
    observed_at timestamp with time zone,
    fresh_until timestamp with time zone,
    supersedes_revision bigint,
    receipt_digest bytea NOT NULL,
    operation_id uuid NOT NULL,
    request_fingerprint bytea NOT NULL,
    recorded_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT client_status_revisions_authority_epoch_check CHECK (((authority_epoch IS NULL) OR (authority_epoch > 0))),
    CONSTRAINT client_status_revisions_binding_version_check CHECK (((binding_version IS NULL) OR (binding_version > 0))),
    CONSTRAINT client_status_revisions_check CHECK ((((disposition = 1) AND (binding_id IS NOT NULL) AND (binding_version IS NOT NULL) AND (policy_revision IS NOT NULL) AND (invalidation_generation IS NOT NULL) AND (authority_epoch IS NOT NULL) AND (fence IS NOT NULL) AND (observed_at IS NOT NULL) AND (fresh_until IS NOT NULL) AND (supersedes_revision IS NULL) AND (observed_at < fresh_until) AND (fresh_until <= (observed_at + '00:05:00'::interval))) OR ((disposition = 2) AND (binding_id IS NULL) AND (binding_version IS NULL) AND (policy_revision IS NULL) AND (invalidation_generation IS NULL) AND (authority_epoch IS NULL) AND (fence IS NULL) AND (observed_at IS NULL) AND (fresh_until IS NULL) AND (supersedes_revision IS NOT NULL) AND (supersedes_revision < revision)))),
    CONSTRAINT client_status_revisions_disposition_check CHECK ((disposition = ANY (ARRAY[1, 2]))),
    CONSTRAINT client_status_revisions_event_author_pubkey_check CHECK ((octet_length(event_author_pubkey) = 32)),
    CONSTRAINT client_status_revisions_fence_check CHECK (((fence IS NULL) OR ((octet_length(fence) = 32) AND (fence <> decode(repeat('00'::text, 32), 'hex'::text))))),
    CONSTRAINT client_status_revisions_invalidation_generation_check CHECK (((invalidation_generation IS NULL) OR (invalidation_generation >= 0))),
    CONSTRAINT client_status_revisions_policy_revision_check CHECK (((policy_revision IS NULL) OR (policy_revision > 0))),
    CONSTRAINT client_status_revisions_receipt_digest_check CHECK ((octet_length(receipt_digest) = 32)),
    CONSTRAINT client_status_revisions_request_fingerprint_check CHECK ((octet_length(request_fingerprint) = 32)),
    CONSTRAINT client_status_revisions_revision_check CHECK ((revision > 0)),
    CONSTRAINT client_status_revisions_supersedes_revision_check CHECK (((supersedes_revision IS NULL) OR (supersedes_revision > 0)))
);


--
-- Name: communities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.communities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    host character varying(255) NOT NULL,
    signing_key bytea,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    icon text,
    archived_at timestamp with time zone,
    CONSTRAINT chk_communities_id_not_nil CHECK ((id <> '00000000-0000-0000-0000-000000000000'::uuid))
);


--
-- Name: community_bans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.community_bans (
    community_id uuid NOT NULL,
    pubkey bytea NOT NULL,
    banned boolean DEFAULT false NOT NULL,
    ban_expires_at timestamp with time zone,
    ban_reason text,
    muted_until timestamp with time zone,
    mute_reason text,
    actor_pubkey bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT community_bans_actor_pubkey_check CHECK ((length(actor_pubkey) = 32)),
    CONSTRAINT community_bans_pubkey_check CHECK ((length(pubkey) = 32))
);


--
-- Name: delivery_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.delivery_log (
    community_id uuid NOT NULL,
    id bigint NOT NULL,
    subscription_id character varying(255),
    event_id bytea,
    method public.delivery_method,
    delivered_at timestamp with time zone DEFAULT now() NOT NULL,
    success boolean,
    http_status integer,
    error_message text,
    attempt_number integer DEFAULT 1
)
PARTITION BY RANGE (delivered_at);


--
-- Name: delivery_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.delivery_log ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.delivery_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: delivery_log_p2026_03; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.delivery_log_p2026_03 (
    community_id uuid NOT NULL,
    id bigint NOT NULL,
    subscription_id character varying(255),
    event_id bytea,
    method public.delivery_method,
    delivered_at timestamp with time zone DEFAULT now() NOT NULL,
    success boolean,
    http_status integer,
    error_message text,
    attempt_number integer DEFAULT 1
);


--
-- Name: delivery_log_p2026_04; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.delivery_log_p2026_04 (
    community_id uuid NOT NULL,
    id bigint NOT NULL,
    subscription_id character varying(255),
    event_id bytea,
    method public.delivery_method,
    delivered_at timestamp with time zone DEFAULT now() NOT NULL,
    success boolean,
    http_status integer,
    error_message text,
    attempt_number integer DEFAULT 1
);


--
-- Name: delivery_log_p2026_05; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.delivery_log_p2026_05 (
    community_id uuid NOT NULL,
    id bigint NOT NULL,
    subscription_id character varying(255),
    event_id bytea,
    method public.delivery_method,
    delivered_at timestamp with time zone DEFAULT now() NOT NULL,
    success boolean,
    http_status integer,
    error_message text,
    attempt_number integer DEFAULT 1
);


--
-- Name: delivery_log_p2026_06; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.delivery_log_p2026_06 (
    community_id uuid NOT NULL,
    id bigint NOT NULL,
    subscription_id character varying(255),
    event_id bytea,
    method public.delivery_method,
    delivered_at timestamp with time zone DEFAULT now() NOT NULL,
    success boolean,
    http_status integer,
    error_message text,
    attempt_number integer DEFAULT 1
);


--
-- Name: delivery_log_p_future; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.delivery_log_p_future (
    community_id uuid NOT NULL,
    id bigint NOT NULL,
    subscription_id character varying(255),
    event_id bytea,
    method public.delivery_method,
    delivered_at timestamp with time zone DEFAULT now() NOT NULL,
    success boolean,
    http_status integer,
    error_message text,
    attempt_number integer DEFAULT 1
);


--
-- Name: delivery_log_p_past; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.delivery_log_p_past (
    community_id uuid NOT NULL,
    id bigint NOT NULL,
    subscription_id character varying(255),
    event_id bytea,
    method public.delivery_method,
    delivered_at timestamp with time zone DEFAULT now() NOT NULL,
    success boolean,
    http_status integer,
    error_message text,
    attempt_number integer DEFAULT 1
);


--
-- Name: event_mentions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_mentions (
    community_id uuid NOT NULL,
    pubkey_hex character varying(64) NOT NULL,
    event_id bytea NOT NULL,
    event_created_at timestamp with time zone NOT NULL,
    channel_id uuid,
    event_kind integer
);


--
-- Name: events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events (
    community_id uuid NOT NULL,
    id bytea NOT NULL,
    pubkey bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    kind integer NOT NULL,
    tags jsonb NOT NULL,
    content text NOT NULL,
    sig bytea NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    channel_id uuid,
    deleted_at timestamp with time zone,
    d_tag text,
    not_before bigint,
    delivered_at bigint,
    search_tsv tsvector GENERATED ALWAYS AS (
CASE
    WHEN (kind = 30350) THEN NULL::tsvector
    ELSE
    CASE
        WHEN (kind = ANY (ARRAY[0, 9, 40002, 45001, 45003])) THEN to_tsvector('simple'::regconfig, content)
        ELSE NULL::tsvector
    END
END) STORED
)
PARTITION BY RANGE (created_at);


--
-- Name: events_p2026_01; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events_p2026_01 (
    community_id uuid NOT NULL,
    id bytea NOT NULL,
    pubkey bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    kind integer NOT NULL,
    tags jsonb NOT NULL,
    content text NOT NULL,
    sig bytea NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    channel_id uuid,
    deleted_at timestamp with time zone,
    d_tag text,
    not_before bigint,
    delivered_at bigint,
    search_tsv tsvector GENERATED ALWAYS AS (
CASE
    WHEN (kind = 30350) THEN NULL::tsvector
    ELSE
    CASE
        WHEN (kind = ANY (ARRAY[0, 9, 40002, 45001, 45003])) THEN to_tsvector('simple'::regconfig, content)
        ELSE NULL::tsvector
    END
END) STORED
);


--
-- Name: events_p2026_02; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events_p2026_02 (
    community_id uuid NOT NULL,
    id bytea NOT NULL,
    pubkey bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    kind integer NOT NULL,
    tags jsonb NOT NULL,
    content text NOT NULL,
    sig bytea NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    channel_id uuid,
    deleted_at timestamp with time zone,
    d_tag text,
    not_before bigint,
    delivered_at bigint,
    search_tsv tsvector GENERATED ALWAYS AS (
CASE
    WHEN (kind = 30350) THEN NULL::tsvector
    ELSE
    CASE
        WHEN (kind = ANY (ARRAY[0, 9, 40002, 45001, 45003])) THEN to_tsvector('simple'::regconfig, content)
        ELSE NULL::tsvector
    END
END) STORED
);


--
-- Name: events_p2026_03; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events_p2026_03 (
    community_id uuid NOT NULL,
    id bytea NOT NULL,
    pubkey bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    kind integer NOT NULL,
    tags jsonb NOT NULL,
    content text NOT NULL,
    sig bytea NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    channel_id uuid,
    deleted_at timestamp with time zone,
    d_tag text,
    not_before bigint,
    delivered_at bigint,
    search_tsv tsvector GENERATED ALWAYS AS (
CASE
    WHEN (kind = 30350) THEN NULL::tsvector
    ELSE
    CASE
        WHEN (kind = ANY (ARRAY[0, 9, 40002, 45001, 45003])) THEN to_tsvector('simple'::regconfig, content)
        ELSE NULL::tsvector
    END
END) STORED
);


--
-- Name: events_p2026_04; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events_p2026_04 (
    community_id uuid NOT NULL,
    id bytea NOT NULL,
    pubkey bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    kind integer NOT NULL,
    tags jsonb NOT NULL,
    content text NOT NULL,
    sig bytea NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    channel_id uuid,
    deleted_at timestamp with time zone,
    d_tag text,
    not_before bigint,
    delivered_at bigint,
    search_tsv tsvector GENERATED ALWAYS AS (
CASE
    WHEN (kind = 30350) THEN NULL::tsvector
    ELSE
    CASE
        WHEN (kind = ANY (ARRAY[0, 9, 40002, 45001, 45003])) THEN to_tsvector('simple'::regconfig, content)
        ELSE NULL::tsvector
    END
END) STORED
);


--
-- Name: events_p2026_05; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events_p2026_05 (
    community_id uuid NOT NULL,
    id bytea NOT NULL,
    pubkey bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    kind integer NOT NULL,
    tags jsonb NOT NULL,
    content text NOT NULL,
    sig bytea NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    channel_id uuid,
    deleted_at timestamp with time zone,
    d_tag text,
    not_before bigint,
    delivered_at bigint,
    search_tsv tsvector GENERATED ALWAYS AS (
CASE
    WHEN (kind = 30350) THEN NULL::tsvector
    ELSE
    CASE
        WHEN (kind = ANY (ARRAY[0, 9, 40002, 45001, 45003])) THEN to_tsvector('simple'::regconfig, content)
        ELSE NULL::tsvector
    END
END) STORED
);


--
-- Name: events_p2026_06; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events_p2026_06 (
    community_id uuid NOT NULL,
    id bytea NOT NULL,
    pubkey bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    kind integer NOT NULL,
    tags jsonb NOT NULL,
    content text NOT NULL,
    sig bytea NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    channel_id uuid,
    deleted_at timestamp with time zone,
    d_tag text,
    not_before bigint,
    delivered_at bigint,
    search_tsv tsvector GENERATED ALWAYS AS (
CASE
    WHEN (kind = 30350) THEN NULL::tsvector
    ELSE
    CASE
        WHEN (kind = ANY (ARRAY[0, 9, 40002, 45001, 45003])) THEN to_tsvector('simple'::regconfig, content)
        ELSE NULL::tsvector
    END
END) STORED
);


--
-- Name: events_p_future; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events_p_future (
    community_id uuid NOT NULL,
    id bytea NOT NULL,
    pubkey bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    kind integer NOT NULL,
    tags jsonb NOT NULL,
    content text NOT NULL,
    sig bytea NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    channel_id uuid,
    deleted_at timestamp with time zone,
    d_tag text,
    not_before bigint,
    delivered_at bigint,
    search_tsv tsvector GENERATED ALWAYS AS (
CASE
    WHEN (kind = 30350) THEN NULL::tsvector
    ELSE
    CASE
        WHEN (kind = ANY (ARRAY[0, 9, 40002, 45001, 45003])) THEN to_tsvector('simple'::regconfig, content)
        ELSE NULL::tsvector
    END
END) STORED
);


--
-- Name: events_p_past; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events_p_past (
    community_id uuid NOT NULL,
    id bytea NOT NULL,
    pubkey bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    kind integer NOT NULL,
    tags jsonb NOT NULL,
    content text NOT NULL,
    sig bytea NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    channel_id uuid,
    deleted_at timestamp with time zone,
    d_tag text,
    not_before bigint,
    delivered_at bigint,
    search_tsv tsvector GENERATED ALWAYS AS (
CASE
    WHEN (kind = 30350) THEN NULL::tsvector
    ELSE
    CASE
        WHEN (kind = ANY (ARRAY[0, 9, 40002, 45001, 45003])) THEN to_tsvector('simple'::regconfig, content)
        ELSE NULL::tsvector
    END
END) STORED
);


--
-- Name: git_repo_names; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.git_repo_names (
    community_id uuid NOT NULL,
    repo_id text NOT NULL,
    owner_pubkey text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: identity_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_bindings (
    community_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    binding_version bigint NOT NULL,
    issuer text NOT NULL COLLATE pg_catalog."C",
    subject text NOT NULL COLLATE pg_catalog."C",
    principal_fingerprint bytea NOT NULL,
    event_author_pubkey bytea NOT NULL,
    binding_state smallint NOT NULL,
    lifecycle_revision bigint NOT NULL,
    binding_provenance smallint NOT NULL,
    policy_revision bigint NOT NULL,
    enrollment_evidence_digest bytea NOT NULL,
    expires_at timestamp with time zone,
    birth_history_id uuid NOT NULL,
    creation_operation_id uuid NOT NULL,
    creation_request_fingerprint bytea NOT NULL,
    retirement_history_id uuid,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT identity_bindings_binding_id_check CHECK ((binding_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT identity_bindings_binding_provenance_check CHECK ((binding_provenance = ANY (ARRAY[1, 2, 3]))),
    CONSTRAINT identity_bindings_binding_state_check CHECK ((binding_state = ANY (ARRAY[1, 2]))),
    CONSTRAINT identity_bindings_binding_version_check CHECK ((binding_version > 0)),
    CONSTRAINT identity_bindings_birth_history_id_check CHECK ((birth_history_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT identity_bindings_check CHECK (((expires_at IS NULL) OR (created_at < expires_at))),
    CONSTRAINT identity_bindings_check1 CHECK ((((binding_state = 1) AND (lifecycle_revision = 1) AND (retirement_history_id IS NULL)) OR ((binding_state = 2) AND (lifecycle_revision = 2) AND (retirement_history_id IS NOT NULL)))),
    CONSTRAINT identity_bindings_creation_operation_id_check CHECK ((creation_operation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT identity_bindings_creation_request_fingerprint_check CHECK ((octet_length(creation_request_fingerprint) = 32)),
    CONSTRAINT identity_bindings_enrollment_evidence_digest_check CHECK ((octet_length(enrollment_evidence_digest) = 32)),
    CONSTRAINT identity_bindings_event_author_pubkey_check CHECK ((octet_length(event_author_pubkey) = 32)),
    CONSTRAINT identity_bindings_issuer_check CHECK (((octet_length(issuer) >= 1) AND (octet_length(issuer) <= 2048))),
    CONSTRAINT identity_bindings_lifecycle_revision_check CHECK ((lifecycle_revision = ANY (ARRAY[(1)::bigint, (2)::bigint]))),
    CONSTRAINT identity_bindings_policy_revision_check CHECK ((policy_revision > 0)),
    CONSTRAINT identity_bindings_principal_fingerprint_check CHECK ((octet_length(principal_fingerprint) = 32)),
    CONSTRAINT identity_bindings_subject_check CHECK (((octet_length(subject) >= 1) AND (octet_length(subject) <= 2048)))
);


--
-- Name: identity_bindings_binding_version_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.identity_bindings ALTER COLUMN binding_version ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.identity_bindings_binding_version_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: identity_enrollment_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_enrollment_policies (
    community_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    enrollment_mode smallint NOT NULL,
    policy_digest bytea NOT NULL,
    effective_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    recorded_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT identity_enrollment_policies_check CHECK (((expires_at IS NULL) OR (effective_at < expires_at))),
    CONSTRAINT identity_enrollment_policies_enrollment_mode_check CHECK ((enrollment_mode = ANY (ARRAY[1, 2, 3]))),
    CONSTRAINT identity_enrollment_policies_policy_digest_check CHECK ((octet_length(policy_digest) = 32)),
    CONSTRAINT identity_enrollment_policies_policy_revision_check CHECK ((policy_revision > 0))
);


--
-- Name: identity_lifecycle_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_lifecycle_history (
    community_id uuid NOT NULL,
    history_id uuid NOT NULL,
    transition_kind smallint NOT NULL,
    outcome_code smallint NOT NULL,
    old_binding_id uuid,
    old_binding_version bigint,
    old_prior_lifecycle_revision bigint,
    old_prior_state smallint,
    old_resulting_lifecycle_revision bigint,
    old_resulting_state smallint,
    successor_binding_id uuid,
    successor_binding_version bigint,
    successor_lifecycle_revision bigint,
    successor_state smallint,
    operation_id uuid NOT NULL,
    request_fingerprint bytea NOT NULL,
    transition_digest bytea NOT NULL,
    recorded_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT identity_lifecycle_history_check CHECK ((((old_binding_id IS NULL) AND (old_binding_version IS NULL) AND (old_prior_lifecycle_revision IS NULL) AND (old_prior_state IS NULL) AND (old_resulting_lifecycle_revision IS NULL) AND (old_resulting_state IS NULL)) OR ((old_binding_id IS NOT NULL) AND (old_binding_version IS NOT NULL) AND (old_prior_lifecycle_revision IS NOT NULL) AND (old_prior_state IS NOT NULL) AND (old_resulting_lifecycle_revision IS NOT NULL) AND (old_resulting_state IS NOT NULL)))),
    CONSTRAINT identity_lifecycle_history_check1 CHECK ((((successor_binding_id IS NULL) AND (successor_binding_version IS NULL) AND (successor_lifecycle_revision IS NULL) AND (successor_state IS NULL)) OR ((successor_binding_id IS NOT NULL) AND (successor_binding_version IS NOT NULL) AND (successor_lifecycle_revision = 1) AND (successor_state = 1)))),
    CONSTRAINT identity_lifecycle_history_check2 CHECK (((old_binding_id IS NULL) OR (successor_binding_id IS NULL) OR (old_binding_id <> successor_binding_id))),
    CONSTRAINT identity_lifecycle_history_check3 CHECK (((old_binding_version IS NULL) OR (successor_binding_version IS NULL) OR (old_binding_version <> successor_binding_version))),
    CONSTRAINT identity_lifecycle_history_check4 CHECK (((old_binding_id IS NULL) OR ((old_prior_lifecycle_revision = 1) AND (old_prior_state = 1) AND (old_resulting_lifecycle_revision = 2) AND (old_resulting_state = 2)) OR ((transition_kind = ANY (ARRAY[7, 8])) AND (old_prior_lifecycle_revision = 2) AND (old_prior_state = 2) AND (old_resulting_lifecycle_revision = 2) AND (old_resulting_state = 2)))),
    CONSTRAINT identity_lifecycle_history_check5 CHECK ((((outcome_code = 3) AND (old_binding_id IS NULL) AND (successor_binding_id IS NULL)) OR ((outcome_code = 1) AND (((transition_kind = ANY (ARRAY[1, 2])) AND (old_binding_id IS NULL) AND (successor_binding_id IS NOT NULL)) OR ((transition_kind = 3) AND (old_binding_id IS NOT NULL) AND (successor_binding_id IS NULL)) OR ((transition_kind = ANY (ARRAY[4, 5])) AND (successor_binding_id IS NULL)) OR ((transition_kind = 6) AND (old_binding_id IS NOT NULL) AND (successor_binding_id IS NOT NULL)) OR ((transition_kind = 7) AND (old_binding_id IS NOT NULL) AND (successor_binding_id IS NOT NULL)) OR ((transition_kind = 8) AND (successor_binding_id IS NOT NULL)) OR ((transition_kind = 9) AND (old_binding_id IS NOT NULL) AND (successor_binding_id IS NULL)))))),
    CONSTRAINT identity_lifecycle_history_history_id_check CHECK ((history_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT identity_lifecycle_history_old_binding_version_check CHECK (((old_binding_version IS NULL) OR (old_binding_version > 0))),
    CONSTRAINT identity_lifecycle_history_old_prior_lifecycle_revision_check CHECK (((old_prior_lifecycle_revision IS NULL) OR (old_prior_lifecycle_revision = ANY (ARRAY[(1)::bigint, (2)::bigint])))),
    CONSTRAINT identity_lifecycle_history_old_prior_state_check CHECK (((old_prior_state IS NULL) OR (old_prior_state = ANY (ARRAY[1, 2])))),
    CONSTRAINT identity_lifecycle_history_old_resulting_lifecycle_revisi_check CHECK (((old_resulting_lifecycle_revision IS NULL) OR (old_resulting_lifecycle_revision = ANY (ARRAY[(1)::bigint, (2)::bigint])))),
    CONSTRAINT identity_lifecycle_history_old_resulting_state_check CHECK (((old_resulting_state IS NULL) OR (old_resulting_state = ANY (ARRAY[1, 2])))),
    CONSTRAINT identity_lifecycle_history_operation_id_check CHECK ((operation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT identity_lifecycle_history_outcome_code_check CHECK ((outcome_code = ANY (ARRAY[1, 3]))),
    CONSTRAINT identity_lifecycle_history_request_fingerprint_check CHECK ((octet_length(request_fingerprint) = 32)),
    CONSTRAINT identity_lifecycle_history_successor_binding_version_check CHECK (((successor_binding_version IS NULL) OR (successor_binding_version > 0))),
    CONSTRAINT identity_lifecycle_history_successor_lifecycle_revision_check CHECK (((successor_lifecycle_revision IS NULL) OR (successor_lifecycle_revision = 1))),
    CONSTRAINT identity_lifecycle_history_successor_state_check CHECK (((successor_state IS NULL) OR (successor_state = 1))),
    CONSTRAINT identity_lifecycle_history_transition_digest_check CHECK ((octet_length(transition_digest) = 32)),
    CONSTRAINT identity_lifecycle_history_transition_kind_check CHECK ((transition_kind = ANY (ARRAY[1, 2, 3, 4, 5, 6, 7, 8, 9])))
);


--
-- Name: identity_lifecycle_selector_consumptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_lifecycle_selector_consumptions (
    community_id uuid NOT NULL,
    selector_id uuid NOT NULL,
    selector_kind smallint NOT NULL,
    history_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    request_fingerprint bytea NOT NULL,
    successor_binding_id uuid NOT NULL,
    successor_binding_version bigint NOT NULL,
    consumed_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT identity_lifecycle_selector_con_successor_binding_version_check CHECK ((successor_binding_version > 0)),
    CONSTRAINT identity_lifecycle_selector_consumpti_request_fingerprint_check CHECK ((octet_length(request_fingerprint) = 32)),
    CONSTRAINT identity_lifecycle_selector_consumptions_selector_kind_check CHECK ((selector_kind = ANY (ARRAY[2, 4])))
);


--
-- Name: identity_lifecycle_selectors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_lifecycle_selectors (
    community_id uuid NOT NULL,
    selector_id uuid NOT NULL,
    selector_kind smallint NOT NULL,
    selector_fingerprint bytea NOT NULL,
    fact_generation bigint NOT NULL,
    principal_fingerprint bytea,
    event_author_pubkey bytea,
    binding_id uuid,
    binding_version bigint,
    asserted_history_id uuid NOT NULL,
    selected_by_operation_id uuid NOT NULL,
    selected_by_request_fingerprint bytea NOT NULL,
    selected_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT identity_lifecycle_selectors_binding_version_check CHECK (((binding_version IS NULL) OR (binding_version > 0))),
    CONSTRAINT identity_lifecycle_selectors_check CHECK ((((selector_kind = 1) AND (fact_generation = 1) AND (principal_fingerprint IS NOT NULL) AND (event_author_pubkey IS NOT NULL) AND (binding_id IS NOT NULL) AND (binding_version IS NOT NULL)) OR ((selector_kind = 2) AND (principal_fingerprint IS NOT NULL) AND (event_author_pubkey IS NULL) AND (binding_id IS NULL) AND (binding_version IS NULL)) OR ((selector_kind = 3) AND (fact_generation = 1) AND (principal_fingerprint IS NULL) AND (event_author_pubkey IS NOT NULL) AND (binding_id IS NULL) AND (binding_version IS NULL)) OR ((selector_kind = 4) AND (principal_fingerprint IS NOT NULL) AND (event_author_pubkey IS NOT NULL) AND (binding_id IS NOT NULL) AND (binding_version IS NOT NULL)))),
    CONSTRAINT identity_lifecycle_selectors_event_author_pubkey_check CHECK (((event_author_pubkey IS NULL) OR (octet_length(event_author_pubkey) = 32))),
    CONSTRAINT identity_lifecycle_selectors_fact_generation_check CHECK ((fact_generation > 0)),
    CONSTRAINT identity_lifecycle_selectors_principal_fingerprint_check CHECK (((principal_fingerprint IS NULL) OR (octet_length(principal_fingerprint) = 32))),
    CONSTRAINT identity_lifecycle_selectors_selected_by_request_fingerpr_check CHECK ((octet_length(selected_by_request_fingerprint) = 32)),
    CONSTRAINT identity_lifecycle_selectors_selector_fingerprint_check CHECK ((octet_length(selector_fingerprint) = 32)),
    CONSTRAINT identity_lifecycle_selectors_selector_id_check CHECK ((selector_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT identity_lifecycle_selectors_selector_kind_check CHECK ((selector_kind = ANY (ARRAY[1, 2, 3, 4])))
);


--
-- Name: join_policy_acceptances; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.join_policy_acceptances (
    community_id uuid NOT NULL,
    pubkey text NOT NULL,
    policy_version text NOT NULL,
    accepted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT join_policy_acceptances_policy_version_check CHECK ((length(policy_version) = 64))
);


--
-- Name: moderation_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.moderation_actions (
    community_id uuid NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_pubkey bytea NOT NULL,
    action text NOT NULL,
    target_pubkey bytea,
    target_event_id bytea,
    channel_id uuid,
    reason_code text,
    public_reason text,
    private_reason text,
    matched_principal text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT moderation_actions_action_check CHECK ((action = ANY (ARRAY['delete_message'::text, 'kick'::text, 'ban'::text, 'unban'::text, 'timeout'::text, 'untimeout'::text, 'dismiss_report'::text, 'escalate'::text, 'resolve:delete'::text, 'resolve:kick'::text, 'resolve:ban'::text, 'resolve:timeout'::text]))),
    CONSTRAINT moderation_actions_actor_pubkey_check CHECK ((length(actor_pubkey) = 32)),
    CONSTRAINT moderation_actions_matched_principal_check CHECK (((matched_principal IS NULL) OR (matched_principal = ANY (ARRAY['self'::text, 'owner'::text])))),
    CONSTRAINT moderation_actions_target_event_id_check CHECK (((target_event_id IS NULL) OR (length(target_event_id) = 32))),
    CONSTRAINT moderation_actions_target_pubkey_check CHECK (((target_pubkey IS NULL) OR (length(target_pubkey) = 32)))
);


--
-- Name: moderation_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.moderation_reports (
    community_id uuid NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    report_event_id bytea NOT NULL,
    reporter_pubkey bytea NOT NULL,
    target_kind text NOT NULL,
    target_event_id bytea,
    target_pubkey bytea,
    target_blob_sha256 bytea,
    channel_id uuid,
    report_type text NOT NULL,
    note text,
    status text DEFAULT 'open'::text NOT NULL,
    resolved_by bytea,
    resolved_at timestamp with time zone,
    action_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT moderation_reports_check CHECK ((((target_kind = 'event'::text) AND (target_event_id IS NOT NULL) AND (target_pubkey IS NULL) AND (target_blob_sha256 IS NULL)) OR ((target_kind = 'pubkey'::text) AND (target_event_id IS NULL) AND (target_pubkey IS NOT NULL) AND (target_blob_sha256 IS NULL)) OR ((target_kind = 'blob'::text) AND (target_event_id IS NULL) AND (target_pubkey IS NULL) AND (target_blob_sha256 IS NOT NULL)))),
    CONSTRAINT moderation_reports_report_event_id_check CHECK ((length(report_event_id) = 32)),
    CONSTRAINT moderation_reports_reporter_pubkey_check CHECK ((length(reporter_pubkey) = 32)),
    CONSTRAINT moderation_reports_status_check CHECK ((status = ANY (ARRAY['open'::text, 'resolved'::text, 'dismissed'::text, 'escalated'::text]))),
    CONSTRAINT moderation_reports_target_blob_sha256_check CHECK (((target_blob_sha256 IS NULL) OR (length(target_blob_sha256) = 32))),
    CONSTRAINT moderation_reports_target_event_id_check CHECK (((target_event_id IS NULL) OR (length(target_event_id) = 32))),
    CONSTRAINT moderation_reports_target_kind_check CHECK ((target_kind = ANY (ARRAY['event'::text, 'pubkey'::text, 'blob'::text]))),
    CONSTRAINT moderation_reports_target_pubkey_check CHECK (((target_pubkey IS NULL) OR (length(target_pubkey) = 32)))
);


--
-- Name: parameterized_event_watermarks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.parameterized_event_watermarks (
    community_id uuid NOT NULL,
    kind integer NOT NULL,
    pubkey bytea NOT NULL,
    d_tag text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    event_id bytea NOT NULL
);


--
-- Name: product_feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.product_feedback (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    community_id uuid NOT NULL,
    event_id bytea NOT NULL,
    submitter_pubkey bytea NOT NULL,
    category text,
    body text NOT NULL,
    tags jsonb DEFAULT '[]'::jsonb NOT NULL,
    event_created_at timestamp with time zone NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT product_feedback_body_check CHECK ((length(btrim(body)) > 0)),
    CONSTRAINT product_feedback_category_check CHECK ((category = ANY (ARRAY['bug'::text, 'praise'::text, 'needs-work'::text]))),
    CONSTRAINT product_feedback_event_id_check CHECK ((length(event_id) = 32)),
    CONSTRAINT product_feedback_submitter_pubkey_check CHECK ((length(submitter_pubkey) = 32)),
    CONSTRAINT product_feedback_tags_check CHECK ((jsonb_typeof(tags) = 'array'::text))
);


--
-- Name: protected_object_authority; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.protected_object_authority (
    community_id uuid NOT NULL,
    object_kind smallint NOT NULL,
    object_key bytea NOT NULL,
    capability smallint NOT NULL,
    actor_pubkey bytea NOT NULL,
    owner_pubkey bytea,
    binding_id uuid NOT NULL,
    binding_version bigint NOT NULL,
    delegated_relationship_id uuid,
    delegated_relationship_revision bigint,
    delegation_conditions_fingerprint bytea,
    policy_revision bigint NOT NULL,
    invalidation_generation bigint NOT NULL,
    authority_epoch bigint NOT NULL,
    fence bytea NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    operation_id uuid NOT NULL,
    request_fingerprint bytea NOT NULL,
    CONSTRAINT protected_object_authority_actor_pubkey_check CHECK ((octet_length(actor_pubkey) = 32)),
    CONSTRAINT protected_object_authority_authority_epoch_check CHECK ((authority_epoch > 0)),
    CONSTRAINT protected_object_authority_binding_version_check CHECK ((binding_version > 0)),
    CONSTRAINT protected_object_authority_capability_check CHECK ((capability = ANY (ARRAY[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27]))),
    CONSTRAINT protected_object_authority_check CHECK ((issued_at < expires_at)),
    CONSTRAINT protected_object_authority_check1 CHECK ((((owner_pubkey IS NULL) AND (delegated_relationship_id IS NULL) AND (delegated_relationship_revision IS NULL) AND (delegation_conditions_fingerprint IS NULL)) OR ((owner_pubkey IS NOT NULL) AND (delegated_relationship_id IS NOT NULL) AND (delegated_relationship_revision IS NOT NULL) AND (delegation_conditions_fingerprint IS NOT NULL)))),
    CONSTRAINT protected_object_authority_delegated_relationship_non_nil CHECK (((delegated_relationship_id IS NULL) OR (delegated_relationship_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT protected_object_authority_delegated_relationship_revisio_check CHECK (((delegated_relationship_revision IS NULL) OR (delegated_relationship_revision > 0))),
    CONSTRAINT protected_object_authority_delegation_conditions_fingerpr_check CHECK (((delegation_conditions_fingerprint IS NULL) OR (octet_length(delegation_conditions_fingerprint) = 32))),
    CONSTRAINT protected_object_authority_fence_check CHECK (((octet_length(fence) = 32) AND (fence <> decode(repeat('00'::text, 32), 'hex'::text)))),
    CONSTRAINT protected_object_authority_invalidation_generation_check CHECK ((invalidation_generation >= 0)),
    CONSTRAINT protected_object_authority_object_key_check CHECK ((octet_length(object_key) = 32)),
    CONSTRAINT protected_object_authority_object_kind_check CHECK ((object_kind = ANY (ARRAY[1, 2, 3, 4, 5, 6, 7]))),
    CONSTRAINT protected_object_authority_owner_pubkey_check CHECK (((owner_pubkey IS NULL) OR (octet_length(owner_pubkey) = 32))),
    CONSTRAINT protected_object_authority_policy_revision_check CHECK ((policy_revision > 0)),
    CONSTRAINT protected_object_authority_request_fingerprint_check CHECK ((octet_length(request_fingerprint) = 32))
);


--
-- Name: pubkey_allowlist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pubkey_allowlist (
    community_id uuid NOT NULL,
    pubkey bytea NOT NULL,
    added_by bytea,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    note text
);


--
-- Name: push_gateway_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_gateway_challenges (
    id uuid NOT NULL,
    challenge_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT push_gateway_challenges_challenge_hash_check CHECK ((length(challenge_hash) = 32))
);


--
-- Name: push_gateway_delegations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_gateway_delegations (
    id uuid NOT NULL,
    installation_id uuid NOT NULL,
    relay_pubkey bytea NOT NULL,
    endpoint_epoch bigint NOT NULL,
    generation bigint NOT NULL,
    not_before timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT push_gateway_delegations_check CHECK ((not_before < expires_at)),
    CONSTRAINT push_gateway_delegations_endpoint_epoch_check CHECK ((endpoint_epoch > 0)),
    CONSTRAINT push_gateway_delegations_generation_check CHECK ((generation > 0)),
    CONSTRAINT push_gateway_delegations_relay_pubkey_check CHECK ((length(relay_pubkey) = 32))
);


--
-- Name: push_gateway_delivery_auth_replays; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_gateway_delivery_auth_replays (
    relay_pubkey bytea NOT NULL,
    auth_event_id bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT push_gateway_delivery_auth_replays_auth_event_id_check CHECK ((length(auth_event_id) = 32)),
    CONSTRAINT push_gateway_delivery_auth_replays_relay_pubkey_check CHECK ((length(relay_pubkey) = 32))
);


--
-- Name: push_gateway_delivery_request_replays; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_gateway_delivery_request_replays (
    relay_pubkey bytea NOT NULL,
    request_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT push_gateway_delivery_request_replays_relay_pubkey_check CHECK ((length(relay_pubkey) = 32))
);


--
-- Name: push_gateway_endpoint_quotas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_gateway_endpoint_quotas (
    token_fingerprint bytea NOT NULL,
    window_started_at timestamp with time zone NOT NULL,
    admitted bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT push_gateway_endpoint_quotas_admitted_check CHECK ((admitted >= 0)),
    CONSTRAINT push_gateway_endpoint_quotas_token_fingerprint_check CHECK ((length(token_fingerprint) = 32))
);


--
-- Name: push_gateway_installations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_gateway_installations (
    id uuid NOT NULL,
    app_attest_key_id bytea NOT NULL,
    app_attest_public_key bytea NOT NULL,
    assertion_counter bigint NOT NULL,
    app_profile text NOT NULL,
    token_ciphertext bytea NOT NULL,
    token_fingerprint bytea NOT NULL,
    endpoint_epoch bigint NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT push_gateway_installations_app_attest_key_id_check CHECK (((octet_length(app_attest_key_id) >= 1) AND (octet_length(app_attest_key_id) <= 128))),
    CONSTRAINT push_gateway_installations_app_attest_public_key_check CHECK (((octet_length(app_attest_public_key) >= 33) AND (octet_length(app_attest_public_key) <= 256))),
    CONSTRAINT push_gateway_installations_app_profile_check CHECK ((app_profile = ANY (ARRAY['buzz-ios-production'::text, 'buzz-ios-sandbox'::text]))),
    CONSTRAINT push_gateway_installations_assertion_counter_check CHECK (((assertion_counter >= 0) AND (assertion_counter <= '4294967295'::bigint))),
    CONSTRAINT push_gateway_installations_endpoint_epoch_check CHECK ((endpoint_epoch > 0)),
    CONSTRAINT push_gateway_installations_token_ciphertext_check CHECK (((octet_length(token_ciphertext) >= 1) AND (octet_length(token_ciphertext) <= 2048))),
    CONSTRAINT push_gateway_installations_token_fingerprint_check CHECK ((length(token_fingerprint) = 32))
);


--
-- Name: push_leases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_leases (
    community_id uuid NOT NULL,
    author bytea NOT NULL,
    installation_id text NOT NULL,
    source_event_id bytea NOT NULL,
    source_created_at bigint NOT NULL,
    generation bigint NOT NULL,
    active boolean NOT NULL,
    app_profile text,
    endpoint_hash bytea,
    endpoint_grant text,
    max_class text,
    subscriptions jsonb,
    expires_at bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    endpoint_enabled boolean DEFAULT true NOT NULL,
    CONSTRAINT push_leases_author_check CHECK ((length(author) = 32)),
    CONSTRAINT push_leases_check CHECK (((active AND (app_profile IS NOT NULL) AND (endpoint_hash IS NOT NULL) AND (endpoint_grant IS NOT NULL) AND (max_class IS NOT NULL) AND (subscriptions IS NOT NULL)) OR ((NOT active) AND (app_profile IS NULL) AND (endpoint_hash IS NULL) AND (endpoint_grant IS NULL) AND (max_class IS NULL) AND (subscriptions IS NULL)))),
    CONSTRAINT push_leases_endpoint_hash_check CHECK (((endpoint_hash IS NULL) OR (length(endpoint_hash) = 32))),
    CONSTRAINT push_leases_generation_check CHECK ((generation > 0)),
    CONSTRAINT push_leases_installation_id_check CHECK (((octet_length(installation_id) >= 1) AND (octet_length(installation_id) <= 64))),
    CONSTRAINT push_leases_max_class_check CHECK (((max_class IS NULL) OR (max_class = ANY (ARRAY['silent'::text, 'default'::text, 'time_sensitive'::text, 'urgent'::text])))),
    CONSTRAINT push_leases_source_event_id_check CHECK ((length(source_event_id) = 32))
);


--
-- Name: push_match_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_match_queue (
    community_id uuid NOT NULL,
    event_id bytea NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_until timestamp with time zone,
    claim_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT push_match_queue_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT push_match_queue_event_id_check CHECK ((length(event_id) = 32)),
    CONSTRAINT push_match_queue_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'matching'::text])))
);


--
-- Name: push_wake_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_wake_outbox (
    community_id uuid NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    author bytea NOT NULL,
    installation_id text NOT NULL,
    lease_generation bigint NOT NULL,
    endpoint_hash bytea NOT NULL,
    event_id bytea NOT NULL,
    class text NOT NULL,
    expires_at bigint NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_until timestamp with time zone,
    claim_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT push_wake_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT push_wake_outbox_author_check CHECK ((length(author) = 32)),
    CONSTRAINT push_wake_outbox_class_check CHECK ((class = ANY (ARRAY['silent'::text, 'default'::text, 'time_sensitive'::text, 'urgent'::text]))),
    CONSTRAINT push_wake_outbox_endpoint_hash_check CHECK ((length(endpoint_hash) = 32)),
    CONSTRAINT push_wake_outbox_event_id_check CHECK ((length(event_id) = 32)),
    CONSTRAINT push_wake_outbox_lease_generation_check CHECK ((lease_generation > 0)),
    CONSTRAINT push_wake_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'sending'::text, 'delivered'::text, 'failed'::text])))
);


--
-- Name: rate_limit_violations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rate_limit_violations (
    id bigint NOT NULL,
    community_id uuid,
    pubkey bytea,
    violation_at timestamp with time zone DEFAULT now() NOT NULL,
    limit_type character varying(64),
    limit_value integer,
    actual_value integer,
    action_taken character varying(64)
);


--
-- Name: rate_limit_violations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.rate_limit_violations ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.rate_limit_violations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: reactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reactions (
    community_id uuid NOT NULL,
    event_created_at timestamp with time zone NOT NULL,
    event_id bytea NOT NULL,
    pubkey bytea NOT NULL,
    emoji character varying(66) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    removed_at timestamp with time zone,
    reaction_event_id bytea
);


--
-- Name: relay_invites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.relay_invites (
    community_id uuid NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_hash bytea NOT NULL,
    role text DEFAULT 'member'::text NOT NULL,
    max_uses integer,
    use_count integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT relay_invites_check CHECK (((max_uses IS NULL) OR (use_count <= max_uses))),
    CONSTRAINT relay_invites_max_uses_check CHECK (((max_uses >= 1) AND (max_uses <= 10000))),
    CONSTRAINT relay_invites_role_check CHECK ((role = 'member'::text)),
    CONSTRAINT relay_invites_token_hash_check CHECK ((length(token_hash) = 32)),
    CONSTRAINT relay_invites_use_count_check CHECK ((use_count >= 0))
);


--
-- Name: relay_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.relay_members (
    community_id uuid NOT NULL,
    pubkey text NOT NULL,
    role text NOT NULL,
    added_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT relay_members_role_check CHECK ((role = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text])))
);


--
-- Name: replica_heartbeat; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.replica_heartbeat (
    id smallint NOT NULL,
    epoch uuid DEFAULT gen_random_uuid() NOT NULL,
    token bigint DEFAULT 0 NOT NULL,
    CONSTRAINT replica_heartbeat_id_check CHECK ((id = 1))
);


--
-- Name: scheduled_workflow_fires; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scheduled_workflow_fires (
    community_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    scheduled_for timestamp with time zone NOT NULL,
    claimed_at timestamp with time zone DEFAULT now() NOT NULL,
    workflow_run_id uuid
);


--
-- Name: subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subscriptions (
    community_id uuid NOT NULL,
    id character varying(255) NOT NULL,
    owner_pubkey bytea NOT NULL,
    filter_kinds jsonb,
    filter_authors jsonb,
    filter_channel_ids jsonb,
    filter_since timestamp with time zone,
    filter_until timestamp with time zone,
    delivery_method public.delivery_method DEFAULT 'webhook'::public.delivery_method NOT NULL,
    delivery_url text,
    status public.subscription_status DEFAULT 'active'::public.subscription_status NOT NULL,
    pause_reason public.pause_reason,
    delivered_count bigint DEFAULT 0 NOT NULL,
    error_count bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: thread_metadata; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.thread_metadata (
    community_id uuid NOT NULL,
    event_created_at timestamp with time zone NOT NULL,
    event_id bytea NOT NULL,
    channel_id uuid NOT NULL,
    parent_event_id bytea,
    parent_event_created_at timestamp with time zone,
    root_event_id bytea,
    root_event_created_at timestamp with time zone,
    depth integer DEFAULT 0 NOT NULL,
    reply_count integer DEFAULT 0 NOT NULL,
    descendant_count integer DEFAULT 0 NOT NULL,
    last_reply_at timestamp with time zone,
    broadcast boolean DEFAULT false NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    community_id uuid NOT NULL,
    pubkey bytea NOT NULL,
    nip05_handle character varying(255),
    display_name character varying(255),
    avatar_url text,
    about text,
    agent_type character varying(255),
    capabilities jsonb,
    okta_user_id character varying(255),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deactivated_at timestamp with time zone,
    metadata_event_id bytea,
    agent_owner_pubkey bytea,
    channel_add_policy public.channel_add_policy DEFAULT 'anyone'::public.channel_add_policy NOT NULL,
    CONSTRAINT chk_users_pubkey_len CHECK ((length(pubkey) = 32))
);


--
-- Name: workflow_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_approvals (
    community_id uuid NOT NULL,
    token bytea NOT NULL,
    workflow_id uuid NOT NULL,
    run_id uuid NOT NULL,
    step_id character varying(64) NOT NULL,
    step_index integer NOT NULL,
    approver_spec text NOT NULL,
    status public.approval_status DEFAULT 'pending'::public.approval_status NOT NULL,
    approver_pubkey bytea,
    note text,
    granted_at timestamp with time zone,
    denied_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: workflow_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_runs (
    community_id uuid NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workflow_id uuid NOT NULL,
    status public.run_status DEFAULT 'pending'::public.run_status NOT NULL,
    trigger_event_id bytea,
    current_step integer DEFAULT 0 NOT NULL,
    execution_trace jsonb DEFAULT '[]'::jsonb NOT NULL,
    trigger_context jsonb,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: workflows; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflows (
    community_id uuid NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    owner_pubkey bytea NOT NULL,
    channel_id uuid,
    definition jsonb NOT NULL,
    definition_hash bytea NOT NULL,
    status public.workflow_status DEFAULT 'active'::public.workflow_status NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: delivery_log_p2026_03; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log ATTACH PARTITION public.delivery_log_p2026_03 FOR VALUES FROM ('2026-03-01 00:00:00+00') TO ('2026-04-01 00:00:00+00');


--
-- Name: delivery_log_p2026_04; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log ATTACH PARTITION public.delivery_log_p2026_04 FOR VALUES FROM ('2026-04-01 00:00:00+00') TO ('2026-05-01 00:00:00+00');


--
-- Name: delivery_log_p2026_05; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log ATTACH PARTITION public.delivery_log_p2026_05 FOR VALUES FROM ('2026-05-01 00:00:00+00') TO ('2026-06-01 00:00:00+00');


--
-- Name: delivery_log_p2026_06; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log ATTACH PARTITION public.delivery_log_p2026_06 FOR VALUES FROM ('2026-06-01 00:00:00+00') TO ('2026-07-01 00:00:00+00');


--
-- Name: delivery_log_p_future; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log ATTACH PARTITION public.delivery_log_p_future FOR VALUES FROM ('2026-07-01 00:00:00+00') TO (MAXVALUE);


--
-- Name: delivery_log_p_past; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log ATTACH PARTITION public.delivery_log_p_past FOR VALUES FROM (MINVALUE) TO ('2026-03-01 00:00:00+00');


--
-- Name: events_p2026_01; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ATTACH PARTITION public.events_p2026_01 FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2026-02-01 00:00:00+00');


--
-- Name: events_p2026_02; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ATTACH PARTITION public.events_p2026_02 FOR VALUES FROM ('2026-02-01 00:00:00+00') TO ('2026-03-01 00:00:00+00');


--
-- Name: events_p2026_03; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ATTACH PARTITION public.events_p2026_03 FOR VALUES FROM ('2026-03-01 00:00:00+00') TO ('2026-04-01 00:00:00+00');


--
-- Name: events_p2026_04; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ATTACH PARTITION public.events_p2026_04 FOR VALUES FROM ('2026-04-01 00:00:00+00') TO ('2026-05-01 00:00:00+00');


--
-- Name: events_p2026_05; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ATTACH PARTITION public.events_p2026_05 FOR VALUES FROM ('2026-05-01 00:00:00+00') TO ('2026-06-01 00:00:00+00');


--
-- Name: events_p2026_06; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ATTACH PARTITION public.events_p2026_06 FOR VALUES FROM ('2026-06-01 00:00:00+00') TO ('2026-07-01 00:00:00+00');


--
-- Name: events_p_future; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ATTACH PARTITION public.events_p_future FOR VALUES FROM ('2026-07-01 00:00:00+00') TO (MAXVALUE);


--
-- Name: events_p_past; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ATTACH PARTITION public.events_p_past FOR VALUES FROM (MINVALUE) TO ('2026-01-01 00:00:00+00');


--
-- Name: _operator_global_tables _operator_global_tables_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public._operator_global_tables
    ADD CONSTRAINT _operator_global_tables_pkey PRIMARY KEY (table_name);


--
-- Name: api_tokens api_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_pkey PRIMARY KEY (community_id, id);


--
-- Name: archived_identities archived_identities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.archived_identities
    ADD CONSTRAINT archived_identities_pkey PRIMARY KEY (community_id, pubkey);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (community_id, seq);


--
-- Name: authorization_authority_epochs authorization_authority_epoch_community_id_object_kind_obje_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_authority_epochs
    ADD CONSTRAINT authorization_authority_epoch_community_id_object_kind_obje_key UNIQUE (community_id, object_kind, object_key, authority_epoch, fence, operation_id, request_fingerprint);


--
-- Name: authorization_authority_epochs authorization_authority_epochs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_authority_epochs
    ADD CONSTRAINT authorization_authority_epochs_pkey PRIMARY KEY (community_id, object_kind, object_key);


--
-- Name: authorization_event_capacity authorization_event_capacity_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_event_capacity
    ADD CONSTRAINT authorization_event_capacity_pkey PRIMARY KEY (community_id);


--
-- Name: authorization_events authorization_events_community_id_event_id_event_kind_opera_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_events
    ADD CONSTRAINT authorization_events_community_id_event_id_event_kind_opera_key UNIQUE (community_id, event_id, event_kind, operation_id);


--
-- Name: authorization_events authorization_events_community_id_event_id_operation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_events
    ADD CONSTRAINT authorization_events_community_id_event_id_operation_id_key UNIQUE (community_id, event_id, operation_id);


--
-- Name: authorization_events authorization_events_community_id_operation_id_event_kind_a_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_events
    ADD CONSTRAINT authorization_events_community_id_operation_id_event_kind_a_key UNIQUE (community_id, operation_id, event_kind, attempt_id);


--
-- Name: authorization_events authorization_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_events
    ADD CONSTRAINT authorization_events_pkey PRIMARY KEY (community_id, event_id);


--
-- Name: authorization_invalidation_domains authorization_invalidation_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_invalidation_domains
    ADD CONSTRAINT authorization_invalidation_domains_pkey PRIMARY KEY (community_id);


--
-- Name: authorization_invalidation_floors authorization_invalidation_floors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_invalidation_floors
    ADD CONSTRAINT authorization_invalidation_floors_pkey PRIMARY KEY (community_id, selector_kind, selector_fingerprint);


--
-- Name: authorization_operation_receipts authorization_operation_recei_community_id_operation_id_re_key1; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operation_receipts
    ADD CONSTRAINT authorization_operation_recei_community_id_operation_id_re_key1 UNIQUE (community_id, operation_id, request_fingerprint, operation_kind, outcome_code);


--
-- Name: authorization_operation_receipts authorization_operation_recei_community_id_operation_id_req_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operation_receipts
    ADD CONSTRAINT authorization_operation_recei_community_id_operation_id_req_key UNIQUE (community_id, operation_id, request_fingerprint);


--
-- Name: authorization_operation_receipts authorization_operation_receipts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operation_receipts
    ADD CONSTRAINT authorization_operation_receipts_pkey PRIMARY KEY (community_id, operation_id);


--
-- Name: authorization_operation_version_delta_manifests authorization_operation_versi_community_id_operation_id_req_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operation_version_delta_manifests
    ADD CONSTRAINT authorization_operation_versi_community_id_operation_id_req_key UNIQUE (community_id, operation_id, request_fingerprint);


--
-- Name: authorization_operation_version_delta_manifests authorization_operation_version_delta_manifests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operation_version_delta_manifests
    ADD CONSTRAINT authorization_operation_version_delta_manifests_pkey PRIMARY KEY (community_id, operation_id);


--
-- Name: authorization_operation_version_deltas authorization_operation_version_deltas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operation_version_deltas
    ADD CONSTRAINT authorization_operation_version_deltas_pkey PRIMARY KEY (community_id, operation_id, component_kind, component_key);


--
-- Name: authorization_operator_preauth_denial_events authorization_operator_preaut_community_id_operation_id_cor_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operator_preauth_denial_events
    ADD CONSTRAINT authorization_operator_preaut_community_id_operation_id_cor_key UNIQUE (community_id, operation_id, correlation_id, semantic_fingerprint, denial_reason);


--
-- Name: authorization_operator_preauth_denial_capacity authorization_operator_preauth_denial_capacity_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operator_preauth_denial_capacity
    ADD CONSTRAINT authorization_operator_preauth_denial_capacity_pkey PRIMARY KEY (community_id);


--
-- Name: authorization_operator_preauth_denial_events authorization_operator_preauth_denial_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operator_preauth_denial_events
    ADD CONSTRAINT authorization_operator_preauth_denial_events_pkey PRIMARY KEY (community_id, event_id);


--
-- Name: channel_members channel_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.channel_members
    ADD CONSTRAINT channel_members_pkey PRIMARY KEY (community_id, channel_id, pubkey);


--
-- Name: channels channels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.channels
    ADD CONSTRAINT channels_pkey PRIMARY KEY (community_id, id);


--
-- Name: client_status_revisions client_status_revisions_community_id_operation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_status_revisions
    ADD CONSTRAINT client_status_revisions_community_id_operation_id_key UNIQUE (community_id, operation_id);


--
-- Name: client_status_revisions client_status_revisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_status_revisions
    ADD CONSTRAINT client_status_revisions_pkey PRIMARY KEY (community_id, event_author_pubkey, revision);


--
-- Name: communities communities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.communities
    ADD CONSTRAINT communities_pkey PRIMARY KEY (id);


--
-- Name: community_bans community_bans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.community_bans
    ADD CONSTRAINT community_bans_pkey PRIMARY KEY (community_id, pubkey);


--
-- Name: delivery_log delivery_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log
    ADD CONSTRAINT delivery_log_pkey PRIMARY KEY (delivered_at, id);


--
-- Name: delivery_log_p2026_03 delivery_log_p2026_03_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log_p2026_03
    ADD CONSTRAINT delivery_log_p2026_03_pkey PRIMARY KEY (delivered_at, id);


--
-- Name: delivery_log_p2026_04 delivery_log_p2026_04_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log_p2026_04
    ADD CONSTRAINT delivery_log_p2026_04_pkey PRIMARY KEY (delivered_at, id);


--
-- Name: delivery_log_p2026_05 delivery_log_p2026_05_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log_p2026_05
    ADD CONSTRAINT delivery_log_p2026_05_pkey PRIMARY KEY (delivered_at, id);


--
-- Name: delivery_log_p2026_06 delivery_log_p2026_06_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log_p2026_06
    ADD CONSTRAINT delivery_log_p2026_06_pkey PRIMARY KEY (delivered_at, id);


--
-- Name: delivery_log_p_future delivery_log_p_future_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log_p_future
    ADD CONSTRAINT delivery_log_p_future_pkey PRIMARY KEY (delivered_at, id);


--
-- Name: delivery_log_p_past delivery_log_p_past_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delivery_log_p_past
    ADD CONSTRAINT delivery_log_p_past_pkey PRIMARY KEY (delivered_at, id);


--
-- Name: event_mentions event_mentions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_mentions
    ADD CONSTRAINT event_mentions_pkey PRIMARY KEY (community_id, pubkey_hex, event_id);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (community_id, created_at, id);


--
-- Name: events_p2026_01 events_p2026_01_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events_p2026_01
    ADD CONSTRAINT events_p2026_01_pkey PRIMARY KEY (community_id, created_at, id);


--
-- Name: events_p2026_02 events_p2026_02_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events_p2026_02
    ADD CONSTRAINT events_p2026_02_pkey PRIMARY KEY (community_id, created_at, id);


--
-- Name: events_p2026_03 events_p2026_03_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events_p2026_03
    ADD CONSTRAINT events_p2026_03_pkey PRIMARY KEY (community_id, created_at, id);


--
-- Name: events_p2026_04 events_p2026_04_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events_p2026_04
    ADD CONSTRAINT events_p2026_04_pkey PRIMARY KEY (community_id, created_at, id);


--
-- Name: events_p2026_05 events_p2026_05_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events_p2026_05
    ADD CONSTRAINT events_p2026_05_pkey PRIMARY KEY (community_id, created_at, id);


--
-- Name: events_p2026_06 events_p2026_06_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events_p2026_06
    ADD CONSTRAINT events_p2026_06_pkey PRIMARY KEY (community_id, created_at, id);


--
-- Name: events_p_future events_p_future_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events_p_future
    ADD CONSTRAINT events_p_future_pkey PRIMARY KEY (community_id, created_at, id);


--
-- Name: events_p_past events_p_past_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events_p_past
    ADD CONSTRAINT events_p_past_pkey PRIMARY KEY (community_id, created_at, id);


--
-- Name: git_repo_names git_repo_names_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.git_repo_names
    ADD CONSTRAINT git_repo_names_pkey PRIMARY KEY (community_id, repo_id);


--
-- Name: identity_bindings identity_bindings_community_id_binding_id_binding_version_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_bindings
    ADD CONSTRAINT identity_bindings_community_id_binding_id_binding_version_key UNIQUE (community_id, binding_id, binding_version);


--
-- Name: identity_bindings identity_bindings_community_id_binding_version_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_bindings
    ADD CONSTRAINT identity_bindings_community_id_binding_version_key UNIQUE (community_id, binding_version);


--
-- Name: identity_bindings identity_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_bindings
    ADD CONSTRAINT identity_bindings_pkey PRIMARY KEY (community_id, binding_id);


--
-- Name: identity_enrollment_policies identity_enrollment_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_enrollment_policies
    ADD CONSTRAINT identity_enrollment_policies_pkey PRIMARY KEY (community_id, policy_revision);


--
-- Name: identity_lifecycle_history identity_lifecycle_history_community_id_history_id_old_bind_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_history
    ADD CONSTRAINT identity_lifecycle_history_community_id_history_id_old_bind_key UNIQUE (community_id, history_id, old_binding_id, old_binding_version, old_resulting_lifecycle_revision, old_resulting_state);


--
-- Name: identity_lifecycle_history identity_lifecycle_history_community_id_history_id_operatio_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_history
    ADD CONSTRAINT identity_lifecycle_history_community_id_history_id_operatio_key UNIQUE (community_id, history_id, operation_id, request_fingerprint);


--
-- Name: identity_lifecycle_history identity_lifecycle_history_community_id_history_id_successo_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_history
    ADD CONSTRAINT identity_lifecycle_history_community_id_history_id_successo_key UNIQUE (community_id, history_id, successor_binding_id, successor_binding_version, operation_id, request_fingerprint);


--
-- Name: identity_lifecycle_history identity_lifecycle_history_community_id_operation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_history
    ADD CONSTRAINT identity_lifecycle_history_community_id_operation_id_key UNIQUE (community_id, operation_id);


--
-- Name: identity_lifecycle_history identity_lifecycle_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_history
    ADD CONSTRAINT identity_lifecycle_history_pkey PRIMARY KEY (community_id, history_id);


--
-- Name: identity_lifecycle_selector_consumptions identity_lifecycle_selector_consumptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selector_consumptions
    ADD CONSTRAINT identity_lifecycle_selector_consumptions_pkey PRIMARY KEY (community_id, selector_id);


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selectors_community_id_selector_id_selec_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selectors
    ADD CONSTRAINT identity_lifecycle_selectors_community_id_selector_id_selec_key UNIQUE (community_id, selector_id, selector_kind);


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selectors_community_id_selector_kind_sel_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selectors
    ADD CONSTRAINT identity_lifecycle_selectors_community_id_selector_kind_sel_key UNIQUE (community_id, selector_kind, selector_fingerprint, fact_generation);


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selectors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selectors
    ADD CONSTRAINT identity_lifecycle_selectors_pkey PRIMARY KEY (community_id, selector_id);


--
-- Name: join_policy_acceptances join_policy_acceptances_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.join_policy_acceptances
    ADD CONSTRAINT join_policy_acceptances_pkey PRIMARY KEY (community_id, pubkey, policy_version);


--
-- Name: moderation_actions moderation_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.moderation_actions
    ADD CONSTRAINT moderation_actions_pkey PRIMARY KEY (community_id, id);


--
-- Name: moderation_reports moderation_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.moderation_reports
    ADD CONSTRAINT moderation_reports_pkey PRIMARY KEY (community_id, id);


--
-- Name: parameterized_event_watermarks parameterized_event_watermarks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.parameterized_event_watermarks
    ADD CONSTRAINT parameterized_event_watermarks_pkey PRIMARY KEY (community_id, kind, pubkey, d_tag);


--
-- Name: product_feedback product_feedback_event_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.product_feedback
    ADD CONSTRAINT product_feedback_event_id_key UNIQUE (event_id);


--
-- Name: product_feedback product_feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.product_feedback
    ADD CONSTRAINT product_feedback_pkey PRIMARY KEY (id);


--
-- Name: protected_object_authority protected_object_authority_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protected_object_authority
    ADD CONSTRAINT protected_object_authority_pkey PRIMARY KEY (community_id, object_kind, object_key);


--
-- Name: pubkey_allowlist pubkey_allowlist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pubkey_allowlist
    ADD CONSTRAINT pubkey_allowlist_pkey PRIMARY KEY (community_id, pubkey);


--
-- Name: push_gateway_challenges push_gateway_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_gateway_challenges
    ADD CONSTRAINT push_gateway_challenges_pkey PRIMARY KEY (id);


--
-- Name: push_gateway_delegations push_gateway_delegations_installation_id_relay_pubkey_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_gateway_delegations
    ADD CONSTRAINT push_gateway_delegations_installation_id_relay_pubkey_key UNIQUE (installation_id, relay_pubkey);


--
-- Name: push_gateway_delegations push_gateway_delegations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_gateway_delegations
    ADD CONSTRAINT push_gateway_delegations_pkey PRIMARY KEY (id);


--
-- Name: push_gateway_delivery_auth_replays push_gateway_delivery_auth_replays_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_gateway_delivery_auth_replays
    ADD CONSTRAINT push_gateway_delivery_auth_replays_pkey PRIMARY KEY (relay_pubkey, auth_event_id);


--
-- Name: push_gateway_delivery_request_replays push_gateway_delivery_request_replays_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_gateway_delivery_request_replays
    ADD CONSTRAINT push_gateway_delivery_request_replays_pkey PRIMARY KEY (relay_pubkey, request_id);


--
-- Name: push_gateway_endpoint_quotas push_gateway_endpoint_quotas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_gateway_endpoint_quotas
    ADD CONSTRAINT push_gateway_endpoint_quotas_pkey PRIMARY KEY (token_fingerprint);


--
-- Name: push_gateway_installations push_gateway_installations_app_attest_key_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_gateway_installations
    ADD CONSTRAINT push_gateway_installations_app_attest_key_id_key UNIQUE (app_attest_key_id);


--
-- Name: push_gateway_installations push_gateway_installations_app_profile_token_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_gateway_installations
    ADD CONSTRAINT push_gateway_installations_app_profile_token_fingerprint_key UNIQUE (app_profile, token_fingerprint);


--
-- Name: push_gateway_installations push_gateway_installations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_gateway_installations
    ADD CONSTRAINT push_gateway_installations_pkey PRIMARY KEY (id);


--
-- Name: push_leases push_leases_community_id_source_event_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_leases
    ADD CONSTRAINT push_leases_community_id_source_event_id_key UNIQUE (community_id, source_event_id);


--
-- Name: push_leases push_leases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_leases
    ADD CONSTRAINT push_leases_pkey PRIMARY KEY (community_id, author, installation_id);


--
-- Name: push_match_queue push_match_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_match_queue
    ADD CONSTRAINT push_match_queue_pkey PRIMARY KEY (community_id, event_id);


--
-- Name: push_wake_outbox push_wake_outbox_community_id_endpoint_hash_event_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_wake_outbox
    ADD CONSTRAINT push_wake_outbox_community_id_endpoint_hash_event_id_key UNIQUE (community_id, endpoint_hash, event_id);


--
-- Name: push_wake_outbox push_wake_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_wake_outbox
    ADD CONSTRAINT push_wake_outbox_pkey PRIMARY KEY (community_id, id);


--
-- Name: rate_limit_violations rate_limit_violations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limit_violations
    ADD CONSTRAINT rate_limit_violations_pkey PRIMARY KEY (id);


--
-- Name: reactions reactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reactions
    ADD CONSTRAINT reactions_pkey PRIMARY KEY (community_id, event_created_at, event_id, pubkey, emoji);


--
-- Name: relay_invites relay_invites_community_id_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.relay_invites
    ADD CONSTRAINT relay_invites_community_id_token_hash_key UNIQUE (community_id, token_hash);


--
-- Name: relay_invites relay_invites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.relay_invites
    ADD CONSTRAINT relay_invites_pkey PRIMARY KEY (community_id, id);


--
-- Name: relay_members relay_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.relay_members
    ADD CONSTRAINT relay_members_pkey PRIMARY KEY (community_id, pubkey);


--
-- Name: replica_heartbeat replica_heartbeat_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.replica_heartbeat
    ADD CONSTRAINT replica_heartbeat_pkey PRIMARY KEY (id);


--
-- Name: scheduled_workflow_fires scheduled_workflow_fires_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_workflow_fires
    ADD CONSTRAINT scheduled_workflow_fires_pkey PRIMARY KEY (community_id, workflow_id, scheduled_for);


--
-- Name: subscriptions subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_pkey PRIMARY KEY (community_id, id);


--
-- Name: thread_metadata thread_metadata_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.thread_metadata
    ADD CONSTRAINT thread_metadata_pkey PRIMARY KEY (community_id, event_created_at, event_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (community_id, pubkey);


--
-- Name: workflow_approvals workflow_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_approvals
    ADD CONSTRAINT workflow_approvals_pkey PRIMARY KEY (community_id, token);


--
-- Name: workflow_runs workflow_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_pkey PRIMARY KEY (community_id, id);


--
-- Name: workflows workflows_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT workflows_pkey PRIMARY KEY (community_id, id);


--
-- Name: authorization_operator_preauth_denial_retention; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX authorization_operator_preauth_denial_retention ON public.authorization_operator_preauth_denial_events USING btree (community_id, retain_until, event_id);


--
-- Name: client_status_revisions_current_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX client_status_revisions_current_lookup ON public.client_status_revisions USING btree (community_id, event_author_pubkey, revision DESC);


--
-- Name: idx_delivery_log_community_sub; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_delivery_log_community_sub ON ONLY public.delivery_log USING btree (community_id, subscription_id);


--
-- Name: delivery_log_p2026_03_community_id_subscription_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX delivery_log_p2026_03_community_id_subscription_id_idx ON public.delivery_log_p2026_03 USING btree (community_id, subscription_id);


--
-- Name: delivery_log_p2026_04_community_id_subscription_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX delivery_log_p2026_04_community_id_subscription_id_idx ON public.delivery_log_p2026_04 USING btree (community_id, subscription_id);


--
-- Name: delivery_log_p2026_05_community_id_subscription_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX delivery_log_p2026_05_community_id_subscription_id_idx ON public.delivery_log_p2026_05 USING btree (community_id, subscription_id);


--
-- Name: delivery_log_p2026_06_community_id_subscription_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX delivery_log_p2026_06_community_id_subscription_id_idx ON public.delivery_log_p2026_06 USING btree (community_id, subscription_id);


--
-- Name: delivery_log_p_future_community_id_subscription_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX delivery_log_p_future_community_id_subscription_id_idx ON public.delivery_log_p_future USING btree (community_id, subscription_id);


--
-- Name: delivery_log_p_past_community_id_subscription_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX delivery_log_p_past_community_id_subscription_id_idx ON public.delivery_log_p_past USING btree (community_id, subscription_id);


--
-- Name: idx_events_community_channel_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_community_channel_created ON ONLY public.events USING btree (community_id, channel_id, created_at DESC, id);


--
-- Name: events_p2026_01_community_id_channel_id_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_01_community_id_channel_id_created_at_id_idx ON public.events_p2026_01 USING btree (community_id, channel_id, created_at DESC, id);


--
-- Name: idx_events_community_deleted; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_community_deleted ON ONLY public.events USING btree (community_id, deleted_at);


--
-- Name: events_p2026_01_community_id_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_01_community_id_deleted_at_idx ON public.events_p2026_01 USING btree (community_id, deleted_at);


--
-- Name: idx_events_community_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_community_id ON ONLY public.events USING btree (community_id, id, created_at DESC);


--
-- Name: events_p2026_01_community_id_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_01_community_id_id_created_at_idx ON public.events_p2026_01 USING btree (community_id, id, created_at DESC);


--
-- Name: idx_events_community_kind_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_community_kind_created ON ONLY public.events USING btree (community_id, kind, created_at DESC, id);


--
-- Name: events_p2026_01_community_id_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_01_community_id_kind_created_at_id_idx ON public.events_p2026_01 USING btree (community_id, kind, created_at DESC, id);


--
-- Name: idx_events_addressable; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_addressable ON ONLY public.events USING btree (community_id, kind, pubkey, channel_id, deleted_at);


--
-- Name: events_p2026_01_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_01_community_id_kind_pubkey_channel_id_deleted_idx ON public.events_p2026_01 USING btree (community_id, kind, pubkey, channel_id, deleted_at);


--
-- Name: idx_events_parameterized; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_parameterized ON ONLY public.events USING btree (community_id, kind, pubkey, d_tag, created_at DESC, id) WHERE ((d_tag IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: events_p2026_01_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_01_community_id_kind_pubkey_d_tag_created_at_i_idx ON public.events_p2026_01 USING btree (community_id, kind, pubkey, d_tag, created_at DESC, id) WHERE ((d_tag IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: idx_events_not_before; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_not_before ON ONLY public.events USING btree (community_id, not_before) WHERE ((not_before IS NOT NULL) AND (deleted_at IS NULL) AND (delivered_at IS NULL));


--
-- Name: events_p2026_01_community_id_not_before_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_01_community_id_not_before_idx ON public.events_p2026_01 USING btree (community_id, not_before) WHERE ((not_before IS NOT NULL) AND (deleted_at IS NULL) AND (delivered_at IS NULL));


--
-- Name: idx_events_community_pubkey_kind_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_community_pubkey_kind_created ON ONLY public.events USING btree (community_id, pubkey, kind, created_at DESC, id);


--
-- Name: events_p2026_01_community_id_pubkey_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_01_community_id_pubkey_kind_created_at_id_idx ON public.events_p2026_01 USING btree (community_id, pubkey, kind, created_at DESC, id);


--
-- Name: idx_events_search_tsv; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_search_tsv ON ONLY public.events USING gin (search_tsv);


--
-- Name: events_p2026_01_search_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_01_search_tsv_idx ON public.events_p2026_01 USING gin (search_tsv);


--
-- Name: idx_events_tags_gin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_tags_gin ON ONLY public.events USING gin (tags jsonb_path_ops);


--
-- Name: events_p2026_01_tags_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_01_tags_idx ON public.events_p2026_01 USING gin (tags jsonb_path_ops);


--
-- Name: events_p2026_02_community_id_channel_id_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_02_community_id_channel_id_created_at_id_idx ON public.events_p2026_02 USING btree (community_id, channel_id, created_at DESC, id);


--
-- Name: events_p2026_02_community_id_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_02_community_id_deleted_at_idx ON public.events_p2026_02 USING btree (community_id, deleted_at);


--
-- Name: events_p2026_02_community_id_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_02_community_id_id_created_at_idx ON public.events_p2026_02 USING btree (community_id, id, created_at DESC);


--
-- Name: events_p2026_02_community_id_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_02_community_id_kind_created_at_id_idx ON public.events_p2026_02 USING btree (community_id, kind, created_at DESC, id);


--
-- Name: events_p2026_02_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_02_community_id_kind_pubkey_channel_id_deleted_idx ON public.events_p2026_02 USING btree (community_id, kind, pubkey, channel_id, deleted_at);


--
-- Name: events_p2026_02_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_02_community_id_kind_pubkey_d_tag_created_at_i_idx ON public.events_p2026_02 USING btree (community_id, kind, pubkey, d_tag, created_at DESC, id) WHERE ((d_tag IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: events_p2026_02_community_id_not_before_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_02_community_id_not_before_idx ON public.events_p2026_02 USING btree (community_id, not_before) WHERE ((not_before IS NOT NULL) AND (deleted_at IS NULL) AND (delivered_at IS NULL));


--
-- Name: events_p2026_02_community_id_pubkey_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_02_community_id_pubkey_kind_created_at_id_idx ON public.events_p2026_02 USING btree (community_id, pubkey, kind, created_at DESC, id);


--
-- Name: events_p2026_02_search_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_02_search_tsv_idx ON public.events_p2026_02 USING gin (search_tsv);


--
-- Name: events_p2026_02_tags_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_02_tags_idx ON public.events_p2026_02 USING gin (tags jsonb_path_ops);


--
-- Name: events_p2026_03_community_id_channel_id_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_03_community_id_channel_id_created_at_id_idx ON public.events_p2026_03 USING btree (community_id, channel_id, created_at DESC, id);


--
-- Name: events_p2026_03_community_id_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_03_community_id_deleted_at_idx ON public.events_p2026_03 USING btree (community_id, deleted_at);


--
-- Name: events_p2026_03_community_id_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_03_community_id_id_created_at_idx ON public.events_p2026_03 USING btree (community_id, id, created_at DESC);


--
-- Name: events_p2026_03_community_id_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_03_community_id_kind_created_at_id_idx ON public.events_p2026_03 USING btree (community_id, kind, created_at DESC, id);


--
-- Name: events_p2026_03_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_03_community_id_kind_pubkey_channel_id_deleted_idx ON public.events_p2026_03 USING btree (community_id, kind, pubkey, channel_id, deleted_at);


--
-- Name: events_p2026_03_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_03_community_id_kind_pubkey_d_tag_created_at_i_idx ON public.events_p2026_03 USING btree (community_id, kind, pubkey, d_tag, created_at DESC, id) WHERE ((d_tag IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: events_p2026_03_community_id_not_before_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_03_community_id_not_before_idx ON public.events_p2026_03 USING btree (community_id, not_before) WHERE ((not_before IS NOT NULL) AND (deleted_at IS NULL) AND (delivered_at IS NULL));


--
-- Name: events_p2026_03_community_id_pubkey_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_03_community_id_pubkey_kind_created_at_id_idx ON public.events_p2026_03 USING btree (community_id, pubkey, kind, created_at DESC, id);


--
-- Name: events_p2026_03_search_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_03_search_tsv_idx ON public.events_p2026_03 USING gin (search_tsv);


--
-- Name: events_p2026_03_tags_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_03_tags_idx ON public.events_p2026_03 USING gin (tags jsonb_path_ops);


--
-- Name: events_p2026_04_community_id_channel_id_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_04_community_id_channel_id_created_at_id_idx ON public.events_p2026_04 USING btree (community_id, channel_id, created_at DESC, id);


--
-- Name: events_p2026_04_community_id_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_04_community_id_deleted_at_idx ON public.events_p2026_04 USING btree (community_id, deleted_at);


--
-- Name: events_p2026_04_community_id_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_04_community_id_id_created_at_idx ON public.events_p2026_04 USING btree (community_id, id, created_at DESC);


--
-- Name: events_p2026_04_community_id_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_04_community_id_kind_created_at_id_idx ON public.events_p2026_04 USING btree (community_id, kind, created_at DESC, id);


--
-- Name: events_p2026_04_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_04_community_id_kind_pubkey_channel_id_deleted_idx ON public.events_p2026_04 USING btree (community_id, kind, pubkey, channel_id, deleted_at);


--
-- Name: events_p2026_04_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_04_community_id_kind_pubkey_d_tag_created_at_i_idx ON public.events_p2026_04 USING btree (community_id, kind, pubkey, d_tag, created_at DESC, id) WHERE ((d_tag IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: events_p2026_04_community_id_not_before_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_04_community_id_not_before_idx ON public.events_p2026_04 USING btree (community_id, not_before) WHERE ((not_before IS NOT NULL) AND (deleted_at IS NULL) AND (delivered_at IS NULL));


--
-- Name: events_p2026_04_community_id_pubkey_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_04_community_id_pubkey_kind_created_at_id_idx ON public.events_p2026_04 USING btree (community_id, pubkey, kind, created_at DESC, id);


--
-- Name: events_p2026_04_search_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_04_search_tsv_idx ON public.events_p2026_04 USING gin (search_tsv);


--
-- Name: events_p2026_04_tags_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_04_tags_idx ON public.events_p2026_04 USING gin (tags jsonb_path_ops);


--
-- Name: events_p2026_05_community_id_channel_id_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_05_community_id_channel_id_created_at_id_idx ON public.events_p2026_05 USING btree (community_id, channel_id, created_at DESC, id);


--
-- Name: events_p2026_05_community_id_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_05_community_id_deleted_at_idx ON public.events_p2026_05 USING btree (community_id, deleted_at);


--
-- Name: events_p2026_05_community_id_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_05_community_id_id_created_at_idx ON public.events_p2026_05 USING btree (community_id, id, created_at DESC);


--
-- Name: events_p2026_05_community_id_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_05_community_id_kind_created_at_id_idx ON public.events_p2026_05 USING btree (community_id, kind, created_at DESC, id);


--
-- Name: events_p2026_05_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_05_community_id_kind_pubkey_channel_id_deleted_idx ON public.events_p2026_05 USING btree (community_id, kind, pubkey, channel_id, deleted_at);


--
-- Name: events_p2026_05_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_05_community_id_kind_pubkey_d_tag_created_at_i_idx ON public.events_p2026_05 USING btree (community_id, kind, pubkey, d_tag, created_at DESC, id) WHERE ((d_tag IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: events_p2026_05_community_id_not_before_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_05_community_id_not_before_idx ON public.events_p2026_05 USING btree (community_id, not_before) WHERE ((not_before IS NOT NULL) AND (deleted_at IS NULL) AND (delivered_at IS NULL));


--
-- Name: events_p2026_05_community_id_pubkey_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_05_community_id_pubkey_kind_created_at_id_idx ON public.events_p2026_05 USING btree (community_id, pubkey, kind, created_at DESC, id);


--
-- Name: events_p2026_05_search_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_05_search_tsv_idx ON public.events_p2026_05 USING gin (search_tsv);


--
-- Name: events_p2026_05_tags_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_05_tags_idx ON public.events_p2026_05 USING gin (tags jsonb_path_ops);


--
-- Name: events_p2026_06_community_id_channel_id_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_06_community_id_channel_id_created_at_id_idx ON public.events_p2026_06 USING btree (community_id, channel_id, created_at DESC, id);


--
-- Name: events_p2026_06_community_id_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_06_community_id_deleted_at_idx ON public.events_p2026_06 USING btree (community_id, deleted_at);


--
-- Name: events_p2026_06_community_id_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_06_community_id_id_created_at_idx ON public.events_p2026_06 USING btree (community_id, id, created_at DESC);


--
-- Name: events_p2026_06_community_id_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_06_community_id_kind_created_at_id_idx ON public.events_p2026_06 USING btree (community_id, kind, created_at DESC, id);


--
-- Name: events_p2026_06_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_06_community_id_kind_pubkey_channel_id_deleted_idx ON public.events_p2026_06 USING btree (community_id, kind, pubkey, channel_id, deleted_at);


--
-- Name: events_p2026_06_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_06_community_id_kind_pubkey_d_tag_created_at_i_idx ON public.events_p2026_06 USING btree (community_id, kind, pubkey, d_tag, created_at DESC, id) WHERE ((d_tag IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: events_p2026_06_community_id_not_before_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_06_community_id_not_before_idx ON public.events_p2026_06 USING btree (community_id, not_before) WHERE ((not_before IS NOT NULL) AND (deleted_at IS NULL) AND (delivered_at IS NULL));


--
-- Name: events_p2026_06_community_id_pubkey_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_06_community_id_pubkey_kind_created_at_id_idx ON public.events_p2026_06 USING btree (community_id, pubkey, kind, created_at DESC, id);


--
-- Name: events_p2026_06_search_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_06_search_tsv_idx ON public.events_p2026_06 USING gin (search_tsv);


--
-- Name: events_p2026_06_tags_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p2026_06_tags_idx ON public.events_p2026_06 USING gin (tags jsonb_path_ops);


--
-- Name: events_p_future_community_id_channel_id_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_future_community_id_channel_id_created_at_id_idx ON public.events_p_future USING btree (community_id, channel_id, created_at DESC, id);


--
-- Name: events_p_future_community_id_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_future_community_id_deleted_at_idx ON public.events_p_future USING btree (community_id, deleted_at);


--
-- Name: events_p_future_community_id_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_future_community_id_id_created_at_idx ON public.events_p_future USING btree (community_id, id, created_at DESC);


--
-- Name: events_p_future_community_id_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_future_community_id_kind_created_at_id_idx ON public.events_p_future USING btree (community_id, kind, created_at DESC, id);


--
-- Name: events_p_future_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_future_community_id_kind_pubkey_channel_id_deleted_idx ON public.events_p_future USING btree (community_id, kind, pubkey, channel_id, deleted_at);


--
-- Name: events_p_future_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_future_community_id_kind_pubkey_d_tag_created_at_i_idx ON public.events_p_future USING btree (community_id, kind, pubkey, d_tag, created_at DESC, id) WHERE ((d_tag IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: events_p_future_community_id_not_before_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_future_community_id_not_before_idx ON public.events_p_future USING btree (community_id, not_before) WHERE ((not_before IS NOT NULL) AND (deleted_at IS NULL) AND (delivered_at IS NULL));


--
-- Name: events_p_future_community_id_pubkey_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_future_community_id_pubkey_kind_created_at_id_idx ON public.events_p_future USING btree (community_id, pubkey, kind, created_at DESC, id);


--
-- Name: events_p_future_search_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_future_search_tsv_idx ON public.events_p_future USING gin (search_tsv);


--
-- Name: events_p_future_tags_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_future_tags_idx ON public.events_p_future USING gin (tags jsonb_path_ops);


--
-- Name: events_p_past_community_id_channel_id_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_past_community_id_channel_id_created_at_id_idx ON public.events_p_past USING btree (community_id, channel_id, created_at DESC, id);


--
-- Name: events_p_past_community_id_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_past_community_id_deleted_at_idx ON public.events_p_past USING btree (community_id, deleted_at);


--
-- Name: events_p_past_community_id_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_past_community_id_id_created_at_idx ON public.events_p_past USING btree (community_id, id, created_at DESC);


--
-- Name: events_p_past_community_id_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_past_community_id_kind_created_at_id_idx ON public.events_p_past USING btree (community_id, kind, created_at DESC, id);


--
-- Name: events_p_past_community_id_kind_pubkey_channel_id_deleted_a_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_past_community_id_kind_pubkey_channel_id_deleted_a_idx ON public.events_p_past USING btree (community_id, kind, pubkey, channel_id, deleted_at);


--
-- Name: events_p_past_community_id_kind_pubkey_d_tag_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_past_community_id_kind_pubkey_d_tag_created_at_id_idx ON public.events_p_past USING btree (community_id, kind, pubkey, d_tag, created_at DESC, id) WHERE ((d_tag IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: events_p_past_community_id_not_before_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_past_community_id_not_before_idx ON public.events_p_past USING btree (community_id, not_before) WHERE ((not_before IS NOT NULL) AND (deleted_at IS NULL) AND (delivered_at IS NULL));


--
-- Name: events_p_past_community_id_pubkey_kind_created_at_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_past_community_id_pubkey_kind_created_at_id_idx ON public.events_p_past USING btree (community_id, pubkey, kind, created_at DESC, id);


--
-- Name: events_p_past_search_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_past_search_tsv_idx ON public.events_p_past USING gin (search_tsv);


--
-- Name: events_p_past_tags_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_p_past_tags_idx ON public.events_p_past USING gin (tags jsonb_path_ops);


--
-- Name: identity_bindings_active_event_author; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX identity_bindings_active_event_author ON public.identity_bindings USING btree (community_id, event_author_pubkey) WHERE (binding_state = 1);


--
-- Name: identity_bindings_active_principal; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX identity_bindings_active_principal ON public.identity_bindings USING btree (community_id, issuer, subject) WHERE (binding_state = 1);


--
-- Name: identity_bindings_current_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_bindings_current_lookup ON public.identity_bindings USING btree (community_id, event_author_pubkey, binding_state, expires_at);


--
-- Name: identity_bindings_principal_fingerprint_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_bindings_principal_fingerprint_lookup ON public.identity_bindings USING btree (community_id, principal_fingerprint) WHERE (binding_state = 1);


--
-- Name: identity_lifecycle_consumptions_history; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_lifecycle_consumptions_history ON public.identity_lifecycle_selector_consumptions USING btree (community_id, history_id, selector_kind);


--
-- Name: identity_lifecycle_history_old_binding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_lifecycle_history_old_binding ON public.identity_lifecycle_history USING btree (community_id, old_binding_id, old_binding_version, recorded_at);


--
-- Name: identity_lifecycle_history_successor_binding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_lifecycle_history_successor_binding ON public.identity_lifecycle_history USING btree (community_id, successor_binding_id, successor_binding_version, recorded_at);


--
-- Name: identity_lifecycle_selectors_asserted_history; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_lifecycle_selectors_asserted_history ON public.identity_lifecycle_selectors USING btree (community_id, asserted_history_id, selector_kind);


--
-- Name: identity_lifecycle_selectors_binding_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_lifecycle_selectors_binding_lookup ON public.identity_lifecycle_selectors USING btree (community_id, selector_kind, binding_id, binding_version, fact_generation);


--
-- Name: identity_lifecycle_selectors_fact_generation; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX identity_lifecycle_selectors_fact_generation ON public.identity_lifecycle_selectors USING btree (community_id, selector_kind, principal_fingerprint, fact_generation) WHERE (selector_kind = ANY (ARRAY[2, 4]));


--
-- Name: identity_lifecycle_selectors_key_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_lifecycle_selectors_key_lookup ON public.identity_lifecycle_selectors USING btree (community_id, selector_kind, event_author_pubkey, fact_generation);


--
-- Name: identity_lifecycle_selectors_permanent_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX identity_lifecycle_selectors_permanent_key ON public.identity_lifecycle_selectors USING btree (community_id, event_author_pubkey) WHERE (selector_kind = 3);


--
-- Name: identity_lifecycle_selectors_permanent_pair; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX identity_lifecycle_selectors_permanent_pair ON public.identity_lifecycle_selectors USING btree (community_id, binding_id, binding_version) WHERE (selector_kind = 1);


--
-- Name: identity_lifecycle_selectors_permanent_principal_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX identity_lifecycle_selectors_permanent_principal_key ON public.identity_lifecycle_selectors USING btree (community_id, principal_fingerprint, event_author_pubkey) WHERE (selector_kind = 1);


--
-- Name: identity_lifecycle_selectors_principal_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_lifecycle_selectors_principal_lookup ON public.identity_lifecycle_selectors USING btree (community_id, selector_kind, principal_fingerprint, fact_generation);


--
-- Name: idx_api_tokens_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_api_tokens_hash ON public.api_tokens USING btree (community_id, token_hash);


--
-- Name: idx_audit_log_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_audit_log_hash ON public.audit_log USING btree (community_id, hash);


--
-- Name: idx_channel_members_pubkey; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_channel_members_pubkey ON public.channel_members USING btree (community_id, pubkey) WHERE (removed_at IS NULL);


--
-- Name: idx_channels_community_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_channels_community_type ON public.channels USING btree (community_id, channel_type);


--
-- Name: idx_channels_community_visibility; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_channels_community_visibility ON public.channels USING btree (community_id, visibility);


--
-- Name: idx_channels_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_channels_created_by ON public.channels USING btree (community_id, created_by);


--
-- Name: idx_channels_dm_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_channels_dm_hash ON public.channels USING btree (community_id, participant_hash) WHERE (participant_hash IS NOT NULL);


--
-- Name: idx_channels_id_live; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_channels_id_live ON public.channels USING btree (id) INCLUDE (community_id) WHERE (deleted_at IS NULL);


--
-- Name: idx_channels_nip29_group; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_channels_nip29_group ON public.channels USING btree (community_id, nip29_group_id) WHERE (nip29_group_id IS NOT NULL);


--
-- Name: idx_channels_ttl_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_channels_ttl_expiry ON public.channels USING btree (ttl_deadline) WHERE ((ttl_seconds IS NOT NULL) AND (archived_at IS NULL) AND (deleted_at IS NULL));


--
-- Name: idx_communities_host; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_communities_host ON public.communities USING btree (lower((host)::text));


--
-- Name: idx_event_mentions_community_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_event_mentions_community_event ON public.event_mentions USING btree (community_id, event_id);


--
-- Name: idx_event_mentions_pubkey_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_event_mentions_pubkey_created ON public.event_mentions USING btree (community_id, pubkey_hex, event_created_at DESC);


--
-- Name: idx_event_mentions_pubkey_kind_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_event_mentions_pubkey_kind_created ON public.event_mentions USING btree (community_id, pubkey_hex, event_kind, event_created_at DESC);


--
-- Name: idx_git_repo_names_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_git_repo_names_owner ON public.git_repo_names USING btree (community_id, owner_pubkey);


--
-- Name: idx_moderation_actions_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_moderation_actions_created ON public.moderation_actions USING btree (community_id, created_at DESC);


--
-- Name: idx_moderation_actions_target_pubkey; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_moderation_actions_target_pubkey ON public.moderation_actions USING btree (community_id, target_pubkey) WHERE (target_pubkey IS NOT NULL);


--
-- Name: idx_moderation_reports_event; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_moderation_reports_event ON public.moderation_reports USING btree (community_id, report_event_id);


--
-- Name: idx_moderation_reports_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_moderation_reports_status ON public.moderation_reports USING btree (community_id, status, created_at DESC);


--
-- Name: idx_moderation_reports_target_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_moderation_reports_target_event ON public.moderation_reports USING btree (community_id, target_event_id) WHERE (target_event_id IS NOT NULL);


--
-- Name: idx_moderation_reports_target_pubkey; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_moderation_reports_target_pubkey ON public.moderation_reports USING btree (community_id, target_pubkey) WHERE (target_pubkey IS NOT NULL);


--
-- Name: idx_product_feedback_community_received; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_product_feedback_community_received ON public.product_feedback USING btree (community_id, received_at DESC, id);


--
-- Name: idx_product_feedback_received; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_product_feedback_received ON public.product_feedback USING btree (received_at DESC, id);


--
-- Name: idx_reactions_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reactions_event ON public.reactions USING btree (community_id, event_id, event_created_at);


--
-- Name: idx_reactions_pubkey; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reactions_pubkey ON public.reactions USING btree (community_id, pubkey);


--
-- Name: idx_reactions_source_event; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_reactions_source_event ON public.reactions USING btree (community_id, reaction_event_id) WHERE (reaction_event_id IS NOT NULL);


--
-- Name: idx_relay_members_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_relay_members_role ON public.relay_members USING btree (community_id, role);


--
-- Name: idx_scheduled_fires_claimed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scheduled_fires_claimed_at ON public.scheduled_workflow_fires USING btree (claimed_at);


--
-- Name: idx_thread_metadata_channel_depth; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_thread_metadata_channel_depth ON public.thread_metadata USING btree (community_id, channel_id, depth, event_created_at);


--
-- Name: idx_thread_metadata_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_thread_metadata_event_id ON public.thread_metadata USING btree (community_id, event_id);


--
-- Name: idx_thread_metadata_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_thread_metadata_parent ON public.thread_metadata USING btree (community_id, parent_event_id);


--
-- Name: idx_thread_metadata_root; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_thread_metadata_root ON public.thread_metadata USING btree (community_id, root_event_id);


--
-- Name: idx_users_nip05; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_users_nip05 ON public.users USING btree (community_id, lower((nip05_handle)::text)) WHERE (nip05_handle IS NOT NULL);


--
-- Name: idx_users_okta; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_users_okta ON public.users USING btree (community_id, okta_user_id) WHERE (okta_user_id IS NOT NULL);


--
-- Name: idx_workflow_approvals_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_approvals_run ON public.workflow_approvals USING btree (community_id, run_id);


--
-- Name: idx_workflow_approvals_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_approvals_status ON public.workflow_approvals USING btree (community_id, status);


--
-- Name: idx_workflow_approvals_workflow; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_approvals_workflow ON public.workflow_approvals USING btree (community_id, workflow_id);


--
-- Name: idx_workflow_runs_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_runs_status ON public.workflow_runs USING btree (community_id, status);


--
-- Name: idx_workflow_runs_workflow; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_runs_workflow ON public.workflow_runs USING btree (community_id, workflow_id);


--
-- Name: idx_workflows_channel_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_channel_active ON public.workflows USING btree (community_id, channel_id, status, enabled);


--
-- Name: idx_workflows_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_enabled ON public.workflows USING btree (enabled, status) WHERE enabled;


--
-- Name: push_gateway_challenges_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_gateway_challenges_expiry ON public.push_gateway_challenges USING btree (expires_at);


--
-- Name: push_gateway_delegations_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_gateway_delegations_expiry ON public.push_gateway_delegations USING btree (expires_at) WHERE (revoked_at IS NULL);


--
-- Name: push_gateway_delivery_auth_replays_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_gateway_delivery_auth_replays_expiry ON public.push_gateway_delivery_auth_replays USING btree (expires_at);


--
-- Name: push_gateway_delivery_request_replays_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_gateway_delivery_request_replays_expiry ON public.push_gateway_delivery_request_replays USING btree (expires_at);


--
-- Name: push_gateway_endpoint_quotas_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_gateway_endpoint_quotas_updated ON public.push_gateway_endpoint_quotas USING btree (updated_at);


--
-- Name: push_gateway_installations_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_gateway_installations_expiry ON public.push_gateway_installations USING btree (expires_at) WHERE (revoked_at IS NULL);


--
-- Name: push_leases_endpoint_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX push_leases_endpoint_unique ON public.push_leases USING btree (community_id, author, app_profile, endpoint_hash) WHERE active;


--
-- Name: push_leases_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_leases_expiry ON public.push_leases USING btree (community_id, expires_at) WHERE active;


--
-- Name: push_match_queue_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_match_queue_due ON public.push_match_queue USING btree (next_attempt_at, created_at) WHERE (state = 'pending'::text);


--
-- Name: push_match_queue_recovery; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_match_queue_recovery ON public.push_match_queue USING btree (lease_until) WHERE (state = 'matching'::text);


--
-- Name: push_wake_outbox_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_wake_outbox_due ON public.push_wake_outbox USING btree (community_id, next_attempt_at) WHERE (state = 'pending'::text);


--
-- Name: push_wake_outbox_recovery; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_wake_outbox_recovery ON public.push_wake_outbox USING btree (community_id, lease_until) WHERE (state = 'sending'::text);


--
-- Name: relay_invites_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX relay_invites_expires_at_idx ON public.relay_invites USING btree (expires_at);


--
-- Name: delivery_log_p2026_03_community_id_subscription_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_delivery_log_community_sub ATTACH PARTITION public.delivery_log_p2026_03_community_id_subscription_id_idx;


--
-- Name: delivery_log_p2026_03_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.delivery_log_pkey ATTACH PARTITION public.delivery_log_p2026_03_pkey;


--
-- Name: delivery_log_p2026_04_community_id_subscription_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_delivery_log_community_sub ATTACH PARTITION public.delivery_log_p2026_04_community_id_subscription_id_idx;


--
-- Name: delivery_log_p2026_04_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.delivery_log_pkey ATTACH PARTITION public.delivery_log_p2026_04_pkey;


--
-- Name: delivery_log_p2026_05_community_id_subscription_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_delivery_log_community_sub ATTACH PARTITION public.delivery_log_p2026_05_community_id_subscription_id_idx;


--
-- Name: delivery_log_p2026_05_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.delivery_log_pkey ATTACH PARTITION public.delivery_log_p2026_05_pkey;


--
-- Name: delivery_log_p2026_06_community_id_subscription_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_delivery_log_community_sub ATTACH PARTITION public.delivery_log_p2026_06_community_id_subscription_id_idx;


--
-- Name: delivery_log_p2026_06_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.delivery_log_pkey ATTACH PARTITION public.delivery_log_p2026_06_pkey;


--
-- Name: delivery_log_p_future_community_id_subscription_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_delivery_log_community_sub ATTACH PARTITION public.delivery_log_p_future_community_id_subscription_id_idx;


--
-- Name: delivery_log_p_future_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.delivery_log_pkey ATTACH PARTITION public.delivery_log_p_future_pkey;


--
-- Name: delivery_log_p_past_community_id_subscription_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_delivery_log_community_sub ATTACH PARTITION public.delivery_log_p_past_community_id_subscription_id_idx;


--
-- Name: delivery_log_p_past_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.delivery_log_pkey ATTACH PARTITION public.delivery_log_p_past_pkey;


--
-- Name: events_p2026_01_community_id_channel_id_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_channel_created ATTACH PARTITION public.events_p2026_01_community_id_channel_id_created_at_id_idx;


--
-- Name: events_p2026_01_community_id_deleted_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_deleted ATTACH PARTITION public.events_p2026_01_community_id_deleted_at_idx;


--
-- Name: events_p2026_01_community_id_id_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_id ATTACH PARTITION public.events_p2026_01_community_id_id_created_at_idx;


--
-- Name: events_p2026_01_community_id_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_kind_created ATTACH PARTITION public.events_p2026_01_community_id_kind_created_at_id_idx;


--
-- Name: events_p2026_01_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_addressable ATTACH PARTITION public.events_p2026_01_community_id_kind_pubkey_channel_id_deleted_idx;


--
-- Name: events_p2026_01_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_parameterized ATTACH PARTITION public.events_p2026_01_community_id_kind_pubkey_d_tag_created_at_i_idx;


--
-- Name: events_p2026_01_community_id_not_before_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_not_before ATTACH PARTITION public.events_p2026_01_community_id_not_before_idx;


--
-- Name: events_p2026_01_community_id_pubkey_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_pubkey_kind_created ATTACH PARTITION public.events_p2026_01_community_id_pubkey_kind_created_at_id_idx;


--
-- Name: events_p2026_01_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.events_pkey ATTACH PARTITION public.events_p2026_01_pkey;


--
-- Name: events_p2026_01_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_search_tsv ATTACH PARTITION public.events_p2026_01_search_tsv_idx;


--
-- Name: events_p2026_01_tags_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_tags_gin ATTACH PARTITION public.events_p2026_01_tags_idx;


--
-- Name: events_p2026_02_community_id_channel_id_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_channel_created ATTACH PARTITION public.events_p2026_02_community_id_channel_id_created_at_id_idx;


--
-- Name: events_p2026_02_community_id_deleted_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_deleted ATTACH PARTITION public.events_p2026_02_community_id_deleted_at_idx;


--
-- Name: events_p2026_02_community_id_id_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_id ATTACH PARTITION public.events_p2026_02_community_id_id_created_at_idx;


--
-- Name: events_p2026_02_community_id_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_kind_created ATTACH PARTITION public.events_p2026_02_community_id_kind_created_at_id_idx;


--
-- Name: events_p2026_02_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_addressable ATTACH PARTITION public.events_p2026_02_community_id_kind_pubkey_channel_id_deleted_idx;


--
-- Name: events_p2026_02_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_parameterized ATTACH PARTITION public.events_p2026_02_community_id_kind_pubkey_d_tag_created_at_i_idx;


--
-- Name: events_p2026_02_community_id_not_before_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_not_before ATTACH PARTITION public.events_p2026_02_community_id_not_before_idx;


--
-- Name: events_p2026_02_community_id_pubkey_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_pubkey_kind_created ATTACH PARTITION public.events_p2026_02_community_id_pubkey_kind_created_at_id_idx;


--
-- Name: events_p2026_02_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.events_pkey ATTACH PARTITION public.events_p2026_02_pkey;


--
-- Name: events_p2026_02_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_search_tsv ATTACH PARTITION public.events_p2026_02_search_tsv_idx;


--
-- Name: events_p2026_02_tags_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_tags_gin ATTACH PARTITION public.events_p2026_02_tags_idx;


--
-- Name: events_p2026_03_community_id_channel_id_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_channel_created ATTACH PARTITION public.events_p2026_03_community_id_channel_id_created_at_id_idx;


--
-- Name: events_p2026_03_community_id_deleted_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_deleted ATTACH PARTITION public.events_p2026_03_community_id_deleted_at_idx;


--
-- Name: events_p2026_03_community_id_id_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_id ATTACH PARTITION public.events_p2026_03_community_id_id_created_at_idx;


--
-- Name: events_p2026_03_community_id_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_kind_created ATTACH PARTITION public.events_p2026_03_community_id_kind_created_at_id_idx;


--
-- Name: events_p2026_03_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_addressable ATTACH PARTITION public.events_p2026_03_community_id_kind_pubkey_channel_id_deleted_idx;


--
-- Name: events_p2026_03_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_parameterized ATTACH PARTITION public.events_p2026_03_community_id_kind_pubkey_d_tag_created_at_i_idx;


--
-- Name: events_p2026_03_community_id_not_before_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_not_before ATTACH PARTITION public.events_p2026_03_community_id_not_before_idx;


--
-- Name: events_p2026_03_community_id_pubkey_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_pubkey_kind_created ATTACH PARTITION public.events_p2026_03_community_id_pubkey_kind_created_at_id_idx;


--
-- Name: events_p2026_03_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.events_pkey ATTACH PARTITION public.events_p2026_03_pkey;


--
-- Name: events_p2026_03_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_search_tsv ATTACH PARTITION public.events_p2026_03_search_tsv_idx;


--
-- Name: events_p2026_03_tags_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_tags_gin ATTACH PARTITION public.events_p2026_03_tags_idx;


--
-- Name: events_p2026_04_community_id_channel_id_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_channel_created ATTACH PARTITION public.events_p2026_04_community_id_channel_id_created_at_id_idx;


--
-- Name: events_p2026_04_community_id_deleted_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_deleted ATTACH PARTITION public.events_p2026_04_community_id_deleted_at_idx;


--
-- Name: events_p2026_04_community_id_id_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_id ATTACH PARTITION public.events_p2026_04_community_id_id_created_at_idx;


--
-- Name: events_p2026_04_community_id_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_kind_created ATTACH PARTITION public.events_p2026_04_community_id_kind_created_at_id_idx;


--
-- Name: events_p2026_04_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_addressable ATTACH PARTITION public.events_p2026_04_community_id_kind_pubkey_channel_id_deleted_idx;


--
-- Name: events_p2026_04_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_parameterized ATTACH PARTITION public.events_p2026_04_community_id_kind_pubkey_d_tag_created_at_i_idx;


--
-- Name: events_p2026_04_community_id_not_before_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_not_before ATTACH PARTITION public.events_p2026_04_community_id_not_before_idx;


--
-- Name: events_p2026_04_community_id_pubkey_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_pubkey_kind_created ATTACH PARTITION public.events_p2026_04_community_id_pubkey_kind_created_at_id_idx;


--
-- Name: events_p2026_04_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.events_pkey ATTACH PARTITION public.events_p2026_04_pkey;


--
-- Name: events_p2026_04_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_search_tsv ATTACH PARTITION public.events_p2026_04_search_tsv_idx;


--
-- Name: events_p2026_04_tags_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_tags_gin ATTACH PARTITION public.events_p2026_04_tags_idx;


--
-- Name: events_p2026_05_community_id_channel_id_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_channel_created ATTACH PARTITION public.events_p2026_05_community_id_channel_id_created_at_id_idx;


--
-- Name: events_p2026_05_community_id_deleted_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_deleted ATTACH PARTITION public.events_p2026_05_community_id_deleted_at_idx;


--
-- Name: events_p2026_05_community_id_id_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_id ATTACH PARTITION public.events_p2026_05_community_id_id_created_at_idx;


--
-- Name: events_p2026_05_community_id_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_kind_created ATTACH PARTITION public.events_p2026_05_community_id_kind_created_at_id_idx;


--
-- Name: events_p2026_05_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_addressable ATTACH PARTITION public.events_p2026_05_community_id_kind_pubkey_channel_id_deleted_idx;


--
-- Name: events_p2026_05_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_parameterized ATTACH PARTITION public.events_p2026_05_community_id_kind_pubkey_d_tag_created_at_i_idx;


--
-- Name: events_p2026_05_community_id_not_before_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_not_before ATTACH PARTITION public.events_p2026_05_community_id_not_before_idx;


--
-- Name: events_p2026_05_community_id_pubkey_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_pubkey_kind_created ATTACH PARTITION public.events_p2026_05_community_id_pubkey_kind_created_at_id_idx;


--
-- Name: events_p2026_05_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.events_pkey ATTACH PARTITION public.events_p2026_05_pkey;


--
-- Name: events_p2026_05_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_search_tsv ATTACH PARTITION public.events_p2026_05_search_tsv_idx;


--
-- Name: events_p2026_05_tags_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_tags_gin ATTACH PARTITION public.events_p2026_05_tags_idx;


--
-- Name: events_p2026_06_community_id_channel_id_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_channel_created ATTACH PARTITION public.events_p2026_06_community_id_channel_id_created_at_id_idx;


--
-- Name: events_p2026_06_community_id_deleted_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_deleted ATTACH PARTITION public.events_p2026_06_community_id_deleted_at_idx;


--
-- Name: events_p2026_06_community_id_id_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_id ATTACH PARTITION public.events_p2026_06_community_id_id_created_at_idx;


--
-- Name: events_p2026_06_community_id_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_kind_created ATTACH PARTITION public.events_p2026_06_community_id_kind_created_at_id_idx;


--
-- Name: events_p2026_06_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_addressable ATTACH PARTITION public.events_p2026_06_community_id_kind_pubkey_channel_id_deleted_idx;


--
-- Name: events_p2026_06_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_parameterized ATTACH PARTITION public.events_p2026_06_community_id_kind_pubkey_d_tag_created_at_i_idx;


--
-- Name: events_p2026_06_community_id_not_before_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_not_before ATTACH PARTITION public.events_p2026_06_community_id_not_before_idx;


--
-- Name: events_p2026_06_community_id_pubkey_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_pubkey_kind_created ATTACH PARTITION public.events_p2026_06_community_id_pubkey_kind_created_at_id_idx;


--
-- Name: events_p2026_06_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.events_pkey ATTACH PARTITION public.events_p2026_06_pkey;


--
-- Name: events_p2026_06_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_search_tsv ATTACH PARTITION public.events_p2026_06_search_tsv_idx;


--
-- Name: events_p2026_06_tags_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_tags_gin ATTACH PARTITION public.events_p2026_06_tags_idx;


--
-- Name: events_p_future_community_id_channel_id_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_channel_created ATTACH PARTITION public.events_p_future_community_id_channel_id_created_at_id_idx;


--
-- Name: events_p_future_community_id_deleted_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_deleted ATTACH PARTITION public.events_p_future_community_id_deleted_at_idx;


--
-- Name: events_p_future_community_id_id_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_id ATTACH PARTITION public.events_p_future_community_id_id_created_at_idx;


--
-- Name: events_p_future_community_id_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_kind_created ATTACH PARTITION public.events_p_future_community_id_kind_created_at_id_idx;


--
-- Name: events_p_future_community_id_kind_pubkey_channel_id_deleted_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_addressable ATTACH PARTITION public.events_p_future_community_id_kind_pubkey_channel_id_deleted_idx;


--
-- Name: events_p_future_community_id_kind_pubkey_d_tag_created_at_i_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_parameterized ATTACH PARTITION public.events_p_future_community_id_kind_pubkey_d_tag_created_at_i_idx;


--
-- Name: events_p_future_community_id_not_before_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_not_before ATTACH PARTITION public.events_p_future_community_id_not_before_idx;


--
-- Name: events_p_future_community_id_pubkey_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_pubkey_kind_created ATTACH PARTITION public.events_p_future_community_id_pubkey_kind_created_at_id_idx;


--
-- Name: events_p_future_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.events_pkey ATTACH PARTITION public.events_p_future_pkey;


--
-- Name: events_p_future_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_search_tsv ATTACH PARTITION public.events_p_future_search_tsv_idx;


--
-- Name: events_p_future_tags_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_tags_gin ATTACH PARTITION public.events_p_future_tags_idx;


--
-- Name: events_p_past_community_id_channel_id_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_channel_created ATTACH PARTITION public.events_p_past_community_id_channel_id_created_at_id_idx;


--
-- Name: events_p_past_community_id_deleted_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_deleted ATTACH PARTITION public.events_p_past_community_id_deleted_at_idx;


--
-- Name: events_p_past_community_id_id_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_id ATTACH PARTITION public.events_p_past_community_id_id_created_at_idx;


--
-- Name: events_p_past_community_id_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_kind_created ATTACH PARTITION public.events_p_past_community_id_kind_created_at_id_idx;


--
-- Name: events_p_past_community_id_kind_pubkey_channel_id_deleted_a_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_addressable ATTACH PARTITION public.events_p_past_community_id_kind_pubkey_channel_id_deleted_a_idx;


--
-- Name: events_p_past_community_id_kind_pubkey_d_tag_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_parameterized ATTACH PARTITION public.events_p_past_community_id_kind_pubkey_d_tag_created_at_id_idx;


--
-- Name: events_p_past_community_id_not_before_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_not_before ATTACH PARTITION public.events_p_past_community_id_not_before_idx;


--
-- Name: events_p_past_community_id_pubkey_kind_created_at_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_community_pubkey_kind_created ATTACH PARTITION public.events_p_past_community_id_pubkey_kind_created_at_id_idx;


--
-- Name: events_p_past_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.events_pkey ATTACH PARTITION public.events_p_past_pkey;


--
-- Name: events_p_past_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_search_tsv ATTACH PARTITION public.events_p_past_search_tsv_idx;


--
-- Name: events_p_past_tags_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_events_tags_gin ATTACH PARTITION public.events_p_past_tags_idx;


--
-- Name: authorization_authority_epochs authorization_authority_epochs_monotonic; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_authority_epochs_monotonic BEFORE UPDATE ON public.authorization_authority_epochs FOR EACH ROW EXECUTE FUNCTION public.authorization_authority_epoch_guard_v1();


--
-- Name: authorization_authority_epochs authorization_authority_epochs_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_authority_epochs_no_delete BEFORE DELETE ON public.authorization_authority_epochs FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: authorization_authority_epochs authorization_authority_epochs_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_authority_epochs_no_truncate BEFORE TRUNCATE ON public.authorization_authority_epochs FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: authorization_event_capacity authorization_event_capacity_monotonic; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_event_capacity_monotonic BEFORE UPDATE ON public.authorization_event_capacity FOR EACH ROW EXECUTE FUNCTION public.authorization_event_capacity_guard_v1();


--
-- Name: authorization_event_capacity authorization_event_capacity_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_event_capacity_no_delete BEFORE DELETE ON public.authorization_event_capacity FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: authorization_event_capacity authorization_event_capacity_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_event_capacity_no_truncate BEFORE TRUNCATE ON public.authorization_event_capacity FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: authorization_event_capacity authorization_event_capacity_policy_prepare; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_event_capacity_policy_prepare BEFORE INSERT ON public.authorization_event_capacity FOR EACH ROW EXECUTE FUNCTION public.authorization_event_capacity_policy_insert_v1();


--
-- Name: authorization_events authorization_events_capacity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_events_capacity BEFORE INSERT ON public.authorization_events FOR EACH ROW EXECUTE FUNCTION public.authorization_event_capacity_before_insert_v1();


--
-- Name: authorization_events authorization_events_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_events_immutable BEFORE DELETE OR UPDATE ON public.authorization_events FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: authorization_events authorization_events_lifecycle_cardinality; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER authorization_events_lifecycle_cardinality AFTER INSERT ON public.authorization_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.authorization_operation_receipt_event_guard_v1();


--
-- Name: authorization_events authorization_events_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_events_no_truncate BEFORE TRUNCATE ON public.authorization_events FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: authorization_invalidation_domains authorization_invalidation_domains_monotonic; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_invalidation_domains_monotonic BEFORE UPDATE ON public.authorization_invalidation_domains FOR EACH ROW EXECUTE FUNCTION public.authorization_invalidation_domain_guard_v1();


--
-- Name: authorization_invalidation_domains authorization_invalidation_domains_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_invalidation_domains_no_delete BEFORE DELETE ON public.authorization_invalidation_domains FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: authorization_invalidation_domains authorization_invalidation_domains_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_invalidation_domains_no_truncate BEFORE TRUNCATE ON public.authorization_invalidation_domains FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: authorization_invalidation_floors authorization_invalidation_floors_monotonic; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_invalidation_floors_monotonic BEFORE UPDATE ON public.authorization_invalidation_floors FOR EACH ROW EXECUTE FUNCTION public.authorization_invalidation_floor_guard_v1();


--
-- Name: authorization_invalidation_floors authorization_invalidation_floors_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_invalidation_floors_no_delete BEFORE DELETE ON public.authorization_invalidation_floors FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: authorization_invalidation_floors authorization_invalidation_floors_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_invalidation_floors_no_truncate BEFORE TRUNCATE ON public.authorization_invalidation_floors FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: authorization_operation_receipts authorization_operation_receipt_event_cardinality; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER authorization_operation_receipt_event_cardinality AFTER INSERT ON public.authorization_operation_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.authorization_operation_receipt_event_guard_v1();


--
-- Name: authorization_operation_receipts authorization_operation_receipt_history_cardinality; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER authorization_operation_receipt_history_cardinality AFTER INSERT ON public.authorization_operation_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.authorization_operation_receipt_history_guard_v1();


--
-- Name: authorization_operation_receipts authorization_operation_receipts_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operation_receipts_immutable BEFORE DELETE OR UPDATE ON public.authorization_operation_receipts FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: authorization_operation_receipts authorization_operation_receipts_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operation_receipts_no_truncate BEFORE TRUNCATE ON public.authorization_operation_receipts FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: authorization_operation_version_deltas authorization_operation_version_delta_component_cardinality; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER authorization_operation_version_delta_component_cardinality AFTER INSERT ON public.authorization_operation_version_deltas DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.authorization_operation_version_delta_cardinality_guard_v1();


--
-- Name: authorization_operation_version_delta_manifests authorization_operation_version_delta_manifest_cardinality; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER authorization_operation_version_delta_manifest_cardinality AFTER INSERT ON public.authorization_operation_version_delta_manifests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.authorization_operation_version_delta_cardinality_guard_v1();


--
-- Name: authorization_operation_version_delta_manifests authorization_operation_version_delta_manifests_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operation_version_delta_manifests_immutable BEFORE DELETE OR UPDATE ON public.authorization_operation_version_delta_manifests FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: authorization_operation_version_delta_manifests authorization_operation_version_delta_manifests_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operation_version_delta_manifests_no_truncate BEFORE TRUNCATE ON public.authorization_operation_version_delta_manifests FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: authorization_operation_version_deltas authorization_operation_version_deltas_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operation_version_deltas_immutable BEFORE DELETE OR UPDATE ON public.authorization_operation_version_deltas FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: authorization_operation_version_deltas authorization_operation_version_deltas_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operation_version_deltas_no_truncate BEFORE TRUNCATE ON public.authorization_operation_version_deltas FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: authorization_operator_preauth_denial_events authorization_operator_preauth_denial_capacity_insert; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operator_preauth_denial_capacity_insert BEFORE INSERT ON public.authorization_operator_preauth_denial_events FOR EACH ROW EXECUTE FUNCTION public.authorization_operator_preauth_denial_capacity_before_insert_v1();


--
-- Name: authorization_operator_preauth_denial_capacity authorization_operator_preauth_denial_capacity_monotonic; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operator_preauth_denial_capacity_monotonic BEFORE INSERT OR UPDATE ON public.authorization_operator_preauth_denial_capacity FOR EACH ROW EXECUTE FUNCTION public.authorization_operator_preauth_denial_capacity_guard_v1();


--
-- Name: authorization_operator_preauth_denial_capacity authorization_operator_preauth_denial_capacity_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operator_preauth_denial_capacity_no_delete BEFORE DELETE ON public.authorization_operator_preauth_denial_capacity FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: authorization_operator_preauth_denial_capacity authorization_operator_preauth_denial_capacity_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operator_preauth_denial_capacity_no_truncate BEFORE TRUNCATE ON public.authorization_operator_preauth_denial_capacity FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: authorization_operator_preauth_denial_events authorization_operator_preauth_denial_events_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operator_preauth_denial_events_immutable BEFORE DELETE OR UPDATE ON public.authorization_operator_preauth_denial_events FOR EACH ROW EXECUTE FUNCTION public.authorization_operator_preauth_denial_events_retention_guard_v1();


--
-- Name: authorization_operator_preauth_denial_events authorization_operator_preauth_denial_events_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_operator_preauth_denial_events_no_truncate BEFORE TRUNCATE ON public.authorization_operator_preauth_denial_events FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: client_status_revisions client_status_revisions_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER client_status_revisions_immutable BEFORE DELETE OR UPDATE ON public.client_status_revisions FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: client_status_revisions client_status_revisions_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER client_status_revisions_no_truncate BEFORE TRUNCATE ON public.client_status_revisions FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: events events_created_at_floor; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER events_created_at_floor AFTER INSERT OR UPDATE OF created_at, channel_id ON public.events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.events_created_at_floor_guard();


--
-- Name: events events_enqueue_push_match; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER events_enqueue_push_match AFTER INSERT ON public.events FOR EACH ROW EXECUTE FUNCTION public.enqueue_push_match_job();


--
-- Name: events events_refresh_channel_ttl; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER events_refresh_channel_ttl AFTER INSERT ON public.events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.refresh_channel_ttl_after_event_insert();


--
-- Name: identity_bindings identity_bindings_birth_eligibility; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_bindings_birth_eligibility AFTER INSERT ON public.identity_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.identity_binding_birth_eligibility_guard_v1();


--
-- Name: identity_bindings identity_bindings_history_semantics; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_bindings_history_semantics AFTER INSERT OR UPDATE ON public.identity_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.identity_binding_history_semantics_guard_v1();


--
-- Name: identity_bindings identity_bindings_insert_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_bindings_insert_guard BEFORE INSERT ON public.identity_bindings FOR EACH ROW EXECUTE FUNCTION public.identity_bindings_insert_guard_v1();


--
-- Name: identity_bindings identity_bindings_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_bindings_no_delete BEFORE DELETE ON public.identity_bindings FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: identity_bindings identity_bindings_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_bindings_no_truncate BEFORE TRUNCATE ON public.identity_bindings FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: identity_bindings identity_bindings_transition_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_bindings_transition_guard BEFORE UPDATE ON public.identity_bindings FOR EACH ROW EXECUTE FUNCTION public.identity_bindings_transition_guard_v1();


--
-- Name: identity_bindings identity_bindings_transition_integrity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_bindings_transition_integrity AFTER INSERT OR UPDATE ON public.identity_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.identity_lifecycle_transition_integrity_guard_v1();


--
-- Name: identity_enrollment_policies identity_enrollment_policies_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_enrollment_policies_immutable BEFORE DELETE OR UPDATE ON public.identity_enrollment_policies FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: identity_enrollment_policies identity_enrollment_policies_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_enrollment_policies_no_truncate BEFORE TRUNCATE ON public.identity_enrollment_policies FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: identity_lifecycle_selector_consumptions identity_lifecycle_consumption_history_semantics; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_lifecycle_consumption_history_semantics AFTER INSERT ON public.identity_lifecycle_selector_consumptions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.identity_lifecycle_consumption_history_guard_v1();


--
-- Name: identity_lifecycle_selector_consumptions identity_lifecycle_consumption_lock; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_lifecycle_consumption_lock BEFORE INSERT ON public.identity_lifecycle_selector_consumptions FOR EACH ROW EXECUTE FUNCTION public.identity_lifecycle_consumption_lock_v1();


--
-- Name: identity_lifecycle_selector_consumptions identity_lifecycle_consumption_transition_integrity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_lifecycle_consumption_transition_integrity AFTER INSERT ON public.identity_lifecycle_selector_consumptions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.identity_lifecycle_transition_integrity_guard_v1();


--
-- Name: identity_lifecycle_history identity_lifecycle_history_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_lifecycle_history_immutable BEFORE DELETE OR UPDATE ON public.identity_lifecycle_history FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: identity_lifecycle_history identity_lifecycle_history_insert_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_lifecycle_history_insert_guard BEFORE INSERT ON public.identity_lifecycle_history FOR EACH ROW EXECUTE FUNCTION public.identity_lifecycle_history_insert_guard_v1();


--
-- Name: identity_lifecycle_history identity_lifecycle_history_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_lifecycle_history_no_truncate BEFORE TRUNCATE ON public.identity_lifecycle_history FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: identity_lifecycle_selector_consumptions identity_lifecycle_selector_consumptions_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_lifecycle_selector_consumptions_immutable BEFORE DELETE OR UPDATE ON public.identity_lifecycle_selector_consumptions FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: identity_lifecycle_selector_consumptions identity_lifecycle_selector_consumptions_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_lifecycle_selector_consumptions_no_truncate BEFORE TRUNCATE ON public.identity_lifecycle_selector_consumptions FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selector_history_semantics; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_lifecycle_selector_history_semantics AFTER INSERT ON public.identity_lifecycle_selectors DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.identity_lifecycle_selector_history_guard_v1();


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selector_insert_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_lifecycle_selector_insert_guard BEFORE INSERT ON public.identity_lifecycle_selectors FOR EACH ROW EXECUTE FUNCTION public.identity_lifecycle_selector_insert_guard_v1();


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selector_transition_integrity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_lifecycle_selector_transition_integrity AFTER INSERT ON public.identity_lifecycle_selectors DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.identity_lifecycle_transition_integrity_guard_v1();


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selectors_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_lifecycle_selectors_immutable BEFORE DELETE OR UPDATE ON public.identity_lifecycle_selectors FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selectors_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_lifecycle_selectors_no_truncate BEFORE TRUNCATE ON public.identity_lifecycle_selectors FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: identity_lifecycle_history identity_lifecycle_transition_integrity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_lifecycle_transition_integrity AFTER INSERT ON public.identity_lifecycle_history DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.identity_lifecycle_transition_integrity_guard_v1();


--
-- Name: protected_object_authority protected_object_authority_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER protected_object_authority_no_delete BEFORE DELETE ON public.protected_object_authority FOR EACH ROW EXECUTE FUNCTION public.nip_fi_reject_row_mutation_v1();


--
-- Name: protected_object_authority protected_object_authority_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER protected_object_authority_no_truncate BEFORE TRUNCATE ON public.protected_object_authority FOR EACH STATEMENT EXECUTE FUNCTION public.nip_fi_reject_truncate_v1();


--
-- Name: protected_object_authority protected_object_authority_strict_replacement; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER protected_object_authority_strict_replacement BEFORE UPDATE ON public.protected_object_authority FOR EACH ROW EXECUTE FUNCTION public.protected_object_authority_guard_v1();


--
-- Name: channels trg_channels_community_id_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_channels_community_id_immutable BEFORE UPDATE ON public.channels FOR EACH ROW EXECUTE FUNCTION public.channels_community_id_immutable();


--
-- Name: event_mentions trg_event_mentions_require_live_event; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_event_mentions_require_live_event BEFORE INSERT ON public.event_mentions FOR EACH ROW EXECUTE FUNCTION public.guard_event_mention_live();


--
-- Name: events trg_events_guard_nip_rs_hard_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_events_guard_nip_rs_hard_delete BEFORE DELETE ON public.events FOR EACH ROW WHEN (((old.kind = 30078) AND (old.d_tag ~ '^read-state:[0-9a-f]{32}$'::text))) EXECUTE FUNCTION public.guard_nip_rs_hard_delete();


--
-- Name: events trg_events_nip_rs_watermark; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_events_nip_rs_watermark BEFORE INSERT ON public.events FOR EACH ROW EXECUTE FUNCTION public.guard_nip_rs_watermark();


--
-- Name: events trg_events_purge_soft_deleted_buzz_mesh_status; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_events_purge_soft_deleted_buzz_mesh_status AFTER UPDATE OF deleted_at ON public.events FOR EACH ROW EXECUTE FUNCTION public.purge_soft_deleted_buzz_mesh_status();


--
-- Name: events trg_events_purge_soft_deleted_nip_rs; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_events_purge_soft_deleted_nip_rs AFTER UPDATE OF deleted_at ON public.events FOR EACH ROW EXECUTE FUNCTION public.purge_soft_deleted_nip_rs();


--
-- Name: api_tokens api_tokens_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: api_tokens api_tokens_community_id_owner_pubkey_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_community_id_owner_pubkey_fkey FOREIGN KEY (community_id, owner_pubkey) REFERENCES public.users(community_id, pubkey);


--
-- Name: archived_identities archived_identities_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.archived_identities
    ADD CONSTRAINT archived_identities_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: audit_log audit_log_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: authorization_authority_epochs authorization_authority_epoch_community_id_operation_id_re_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_authority_epochs
    ADD CONSTRAINT authorization_authority_epoch_community_id_operation_id_re_fkey FOREIGN KEY (community_id, operation_id, request_fingerprint) REFERENCES public.authorization_operation_receipts(community_id, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: authorization_authority_epochs authorization_authority_epochs_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_authority_epochs
    ADD CONSTRAINT authorization_authority_epochs_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: authorization_event_capacity authorization_event_capacity_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_event_capacity
    ADD CONSTRAINT authorization_event_capacity_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: authorization_events authorization_events_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_events
    ADD CONSTRAINT authorization_events_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: authorization_events authorization_events_community_id_operation_id_request_fin_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_events
    ADD CONSTRAINT authorization_events_community_id_operation_id_request_fin_fkey FOREIGN KEY (community_id, operation_id, request_fingerprint) REFERENCES public.authorization_operation_receipts(community_id, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: authorization_invalidation_domains authorization_invalidation_domains_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_invalidation_domains
    ADD CONSTRAINT authorization_invalidation_domains_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: authorization_invalidation_floors authorization_invalidation_fl_community_id_operation_id_re_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_invalidation_floors
    ADD CONSTRAINT authorization_invalidation_fl_community_id_operation_id_re_fkey FOREIGN KEY (community_id, operation_id, request_fingerprint) REFERENCES public.authorization_operation_receipts(community_id, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: authorization_invalidation_floors authorization_invalidation_floors_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_invalidation_floors
    ADD CONSTRAINT authorization_invalidation_floors_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: authorization_operation_receipts authorization_operation_receipts_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operation_receipts
    ADD CONSTRAINT authorization_operation_receipts_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: authorization_operation_version_delta_manifests authorization_operation_versi_community_id_operation_id_re_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operation_version_delta_manifests
    ADD CONSTRAINT authorization_operation_versi_community_id_operation_id_re_fkey FOREIGN KEY (community_id, operation_id, request_fingerprint) REFERENCES public.authorization_operation_receipts(community_id, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: authorization_operation_version_deltas authorization_operation_version__community_id_operation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operation_version_deltas
    ADD CONSTRAINT authorization_operation_version__community_id_operation_id_fkey FOREIGN KEY (community_id, operation_id) REFERENCES public.authorization_operation_version_delta_manifests(community_id, operation_id);


--
-- Name: authorization_operation_version_delta_manifests authorization_operation_version_delta_manifes_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operation_version_delta_manifests
    ADD CONSTRAINT authorization_operation_version_delta_manifes_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: authorization_operation_version_deltas authorization_operation_version_deltas_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operation_version_deltas
    ADD CONSTRAINT authorization_operation_version_deltas_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: authorization_operator_preauth_denial_capacity authorization_operator_preauth_denial_capacit_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operator_preauth_denial_capacity
    ADD CONSTRAINT authorization_operator_preauth_denial_capacit_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: authorization_operator_preauth_denial_events authorization_operator_preauth_denial_events_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_operator_preauth_denial_events
    ADD CONSTRAINT authorization_operator_preauth_denial_events_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: channel_members channel_members_community_id_channel_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.channel_members
    ADD CONSTRAINT channel_members_community_id_channel_id_fkey FOREIGN KEY (community_id, channel_id) REFERENCES public.channels(community_id, id) ON DELETE CASCADE;


--
-- Name: channel_members channel_members_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.channel_members
    ADD CONSTRAINT channel_members_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: channels channels_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.channels
    ADD CONSTRAINT channels_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: client_status_revisions client_status_revisions_community_id_binding_id_binding_ve_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_status_revisions
    ADD CONSTRAINT client_status_revisions_community_id_binding_id_binding_ve_fkey FOREIGN KEY (community_id, binding_id, binding_version) REFERENCES public.identity_bindings(community_id, binding_id, binding_version) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: client_status_revisions client_status_revisions_community_id_event_author_pubkey_s_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_status_revisions
    ADD CONSTRAINT client_status_revisions_community_id_event_author_pubkey_s_fkey FOREIGN KEY (community_id, event_author_pubkey, supersedes_revision) REFERENCES public.client_status_revisions(community_id, event_author_pubkey, revision) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: client_status_revisions client_status_revisions_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_status_revisions
    ADD CONSTRAINT client_status_revisions_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: client_status_revisions client_status_revisions_community_id_operation_id_request__fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_status_revisions
    ADD CONSTRAINT client_status_revisions_community_id_operation_id_request__fkey FOREIGN KEY (community_id, operation_id, request_fingerprint) REFERENCES public.authorization_operation_receipts(community_id, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: community_bans community_bans_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.community_bans
    ADD CONSTRAINT community_bans_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: delivery_log delivery_log_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.delivery_log
    ADD CONSTRAINT delivery_log_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: event_mentions event_mentions_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_mentions
    ADD CONSTRAINT event_mentions_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: events events_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.events
    ADD CONSTRAINT events_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: git_repo_names git_repo_names_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.git_repo_names
    ADD CONSTRAINT git_repo_names_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: identity_bindings identity_bindings_community_id_fkey1; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_bindings
    ADD CONSTRAINT identity_bindings_community_id_fkey1 FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: identity_bindings identity_bindings_community_id_policy_revision_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_bindings
    ADD CONSTRAINT identity_bindings_community_id_policy_revision_fkey FOREIGN KEY (community_id, policy_revision) REFERENCES public.identity_enrollment_policies(community_id, policy_revision);


--
-- Name: identity_bindings identity_bindings_exact_birth_history_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_bindings
    ADD CONSTRAINT identity_bindings_exact_birth_history_fk FOREIGN KEY (community_id, birth_history_id, binding_id, binding_version, creation_operation_id, creation_request_fingerprint) REFERENCES public.identity_lifecycle_history(community_id, history_id, successor_binding_id, successor_binding_version, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: identity_bindings identity_bindings_exact_retirement_history_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_bindings
    ADD CONSTRAINT identity_bindings_exact_retirement_history_fk FOREIGN KEY (community_id, retirement_history_id, binding_id, binding_version, lifecycle_revision, binding_state) REFERENCES public.identity_lifecycle_history(community_id, history_id, old_binding_id, old_binding_version, old_resulting_lifecycle_revision, old_resulting_state) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: identity_enrollment_policies identity_enrollment_policies_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_enrollment_policies
    ADD CONSTRAINT identity_enrollment_policies_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: identity_lifecycle_history identity_lifecycle_history_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_history
    ADD CONSTRAINT identity_lifecycle_history_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: identity_lifecycle_history identity_lifecycle_history_community_id_old_binding_id_old_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_history
    ADD CONSTRAINT identity_lifecycle_history_community_id_old_binding_id_old_fkey FOREIGN KEY (community_id, old_binding_id, old_binding_version) REFERENCES public.identity_bindings(community_id, binding_id, binding_version) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: identity_lifecycle_history identity_lifecycle_history_community_id_operation_id_reque_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_history
    ADD CONSTRAINT identity_lifecycle_history_community_id_operation_id_reque_fkey FOREIGN KEY (community_id, operation_id, request_fingerprint, transition_kind, outcome_code) REFERENCES public.authorization_operation_receipts(community_id, operation_id, request_fingerprint, operation_kind, outcome_code) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: identity_lifecycle_history identity_lifecycle_history_community_id_successor_binding__fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_history
    ADD CONSTRAINT identity_lifecycle_history_community_id_successor_binding__fkey FOREIGN KEY (community_id, successor_binding_id, successor_binding_version) REFERENCES public.identity_bindings(community_id, binding_id, binding_version) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: identity_lifecycle_selector_consumptions identity_lifecycle_selector_c_community_id_history_id_succ_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selector_consumptions
    ADD CONSTRAINT identity_lifecycle_selector_c_community_id_history_id_succ_fkey FOREIGN KEY (community_id, history_id, successor_binding_id, successor_binding_version, operation_id, request_fingerprint) REFERENCES public.identity_lifecycle_history(community_id, history_id, successor_binding_id, successor_binding_version, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: identity_lifecycle_selector_consumptions identity_lifecycle_selector_c_community_id_operation_id_re_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selector_consumptions
    ADD CONSTRAINT identity_lifecycle_selector_c_community_id_operation_id_re_fkey FOREIGN KEY (community_id, operation_id, request_fingerprint) REFERENCES public.authorization_operation_receipts(community_id, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: identity_lifecycle_selector_consumptions identity_lifecycle_selector_c_community_id_selector_id_sel_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selector_consumptions
    ADD CONSTRAINT identity_lifecycle_selector_c_community_id_selector_id_sel_fkey FOREIGN KEY (community_id, selector_id, selector_kind) REFERENCES public.identity_lifecycle_selectors(community_id, selector_id, selector_kind) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: identity_lifecycle_selector_consumptions identity_lifecycle_selector_consumptions_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selector_consumptions
    ADD CONSTRAINT identity_lifecycle_selector_consumptions_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selectors_community_id_asserted_history_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selectors
    ADD CONSTRAINT identity_lifecycle_selectors_community_id_asserted_history_fkey FOREIGN KEY (community_id, asserted_history_id, selected_by_operation_id, selected_by_request_fingerprint) REFERENCES public.identity_lifecycle_history(community_id, history_id, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selectors_community_id_binding_id_bindi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selectors
    ADD CONSTRAINT identity_lifecycle_selectors_community_id_binding_id_bindi_fkey FOREIGN KEY (community_id, binding_id, binding_version) REFERENCES public.identity_bindings(community_id, binding_id, binding_version) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selectors_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selectors
    ADD CONSTRAINT identity_lifecycle_selectors_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: identity_lifecycle_selectors identity_lifecycle_selectors_community_id_selected_by_oper_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_lifecycle_selectors
    ADD CONSTRAINT identity_lifecycle_selectors_community_id_selected_by_oper_fkey FOREIGN KEY (community_id, selected_by_operation_id, selected_by_request_fingerprint) REFERENCES public.authorization_operation_receipts(community_id, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: join_policy_acceptances join_policy_acceptances_community_id_pubkey_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.join_policy_acceptances
    ADD CONSTRAINT join_policy_acceptances_community_id_pubkey_fkey FOREIGN KEY (community_id, pubkey) REFERENCES public.relay_members(community_id, pubkey) ON DELETE CASCADE;


--
-- Name: moderation_actions moderation_actions_community_id_channel_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.moderation_actions
    ADD CONSTRAINT moderation_actions_community_id_channel_id_fkey FOREIGN KEY (community_id, channel_id) REFERENCES public.channels(community_id, id);


--
-- Name: moderation_actions moderation_actions_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.moderation_actions
    ADD CONSTRAINT moderation_actions_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: moderation_reports moderation_reports_community_id_action_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.moderation_reports
    ADD CONSTRAINT moderation_reports_community_id_action_id_fkey FOREIGN KEY (community_id, action_id) REFERENCES public.moderation_actions(community_id, id);


--
-- Name: moderation_reports moderation_reports_community_id_channel_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.moderation_reports
    ADD CONSTRAINT moderation_reports_community_id_channel_id_fkey FOREIGN KEY (community_id, channel_id) REFERENCES public.channels(community_id, id);


--
-- Name: moderation_reports moderation_reports_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.moderation_reports
    ADD CONSTRAINT moderation_reports_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: parameterized_event_watermarks parameterized_event_watermarks_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.parameterized_event_watermarks
    ADD CONSTRAINT parameterized_event_watermarks_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: product_feedback product_feedback_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.product_feedback
    ADD CONSTRAINT product_feedback_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: protected_object_authority protected_object_authority_community_id_binding_id_binding_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protected_object_authority
    ADD CONSTRAINT protected_object_authority_community_id_binding_id_binding_fkey FOREIGN KEY (community_id, binding_id, binding_version) REFERENCES public.identity_bindings(community_id, binding_id, binding_version) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: protected_object_authority protected_object_authority_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protected_object_authority
    ADD CONSTRAINT protected_object_authority_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: protected_object_authority protected_object_authority_community_id_object_kind_object_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protected_object_authority
    ADD CONSTRAINT protected_object_authority_community_id_object_kind_object_fkey FOREIGN KEY (community_id, object_kind, object_key, authority_epoch, fence, operation_id, request_fingerprint) REFERENCES public.authorization_authority_epochs(community_id, object_kind, object_key, authority_epoch, fence, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: protected_object_authority protected_object_authority_community_id_operation_id_reque_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protected_object_authority
    ADD CONSTRAINT protected_object_authority_community_id_operation_id_reque_fkey FOREIGN KEY (community_id, operation_id, request_fingerprint) REFERENCES public.authorization_operation_receipts(community_id, operation_id, request_fingerprint) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pubkey_allowlist pubkey_allowlist_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pubkey_allowlist
    ADD CONSTRAINT pubkey_allowlist_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: push_gateway_delegations push_gateway_delegations_installation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_gateway_delegations
    ADD CONSTRAINT push_gateway_delegations_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES public.push_gateway_installations(id);


--
-- Name: push_leases push_leases_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_leases
    ADD CONSTRAINT push_leases_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: push_match_queue push_match_queue_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_match_queue
    ADD CONSTRAINT push_match_queue_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: push_wake_outbox push_wake_outbox_community_id_author_installation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_wake_outbox
    ADD CONSTRAINT push_wake_outbox_community_id_author_installation_id_fkey FOREIGN KEY (community_id, author, installation_id) REFERENCES public.push_leases(community_id, author, installation_id);


--
-- Name: push_wake_outbox push_wake_outbox_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_wake_outbox
    ADD CONSTRAINT push_wake_outbox_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: reactions reactions_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reactions
    ADD CONSTRAINT reactions_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: relay_invites relay_invites_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.relay_invites
    ADD CONSTRAINT relay_invites_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: relay_members relay_members_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.relay_members
    ADD CONSTRAINT relay_members_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: scheduled_workflow_fires scheduled_workflow_fires_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_workflow_fires
    ADD CONSTRAINT scheduled_workflow_fires_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: scheduled_workflow_fires scheduled_workflow_fires_community_id_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_workflow_fires
    ADD CONSTRAINT scheduled_workflow_fires_community_id_workflow_id_fkey FOREIGN KEY (community_id, workflow_id) REFERENCES public.workflows(community_id, id) ON DELETE CASCADE;


--
-- Name: scheduled_workflow_fires scheduled_workflow_fires_community_id_workflow_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_workflow_fires
    ADD CONSTRAINT scheduled_workflow_fires_community_id_workflow_run_id_fkey FOREIGN KEY (community_id, workflow_run_id) REFERENCES public.workflow_runs(community_id, id);


--
-- Name: subscriptions subscriptions_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: subscriptions subscriptions_community_id_owner_pubkey_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_community_id_owner_pubkey_fkey FOREIGN KEY (community_id, owner_pubkey) REFERENCES public.users(community_id, pubkey);


--
-- Name: thread_metadata thread_metadata_community_id_channel_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.thread_metadata
    ADD CONSTRAINT thread_metadata_community_id_channel_id_fkey FOREIGN KEY (community_id, channel_id) REFERENCES public.channels(community_id, id);


--
-- Name: thread_metadata thread_metadata_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.thread_metadata
    ADD CONSTRAINT thread_metadata_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: users users_community_id_agent_owner_pubkey_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_community_id_agent_owner_pubkey_fkey FOREIGN KEY (community_id, agent_owner_pubkey) REFERENCES public.users(community_id, pubkey) ON DELETE SET NULL;


--
-- Name: users users_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: workflow_approvals workflow_approvals_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_approvals
    ADD CONSTRAINT workflow_approvals_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: workflow_approvals workflow_approvals_community_id_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_approvals
    ADD CONSTRAINT workflow_approvals_community_id_run_id_fkey FOREIGN KEY (community_id, run_id) REFERENCES public.workflow_runs(community_id, id) ON DELETE CASCADE;


--
-- Name: workflow_approvals workflow_approvals_community_id_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_approvals
    ADD CONSTRAINT workflow_approvals_community_id_workflow_id_fkey FOREIGN KEY (community_id, workflow_id) REFERENCES public.workflows(community_id, id) ON DELETE CASCADE;


--
-- Name: workflow_runs workflow_runs_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: workflow_runs workflow_runs_community_id_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_community_id_workflow_id_fkey FOREIGN KEY (community_id, workflow_id) REFERENCES public.workflows(community_id, id) ON DELETE CASCADE;


--
-- Name: workflows workflows_community_id_channel_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT workflows_community_id_channel_id_fkey FOREIGN KEY (community_id, channel_id) REFERENCES public.channels(community_id, id);


--
-- Name: workflows workflows_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT workflows_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id);


--
-- Name: workflows workflows_community_id_owner_pubkey_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT workflows_community_id_owner_pubkey_fkey FOREIGN KEY (community_id, owner_pubkey) REFERENCES public.users(community_id, pubkey);


--
-- Name: FUNCTION authorization_operator_preauth_denial_capacity_before_insert_v1(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.authorization_operator_preauth_denial_capacity_before_insert_v1() FROM PUBLIC;


--
-- Name: FUNCTION authorization_operator_preauth_denial_capacity_guard_v1(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.authorization_operator_preauth_denial_capacity_guard_v1() FROM PUBLIC;


--
-- Name: FUNCTION authorization_operator_preauth_denial_events_retention_guard_v1(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.authorization_operator_preauth_denial_events_retention_guard_v1() FROM PUBLIC;


--
-- PostgreSQL database dump complete
--


-- Deterministic seed state installed by migrations.
INSERT INTO public._operator_global_tables (table_name, reason) VALUES
('_operator_global_tables', 'the registry table itself'),
    ('communities', 'the tenant registry itself; id IS the community key'),
    ('product_feedback', 'deployment product inbox; community_id is provenance only'),
    ('push_gateway_challenges', 'public gateway one-time challenges span relay communities'),
    ('push_gateway_delegations', 'public gateway relay delegations span relay communities'),
    ('push_gateway_delivery_auth_replays', 'public gateway signed-event replay admission spans relay communities'),
    ('push_gateway_delivery_request_replays', 'public gateway stable request-id admission spans relay communities'),
    ('push_gateway_endpoint_quotas', 'public gateway endpoint abuse ceilings span relay communities'),
    ('push_gateway_installations', 'public gateway installation authority spans relay communities'),
    ('rate_limit_violations', 'deployment abuse/health; never tenant-observable; community_id is an attribution label only'),
    ('replica_heartbeat', 'single-row replication freshness token; describes deployment topology, never tenant data');

INSERT INTO public.replica_heartbeat (id) VALUES (1);
