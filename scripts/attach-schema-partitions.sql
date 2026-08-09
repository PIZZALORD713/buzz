-- Attach partition child tables after pgschema apply.
--
-- pgschema currently emits existing partition children as standalone CREATE TABLE
-- statements when applying schema/schema.sql in CI. The tables exist, but they
-- are not attached to their partitioned parents, so inserts into events or
-- delivery_log fail with "no partition of relation ... found for row". Keep this
-- idempotent: raw psql/schema.sql already attaches these partitions, while
-- pgschema-created schemas need this repair step.

CREATE OR REPLACE FUNCTION pg_temp.drop_cloned_parent_triggers(
    parent_table regclass,
    child_table regclass
) RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    cloned_trigger record;
BEGIN
    -- pgschema creates standalone children with copies of every non-internal
    -- parent trigger. PostgreSQL recreates the inherited trigger during
    -- ATTACH, so remove every same-named clone based on the live parent
    -- catalog instead of maintaining a brittle trigger-name allow-list.
    FOR cloned_trigger IN
        SELECT child_trigger.tgname
        FROM pg_trigger AS child_trigger
        JOIN pg_trigger AS parent_trigger
          ON parent_trigger.tgrelid = parent_table
         AND parent_trigger.tgname = child_trigger.tgname
         AND NOT parent_trigger.tgisinternal
        WHERE child_trigger.tgrelid = child_table
          AND NOT child_trigger.tgisinternal
    LOOP
        EXECUTE format(
            'DROP TRIGGER IF EXISTS %I ON %s',
            cloned_trigger.tgname,
            child_table
        );
    END LOOP;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p_past'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('events', 'events_p_past');
        ALTER TABLE events ATTACH PARTITION events_p_past
            FOR VALUES FROM (MINVALUE) TO ('2026-01-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_01'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('events', 'events_p2026_01');
        ALTER TABLE events ATTACH PARTITION events_p2026_01
            FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_02'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('events', 'events_p2026_02');
        ALTER TABLE events ATTACH PARTITION events_p2026_02
            FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_03'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('events', 'events_p2026_03');
        ALTER TABLE events ATTACH PARTITION events_p2026_03
            FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_04'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('events', 'events_p2026_04');
        ALTER TABLE events ATTACH PARTITION events_p2026_04
            FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_05'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('events', 'events_p2026_05');
        ALTER TABLE events ATTACH PARTITION events_p2026_05
            FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_06'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('events', 'events_p2026_06');
        ALTER TABLE events ATTACH PARTITION events_p2026_06
            FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p_future'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('events', 'events_p_future');
        ALTER TABLE events ATTACH PARTITION events_p_future
            FOR VALUES FROM ('2026-07-01') TO (MAXVALUE);
    END IF;

    -- When pgschema creates partition children as standalone tables, it also
    -- preserves the parent's identity column on delivery_log children. PostgreSQL
    -- rejects attaching a child table that has its own identity column, so each
    -- delivery_log attach path drops that standalone identity first. Raw
    -- schema-created partitions are already attached, so these branches do not
    -- run against inherited partition columns.

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p_past'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('delivery_log', 'delivery_log_p_past');
        ALTER TABLE delivery_log_p_past ALTER COLUMN id DROP IDENTITY IF EXISTS;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p_past
            FOR VALUES FROM (MINVALUE) TO ('2026-03-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p2026_03'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('delivery_log', 'delivery_log_p2026_03');
        ALTER TABLE delivery_log_p2026_03 ALTER COLUMN id DROP IDENTITY IF EXISTS;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p2026_03
            FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p2026_04'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('delivery_log', 'delivery_log_p2026_04');
        ALTER TABLE delivery_log_p2026_04 ALTER COLUMN id DROP IDENTITY IF EXISTS;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p2026_04
            FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p2026_05'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('delivery_log', 'delivery_log_p2026_05');
        ALTER TABLE delivery_log_p2026_05 ALTER COLUMN id DROP IDENTITY IF EXISTS;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p2026_05
            FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p2026_06'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('delivery_log', 'delivery_log_p2026_06');
        ALTER TABLE delivery_log_p2026_06 ALTER COLUMN id DROP IDENTITY IF EXISTS;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p2026_06
            FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p_future'::regclass
    ) THEN
        PERFORM pg_temp.drop_cloned_parent_triggers('delivery_log', 'delivery_log_p_future');
        ALTER TABLE delivery_log_p_future ALTER COLUMN id DROP IDENTITY IF EXISTS;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p_future
            FOR VALUES FROM ('2026-07-01') TO (MAXVALUE);
    END IF;
END $$;
