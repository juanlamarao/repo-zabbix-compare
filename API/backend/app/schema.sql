CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS app_meta (
    key text PRIMARY KEY,
    value jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS baselines (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    status text NOT NULL DEFAULT 'REQUESTED',
    source_version text,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    frozen_at timestamptz,
    totals jsonb NOT NULL DEFAULT '{}'::jsonb,
    error text
);

CREATE TABLE IF NOT EXISTS baseline_hosts (
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    hostid bigint NOT NULL,
    host text NOT NULL,
    name text NOT NULL,
    proxyid bigint,
    status integer NOT NULL,
    maintenance_status integer NOT NULL DEFAULT 0,
    eligible boolean NOT NULL DEFAULT true,
    PRIMARY KEY (baseline_id, hostid)
);
CREATE INDEX IF NOT EXISTS idx_baseline_hosts_proxy ON baseline_hosts(baseline_id, proxyid);

CREATE TABLE IF NOT EXISTS baseline_interfaces (
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    interfaceid bigint NOT NULL,
    hostid bigint NOT NULL,
    type integer NOT NULL,
    main integer NOT NULL,
    useip integer NOT NULL,
    ip text,
    dns text,
    port text,
    available integer,
    error text,
    errors_from bigint,
    disable_until bigint,
    eligible boolean NOT NULL,
    PRIMARY KEY (baseline_id, interfaceid)
);
CREATE INDEX IF NOT EXISTS idx_baseline_interfaces_host ON baseline_interfaces(baseline_id, hostid);

CREATE TABLE IF NOT EXISTS baseline_items (
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    itemid bigint NOT NULL,
    hostid bigint NOT NULL,
    proxyid bigint,
    interfaceid bigint,
    name text,
    key_ text,
    type integer,
    status integer,
    state integer,
    error text,
    lastclock bigint,
    lastvalue text,
    delay text,
    flags integer,
    discovery_ruleid bigint,
    prototype_itemid bigint,
    discovery_status integer,
    last_discovered bigint,
    ts_delete bigint,
    ts_disable bigint,
    eligible boolean NOT NULL,
    PRIMARY KEY (baseline_id, itemid)
);
CREATE INDEX IF NOT EXISTS idx_baseline_items_host ON baseline_items(baseline_id, hostid);
CREATE INDEX IF NOT EXISTS idx_baseline_items_lld ON baseline_items(baseline_id, discovery_ruleid, prototype_itemid);
CREATE INDEX IF NOT EXISTS idx_baseline_items_eligible ON baseline_items(baseline_id, eligible) WHERE eligible;

CREATE TABLE IF NOT EXISTS baseline_triggers (
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    triggerid bigint NOT NULL,
    description text,
    status integer,
    state integer,
    value integer,
    error text,
    lastchange bigint,
    priority integer,
    flags integer,
    discovery_ruleid bigint,
    prototype_triggerid bigint,
    discovery_status integer,
    ts_delete bigint,
    ts_disable bigint,
    eligible boolean NOT NULL,
    PRIMARY KEY (baseline_id, triggerid)
);
CREATE INDEX IF NOT EXISTS idx_baseline_triggers_lld ON baseline_triggers(baseline_id, discovery_ruleid, prototype_triggerid);
CREATE INDEX IF NOT EXISTS idx_baseline_triggers_eligible ON baseline_triggers(baseline_id, eligible) WHERE eligible;

CREATE TABLE IF NOT EXISTS baseline_llds (
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    itemid bigint NOT NULL,
    hostid bigint NOT NULL,
    name text,
    key_ text,
    status integer,
    state integer,
    error text,
    delay text,
    lifetime text,
    lifetime_type integer,
    enabled_lifetime text,
    enabled_lifetime_type integer,
    eligible boolean NOT NULL,
    PRIMARY KEY (baseline_id, itemid)
);
CREATE INDEX IF NOT EXISTS idx_baseline_llds_host ON baseline_llds(baseline_id, hostid);

CREATE TABLE IF NOT EXISTS baseline_proxies (
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    proxyid bigint NOT NULL,
    name text NOT NULL,
    mode text,
    lastaccess bigint,
    version text,
    compatibility integer,
    state integer,
    raw jsonb NOT NULL,
    PRIMARY KEY (baseline_id, proxyid)
);

CREATE TABLE IF NOT EXISTS baseline_actions (
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    actionid bigint NOT NULL,
    name text NOT NULL,
    status integer,
    eventsource integer,
    raw jsonb NOT NULL,
    eligible boolean NOT NULL,
    PRIMARY KEY (baseline_id, actionid)
);

CREATE TABLE IF NOT EXISTS baseline_media_types (
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    mediatypeid bigint NOT NULL,
    name text NOT NULL,
    type integer,
    status integer,
    raw jsonb NOT NULL,
    eligible boolean NOT NULL,
    PRIMARY KEY (baseline_id, mediatypeid)
);

CREATE TABLE IF NOT EXISTS baseline_action_runs (
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    actionid bigint NOT NULL,
    rank integer NOT NULL,
    eventid bigint NOT NULL,
    clock bigint NOT NULL,
    summary_status text NOT NULL,
    alerts jsonb NOT NULL,
    PRIMARY KEY (baseline_id, actionid, rank)
);

CREATE TABLE IF NOT EXISTS expected_changes (
    id bigserial PRIMARY KEY,
    object_type text NOT NULL,
    object_id bigint NOT NULL,
    field text NOT NULL,
    note text,
    enabled boolean NOT NULL DEFAULT true,
    UNIQUE(object_type, object_id, field)
);

CREATE TABLE IF NOT EXISTS cycles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    slot smallint NOT NULL,
    status text NOT NULL DEFAULT 'RUNNING',
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    hosts_total integer NOT NULL DEFAULT 0,
    hosts_processed integer NOT NULL DEFAULT 0,
    api_errors integer NOT NULL DEFAULT 0,
    retries integer NOT NULL DEFAULT 0,
    metrics jsonb NOT NULL DEFAULT '{}'::jsonb,
    error text
);
CREATE INDEX IF NOT EXISTS idx_cycles_baseline_started ON cycles(baseline_id, started_at DESC);

CREATE TABLE IF NOT EXISTS state_hosts (
    slot smallint NOT NULL,
    hostid bigint NOT NULL,
    host text,
    name text,
    proxyid bigint,
    status integer,
    maintenance_status integer,
    PRIMARY KEY (slot, hostid)
);
CREATE INDEX IF NOT EXISTS idx_state_hosts_proxy ON state_hosts(slot, proxyid);

CREATE TABLE IF NOT EXISTS state_interfaces (
    slot smallint NOT NULL,
    interfaceid bigint NOT NULL,
    hostid bigint NOT NULL,
    available integer,
    error text,
    errors_from bigint,
    disable_until bigint,
    PRIMARY KEY (slot, interfaceid)
);
CREATE INDEX IF NOT EXISTS idx_state_interfaces_host ON state_interfaces(slot, hostid);

CREATE TABLE IF NOT EXISTS state_items (
    slot smallint NOT NULL,
    itemid bigint NOT NULL,
    hostid bigint NOT NULL,
    proxyid bigint,
    status integer,
    state integer,
    error text,
    lastclock bigint,
    discovery_ruleid bigint,
    prototype_itemid bigint,
    discovery_status integer,
    last_discovered bigint,
    ts_delete bigint,
    ts_disable bigint,
    PRIMARY KEY (slot, itemid)
);
CREATE INDEX IF NOT EXISTS idx_state_items_host ON state_items(slot, hostid);
CREATE INDEX IF NOT EXISTS idx_state_items_lld ON state_items(slot, discovery_ruleid, prototype_itemid);

CREATE TABLE IF NOT EXISTS state_triggers (
    slot smallint NOT NULL,
    triggerid bigint NOT NULL,
    status integer,
    state integer,
    value integer,
    error text,
    lastchange bigint,
    discovery_ruleid bigint,
    prototype_triggerid bigint,
    discovery_status integer,
    ts_delete bigint,
    ts_disable bigint,
    PRIMARY KEY (slot, triggerid)
);
CREATE INDEX IF NOT EXISTS idx_state_triggers_lld ON state_triggers(slot, discovery_ruleid, prototype_triggerid);

CREATE TABLE IF NOT EXISTS state_llds (
    slot smallint NOT NULL,
    itemid bigint NOT NULL,
    hostid bigint NOT NULL,
    status integer,
    state integer,
    error text,
    lifetime text,
    lifetime_type integer,
    enabled_lifetime text,
    enabled_lifetime_type integer,
    PRIMARY KEY (slot, itemid)
);

CREATE TABLE IF NOT EXISTS state_proxies (
    slot smallint NOT NULL,
    proxyid bigint NOT NULL,
    name text NOT NULL,
    mode text,
    lastaccess bigint,
    version text,
    compatibility integer,
    state integer,
    raw jsonb NOT NULL,
    PRIMARY KEY (slot, proxyid)
);

CREATE TABLE IF NOT EXISTS state_actions (
    slot smallint NOT NULL,
    actionid bigint NOT NULL,
    name text,
    status integer,
    raw jsonb NOT NULL,
    PRIMARY KEY (slot, actionid)
);

CREATE TABLE IF NOT EXISTS state_media_types (
    slot smallint NOT NULL,
    mediatypeid bigint NOT NULL,
    name text,
    type integer,
    status integer,
    raw jsonb NOT NULL,
    PRIMARY KEY (slot, mediatypeid)
);

CREATE TABLE IF NOT EXISTS state_action_runs (
    slot smallint NOT NULL,
    actionid bigint NOT NULL,
    rank integer NOT NULL,
    eventid bigint NOT NULL,
    clock bigint NOT NULL,
    summary_status text NOT NULL,
    alerts jsonb NOT NULL,
    PRIMARY KEY (slot, actionid, rank)
);

CREATE TABLE IF NOT EXISTS baseline_lld_child_stats (
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    lldid bigint NOT NULL,
    object_kind text NOT NULL,
    prototype_id bigint NOT NULL,
    total_children bigint NOT NULL,
    eligible_children bigint NOT NULL,
    PRIMARY KEY (baseline_id, lldid, object_kind, prototype_id)
);

CREATE TABLE IF NOT EXISTS state_lld_child_stats (
    slot smallint NOT NULL,
    lldid bigint NOT NULL,
    object_kind text NOT NULL,
    prototype_id bigint NOT NULL,
    existing_children bigint NOT NULL,
    discovered_children bigint NOT NULL,
    lost_children bigint NOT NULL,
    scheduled_delete bigint NOT NULL,
    scheduled_disable bigint NOT NULL,
    PRIMARY KEY (slot, lldid, object_kind, prototype_id)
);

CREATE TABLE IF NOT EXISTS change_events (
    id bigserial PRIMARY KEY,
    cycle_id uuid NOT NULL REFERENCES cycles(id) ON DELETE CASCADE,
    object_type text NOT NULL,
    object_id bigint NOT NULL,
    severity text NOT NULL,
    code text NOT NULL,
    message text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_change_events_cycle ON change_events(cycle_id, severity, object_type);

CREATE TABLE IF NOT EXISTS baseline_drules (
    baseline_id uuid NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    druleid bigint NOT NULL,
    name text NOT NULL,
    status integer,
    proxyid bigint,
    delay text,
    raw jsonb NOT NULL,
    eligible boolean NOT NULL,
    PRIMARY KEY (baseline_id, druleid)
);

CREATE TABLE IF NOT EXISTS state_drules (
    slot smallint NOT NULL,
    druleid bigint NOT NULL,
    name text,
    status integer,
    proxyid bigint,
    delay text,
    raw jsonb NOT NULL,
    PRIMARY KEY (slot, druleid)
);
