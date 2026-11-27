-- JITER Control Plane Schema (Supabase / PostgreSQL)
-- Keeps all VPS relay endpoints and PSK credentials under developer control
-- so users only tap GO with zero manual configuration.

create table if not exists public.jiter_relay_nodes (
    id text primary key,
    region text not null,              -- e.g. 'JKT-1', 'SG-1'
    host text not null,                -- IPv4 or FQDN of your VPS
    port integer not null default 51820 check (port between 1 and 65535),
    psk_secret text not null,          -- Matches JITER_PSK on that VPS
    priority integer not null default 10,
    max_sessions integer not null default 2000 check (max_sessions > 0),
    active_load integer not null default 0 check (active_load >= 0),
    enabled boolean not null default true,
    updated_at timestamptz not null default now()
);

create table if not exists public.jiter_client_policy (
    id text primary key default 'default',
    tunnel_scope text not null default 'FULL_INTERNET_TUNNEL',
    routing_mode text not null default 'HYBRID_ADAPTIVE',
    failure_policy text not null default 'FAIL_OPEN',
    fec_policy text not null default 'AUTO_ADAPTIVE',
    probe_host text not null default '1.1.1.1',
    probe_port integer not null default 443 check (probe_port between 1 and 65535),
    ttl_seconds integer not null default 300 check (ttl_seconds between 30 and 3600),
    updated_at timestamptz not null default now()
);

-- Enforce Row Level Security: public anon key CANNOT read PSK secrets.
-- Only backend Control Plane (using SUPABASE_SERVICE_ROLE_KEY) can access these tables.
alter table public.jiter_relay_nodes enable row level security;
alter table public.jiter_client_policy enable row level security;

insert into public.jiter_client_policy (id)
values ('default')
on conflict (id) do nothing;

-- Example node registration (replace with your real VPS IP & JITER_PSK):
-- insert into public.jiter_relay_nodes (id, region, host, port, psk_secret, priority)
-- values
--   ('jkt-1', 'JKT-1', '203.0.113.10', 51820, 'replace-with-jiter-psk-jkt', 1),
--   ('sg-1',  'SG-1',  '198.51.100.20', 51820, 'replace-with-jiter-psk-sg', 2);
