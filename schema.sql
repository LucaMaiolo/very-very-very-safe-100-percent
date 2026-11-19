-- Run once in the Supabase dashboard: SQL Editor -> New query -> paste -> Run.
-- Safe to re-run: each statement is guarded with "if not exists" / "add column if not exists".
create table if not exists devices (
  device_id  text primary key,
  label      text,
  first_seen timestamptz not null default now(),
  last_seen  timestamptz not null default now()
);

create table if not exists visits (
  id         text primary key,
  time_utc   timestamptz not null,
  ip         text not null,
  device_id  text references devices(device_id),
  is_bot     boolean not null default false,
  country    text, region text, city text, isp text,
  lat        double precision, lon double precision,
  user_agent text,
  link       text
);
alter table visits add column if not exists device_id text references devices(device_id);
alter table visits add column if not exists is_bot boolean not null default false;

-- visit_id is the primary key, so a visit can only have one telemetry row,
-- and the foreign key rejects telemetry for visits that don't exist.
create table if not exists telemetry (
  visit_id    text primary key references visits(id) on delete cascade,
  time_utc    timestamptz not null,
  timezone    text, language text, screen text, viewport text, pixel_ratio text
);

-- Row level security on with no policies: the public anon key can read/write nothing.
-- Only the server's service_role key (which bypasses RLS) can touch these tables.
alter table devices   enable row level security;
alter table visits    enable row level security;
alter table telemetry enable row level security;
