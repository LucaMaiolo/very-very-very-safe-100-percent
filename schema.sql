-- Run once in the Supabase dashboard: SQL Editor -> New query -> paste -> Run.
create table visits (
  id         text primary key,
  time_utc   timestamptz not null,
  ip         text not null,
  country    text, region text, city text, isp text,
  lat        double precision, lon double precision,
  user_agent text,
  link       text
);

-- visit_id is the primary key, so a visit can only have one telemetry row,
-- and the foreign key rejects telemetry for visits that don't exist.
create table telemetry (
  visit_id    text primary key references visits(id) on delete cascade,
  time_utc    timestamptz not null,
  timezone    text, language text, screen text, viewport text, pixel_ratio text
);

-- Row level security on with no policies: the public anon key can read/write nothing.
-- Only the server's service_role key (which bypasses RLS) can touch these tables.
alter table visits    enable row level security;
alter table telemetry enable row level security;
