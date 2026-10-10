-- =====================================================================
-- MERRY-GO-ROUND NUMBER SELECTOR v2: run once in Supabase > SQL Editor.
-- It REPLACES the earlier tables, so earlier test data is deleted.
-- =====================================================================

-- ---------- clean up earlier versions ----------
drop trigger if exists on_auth_user_created_admin on auth.users;
drop table if exists assignments, members, invitations, audit_log, public_status, settings, rounds, admins, picks, admin_settings cascade;
drop function if exists handle_new_user(), is_admin(), code_hash(text), new_code(), public_progress(), member_status(text,text),
  pick_number(text,text), admin_overview(), admin_add_member(text,text), admin_new_code(uuid), admin_remove_member(uuid), admin_reset();

-- ---------- tables ----------

-- ONLY ONE administrator can ever exist: "singleton" is the primary key and must be true.
create table admins (
  singleton boolean primary key default true check (singleton),
  user_id   uuid not null unique references auth.users(id) on delete cascade
);

create table rounds (
  id           bigint generated always as identity primary key,
  status       text not null default 'open' check (status in ('open','full','closed','reset')),
  created_at   timestamptz not null default now(),
  completed_at timestamptz,
  ended_at     timestamptz
);

create table settings (
  id                int primary key default 1 check (id = 1),
  platform_name     text    not null default 'Merry-Go-Round Number Selector',
  registration_open boolean not null default true,
  require_code      boolean not null default true,    -- members need an invitation code
  reset_reopens     boolean not null default true,    -- after a reset, registration reopens
  current_round_id  bigint references rounds(id)
);

create table invitations (
  id         uuid primary key default gen_random_uuid(),
  label      text not null check (length(trim(label)) between 1 and 60),
  code_hash  text not null unique,                    -- only a hash of the code is stored
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

create table members (
  id            uuid primary key default gen_random_uuid(),
  full_name     text not null check (length(trim(full_name)) between 2 and 60),
  identity_hash text not null unique,                 -- one identity = one member (code or browser token)
  invitation_id uuid references invitations(id) on delete set null,
  created_at    timestamptz not null default now()
);

create table assignments (
  id          bigint generated always as identity primary key,
  round_id    bigint not null references rounds(id),
  member_id   uuid   not null references members(id),
  number      int    not null check (number between 1 and 4),   -- only 1 to 4, so max 4 per round
  assigned_at timestamptz not null default now(),
  status      text   not null default 'confirmed',
  unique (round_id, number),                          -- a number is used once per round
  unique (round_id, member_id)                        -- a member registers once per round
);

create table audit_log (
  id          bigint generated always as identity primary key,
  at          timestamptz not null default now(),
  event       text not null,
  admin_email text,
  round_id    bigint,
  detail      text
);

-- Public, safe-to-share status (no names, no member data). Members' browsers listen to this live.
create table public_status (
  id                int primary key default 1 check (id = 1),
  platform_name     text,
  round_id          bigint,
  round_status      text,
  registration_open boolean not null default false,
  require_code      boolean not null default true,
  taken             int[]   not null default '{}'
);

-- ---------- Row Level Security ----------
alter table admins        enable row level security;
alter table rounds        enable row level security;
alter table settings      enable row level security;
alter table invitations   enable row level security;
alter table members       enable row level security;
alter table assignments   enable row level security;
alter table audit_log     enable row level security;
alter table public_status enable row level security;

create or replace function is_admin() returns boolean
language sql stable security definer set search_path = public as
$$ select exists (select 1 from admins where user_id = auth.uid()) $$;

-- the ONLY thing the public can read directly
create policy "public reads status" on public_status for select to anon, authenticated using (true);

-- the administrator can read everything (used for live dashboard updates)
create policy "admin reads rounds"      on rounds      for select to authenticated using (is_admin());
create policy "admin reads assignments" on assignments for select to authenticated using (is_admin());
create policy "admin reads members"     on members     for select to authenticated using (is_admin());
create policy "admin reads audit"       on audit_log   for select to authenticated using (is_admin());
-- (no insert/update/delete policies exist: every change goes through the secure functions below)

-- live updates
do $$ begin alter publication supabase_realtime add table public_status;
exception when others then null; end $$;
do $$ begin alter publication supabase_realtime add table assignments;
exception when others then null; end $$;

-- ---------- the single administrator ----------
-- The FIRST user created in Supabase Auth automatically becomes the administrator.
-- Nobody else can ever be added (the admins table accepts only one row).
create or replace function handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into admins (user_id) values (new.id) on conflict do nothing;
  return new;
end $$;

create trigger on_auth_user_created_admin after insert on auth.users
  for each row execute function handle_new_user();

-- if you already created a user before running this file, that (oldest) user becomes the administrator
insert into admins (user_id) select id from auth.users order by created_at limit 1 on conflict do nothing;

-- ---------- helpers (not callable by the public) ----------
create or replace function code_hash(t text) returns text
language sql immutable as
$$ select encode(sha256(convert_to(upper(regexp_replace(coalesce(t,''),'[^A-Za-z0-9]','','g')),'utf8')),'hex') $$;

create or replace function new_code() returns text
language sql volatile as
$$ select upper(substr(replace(gen_random_uuid()::text,'-',''),1,12)) $$;

create or replace function log_event(p_event text, p_detail text default null) returns void
language plpgsql security definer set search_path = public as $$
begin
  insert into audit_log (event, admin_email, round_id, detail)
  values (p_event, auth.jwt() ->> 'email', (select current_round_id from settings where id = 1), p_detail);
end $$;

-- refresh the public status row (called after every change)
create or replace function sync_public() returns void
language plpgsql security definer set search_path = public as $$
declare s settings; r rounds;
begin
  select * into s from settings where id = 1;
  select * into r from rounds where id = s.current_round_id;
  insert into public_status (id, platform_name, round_id, round_status, registration_open, require_code, taken)
  values (1, s.platform_name, r.id, r.status, (s.registration_open and r.status = 'open'), s.require_code,
          coalesce((select array_agg(number order by number) from assignments where round_id = r.id), '{}'::int[]))
  on conflict (id) do update set
    platform_name = excluded.platform_name, round_id = excluded.round_id, round_status = excluded.round_status,
    registration_open = excluded.registration_open, require_code = excluded.require_code, taken = excluded.taken;
end $$;

-- who is this member? (invitation code, or a browser token when codes are switched off)
create or replace function resolve_identity(p_code text, p_token text, out ident text, out inv uuid)
language plpgsql security definer set search_path = public as $$
declare s settings;
begin
  select * into s from settings where id = 1;
  if s.require_code then
    select id into inv from invitations
      where code_hash = code_hash(p_code) and (expires_at is null or expires_at > now());
    if inv is not null then ident := 'inv:' || inv; end if;
  elsif length(coalesce(p_token,'')) >= 16 then
    ident := 'tok:' || code_hash(p_token);
  end if;
end $$;

-- first round + settings
with r as (insert into rounds default values returning id)
insert into settings (current_round_id) select id from r;
select sync_public();

-- ---------- public functions (members) ----------

-- THE random draw: server-side, atomic, once per member per round
create or replace function register_member(p_name text, p_code text, p_token text, p_round bigint default null)
returns json language plpgsql security definer set search_path = public as $$
declare
  s settings; r rounds; v_ident text; v_inv uuid; v_mid uuid; n int; cnt int;
  nm text := regexp_replace(trim(coalesce(p_name,'')), '\s+', ' ', 'g');
begin
  if nm !~ '^[[:alpha:]][[:alpha:] .''-]{1,59}$' then
    return json_build_object('ok', false, 'error', 'bad_name');
  end if;

  select * into v_ident, v_inv from resolve_identity(p_code, p_token);
  if v_ident is null then
    perform pg_sleep(1);                                  -- slows down code guessing
    return json_build_object('ok', false, 'error', 'invalid_code');
  end if;

  perform pg_advisory_xact_lock(7001);                    -- one registration at a time
  select * into s from settings where id = 1;
  select * into r from rounds where id = s.current_round_id for update;

  if p_round is not null and p_round <> r.id then        -- stale page from before a reset
    return json_build_object('ok', false, 'error', 'stale_round');
  end if;

  select id into v_mid from members where identity_hash = v_ident;
  if v_mid is not null then
    select number into n from assignments where round_id = r.id and member_id = v_mid;
    if n is not null then                                 -- already registered: return the SAME number
      return json_build_object('ok', true, 'already', true, 'name', (select full_name from members where id = v_mid), 'number', n);
    end if;
  end if;

  if not s.registration_open or r.status <> 'open' then
    return json_build_object('ok', false, 'error', case when r.status = 'full' then 'full' else 'closed' end);
  end if;

  select g into n from generate_series(1,4) g
  where g not in (select number from assignments where round_id = r.id)
  order by random() limit 1;

  if n is null then
    update rounds set status = 'full', completed_at = now() where id = r.id;
    perform sync_public();
    return json_build_object('ok', false, 'error', 'full');
  end if;

  insert into members (full_name, identity_hash, invitation_id) values (nm, v_ident, v_inv)
  on conflict (identity_hash) do update set full_name = excluded.full_name
  returning id into v_mid;

  insert into assignments (round_id, member_id, number) values (r.id, v_mid, n);

  select count(*) into cnt from assignments where round_id = r.id;
  if cnt >= 4 then
    update rounds set status = 'full', completed_at = now() where id = r.id;
    insert into audit_log (event, round_id, detail) values ('round_full', r.id, 'all four numbers assigned');
  end if;

  perform sync_public();
  return json_build_object('ok', true, 'already', false, 'name', nm, 'number', n);
end $$;

-- a returning member retrieves their OWN number
create or replace function my_assignment(p_code text, p_token text) returns json
language plpgsql security definer set search_path = public as $$
declare v_ident text; v_inv uuid; n int; nm text;
begin
  select * into v_ident, v_inv from resolve_identity(p_code, p_token);
  if v_ident is null then
    perform pg_sleep(1);
    return json_build_object('ok', false, 'error', 'invalid_code');
  end if;
  select a.number, m.full_name into n, nm
  from members m join assignments a on a.member_id = m.id
  where m.identity_hash = v_ident and a.round_id = (select current_round_id from settings where id = 1);
  return json_build_object('ok', true, 'number', n, 'name', nm);
end $$;

-- ---------- administrator functions (each one checks is_admin()) ----------

create or replace function admin_overview() returns json
language plpgsql security definer set search_path = public as $$
declare s settings; r rounds;
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  select * into s from settings where id = 1;
  select * into r from rounds where id = s.current_round_id;
  return json_build_object(
    'admin_email', auth.jwt() ->> 'email',
    'settings', json_build_object('platform_name', s.platform_name, 'registration_open', s.registration_open,
                                  'require_code', s.require_code, 'reset_reopens', s.reset_reopens),
    'round', json_build_object('id', r.id, 'status', r.status, 'created_at', r.created_at, 'completed_at', r.completed_at),
    'members', (select coalesce(json_agg(json_build_object('id', a.id, 'name', m.full_name, 'number', a.number,
                  'at', a.assigned_at, 'status', a.status, 'round_id', a.round_id, 'invite', i.label)
                  order by a.assigned_at), '[]'::json)
                from assignments a join members m on m.id = a.member_id
                left join invitations i on i.id = m.invitation_id where a.round_id = r.id),
    'invitations', (select coalesce(json_agg(json_build_object('id', i.id, 'label', i.label, 'expires_at', i.expires_at,
                  'used', exists (select 1 from members m join assignments a on a.member_id = m.id
                                  where m.invitation_id = i.id and a.round_id = r.id))
                  order by i.created_at), '[]'::json) from invitations i),
    'history', (select coalesce(json_agg(h order by h.id desc), '[]'::json) from (
                  select rd.id, rd.status, rd.created_at, rd.completed_at, rd.ended_at,
                    (select coalesce(json_agg(json_build_object('name', m.full_name, 'number', a.number) order by a.number), '[]'::json)
                     from assignments a join members m on m.id = a.member_id where a.round_id = rd.id) as results
                  from rounds rd where rd.id <> r.id) h),
    'audit', (select coalesce(json_agg(x), '[]'::json) from (
                  select at, event, admin_email, round_id, detail from audit_log order by id desc limit 100) x));
end $$;

create or replace function admin_log(p_event text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  if p_event in ('login','logout','password_changed') then perform log_event(p_event); end if;
end $$;

create or replace function admin_set_registration(p_open boolean) returns json
language plpgsql security definer set search_path = public as $$
declare cur bigint;
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  select current_round_id into cur from settings where id = 1;
  if p_open then
    update rounds set status = case when (select count(*) from assignments where round_id = cur) >= 4 then 'full' else 'open' end
    where id = cur and status in ('open','closed');
  else
    update rounds set status = 'closed' where id = cur and status = 'open';
  end if;
  update settings set registration_open = p_open where id = 1;
  perform log_event(case when p_open then 'registration_opened' else 'registration_closed' end);
  perform sync_public();
  return json_build_object('ok', true);
end $$;

create or replace function admin_save_settings(p_name text, p_require_code boolean, p_reset_reopens boolean) returns json
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  if length(trim(coalesce(p_name,''))) not between 2 and 80 then return json_build_object('ok', false, 'error', 'bad_name'); end if;
  update settings set platform_name = trim(p_name), require_code = p_require_code, reset_reopens = p_reset_reopens where id = 1;
  perform log_event('settings_changed', 'name / invitation requirement / reset behaviour updated');
  perform sync_public();
  return json_build_object('ok', true);
end $$;

-- p_kind = 'reset' (clear the active round, keep it in history) or 'new' (start a fresh round after a full/closed one)
create or replace function admin_new_round(p_kind text) returns json
language plpgsql security definer set search_path = public as $$
declare cur rounds; nid bigint; s settings;
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  select * into s from settings where id = 1;
  select * into cur from rounds where id = s.current_round_id for update;
  if p_kind = 'reset' then
    update rounds set status = 'reset', ended_at = now() where id = cur.id;
  elsif p_kind = 'new' then
    if cur.status not in ('full','closed') then return json_build_object('ok', false, 'error', 'round_active'); end if;
    update rounds set ended_at = now() where id = cur.id;
  else
    return json_build_object('ok', false, 'error', 'bad_kind');
  end if;
  insert into rounds default values returning id into nid;
  update settings set current_round_id = nid,
    registration_open = case when p_kind = 'reset' then s.reset_reopens else true end where id = 1;
  perform log_event(case when p_kind = 'reset' then 'round_reset' else 'round_created' end,
                    'round ' || cur.id || ' -> new round ' || nid);
  perform sync_public();
  return json_build_object('ok', true, 'round_id', nid);
end $$;

create or replace function admin_add_invitation(p_label text, p_days int default null) returns json
language plpgsql security definer set search_path = public as $$
declare c text := new_code();
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  if (select count(*) from invitations) >= 4 then return json_build_object('ok', false, 'error', 'limit'); end if;
  if length(trim(coalesce(p_label,''))) = 0 then return json_build_object('ok', false, 'error', 'no_label'); end if;
  insert into invitations (label, code_hash, expires_at)
  values (trim(p_label), code_hash(c), case when p_days is null then null else now() + (p_days || ' days')::interval end);
  perform log_event('invitation_added', trim(p_label));
  return json_build_object('ok', true, 'code', c);
end $$;

create or replace function admin_regen_invitation(p_id uuid) returns json
language plpgsql security definer set search_path = public as $$
declare c text := new_code(); lbl text;
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  update invitations set code_hash = code_hash(c) where id = p_id returning label into lbl;
  if lbl is null then return json_build_object('ok', false, 'error', 'not_found'); end if;
  perform log_event('invitation_code_changed', lbl);
  return json_build_object('ok', true, 'code', c);
end $$;

create or replace function admin_delete_invitation(p_id uuid) returns json
language plpgsql security definer set search_path = public as $$
declare lbl text;
begin
  if not is_admin() then raise exception 'not authorized'; end if;
  delete from invitations where id = p_id returning label into lbl;
  perform log_event('invitation_deleted', lbl);
  return json_build_object('ok', true);
end $$;

-- ---------- permissions ----------
revoke all on function is_admin(), handle_new_user(), code_hash(text), new_code(), log_event(text,text), sync_public(),
  resolve_identity(text,text), register_member(text,text,text,bigint), my_assignment(text,text),
  admin_overview(), admin_log(text), admin_set_registration(boolean), admin_save_settings(text,boolean,boolean),
  admin_new_round(text), admin_add_invitation(text,int), admin_regen_invitation(uuid), admin_delete_invitation(uuid) from public;

grant execute on function register_member(text,text,text,bigint), my_assignment(text,text) to anon, authenticated;
grant execute on function is_admin(), admin_overview(), admin_log(text), admin_set_registration(boolean),
  admin_save_settings(text,boolean,boolean), admin_new_round(text), admin_add_invitation(text,int),
  admin_regen_invitation(uuid), admin_delete_invitation(uuid) to authenticated;
