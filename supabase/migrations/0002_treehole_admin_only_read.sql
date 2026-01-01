-- Treehole mode:
-- - Anyone (anon/authenticated) can INSERT messages.
-- - Only admins can SELECT/DELETE messages.
-- - Public key(s) for client-side encryption are readable by anyone; only admins can manage them.

create extension if not exists pgcrypto;

-- Admin list (do not expose via SELECT to clients).
create table if not exists public.admins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

revoke all on table public.admins from anon, authenticated;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from public.admins a where a.user_id = auth.uid());
$$;

revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to anon, authenticated;

-- Public encryption keys (admin publishes one or more recipient public keys).
create table if not exists public.encryption_public_keys (
  kid text primary key,
  alg text not null,
  public_key text not null,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  constraint encryption_public_keys_kid_nonempty check (length(kid) > 0),
  constraint encryption_public_keys_alg_nonempty check (length(alg) > 0),
  constraint encryption_public_keys_public_key_nonempty check (length(public_key) > 0)
);

alter table public.encryption_public_keys enable row level security;

drop policy if exists "encryption_public_keys_select_all" on public.encryption_public_keys;
create policy "encryption_public_keys_select_all"
  on public.encryption_public_keys
  for select
  to anon, authenticated
  using (true);

drop policy if exists "encryption_public_keys_write_admin" on public.encryption_public_keys;
create policy "encryption_public_keys_write_admin"
  on public.encryption_public_keys
  for all
  to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- messages: relax user_id to allow anonymous inserts (auth.uid() => null).
alter table public.messages
  alter column user_id drop not null;

alter table public.messages
  drop constraint if exists messages_user_id_fkey;

alter table public.messages
  add constraint messages_user_id_fkey
  foreign key (user_id) references auth.users (id) on delete set null;

-- Replace policies to match treehole behavior.
drop policy if exists "messages_select_own" on public.messages;
drop policy if exists "messages_insert_own" on public.messages;
drop policy if exists "messages_delete_own" on public.messages;

drop policy if exists "messages_insert_any" on public.messages;
create policy "messages_insert_any"
  on public.messages
  for insert
  to anon, authenticated
  with check (true);

drop policy if exists "messages_select_admin" on public.messages;
create policy "messages_select_admin"
  on public.messages
  for select
  to authenticated
  using (public.is_admin());

drop policy if exists "messages_delete_admin" on public.messages;
create policy "messages_delete_admin"
  on public.messages
  for delete
  to authenticated
  using (public.is_admin());

