-- Encrypted guestbook (messages + per-user keyring).
-- Apply in Supabase SQL Editor or via Supabase CLI migrations.

create extension if not exists pgcrypto;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- Stores the per-user wrapped message-encryption-key (MEK).
-- The MEK is generated client-side, wrapped client-side, and never stored in plaintext.
create table if not exists public.user_keyrings (
  user_id uuid primary key default auth.uid() references auth.users (id) on delete cascade,
  version int not null default 1,
  kdf text not null,
  kdf_params jsonb not null default '{}'::jsonb,
  salt text not null,
  wrapped_key text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint user_keyrings_wrapped_key_nonempty check (length(wrapped_key) > 0),
  constraint user_keyrings_salt_nonempty check (length(salt) > 0),
  constraint user_keyrings_kdf_nonempty check (length(kdf) > 0)
);

drop trigger if exists set_updated_at_user_keyrings on public.user_keyrings;
create trigger set_updated_at_user_keyrings
before update on public.user_keyrings
for each row execute function public.set_updated_at();

-- Encrypted messages. Only ciphertext + crypto metadata are stored.
create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  version int not null default 1,
  alg text not null default 'AES-GCM',
  nonce text not null,
  ciphertext text not null,
  aad text,
  created_at timestamptz not null default now(),
  constraint messages_ciphertext_nonempty check (length(ciphertext) > 0),
  constraint messages_nonce_nonempty check (length(nonce) > 0)
);

create index if not exists messages_user_id_created_at_idx on public.messages (user_id, created_at desc);

-- Row Level Security
alter table public.user_keyrings enable row level security;
alter table public.messages enable row level security;

-- user_keyrings: only the owner can read/write their keyring.
drop policy if exists "user_keyrings_select_own" on public.user_keyrings;
create policy "user_keyrings_select_own"
  on public.user_keyrings
  for select
  using (user_id = auth.uid());

drop policy if exists "user_keyrings_insert_own" on public.user_keyrings;
create policy "user_keyrings_insert_own"
  on public.user_keyrings
  for insert
  with check (user_id = auth.uid());

drop policy if exists "user_keyrings_update_own" on public.user_keyrings;
create policy "user_keyrings_update_own"
  on public.user_keyrings
  for update
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- messages: only the owner can read/write their encrypted messages.
drop policy if exists "messages_select_own" on public.messages;
create policy "messages_select_own"
  on public.messages
  for select
  using (user_id = auth.uid());

drop policy if exists "messages_insert_own" on public.messages;
create policy "messages_insert_own"
  on public.messages
  for insert
  with check (user_id = auth.uid());

drop policy if exists "messages_delete_own" on public.messages;
create policy "messages_delete_own"
  on public.messages
  for delete
  using (user_id = auth.uid());
