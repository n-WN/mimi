-- Support hybrid encryption for treehole:
-- - message body encrypted with a random per-message key (e.g., AES-GCM)
-- - per-message key wrapped to an admin public key (so only admin can decrypt)

alter table public.messages
  add column if not exists kid text,
  add column if not exists wrapped_key text;

alter table public.messages
  drop constraint if exists messages_kid_nonempty,
  add constraint messages_kid_nonempty check (kid is null or length(kid) > 0);

alter table public.messages
  drop constraint if exists messages_wrapped_key_nonempty,
  add constraint messages_wrapped_key_nonempty check (wrapped_key is null or length(wrapped_key) > 0);

