-- Security hardening:
-- Prevent any JWT-based client (even an admin user token) from swapping encryption public keys.
-- Key publishing should be done via Supabase SQL editor / management API / service_role only.

-- Remove the policy that allowed authenticated admins to write keys.
drop policy if exists "encryption_public_keys_write_admin" on public.encryption_public_keys;

-- Explicitly revoke table privileges from client roles (defense-in-depth; RLS already blocks writes).
revoke insert, update, delete on table public.encryption_public_keys from anon, authenticated;

