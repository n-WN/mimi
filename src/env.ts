import { HTTPException } from "hono/http-exception";

export type Env = {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  SUPABASE_JWT_SECRET?: string;
  SUPABASE_JWT_ISSUER?: string;
  ALLOWED_ORIGIN?: string;
};

export function requireEnv(env: Env, key: keyof Env): string {
  const value = env[key];
  if (!value) {
    throw new HTTPException(500, {
      res: new Response(JSON.stringify({ error: "Server misconfigured", missing: String(key) }), {
        status: 500,
        headers: { "content-type": "application/json" },
      }),
    });
  }
  return value;
}
