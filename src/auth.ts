import { jwtVerify } from "jose";
import { HTTPException } from "hono/http-exception";
import type { Env } from "./env";

export type Authenticated = {
  userId: string;
  token: string;
};

function parseBearerToken(authorizationHeader: string | null): string | null {
  if (!authorizationHeader) return null;
  const match = authorizationHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() ?? null;
}

export function requireBearerToken(authorizationHeader: string | null): string {
  const token = parseBearerToken(authorizationHeader);
  if (!token) {
    throw new HTTPException(401, {
      res: new Response(JSON.stringify({ error: "Missing Authorization: Bearer <token>" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    });
  }
  return token;
}

export async function authenticateRequest(
  env: Env,
  authorizationHeader: string | null,
): Promise<Authenticated> {
  const token = requireBearerToken(authorizationHeader);
  if (!env.SUPABASE_JWT_SECRET) {
    throw new HTTPException(500, {
      res: new Response(JSON.stringify({ error: "Server misconfigured", missing: "SUPABASE_JWT_SECRET" }), {
        status: 500,
        headers: { "content-type": "application/json" },
      }),
    });
  }

  const secret = new TextEncoder().encode(env.SUPABASE_JWT_SECRET);

  const issuer =
    env.SUPABASE_JWT_ISSUER?.trim() ||
    (env.SUPABASE_URL ? `${env.SUPABASE_URL.replace(/\/+$/, "")}/auth/v1` : undefined);

  let payload: Record<string, unknown>;
  try {
    payload = (await jwtVerify(token, secret, { issuer, audience: "authenticated" })).payload as Record<string, unknown>;
  } catch {
    throw new HTTPException(401, {
      res: new Response(JSON.stringify({ error: "Invalid token" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    });
  }

  const userId = typeof payload.sub === "string" ? payload.sub : null;
  if (!userId) {
    throw new HTTPException(401, {
      res: new Response(JSON.stringify({ error: "Invalid token" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    });
  }

  return { userId, token };
}
