import { Hono } from "hono";
import { cors } from "hono/cors";
import type { Context } from "hono";
import { HTTPException } from "hono/http-exception";
import type { Env } from "./env";
import { requireEnv } from "./env";
import { authenticateRequest, requireBearerToken } from "./auth";
import { postgrestFetch, readJsonOrThrow } from "./supabaseRest";
import { html } from "./frontend";

type Variables = { userId?: string; token?: string };

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

type AppContext = Context<{ Bindings: Env; Variables: Variables }>;

app.onError((err, c) => {
  if (err instanceof HTTPException) return err.getResponse();
  return c.json({ error: "Internal error" }, 500);
});

app.use("*", async (c, next) => {
  const allowed = (c.env.ALLOWED_ORIGIN ?? "").trim();
  return cors({
    origin: allowed ? [allowed] : "*",
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders: ["Authorization", "Content-Type"],
    maxAge: 86400,
  })(c, next);
});

app.use("*", async (c, next) => {
  await next();
  c.header("cache-control", "no-store");
});

app.get("/", (c) => c.html(html));

app.get("/index.html", (c) => c.html(html));

app.get("/v1/health", (c) => c.json({ ok: true }));

function requireCoreSupabaseEnv(c: AppContext) {
  requireEnv(c.env, "SUPABASE_URL");
  requireEnv(c.env, "SUPABASE_ANON_KEY");
}

async function requireAuth(c: AppContext) {
  requireCoreSupabaseEnv(c);
  const token = requireBearerToken(c.req.header("authorization") ?? null);
  c.set("token", token);

  // Optional local JWT verification. If not provided, rely on Supabase to validate the token.
  if (c.env.SUPABASE_JWT_SECRET) {
    const auth = await authenticateRequest(c.env, `Bearer ${token}`);
    c.set("userId", auth.userId);
  }
}

app.get("/v1/crypto/public-keys", async (c) => {
  requireCoreSupabaseEnv(c);
  const res = await postgrestFetch(c.env, null, "encryption_public_keys", {
    method: "GET",
    query: {
      select: "kid,alg,public_key,active,created_at",
      active: "eq.true",
      order: "created_at.desc",
    },
  });
  const data = await readJsonOrThrow(res);
  return c.json({ data });
});

app.get("/v1/admin/status", async (c) => {
  await requireAuth(c);
  // Calls the SECURITY DEFINER `public.is_admin()` function so clients can check whether a token
  // has admin access without being able to read `public.admins` directly.
  const res = await postgrestFetch(c.env, c.get("token") ?? null, "rpc/is_admin", {
    method: "POST",
    body: "{}",
  });
  const data = await readJsonOrThrow(res);
  return c.json({ is_admin: data === true });
});

app.get("/v1/messages", async (c) => {
  await requireAuth(c);
  const limit = Math.min(Math.max(Number(c.req.query("limit") ?? "50"), 1), 200);
  const offset = Math.max(Number(c.req.query("offset") ?? "0"), 0);

  const res = await postgrestFetch(c.env, c.get("token") ?? null, "messages", {
    method: "GET",
    query: {
      select: "id,version,alg,kid,wrapped_key,nonce,ciphertext,aad,created_at",
      order: "created_at.desc",
      limit: String(limit),
      offset: String(offset),
    },
  });

  const data = await readJsonOrThrow(res);
  return c.json({ data, paging: { limit, offset } });
});

app.post("/v1/messages", async (c) => {
  requireCoreSupabaseEnv(c);

  const body = (await c.req.json().catch(() => null)) as
    | {
        version?: number;
        alg?: string;
        kid?: string;
        wrapped_key?: string;
        nonce?: string;
        ciphertext?: string;
        aad?: string | null;
      }
    | null;

  if (
    !body ||
    typeof body.kid !== "string" ||
    typeof body.wrapped_key !== "string" ||
    typeof body.nonce !== "string" ||
    typeof body.ciphertext !== "string"
  ) {
    return c.json({ error: "Invalid body" }, 400);
  }
  if (
    body.kid.length > 256 ||
    body.wrapped_key.length > 50_000 ||
    body.nonce.length > 2048 ||
    body.ciphertext.length > 200_000 ||
    (typeof body.aad === "string" && body.aad.length > 8192)
  ) {
    return c.json({ error: "Payload too large" }, 413);
  }

  const payload = {
    version: typeof body.version === "number" ? body.version : 1,
    alg: typeof body.alg === "string" && body.alg ? body.alg : "AES-GCM",
    kid: body.kid,
    wrapped_key: body.wrapped_key,
    nonce: body.nonce,
    ciphertext: body.ciphertext,
    aad: typeof body.aad === "string" ? body.aad : null,
  };

  // Treehole: allow unauthenticated submit (anon role) by omitting Authorization header.
  // If the client sends a Supabase access token, we forward it; DB can record user_id via auth.uid().
  const maybeAuth = c.req.header("authorization") ?? null;
  let token: string | null = null;
  if (maybeAuth?.toLowerCase().startsWith("bearer ")) token = maybeAuth.slice(7).trim() || null;

  const res = await postgrestFetch(c.env, token, "messages", {
    method: "POST",
    headers: {
      // Important: in treehole mode, SELECT is admin-only.
      // Returning the inserted row would require passing SELECT RLS checks (and would leak it back),
      // so we use minimal return here.
      prefer: "return=minimal",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) await readJsonOrThrow(res);
  return c.json({ ok: true }, 201);
});

app.delete("/v1/messages/:id", async (c) => {
  await requireAuth(c);
  const id = c.req.param("id");
  if (!id) return c.json({ error: "Missing id" }, 400);

  const res = await postgrestFetch(c.env, c.get("token") ?? null, "messages", {
    method: "DELETE",
    query: { id: `eq.${id}` },
    headers: { prefer: "return=representation" },
  });

  const data = await readJsonOrThrow(res);
  return c.json({ data });
});

export default app;
