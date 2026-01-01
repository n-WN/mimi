import { HTTPException } from "hono/http-exception";
import type { Env } from "./env";

export type SupabaseError = {
  message?: string;
  details?: string;
  hint?: string;
  code?: string;
};

export async function postgrestFetch(
  env: Env,
  token: string | null,
  path: string,
  init: RequestInit & { query?: Record<string, string> } = {},
): Promise<Response> {
  const base = env.SUPABASE_URL.replace(/\/+$/, "");
  const url = new URL(`${base}/rest/v1/${path.replace(/^\/+/, "")}`);
  for (const [k, v] of Object.entries(init.query ?? {})) url.searchParams.set(k, v);

  const headers = new Headers(init.headers);
  headers.set("apikey", env.SUPABASE_ANON_KEY);
  if (token) headers.set("authorization", `Bearer ${token}`);
  if (!headers.has("content-type")) headers.set("content-type", "application/json");

  try {
    return await fetch(url, { ...init, headers });
  } catch (err) {
    const message = err instanceof Error ? err.message : "fetch failed";
    throw new HTTPException(502, {
      res: new Response(JSON.stringify({ error: "Upstream fetch failed", message }), {
        status: 502,
        headers: { "content-type": "application/json" },
      }),
    });
  }
}

export async function readJsonOrThrow(res: Response): Promise<unknown> {
  const contentType = res.headers.get("content-type") ?? "";
  const isJson = contentType.includes("application/json");
  if (res.ok) return isJson ? await res.json() : await res.text();

  const body = isJson ? ((await res.json()) as SupabaseError) : { message: await res.text() };
  const message = body.message || `Supabase error (${res.status})`;
  throw new HTTPException(res.status as any, {
    res: new Response(JSON.stringify({ error: message, details: body.details, code: body.code }), {
      status: res.status,
      headers: { "content-type": "application/json" },
    }),
  });
}
