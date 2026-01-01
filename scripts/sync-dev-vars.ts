import { writeFile } from "node:fs/promises";

type ApiKey = {
  api_key?: string;
  type?: string;
  name?: string;
};

function parseDotEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const idx = line.indexOf("=");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    let value = line.slice(idx + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

async function main() {
  const envText = await Bun.file(".env").text();
  const env = parseDotEnv(envText);
  const pat = env["supabase"];
  if (!pat) throw new Error("Missing `supabase` in .env (Supabase Management API PAT)");

  const preferredName = (Bun.argv[2] ?? "mimi").trim();

  const projectsRes = await fetch("https://api.supabase.com/v1/projects", {
    headers: { Authorization: `Bearer ${pat}`, Accept: "application/json" },
  });
  if (!projectsRes.ok) throw new Error(`Failed to list projects: HTTP ${projectsRes.status}`);
  const projects = (await projectsRes.json()) as Array<{ ref?: string; status?: string }>;
  const selected =
    projects.find((p: any) => (p?.name as string | undefined)?.toLowerCase?.() === preferredName.toLowerCase()) ??
    projects.find((p: any) => (p?.ref as string | undefined)?.toLowerCase?.().includes(preferredName.toLowerCase())) ??
    (projects.length === 1 ? projects[0] : null);
  if (!selected?.ref) {
    const names = projects.map((p: any) => p?.name).filter(Boolean);
    throw new Error(`Could not select project '${preferredName}'. Available: ${names.join(", ")}`);
  }

  const ref = selected.ref;
  const status = selected.status ?? "UNKNOWN";
  if (!String(status).startsWith("ACTIVE")) {
    throw new Error(
      `Supabase project is not ACTIVE (status=${status}). Unpause it in Supabase Dashboard, then rerun.`,
    );
  }

  const keysUrl = `https://api.supabase.com/v1/projects/${ref}/api-keys?reveal=true`;
  const keysRes = await fetch(keysUrl, {
    headers: { Authorization: `Bearer ${pat}`, Accept: "application/json" },
  });
  if (!keysRes.ok) throw new Error(`Failed to get api keys: HTTP ${keysRes.status}`);
  const keys = (await keysRes.json()) as ApiKey[];

  const anonLegacy = keys.find(
    (k) => k.type === "legacy" && k.name === "anon" && typeof k.api_key === "string",
  );
  const publishable = keys.find((k) => k.type === "publishable" && typeof k.api_key === "string");
  const key = anonLegacy?.api_key ?? publishable?.api_key;
  if (!key) throw new Error("No usable API key found (legacy anon or publishable).");

  const supabaseUrl = `https://${ref}.supabase.co`;
  const devVars =
    `SUPABASE_URL=${supabaseUrl}\n` +
    `SUPABASE_ANON_KEY=${key}\n` +
    `ALLOWED_ORIGIN=\n`;

  await writeFile(".dev.vars", devVars, "utf-8");
  process.stdout.write("Wrote .dev.vars (SUPABASE_URL + SUPABASE_ANON_KEY).\\n");
}

main().catch((err) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`${msg}\\n`);
  process.exit(1);
});
