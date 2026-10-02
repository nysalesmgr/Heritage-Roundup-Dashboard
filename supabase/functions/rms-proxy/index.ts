// rms-proxy — Supabase Edge Function
// Holds RMS Cloud credentials server-side and forwards a small allow-list of calls
// from the Heritage dashboard. The browser never sees RMS credentials or tokens.
//
// Supports several RMS accounts (one per property / client ID).
//
// Required secrets (supabase secrets set ...):
//   RMS_BASE_URL     e.g. https://restapi12.rmscloud.com
//   RMS_AGENT_ID     agent ID issued by RMS
//   RMS_AGENT_PWD    agent password issued by RMS
//   RMS_CLIENTS      JSON list, one entry per RMS account:
//                    [{"key":"p1","name":"Property name","clientId":1234,"password":"web services password"}, ...]
//                    ("baseUrl" may be added to an entry if RMS gives that account a different URL)
//   ALLOWED_ORIGIN   the dashboard origin, e.g. https://nysalesmgr.github.io

type Client = { key: string; name: string; clientId: number; password: string; baseUrl?: string };

const env = (k: string) => Deno.env.get(k) ?? "";
const BASE = env("RMS_BASE_URL").replace(/\/+$/, "");
const ALLOWED_ORIGIN = env("ALLOWED_ORIGIN");

let CLIENTS: Client[] = [];
let CLIENTS_ERROR = "";
try {
  const parsed = JSON.parse(env("RMS_CLIENTS") || "[]");
  CLIENTS = (Array.isArray(parsed) ? parsed : []).filter(
    (c) => c && typeof c.key === "string" && /^[a-z0-9_-]{1,40}$/i.test(c.key) && Number(c.clientId) && c.password,
  ).map((c) => ({ ...c, clientId: Number(c.clientId), name: String(c.name || c.key) }));
} catch {
  CLIENTS_ERROR = "RMS_CLIENTS secret is not valid JSON";
}
const clientByKey = (k: string) => CLIENTS.find((c) => c.key === k);

// Only the calls the dashboard actually makes. Anything else is rejected.
const ALLOW: Array<[string, RegExp]> = [
  ["GET", /^\/_clients$/],
  ["GET", /^\/properties\?modelType=basic$/],
  ["GET", /^\/categories\?modelType=basic&propertyId=\d+$/],
  ["GET", /^\/areas\?modelType=basic&propertyId=\d+&limit=\d+$/],
  ["POST", /^\/availableAreas$/],
  ["POST", /^\/guests\/search\?modelType=basic$/],
  ["POST", /^\/guests$/],
  ["POST", /^\/reservations$/],
  ["GET", /^\/reservations\/\d+\?modelType=full$/],
  ["POST", /^\/reservations\/\d+\/document$/],
];

const cors = (origin: string) => ({
  "Access-Control-Allow-Origin": origin === ALLOWED_ORIGIN ? origin : "null",
  "Access-Control-Allow-Headers": "content-type, apikey, authorization, x-rms-path, x-rms-method, x-rms-client",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
});

// One cached RMS token per account
const tokens = new Map<string, { token: string; expires: number }>();

async function getToken(c: Client, force = false): Promise<string> {
  const cached = tokens.get(c.key);
  if (!force && cached && Date.now() < cached.expires) return cached.token;
  const res = await fetch(`${(c.baseUrl || BASE).replace(/\/+$/, "")}/authToken`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      agentId: Number(env("RMS_AGENT_ID")),
      agentPassword: env("RMS_AGENT_PWD"),
      clientId: c.clientId,
      clientPassword: c.password,
      moduleType: ["GuestServices"],
    }),
  });
  if (!res.ok) throw new Error(`RMS login failed for ${c.name} (${res.status})`);
  const data = await res.json();
  const token = data.token ?? data.authToken;
  const exp = data.expiryDate ? Date.parse(data.expiryDate) : NaN;
  tokens.set(c.key, { token, expires: (isNaN(exp) ? Date.now() + 60 * 60 * 1000 : exp) - 5 * 60 * 1000 });
  return token;
}

Deno.serve(async (req) => {
  const origin = req.headers.get("origin") ?? "";
  const headers = { ...cors(origin), "Content-Type": "application/json" };
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers });

  if (req.method === "OPTIONS") return new Response(null, { headers });
  if (req.method !== "POST") return json(405, { error: "method not allowed" });
  if (!ALLOWED_ORIGIN || origin !== ALLOWED_ORIGIN) return json(403, { error: "origin not allowed" });

  const path = req.headers.get("x-rms-path") ?? "";
  const method = (req.headers.get("x-rms-method") ?? "GET").toUpperCase();
  if (!ALLOW.some(([m, re]) => m === method && re.test(path))) return json(403, { error: "call not allowed" });

  if (CLIENTS_ERROR) return json(500, { error: CLIENTS_ERROR });
  if (!BASE || !env("RMS_AGENT_ID") || !env("RMS_AGENT_PWD") || !CLIENTS.length) {
    return json(500, { error: "RMS secrets not configured" });
  }

  // List of accounts for the dashboard's property dropdown (never includes passwords)
  if (path === "/_clients") return json(200, CLIENTS.map((c) => ({ key: c.key, name: c.name })));

  const client = clientByKey(req.headers.get("x-rms-client") ?? "");
  if (!client) return json(400, { error: "unknown RMS account" });

  const body = method === "POST" ? await req.text() : undefined;
  const base = (client.baseUrl || BASE).replace(/\/+$/, "");
  try {
    const send = async (t: string) =>
      fetch(`${base}${path}`, { method, headers: { "Content-Type": "application/json", authtoken: t }, body });
    let res = await send(await getToken(client));
    if (res.status === 401) res = await send(await getToken(client, true)); // token expired — refresh once
    return new Response(await res.text(), { status: res.status, headers });
  } catch (e) {
    return json(502, { error: (e as Error).message });
  }
});
