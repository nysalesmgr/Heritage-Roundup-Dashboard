// rms-proxy — Supabase Edge Function
// Holds RMS Cloud credentials server-side and forwards a small allow-list of calls
// from the Heritage dashboard. The browser never sees RMS credentials or tokens.
//
// Required secrets (supabase secrets set ...) — RMS production credentials:
//   RMS_BASE_URL                 e.g. https://restapi12.rmscloud.com
//   RMS_AGENT_ID, RMS_AGENT_PWD, RMS_CLIENT_ID, RMS_CLIENT_PWD
//   ALLOWED_ORIGIN               the dashboard origin, e.g. https://nysalesmgr.github.io

const cfg = (k: string) => Deno.env.get(`RMS_${k}`) ?? "";
const BASE = cfg("BASE_URL").replace(/\/+$/, "");
const ALLOWED_ORIGIN = Deno.env.get("ALLOWED_ORIGIN") ?? "";

// Only the calls the dashboard actually makes. Anything else is rejected.
const ALLOW: Array<[string, RegExp]> = [
  ["GET", /^\/properties\?modelType=basic$/],
  ["GET", /^\/categories\?modelType=basic&propertyId=\d+$/],
  ["GET", /^\/areas\?modelType=basic&propertyId=\d+&limit=\d+$/],
  ["POST", /^\/guests\/search\?modelType=basic$/],
  ["POST", /^\/guests$/],
  ["POST", /^\/reservations$/],
  ["POST", /^\/reservations\/\d+\/document$/],
];

const cors = (origin: string) => ({
  "Access-Control-Allow-Origin": origin === ALLOWED_ORIGIN ? origin : "null",
  "Access-Control-Allow-Headers": "content-type, apikey, authorization, x-rms-path, x-rms-method",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
});

let token: string | null = null;
let tokenExpires = 0;

async function getToken(force = false): Promise<string> {
  if (!force && token && Date.now() < tokenExpires) return token;
  const res = await fetch(`${BASE}/authToken`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      agentId: Number(cfg("AGENT_ID")),
      agentPassword: cfg("AGENT_PWD"),
      clientId: Number(cfg("CLIENT_ID")),
      clientPassword: cfg("CLIENT_PWD"),
      moduleType: ["GuestServices"],
    }),
  });
  if (!res.ok) throw new Error(`RMS auth failed (${res.status})`);
  const data = await res.json();
  token = data.token ?? data.authToken;
  const exp = data.expiryDate ? Date.parse(data.expiryDate) : NaN;
  tokenExpires = (isNaN(exp) ? Date.now() + 60 * 60 * 1000 : exp) - 5 * 60 * 1000;
  return token!;
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

  if (!BASE || !cfg("AGENT_ID") || !cfg("CLIENT_ID")) return json(500, { error: "RMS secrets not configured" });

  const body = method === "POST" ? await req.text() : undefined;
  try {
    const send = async (t: string) =>
      fetch(`${BASE}${path}`, { method, headers: { "Content-Type": "application/json", authtoken: t }, body });
    let res = await send(await getToken());
    if (res.status === 401) res = await send(await getToken(true)); // token expired — refresh once
    return new Response(await res.text(), { status: res.status, headers });
  } catch (e) {
    return json(502, { error: (e as Error).message });
  }
});
