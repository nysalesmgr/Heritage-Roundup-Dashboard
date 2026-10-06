// doc-scan: reads an applicant's passport / ID with Google Vision, or returns the file for upload to RMS.
// Called only by the Heritage dashboard (https://nysalesmgr.github.io).
//
// Body: { url } or { storage_path, bucket }   + optional mode: "upload"
//   OCR (default) → { text }        upload → { base64 }
// Images use Vision images:annotate; PDFs use Vision files:annotate (first 2 pages).
//
// Secrets: GOOGLE_VISION_KEY (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are provided by Supabase)
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const ALLOWED_ORIGIN = "https://nysalesmgr.github.io";
// Only documents from the application forms can be read — not any address on the internet
const ALLOWED_HOSTS = [/^booking\.hericollboston\.com$/, /^booking\.hericollny\.com$/, /^fs\d+\.formsite\.com$/, /^www\.formsite\.com$/];
const ALLOWED_BUCKETS = ["boston-applications", "ny-applications", "boston-formsite", "ny-formsite", "documents"];
const MAX_BYTES = 20 * 1024 * 1024;

serve(async (req) => {
  const origin = req.headers.get("origin") ?? "";
  const corsHeaders = {
    "Access-Control-Allow-Origin": origin === ALLOWED_ORIGIN ? origin : "null",
    "Access-Control-Allow-Headers": "content-type, apikey, authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
    "Content-Type": "application/json",
  };
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: corsHeaders });

  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json(405, { error: "method not allowed" });
  // Browsers on other websites are refused (calls without an Origin header, e.g. server-to-server, still work)
  if (origin && origin !== ALLOWED_ORIGIN) return json(403, { error: "origin not allowed" });

  try {
    const body = await req.json();
    const url = typeof body.url === "string" ? body.url.trim() : "";
    const storagePath = typeof body.storage_path === "string" ? body.storage_path.trim() : "";
    const mode = body.mode === "upload" ? "upload" : "ocr";
    const bucket = typeof body.bucket === "string" && body.bucket ? body.bucket : "documents";

    let fetchUrl = "";
    if (storagePath) {
      if (!ALLOWED_BUCKETS.includes(bucket)) return json(400, { error: "bucket not allowed" });
      if (storagePath.includes("..") || storagePath.startsWith("/")) return json(400, { error: "invalid storage path" });
      const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
      const { data, error } = await supabase.storage.from(bucket).createSignedUrl(storagePath, 300); // 5 minutes
      if (error || !data) return json(400, { error: "Failed to generate signed URL: " + (error?.message || "unknown") });
      fetchUrl = data.signedUrl;
    } else if (url) {
      let u: URL;
      try { u = new URL(url); } catch { return json(400, { error: "invalid url" }); }
      if (u.protocol !== "https:" || !ALLOWED_HOSTS.some((re) => re.test(u.hostname))) return json(400, { error: "url not allowed" });
      fetchUrl = u.toString();
    } else {
      return json(400, { error: "No URL or storage path provided" });
    }

    const docRes = await fetch(fetchUrl, { redirect: "follow" });
    if (!docRes.ok) return json(400, { error: "Fetch failed: " + docRes.status });
    const len = Number(docRes.headers.get("content-length") || 0);
    if (len > MAX_BYTES) return json(400, { error: "File too large" });
    const bytes = new Uint8Array(await docRes.arrayBuffer());
    if (bytes.length > MAX_BYTES) return json(400, { error: "File too large" });

    let binary = "";
    for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
    const base64 = btoa(binary);

    if (mode === "upload") return json(200, { base64 });

    const visionKey = Deno.env.get("GOOGLE_VISION_KEY") ?? "";
    if (!visionKey) return json(400, { error: "Vision API not configured" });

    // PDF? (file starts with "%PDF")
    const isPdf = bytes.length > 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46;
    let text = "";
    if (isPdf) {
      const r = await fetch("https://vision.googleapis.com/v1/files:annotate?key=" + visionKey, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ requests: [{
          inputConfig: { content: base64, mimeType: "application/pdf" },
          features: [{ type: "DOCUMENT_TEXT_DETECTION" }],
          pages: [1, 2],
        }] }),
      });
      const d = await r.json();
      const pages = d?.responses?.[0]?.responses || [];
      text = pages.map((p: { fullTextAnnotation?: { text?: string } }) => p?.fullTextAnnotation?.text || "").join("\n");
      if (!r.ok) console.error("Vision (PDF) status:", r.status);
    } else {
      const r = await fetch("https://vision.googleapis.com/v1/images:annotate?key=" + visionKey, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ requests: [{ image: { content: base64 }, features: [{ type: "DOCUMENT_TEXT_DETECTION" }] }] }),
      });
      const d = await r.json();
      text = d?.responses?.[0]?.fullTextAnnotation?.text || "";
      if (!r.ok) console.error("Vision status:", r.status);
    }

    // Only the text goes back for a scan (the file itself is returned only for uploads to RMS)
    return json(200, { text });
  } catch (e) {
    console.error("doc-scan error:", (e as Error).message);
    return json(500, { error: (e as Error).message });
  }
});
