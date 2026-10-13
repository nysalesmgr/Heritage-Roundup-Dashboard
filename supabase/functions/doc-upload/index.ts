// doc-upload: staff upload a newer copy of an applicant's document from the Heritage dashboard,
// and open stored documents with a short-lived link.
// Called only by the dashboard (https://nysalesmgr.github.io).
//
//   { action: "upload", bucket, ref, doc_type, ext, base64 }  → { bucket, path }
//   { action: "sign",   bucket, path }                        → { url }   (valid 5 minutes)
//
// Files go to <bucket>/<ref>/staff-<doc_type>-<timestamp>.<ext>; nothing is overwritten or deleted.
// Secrets: SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY (provided by Supabase)
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const ALLOWED_ORIGIN = "https://nysalesmgr.github.io";
const UPLOAD_BUCKETS = ["boston-applications", "ny-applications"];
const SIGN_BUCKETS = ["boston-applications", "ny-applications", "boston-formsite", "ny-formsite", "documents"];
const DOC_TYPES = ["passport", "i20", "visa", "enrollment", "internship", "other"];
const TYPES: Record<string, { mime: string; magic: (b: Uint8Array) => boolean }> = {
  pdf:  { mime: "application/pdf", magic: (b) => b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46 },  // %PDF
  jpg:  { mime: "image/jpeg",      magic: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  jpeg: { mime: "image/jpeg",      magic: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  png:  { mime: "image/png",       magic: (b) => b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 },
};
const MAX_BYTES = 10 * 1024 * 1024;

serve(async (req) => {
  const origin = req.headers.get("origin") ?? "";
  const headers = {
    "Access-Control-Allow-Origin": origin === ALLOWED_ORIGIN ? origin : "null",
    "Access-Control-Allow-Headers": "content-type, apikey, authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
    "Content-Type": "application/json",
  };
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers });

  if (req.method === "OPTIONS") return new Response("ok", { headers });
  if (req.method !== "POST") return json(405, { error: "method not allowed" });
  if (origin !== ALLOWED_ORIGIN) return json(403, { error: "origin not allowed" });

  try {
    const body = await req.json();
    const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    if (body.action === "sign") {
      const bucket = String(body.bucket || ""), path = String(body.path || "");
      if (!SIGN_BUCKETS.includes(bucket)) return json(400, { error: "bucket not allowed" });
      if (!path || path.includes("..") || path.startsWith("/")) return json(400, { error: "invalid path" });
      const { data, error } = await supabase.storage.from(bucket).createSignedUrl(path, 300);
      if (error || !data) return json(400, { error: "could not open file" });
      return json(200, { url: data.signedUrl });
    }

    if (body.action === "upload") {
      const bucket = String(body.bucket || "");
      const ref = String(body.ref || "");
      const docType = String(body.doc_type || "");
      const ext = String(body.ext || "").toLowerCase();
      if (!UPLOAD_BUCKETS.includes(bucket)) return json(400, { error: "bucket not allowed" });
      if (!/^[A-Za-z0-9-]{3,64}$/.test(ref)) return json(400, { error: "invalid reference" });
      if (!DOC_TYPES.includes(docType)) return json(400, { error: "invalid document type" });
      const type = TYPES[ext];
      if (!type) return json(400, { error: "only PDF, JPG or PNG files" });
      const b64 = String(body.base64 || "");
      if (!b64 || b64.length > Math.ceil(MAX_BYTES * 4 / 3) + 8) return json(400, { error: "file too large (max 10 MB)" });
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      if (bytes.length > MAX_BYTES) return json(400, { error: "file too large (max 10 MB)" });
      if (!type.magic(bytes)) return json(400, { error: "file content doesn't match its type" });
      const path = `${ref}/staff-${docType}-${Date.now()}.${ext === "jpeg" ? "jpg" : ext}`;
      const { error } = await supabase.storage.from(bucket).upload(path, bytes, { contentType: type.mime, upsert: false });
      if (error) return json(400, { error: "upload failed: " + error.message });
      return json(200, { bucket, path });
    }

    return json(400, { error: "unknown action" });
  } catch (e) {
    console.error("doc-upload error:", (e as Error).message);
    return json(500, { error: (e as Error).message });
  }
});
