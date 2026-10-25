type Env = { SESSION_SECRET: string; ROUTEFORCE_DB: D1Database };
type Context = { request: Request; env: Env };

function cookie(request: Request, name: string) { return request.headers.get("Cookie")?.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1); }
function b64(value: string) { const p=value.replaceAll("-","+").replaceAll("_","/")+"=".repeat((4-value.length%4)%4); return new TextDecoder().decode(Uint8Array.from(atob(p), c=>c.charCodeAt(0))); }
function out(data: ArrayBuffer) { return btoa(String.fromCharCode(...new Uint8Array(data))).replaceAll("+","-").replaceAll("/","_").replaceAll("=",""); }
async function user(context: Context) {
  const token=cookie(context.request,"rf_session"), [payload,sig]=(token||"").split(".");
  if (!payload || !sig || !context.env.SESSION_SECRET) return null;
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(context.env.SESSION_SECRET),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  if (sig !== out(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(payload)))) return null;
  try { const session=JSON.parse(b64(payload)); return session.exp>Date.now()?session:null; } catch { return null; }
}
export async function onRequestGet(context: Context) {
  const session=await user(context); if (!session) return Response.json({error:"auth_required"},{status:401});
  const results=await context.env.ROUTEFORCE_DB.prepare("SELECT id,name,description,created_at,updated_at FROM projects WHERE user_id=? ORDER BY updated_at DESC").bind(String(session.sub)).all();
  return Response.json({projects:results.results});
}
export async function onRequestPost(context: Context) {
  const session=await user(context); if (!session) return Response.json({error:"auth_required"},{status:401});
  const body=await context.request.json() as { name?: string; description?: string };
  const name=body.name?.trim().slice(0,80); if (!name) return Response.json({error:"project_name_required"},{status:400});
  const id=crypto.randomUUID();
  await context.env.ROUTEFORCE_DB.prepare("INSERT INTO projects (id,user_id,name,description) VALUES (?,?,?,?)").bind(id,String(session.sub),name,body.description?.trim().slice(0,240)||null).run();
  return Response.json({project:{id,name,description:body.description||null}},{status:201});
}