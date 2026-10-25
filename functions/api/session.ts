type Env = { SESSION_SECRET: string; ROUTEFORCE_DB: D1Database };
type Context = { request: Request; env: Env };
function cookie(request: Request, name: string) { return request.headers.get("Cookie")?.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="))?.slice(name.length + 1); }
function decode(value: string) { const padded=value.replaceAll("-","+").replaceAll("_","/")+"=".repeat((4-value.length%4)%4); return new TextDecoder().decode(Uint8Array.from(atob(padded), c=>c.charCodeAt(0))); }
function b64(data: ArrayBuffer) { return btoa(String.fromCharCode(...new Uint8Array(data))).replaceAll("+","-").replaceAll("/","_").replaceAll("=",""); }
async function sign(value:string,secret:string){const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return b64(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(value)))}
export async function onRequestGet(context: Context) {
  const token=cookie(context.request,"rf_session"); if(!token||!context.env.SESSION_SECRET)return Response.json({authenticated:false},{status:401});
  const [payload,signature]=token.split("."); if(!payload||!signature||signature!==await sign(payload,context.env.SESSION_SECRET))return Response.json({authenticated:false},{status:401});
  try{const s=JSON.parse(decode(payload)) as {sub:string;login:string;exp:number};if(!s.sub||!s.login||s.exp<Date.now())throw Error("expired");const user=await context.env.ROUTEFORCE_DB.prepare("SELECT status,role FROM users WHERE id=?").bind(s.sub).first<{status:string;role:string}>();if(!user||(user.status!=="approved"&&user.role!=="admin"))throw Error("not_approved");return Response.json({authenticated:true,user:{id:s.sub,login:s.login,role:user.role}})}catch{return Response.json({authenticated:false},{status:401})}
}