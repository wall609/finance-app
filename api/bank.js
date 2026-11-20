const crypto = require('node:crypto');
const httpsOrigin = 'https://finance-app-zeta-mauve.vercel.app';
const cookieName = '__Host-finance_session';
const key = () => crypto.createHash('sha256').update(process.env.APP_SESSION_KEY).digest();
const mac = v => crypto.createHmac('sha256', key()).update('session:'+v).digest('base64url');
function equal(a,b) { const x=Buffer.from(String(a)),y=Buffer.from(String(b)); return x.length===y.length&&crypto.timingSafeEqual(x,y); }
function seal(v){const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',key(),iv);return [iv,c.update(v,'utf8'),c.final(),c.getAuthTag()].map(x=>x.toString('base64url')).join('.');}
function unseal(v){const [iv,a,b,tag]=v.split('.').map(x=>Buffer.from(x,'base64url')),d=crypto.createDecipheriv('aes-256-gcm',key(),iv);d.setAuthTag(tag);return Buffer.concat([d.update(a),d.update(b),d.final()]).toString('utf8');}
function session(req){let v=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(cookieName+'='))?.slice(cookieName.length+1);if(!v)return false;let [exp,nonce,sig]=v.split('.');return Boolean(exp&&nonce&&sig&&Number(exp)>Date.now()&&equal(mac(exp+'.'+nonce),sig));}
function setCookie(res,v,age){res.setHeader('Set-Cookie',`${cookieName}=${v}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${age}`);}
const env=()=>process.env.PLAID_ENV==='production'?'production':'sandbox';
async function redis(...cmd){const url=process.env.UPSTASH_REDIS_REST_URL||process.env.KV_REST_API_URL,token=process.env.UPSTASH_REDIS_REST_TOKEN||process.env.KV_REST_API_TOKEN;if(!url||!token)throw Error('STORAGE_NOT_CONFIGURED');const r=await fetch(url,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(cmd),signal:AbortSignal.timeout(12000)});let j=await r.json();if(!r.ok||j.error)throw Error('STORAGE_ERROR');return j.result;}
async function plaid(path,body){if(!process.env.PLAID_CLIENT_ID||!process.env.PLAID_SECRET)throw Error('PLAID_NOT_CONFIGURED');const r=await fetch(`https://${env()}.plaid.com${path}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...body,client_id:process.env.PLAID_CLIENT_ID,secret:process.env.PLAID_SECRET}),signal:AbortSignal.timeout(25000)});const j=await r.json();if(!r.ok||j.error_code)throw Error('PLAID_'+String(j.error_code||'API_ERROR').replace(/[^A-Z0-9_]/g,''));return j;}
const store=()=>`finance:v7:${env()}:items`;
module.exports=async(req,res)=>{res.setHeader('Cache-Control','no-store, private');res.setHeader('X-Content-Type-Options','nosniff');try{
 if(req.method!=='POST')return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
 if(req.headers.origin!==httpsOrigin)return res.status(403).json({error:'ORIGIN_DENIED'});
 if(!process.env.APP_PASSWORD||process.env.APP_PASSWORD.length<16||!process.env.APP_SESSION_KEY||process.env.APP_SESSION_KEY.length<32)return res.status(503).json({error:'LOGIN_NOT_CONFIGURED'});
 let b=typeof req.body==='string'?JSON.parse(req.body):req.body||{};
 if(b.action==='login'){
  const attempts=await redis('INCR','finance:v7:login-attempts');if(attempts===1)await redis('EXPIRE','finance:v7:login-attempts',600);if(attempts>10)return res.status(429).json({error:'TOO_MANY_ATTEMPTS'});
  if(typeof b.password!=='string'||b.password.length>512||!equal(b.password,process.env.APP_PASSWORD))return res.status(401).json({error:'INVALID_PASSWORD'});
  await redis('DEL','finance:v7:login-attempts');const v=(Date.now()+12*3600000)+'.'+crypto.randomBytes(24).toString('base64url');setCookie(res,v+'.'+mac(v),43200);return res.json({ok:true});
 }
 if(!session(req))return res.status(401).json({error:'LOGIN_REQUIRED'});
 if(b.action==='logout'){setCookie(res,'',0);return res.json({ok:true});}
 if(b.action==='status')return res.json({ok:true,environment:env()});
 if(b.action==='link'){
  const product=b.product==='investments'?'investments':'transactions';
  const j=await plaid('/link/token/create',{client_name:'Freedom Ledger',user:{client_user_id:'owner'},products:[product],country_codes:['US'],language:'en',redirect_uri:httpsOrigin+'/'});return res.json({link_token:j.link_token,environment:env()});
 }
 if(b.action==='exchange'){
  if(typeof b.public_token!=='string'||!b.public_token.startsWith('public-'+env()+'-')||b.public_token.length>300)return res.status(400).json({error:'INVALID_PUBLIC_TOKEN'});
  const j=await plaid('/item/public_token/exchange',{public_token:b.public_token});await redis('HSET',store(),j.item_id,seal(j.access_token));return res.json({ok:true});
 }
 if(b.action==='balances'){
  const data=await redis('HGETALL',store())||[],items=Array.isArray(data)?Array.from({length:Math.floor(data.length/2)},(_,i)=>[data[i*2],data[i*2+1]]):Object.entries(data);let accounts=[],errors=[];
  for(const [itemId,token] of items){try{const access_token=unseal(token);let j=await plaid('/accounts/get',{access_token}),fresh=false;if(b.live===true){try{j=await plaid('/accounts/balance/get',{access_token});fresh=true;}catch(e){errors.push({item:itemId,error:e.message});}}let name='已连接机构';try{if(j.item?.institution_id){let info=await plaid('/institutions/get_by_id',{institution_id:j.item.institution_id,country_codes:['US']});name=info.institution.name;}}catch{}for(const a of j.accounts||[]){const type=a.type==='credit'||a.type==='loan'?'debt':a.type==='investment'?'invest':a.type==='depository'?'cash':null;if(!type)continue;const amount=a.balances?.current;accounts.push({id:'plaid-'+a.account_id,item:itemId,name:name+' · '+a.name+(a.mask?' · '+a.mask:''),type,amount:typeof amount==='number'?amount:null,currency:a.balances?.iso_currency_code||null,fresh});}}catch(e){errors.push({item:itemId,error:e.message});}}
  return res.json({accounts,errors,itemCount:items.length,queriedAt:new Date().toISOString(),environment:env()});
 }
 if(b.action==='unlink'){
  const id=String(b.item||'');let token=await redis('HGET',store(),id);if(token){await plaid('/item/remove',{access_token:unseal(token)});await redis('HDEL',store(),id);}return res.json({ok:true});
 }
 return res.status(400).json({error:'UNKNOWN_ACTION'});
 }catch(e){return res.status(502).json({error:/^(PLAID_[A-Z0-9_]+|STORAGE_[A-Z0-9_]+)$/.test(e.message)?e.message:'SERVER_ERROR'});}
};
