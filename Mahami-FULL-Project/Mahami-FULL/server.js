import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import Anthropic from '@anthropic-ai/sdk';
import Stripe from 'stripe';
import { createRemoteJWKSet, jwtVerify, SignJWT } from 'jose';
import nodemailer from 'nodemailer';

const app = express();
const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.ANTHROPIC_API_KEY;
const MODEL = process.env.CLAUDE_MODEL || 'claude-sonnet-5';
const SESSION_SECRET = process.env.SESSION_SECRET;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5500';
const MAX_FILE_SIZE = 8 * 1024 * 1024;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const USERNAME_DB_FILE = process.env.USERNAME_DB_FILE || path.join(__dirname, 'usernames.json');
const LEADERBOARD_DB_FILE = process.env.LEADERBOARD_DB_FILE || path.join(__dirname, 'leaderboard.json');
const SOCIAL_DB_FILE = process.env.SOCIAL_DB_FILE || path.join(__dirname, 'social.json');
const SOCIAL_PREFS_DB_FILE = process.env.SOCIAL_PREFS_DB_FILE || path.join(__dirname, 'social-prefs.json');
const SUPPORT_TICKETS_DB_FILE = process.env.SUPPORT_TICKETS_DB_FILE || path.join(__dirname, 'support-tickets.json');
const SUPPORT_ATTACHMENTS_DIR = process.env.SUPPORT_ATTACHMENTS_DIR || path.join(__dirname, 'support-attachments');
const PUBLIC_APP_URL = (process.env.PUBLIC_APP_URL || 'http://localhost:5500').replace(/\/$/, '');
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PRICE_PRO = process.env.STRIPE_PRICE_PRO || '';
const STRIPE_MODE = process.env.STRIPE_MODE || 'subscription';
const AUTH_USERS_DB_FILE = process.env.AUTH_USERS_DB_FILE || path.join(__dirname, 'auth-users.json');
const ADMIN_EMAILS = new Set((process.env.ADMIN_EMAILS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean));
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || `${PUBLIC_APP_URL}/api/auth/google/callback`;
const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID || '';
const APPLE_TEAM_ID = process.env.APPLE_TEAM_ID || '';
const APPLE_KEY_ID = process.env.APPLE_KEY_ID || '';
const APPLE_PRIVATE_KEY = (process.env.APPLE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
const APPLE_REDIRECT_URI = process.env.APPLE_REDIRECT_URI || `${PUBLIC_APP_URL}/api/auth/apple/callback`;
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const EMAIL_FROM = process.env.EMAIL_FROM || SMTP_USER;
const mailer = SMTP_HOST && SMTP_USER && SMTP_PASS ? nodemailer.createTransport({host:SMTP_HOST,port:SMTP_PORT,secure:SMTP_PORT===465,auth:{user:SMTP_USER,pass:SMTP_PASS}}) : null;
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

if (!API_KEY) throw new Error('ANTHROPIC_API_KEY غير موجود في ملف .env');
if (!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET يجب أن يكون 32 حرفًا على الأقل');

const anthropic = new Anthropic({ apiKey: API_KEY });
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ok = file.mimetype === 'application/pdf' || /^image\/(jpeg|png|gif|webp)$/i.test(file.mimetype);
    cb(ok ? null : new Error('يسمح فقط بصورة أو PDF'), ok);
  }
});


fs.mkdirSync(SUPPORT_ATTACHMENTS_DIR, { recursive: true });
const ticketUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 4 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ok = file.mimetype === 'application/pdf' || /^image\/(jpeg|png|gif|webp)$/i.test(file.mimetype);
    cb(ok ? null : new Error('مرفق التذكرة يجب أن يكون صورة أو PDF'), ok);
  }
});
const supportTicketsStore = {};
function saveSupportTickets(){ fs.writeFileSync(SUPPORT_TICKETS_DB_FILE, JSON.stringify(supportTicketsStore, null, 2), 'utf8'); }
function ticketFor(ticketId){ return supportTicketsStore[ticketId] || null; }
function makeTicketNumber(){ return `SUP-${new Date().toISOString().slice(0,10).replace(/-/g,'')}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`; }
function safeFileExt(mime){ return ({'image/jpeg':'jpg','image/png':'png','image/gif':'gif','image/webp':'webp','application/pdf':'pdf'}[mime] || 'bin'); }

const allowedOrigins = ALLOWED_ORIGIN.split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin(origin, cb) {
  if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
  return cb(new Error('Origin غير مسموح'));
}}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

app.get('/api/health', (_req, res) => res.json({ ok: true, model: MODEL }));

function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function unbase64url(input) {
  return Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}
function signSession(studentId, claims = {}) {
  const payload = base64url(JSON.stringify({ sub: studentId, exp: Date.now() + 7 * 24 * 60 * 60 * 1000, ...claims }));
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function normalizeEmail(email){ return cleanText(email, 320).trim().toLowerCase(); }
function roleForEmail(email){ return ADMIN_EMAILS.has(normalizeEmail(email)) ? 'admin' : 'user'; }
function stableStudentId(provider, subject){ return crypto.createHash('sha256').update(`${provider}:${subject}`).digest('hex').slice(0,40); }
function upsertAuthUser({provider, subject, email, name}){
  const key=`${provider}:${subject}`; const normalizedEmail=normalizeEmail(email);
  let user=authUsersStore[key];
  if(!user){
    const existingKey=Object.keys(authUsersStore).find(k=>authUsersStore[k]?.email===normalizedEmail);
    user=existingKey?authUsersStore[existingKey]:null;
  }
  if(!user){ user={studentId:stableStudentId(provider,subject),provider,subject,email:normalizedEmail,name:cleanText(name,100)||normalizedEmail.split('@')[0],createdAt:Date.now()}; }
  user.provider=provider; user.subject=subject; user.email=normalizedEmail; if(name)user.name=cleanText(name,100); user.updatedAt=Date.now(); user.role=roleForEmail(normalizedEmail);
  authUsersStore[key]=user; writeJsonFile(AUTH_USERS_DB_FILE,authUsersStore);
  return user;
}
function authTokenForUser(user){ return signSession(user.studentId,{email:user.email,name:user.name,provider:user.provider,role:user.role||roleForEmail(user.email)}); }
function createOneTimeAuthCode(token){ const code=crypto.randomBytes(24).toString('hex'); oneTimeAuthCodes.set(code,{token,expiresAt:Date.now()+2*60*1000}); return code; }
function createOAuthState(provider,nonce){ const state=crypto.randomBytes(24).toString('hex'); oauthStateStore.set(state,{provider,nonce,expiresAt:Date.now()+10*60*1000}); return state; }
function consumeOAuthState(state,provider){ const v=oauthStateStore.get(state); oauthStateStore.delete(state); if(!v||v.provider!==provider||v.expiresAt<Date.now())return null; return v; }
async function makeAppleClientSecret(){
  if(!APPLE_TEAM_ID||!APPLE_KEY_ID||!APPLE_CLIENT_ID||!APPLE_PRIVATE_KEY)throw new Error('إعدادات Apple OAuth غير مكتملة');
  return new SignJWT({}).setProtectedHeader({alg:'ES256',kid:APPLE_KEY_ID,typ:'JWT'}).setIssuer(APPLE_TEAM_ID).setSubject(APPLE_CLIENT_ID).setAudience('https://appleid.apple.com').setIssuedAt().setExpirationTime('180d').sign(await import('jose').then(({importPKCS8})=>importPKCS8(APPLE_PRIVATE_KEY,'ES256')));
}
function callbackRedirect(code){ return `${PUBLIC_APP_URL}/?auth_code=${encodeURIComponent(code)}`; }
function verifySession(token) {
  try {
    const [payload, sig] = String(token || '').split('.');
    if (!payload || !sig) return null;
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const body = JSON.parse(unbase64url(payload));
    if (!body?.sub || !body?.exp || body.exp < Date.now()) return null;
    return body;
  } catch {
    return null;
  }
}
function getBearer(req) {
  const h = req.get('authorization') || '';
  return h.startsWith('Bearer ') ? h.slice(7) : '';
}
function cleanText(value, max = 5000) {
  return String(value ?? '').slice(0, max);
}

function readJsonFile(file, fallback) {
  try { if (!fs.existsSync(file)) return fallback; const raw = fs.readFileSync(file, 'utf8'); return JSON.parse(raw); } catch { return fallback; }
}
const loadedSupportTickets = readJsonFile(SUPPORT_TICKETS_DB_FILE, {});
Object.assign(supportTicketsStore, loadedSupportTickets);
function writeJsonFile(file, value) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}
function normalizeUsername(value) { return cleanText(value, 30).normalize('NFKC').trim().toLowerCase(); }
function validUsername(value) { return /^[a-zA-Z0-9_.-]{2,30}$/.test(value); }
let usernameStore = readJsonFile(USERNAME_DB_FILE, {});
let leaderboardStore = readJsonFile(LEADERBOARD_DB_FILE, {});
let socialStore = readJsonFile(SOCIAL_DB_FILE, {});
let socialPrefsStore = readJsonFile(SOCIAL_PREFS_DB_FILE, {});
let authUsersStore = readJsonFile(AUTH_USERS_DB_FILE, {});
const oauthStateStore = new Map();
const oneTimeAuthCodes = new Map();
const pendingEmailOtps = new Map();
const googleJWKS = GOOGLE_CLIENT_ID ? createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs')) : null;
const appleJWKS = APPLE_CLIENT_ID ? createRemoteJWKSet(new URL('https://appleid.apple.com/auth/keys')) : null;
function saveStores() { writeJsonFile(USERNAME_DB_FILE, usernameStore); writeJsonFile(LEADERBOARD_DB_FILE, leaderboardStore); writeJsonFile(SOCIAL_DB_FILE, socialStore); writeJsonFile(SOCIAL_PREFS_DB_FILE, socialPrefsStore); writeJsonFile(AUTH_USERS_DB_FILE, authUsersStore); }
function socialFor(studentId){ if(!socialStore[studentId]) socialStore[studentId]={friends:[],incomingFriendRequests:[],outgoingFriendRequests:[],followers:[],following:[]}; return socialStore[studentId]; }
function usernameForStudent(studentId){ const pair=Object.entries(usernameStore).find(([,id])=>id===studentId); return pair?.[0]||'مستخدم'; }
function prefsFor(studentId){ return socialPrefsStore[studentId] || {showInLeaderboard:true,allowFriendRequests:true,allowFollows:true,username:usernameForStudent(studentId)}; }



// ===== Real authentication: Google, Apple, Email OTP =====
app.post('/api/auth/guest', (_req,res)=>{
  const guestId='guest-'+crypto.randomBytes(12).toString('hex');
  const user={studentId:stableStudentId('guest',guestId),provider:'guest',subject:guestId,email:'',name:'ضيف',role:'user',createdAt:Date.now()};
  const token=authTokenForUser(user);
  return res.status(201).json({ok:true,token,user:{studentId:user.studentId,email:'',name:'ضيف',provider:'guest',role:'user'}});
});

app.get('/api/auth/google/start', (req,res)=>{
  if(!GOOGLE_CLIENT_ID||!GOOGLE_CLIENT_SECRET) return res.status(503).send('Google Sign-In غير مفعّل على السيرفر. أضف GOOGLE_CLIENT_ID وGOOGLE_CLIENT_SECRET وGOOGLE_REDIRECT_URI إلى .env.');
  const nonce=crypto.randomBytes(16).toString('hex'); const state=createOAuthState('google',nonce);
  const u=new URL('https://accounts.google.com/o/oauth2/v2/auth');
  u.searchParams.set('client_id',GOOGLE_CLIENT_ID); u.searchParams.set('redirect_uri',GOOGLE_REDIRECT_URI); u.searchParams.set('response_type','code'); u.searchParams.set('scope','openid email profile'); u.searchParams.set('state',state); u.searchParams.set('nonce',nonce); u.searchParams.set('prompt','select_account');
  return res.redirect(u.toString());
});
app.get('/api/auth/google/callback', async (req,res)=>{
  try{
    const state=consumeOAuthState(req.query?.state,'google'); if(!state)throw new Error('حالة Google غير صالحة أو منتهية');
    const code=cleanText(req.query?.code,4000); if(!code)throw new Error('لم يصل رمز Google');
    const tokenRes=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({code,client_id:GOOGLE_CLIENT_ID,client_secret:GOOGLE_CLIENT_SECRET,redirect_uri:GOOGLE_REDIRECT_URI,grant_type:'authorization_code'})});
    const tokens=await tokenRes.json(); if(!tokenRes.ok||!tokens.id_token)throw new Error('تعذر استبدال رمز Google');
    const verified=await jwtVerify(tokens.id_token,googleJWKS,{issuer:['https://accounts.google.com','accounts.google.com'],audience:GOOGLE_CLIENT_ID});
    if(verified.payload.nonce!==state.nonce)throw new Error('فشل تحقق nonce في Google');
    if(verified.payload.email_verified!==true)throw new Error('حساب Google لا يملك بريدًا موثقًا');
    const user=upsertAuthUser({provider:'google',subject:String(verified.payload.sub),email:String(verified.payload.email),name:String(verified.payload.name||verified.payload.given_name||'مستخدم')});
    const authCode=createOneTimeAuthCode(authTokenForUser(user)); return res.redirect(callbackRedirect(authCode));
  }catch(error){ console.error(error); return res.status(400).send(`تعذر تسجيل الدخول باستخدام Google: ${cleanText(error?.message||'خطأ غير معروف',300)}`); }
});

app.get('/api/auth/apple/start', (req,res)=>{
  if(!APPLE_CLIENT_ID||!APPLE_TEAM_ID||!APPLE_KEY_ID||!APPLE_PRIVATE_KEY) return res.status(503).send('Apple Sign-In غير مفعّل على السيرفر. أكمل إعدادات Apple في .env.');
  const nonce=crypto.randomBytes(16).toString('hex'); const state=createOAuthState('apple',nonce);
  const u=new URL('https://appleid.apple.com/auth/authorize'); u.searchParams.set('client_id',APPLE_CLIENT_ID); u.searchParams.set('redirect_uri',APPLE_REDIRECT_URI); u.searchParams.set('response_type','code id_token'); u.searchParams.set('response_mode','form_post'); u.searchParams.set('scope','name email'); u.searchParams.set('state',state); u.searchParams.set('nonce',nonce);
  return res.redirect(u.toString());
});
app.post('/api/auth/apple/callback', async (req,res)=>{
  try{
    const state=consumeOAuthState(req.body?.state,'apple'); if(!state)throw new Error('حالة Apple غير صالحة أو منتهية');
    const code=cleanText(req.body?.code,4000); if(!code)throw new Error('لم يصل رمز Apple');
    const clientSecret=await makeAppleClientSecret();
    const tokenRes=await fetch('https://appleid.apple.com/auth/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:APPLE_CLIENT_ID,client_secret:clientSecret,code,grant_type:'authorization_code',redirect_uri:APPLE_REDIRECT_URI})});
    const tokens=await tokenRes.json(); if(!tokenRes.ok||!tokens.id_token)throw new Error('تعذر استبدال رمز Apple');
    const verified=await jwtVerify(tokens.id_token,appleJWKS,{issuer:'https://appleid.apple.com',audience:APPLE_CLIENT_ID});
    if(verified.payload.nonce&&verified.payload.nonce!==state.nonce)throw new Error('فشل تحقق nonce في Apple');
    const rawUser=req.body?.user?JSON.parse(req.body.user):{}; const email=String(verified.payload.email||''); if(!email)throw new Error('لم يصل بريد Apple');
    const displayName=rawUser?.name?`${rawUser.name.firstName||''} ${rawUser.name.lastName||''}`.trim():'مستخدم Apple';
    const user=upsertAuthUser({provider:'apple',subject:String(verified.payload.sub),email,name:displayName});
    const authCode=createOneTimeAuthCode(authTokenForUser(user)); return res.redirect(callbackRedirect(authCode));
  }catch(error){ console.error(error); return res.status(400).send(`تعذر تسجيل الدخول باستخدام Apple: ${cleanText(error?.message||'خطأ غير معروف',300)}`); }
});

app.post('/api/auth/anonymous',(req,res)=>{
  const rawStudentId=cleanText(req.body?.studentId,120);
  const name=cleanText(req.body?.name,100)||'مستخدم مهامي';
  if(!rawStudentId||rawStudentId.length<8) return res.status(400).json({error:'هوية الجهاز غير صالحة'});
  const studentId=stableStudentId('anonymous',rawStudentId);
  const internalEmail=`anon_${studentId.slice(0,24)}@anonymous.local`;
  const user=upsertAuthUser({provider:'anonymous',subject:rawStudentId,email:internalEmail,name});
  user.role='user';
  authUsersStore[`anonymous:${rawStudentId}`]=user;
  writeJsonFile(AUTH_USERS_DB_FILE,authUsersStore);
  const token=signSession(user.studentId,{email:'',name:user.name,provider:'anonymous',role:'user'});
  return res.json({ok:true,token,user:{studentId:user.studentId,name:user.name,provider:'anonymous',role:'user'}});
});
app.post('/api/auth/email/request', async (req,res)=>{
  const email=normalizeEmail(req.body?.email); if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:'البريد الإلكتروني غير صالح'});
  if(!mailer)return res.status(503).json({error:'تسجيل الدخول بالبريد يحتاج إعداد SMTP في السيرفر أولًا.'});
  const existing=pendingEmailOtps.get(email); if(existing&&existing.lastSentAt>Date.now()-60000)return res.status(429).json({error:'انتظر دقيقة قبل طلب رمز جديد.'});
  const code=String(crypto.randomInt(0,1000000)).padStart(6,'0'); pendingEmailOtps.set(email,{hash:crypto.createHash('sha256').update(code).digest('hex'),expiresAt:Date.now()+10*60*1000,attempts:0,lastSentAt:Date.now()});
  try{await mailer.sendMail({from:EMAIL_FROM,to:email,subject:'رمز الدخول إلى مهامي',text:`رمز الدخول إلى تطبيق مهامي هو: ${code}\nصلاحية الرمز 10 دقائق. إذا لم تطلبه فتجاهل الرسالة.`,html:`<div dir="rtl" style="font-family:Arial,sans-serif"><h2>دخول مهامي</h2><p>رمز التحقق الخاص بك:</p><div style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</div><p>ينتهي خلال 10 دقائق.</p></div>`});return res.json({ok:true});}catch(error){pendingEmailOtps.delete(email);console.error(error);return res.status(500).json({error:'تعذر إرسال رسالة التحقق'});}
});
app.post('/api/auth/email/verify', (req,res)=>{
  const email=normalizeEmail(req.body?.email), code=cleanText(req.body?.code,20); const pending=pendingEmailOtps.get(email);
  if(!pending||pending.expiresAt<Date.now())return res.status(400).json({error:'رمز التحقق منتهي أو غير موجود'});
  pending.attempts+=1; if(pending.attempts>5){pendingEmailOtps.delete(email);return res.status(429).json({error:'تم تجاوز عدد محاولات التحقق. اطلب رمزًا جديدًا.'});}
  const hash=crypto.createHash('sha256').update(code).digest('hex'); if(hash!==pending.hash)return res.status(400).json({error:'رمز التحقق غير صحيح'});
  pendingEmailOtps.delete(email); const user=upsertAuthUser({provider:'email',subject:email,email,name:email.split('@')[0]}); const token=authTokenForUser(user); return res.json({ok:true,token,user:{studentId:user.studentId,email:user.email,name:user.name,provider:user.provider,role:user.role}});
});
app.post('/api/auth/exchange',(req,res)=>{ const code=cleanText(req.body?.code,100); const item=oneTimeAuthCodes.get(code); oneTimeAuthCodes.delete(code); if(!item||item.expiresAt<Date.now())return res.status(400).json({error:'رمز تسجيل الدخول منتهي أو غير صالح'}); const verified=verifySession(item.token); if(!verified)return res.status(400).json({error:'جلسة تسجيل الدخول غير صالحة'}); return res.json({ok:true,token:item.token,user:{studentId:verified.sub,email:verified.email||'',name:verified.name||'',provider:verified.provider||'',role:verified.role||'user'}}); });
app.get('/api/auth/me',(req,res)=>{ const session=verifySession(getBearer(req)); if(!session)return res.status(401).json({error:'الجلسة منتهية'}); return res.json({user:{studentId:session.sub,email:session.email||'',name:session.name||'',provider:session.provider||'',role:session.role||'user'}}); });

app.post('/api/session', (req, res) => {
  const auth = verifySession(getBearer(req) || req.body?.authToken);
  if (!auth?.sub) return res.status(401).json({ error: 'يجب تسجيل الدخول أولاً' });
  return res.json({ token: signSession(auth.sub,{email:auth.email||'',name:auth.name||'',provider:auth.provider||'session',role:auth.role||'user'}), expiresIn: 7 * 24 * 60 * 60 });
});


app.get('/api/usernames/check', (req, res) => {
  const username = normalizeUsername(req.query?.username);
  if (!validUsername(username)) return res.status(400).json({ available: false, error: 'اسم المستخدم غير صالح' });
  const owner = usernameStore[username];
  return res.json({ available: !owner });
});

app.post('/api/usernames/register', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const username = normalizeUsername(req.body?.username);
  if (!validUsername(username)) return res.status(400).json({ error: 'اسم المستخدم يجب أن يكون من 2 إلى 30 رمزًا إنجليزيًا/رقميًا، ويمكن استخدام _ أو . أو - فقط.' });
  const owner = usernameStore[username];
  if (owner && owner !== session.sub) return res.status(409).json({ error: 'اسم المستخدم مستخدم بالفعل، اختر اسمًا آخر.' });
  // Release previous username owned by this student only.
  for (const [key, value] of Object.entries(usernameStore)) if (value === session.sub && key !== username) delete usernameStore[key];
  usernameStore[username] = session.sub;
  writeJsonFile(USERNAME_DB_FILE, usernameStore);
  return res.json({ ok: true, username });
});

app.post('/api/profile/preferences', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const username = normalizeUsername(req.body?.username || usernameForStudent(session.sub));
  const showInLeaderboard = req.body?.showInLeaderboard !== false;
  socialPrefsStore[session.sub] = {
    username,
    displayName: cleanText(req.body?.displayName, 80) || username,
    showInLeaderboard,
    allowFriendRequests: req.body?.allowFriendRequests !== false,
    allowFollows: req.body?.allowFollows !== false,
    updatedAt: Date.now()
  };
  if (!showInLeaderboard) delete leaderboardStore[session.sub];
  writeJsonFile(SOCIAL_PREFS_DB_FILE, socialPrefsStore);
  writeJsonFile(LEADERBOARD_DB_FILE, leaderboardStore);
  return res.json({ ok: true, hidden: !showInLeaderboard });
});

app.get('/api/social/status', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const me = socialFor(session.sub);
  return res.json({
    friendsCount: me.friends.length,
    followingCount: me.following.length,
    followersCount: me.followers.length,
    incomingFriendRequests: me.incomingFriendRequests.map(studentId => ({ studentId, username: usernameForStudent(studentId) })),
    outgoingFriendRequests: me.outgoingFriendRequests.map(studentId => ({ studentId, username: usernameForStudent(studentId) }))
  });
});

app.post('/api/social/friend/request', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const targetUsername = normalizeUsername(req.body?.targetUsername);
  if (!validUsername(targetUsername)) return res.status(400).json({ error: 'اسم المستخدم غير صالح' });
  const targetId = usernameStore[targetUsername];
  if (!targetId) return res.status(404).json({ error: 'لم يتم العثور على هذا المستخدم' });
  if (targetId === session.sub) return res.status(400).json({ error: 'لا يمكنك إرسال طلب لنفسك' });
  if (!prefsFor(targetId).allowFriendRequests) return res.status(403).json({ error: 'هذا المستخدم لا يستقبل طلبات الصداقة حاليًا' });
  const me = socialFor(session.sub), target = socialFor(targetId);
  if (me.friends.includes(targetId)) return res.status(409).json({ error: 'أنتم أصدقاء بالفعل' });
  if (!me.outgoingFriendRequests.includes(targetId)) me.outgoingFriendRequests.push(targetId);
  if (!target.incomingFriendRequests.includes(session.sub)) target.incomingFriendRequests.push(session.sub);
  saveStores();
  return res.json({ ok:true, message:`تم إرسال طلب صداقة إلى ${targetUsername}.` });
});

app.post('/api/social/friend/respond', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const senderId = cleanText(req.body?.senderStudentId, 120);
  const action = req.body?.action === 'accept' ? 'accept' : 'reject';
  const me = socialFor(session.sub), sender = socialFor(senderId);
  if (!me.incomingFriendRequests.includes(senderId)) return res.status(404).json({ error: 'الطلب غير موجود' });
  me.incomingFriendRequests = me.incomingFriendRequests.filter(x=>x!==senderId);
  sender.outgoingFriendRequests = sender.outgoingFriendRequests.filter(x=>x!==session.sub);
  if (action === 'accept') {
    if (!me.friends.includes(senderId)) me.friends.push(senderId);
    if (!sender.friends.includes(session.sub)) sender.friends.push(session.sub);
  }
  saveStores();
  return res.json({ ok:true, message: action==='accept' ? 'تم قبول طلب الصداقة.' : 'تم رفض طلب الصداقة.' });
});

app.post('/api/social/follow', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const targetUsername = normalizeUsername(req.body?.targetUsername);
  if (!validUsername(targetUsername)) return res.status(400).json({ error: 'اسم المستخدم غير صالح' });
  const targetId = usernameStore[targetUsername];
  if (!targetId) return res.status(404).json({ error: 'لم يتم العثور على هذا المستخدم' });
  if (targetId === session.sub) return res.status(400).json({ error: 'لا يمكنك متابعة نفسك' });
  if (!prefsFor(targetId).allowFollows) return res.status(403).json({ error: 'هذا المستخدم لا يسمح بالمتابعة حاليًا' });
  const me = socialFor(session.sub), target = socialFor(targetId);
  if (!me.following.includes(targetId)) me.following.push(targetId);
  if (!target.followers.includes(session.sub)) target.followers.push(session.sub);
  saveStores();
  return res.json({ ok:true, message:`تمت متابعة ${targetUsername}.` });
});

app.get('/api/leaderboard', (req, res) => {
  const limit = Math.min(100, Math.max(1, Number(req.query?.limit) || 50));
  const rows = Object.values(leaderboardStore).sort((a,b)=>(Number(b.focusMinutes)||0)-(Number(a.focusMinutes)||0)).slice(0, limit);
  return res.json({ rows });
});

app.post('/api/leaderboard/report', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const prefs = prefsFor(session.sub);
  if (prefs.showInLeaderboard === false) { delete leaderboardStore[session.sub]; writeJsonFile(LEADERBOARD_DB_FILE, leaderboardStore); return res.json({ ok:true, hidden:true }); }
  const username = normalizeUsername(req.body?.username || prefs.username || 'مستخدم');
  const focusMinutes = Math.max(0, Math.min(1000000, Number(req.body?.focusMinutes)||0));
  const stageLevel = Math.max(1, Math.min(7, Number(req.body?.stageLevel)||1));
  const buildingBadge = cleanText(req.body?.buildingBadge, 80) || '🏗️ قيد البناء';
  const displayName = cleanText(req.body?.displayName, 80) || username;
  leaderboardStore[session.sub] = { studentId: session.sub, username, name: displayName, focusMinutes, stageLevel, buildingBadge, updatedAt: Date.now() };
  writeJsonFile(LEADERBOARD_DB_FILE, leaderboardStore);
  return res.json({ ok: true });
});

app.get('/api/billing/config', (_req, res) => res.json({ enabled: !!stripe && !!STRIPE_PRICE_PRO, mode: STRIPE_MODE, wallets: { applePay: true, googlePay: true } }));

app.post('/api/billing/create-checkout-session', async (req, res) => {
  try {
    const session = verifySession(getBearer(req));
    if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
    if (!stripe || !STRIPE_PRICE_PRO) return res.status(503).json({ error: 'بوابة الدفع غير مفعلة على السيرفر بعد. أضف STRIPE_SECRET_KEY و STRIPE_PRICE_PRO إلى .env.' });
    const mode = STRIPE_MODE === 'payment' ? 'payment' : 'subscription';
    const checkout = await stripe.checkout.sessions.create({
      mode,
      line_items: [{ price: STRIPE_PRICE_PRO, quantity: 1 }],
      client_reference_id: session.sub,
      success_url: `${PUBLIC_APP_URL}/?billing=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${PUBLIC_APP_URL}/?billing=cancelled`,
      metadata: { studentId: session.sub, plan: cleanText(req.body?.plan || 'pro', 40) },
      allow_promotion_codes: true,
      billing_address_collection: 'auto'
    });
    return res.json({ url: checkout.url });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: error?.message || 'تعذر إنشاء جلسة الدفع' });
  }
});

const tools = [
  {
    name: 'add_task',
    description: 'أضف مهمة جديدة للمستخدم. استخدمها عندما يطلب بوضوح إنشاء مهمة.',
    input_schema: { type: 'object', additionalProperties: false, properties: {
      title: { type: 'string' }, date: { type: 'string', description: 'YYYY-MM-DD أو اتركها فارغة لليوم' }, time: { type: 'string', description: 'HH:MM أو فارغ' }, duration: { type: 'number' }
    }, required: ['title'] }
  },
  {
    name: 'complete_task',
    description: 'أكمل مهمة موجودة. فضّل id إن كان متاحًا، وإلا استخدم عنوانًا مطابقًا.',
    input_schema: { type: 'object', additionalProperties: false, properties: { id: { type: ['string','number'] }, title: { type: 'string' } } }
  },
  {
    name: 'add_note',
    description: 'أنشئ ملاحظة جديدة للمستخدم.',
    input_schema: { type: 'object', additionalProperties: false, properties: { title: { type: 'string' }, body: { type: 'string' } }, required: ['body'] }
  },
  {
    name: 'add_expense',
    description: 'سجل مصروفًا للمستخدم.',
    input_schema: { type: 'object', additionalProperties: false, properties: { name: { type: 'string' }, amount: { type: 'number' }, category: { type: 'string' } }, required: ['name','amount'] }
  },
  {
    name: 'delete_task',
    description: 'يطلب حذف مهمة. هذا الإجراء حساس ويجب أن يعود للتطبيق كطلب تأكيد ولا ينفذ مباشرة.',
    input_schema: { type: 'object', additionalProperties: false, properties: { id: { type: ['string','number'] }, title: { type: 'string' } } }
  },
  {
    name: 'delete_note',
    description: 'يطلب حذف ملاحظة. هذا الإجراء حساس ويجب أن يعود للتطبيق كطلب تأكيد ولا ينفذ مباشرة.',
    input_schema: { type: 'object', additionalProperties: false, properties: { id: { type: ['string','number'] }, title: { type: 'string' } } }
  }
];

function buildSystem(context) {
  return `أنت المساعد الذكي الرسمي والشامل داخل تطبيق «مهامي» للطلاب. مهمتك مساعدة المستخدم في احتياجاته الأكاديمية والمالية والشخصية المرتبطة بالتطبيق بدقة واحترافية، مع أسلوب إنساني وودود.\n\n`+
`أسلوب التفاعل:\n`+
`- تحدث بعربية سعودية بسيطة وطبيعية وودودة ومشجعة، وبشكل مباشر من غير حشو أو مبالغة.\n`+
`- نظّم الرد عند الحاجة باستخدام عناوين قصيرة، نقاط، خطوات، أو جداول نصية بسيطة لتكون القراءة سريعة وواضحة.\n`+
`- إذا احتاج المستخدم شرحًا، اشرح ثم أعطِ مثالًا عمليًا قصيرًا عند فائدته.\n`+
`- لا تدّعي تنفيذ شيء لم يتم تنفيذه فعليًا من خلال أداة أو من التطبيق.\n\n`+
`نطاق المعرفة والوصول:\n`+
`- اعتبر بيانات <student_data> هي بيانات المستخدم الحالية التي يزوّدك بها التطبيق، ويمكنك تحليلها والربط بينها والإجابة عن الأسئلة المتعلقة بها.\n`+
`- عند وجود صورة أو PDF مرفق في الطلب، اقرأ محتواه واستخرج منه النص والمعلومات والتمارين والنقاط المهمة قبل الإجابة.\n`+
`- لا تخترع بيانات غير موجودة في سياق الطالب، وإذا كانت معلومة أساسية ناقصة فاذكر ذلك بوضوح واسأل عند الحاجة.\n`+
`- لا تطلب مفاتيح API أو أسرار الخادم أو كلمات المرور.\n\n`+
`المهام الأكاديمية والتعليمية:\n`+
`- ساعد الطلاب من المرحلة المتوسطة والثانوية والجامعة والخريجين، وفي مختلف التخصصات والمواد.\n`+
`- لخّص الدروس والمحاضرات والملفات، واستخرج الأفكار الرئيسية، التعريفات، القوانين، المصطلحات، والأسئلة المتوقعة.\n`+
`- حوّل المحتوى عند الطلب إلى نقاط حفظ سريعة، خطوات، أسئلة وأجوبة، أو خريطة ذهنية نصية.\n`+
`- اشرح الواجبات والمسائل والقواعد والمصطلحات المعقدة بطريقة مبسطة ومتدرجة حسب مستوى الطالب.\n`+
`- عند وجود سؤال دراسي من صورة أو PDF: اقرأه أولًا، ثم حدّد المطلوب، ثم اشرح الحل أو الفكرة بوضوح.\n\n`+
`الإدارة المالية داخل التطبيق:\n`+
`- ساعد في تسجيل المصروفات اليومية وتصنيفها حسب نوعها مثل دراسة، مواصلات، شخصي وغيرها.\n`+
`- استخدم بيانات المصروفات الحالية لإعطاء مجموعات وتقارير وملخصات عند الطلب، مثل مصروف اليوم، حسب التصنيف، أو مقارنة الإنفاق بالميزانية الموجودة في السياق.\n`+
`- لا تغيّر أي مبلغ أو مصروف إلا من خلال أداة التطبيق المخصصة لذلك.\n\n`+
`إدارة بيانات التطبيق:\n`+
`- استخدم الأدوات عندما يريد المستخدم بوضوح إنشاء مهمة، إكمال مهمة، إضافة ملاحظة، أو تسجيل مصروف.\n`+
`- عند عرض مهام اليوم أو الإحصائيات أو المصروفات، اعتمد على البيانات الحالية داخل <student_data> ولا تتوقع أرقامًا من عندك.\n`+
`- عند وجود أكثر من عنصر متشابه، استخدم المعرّف إن كان متاحًا أو اطلب توضيحًا قبل التغيير.\n`+
`- حذف مهمة أو ملاحظة إجراء حساس: استخدم أداة الحذف فقط لإرجاع طلب تأكيد للتطبيق، ولا تنفذ الحذف مباشرة.\n`+
`- إذا كان الطلب غامضًا بطريقة قد تؤدي إلى تعديل خاطئ للبيانات، اسأل سؤالًا واحدًا واضحًا بدل التخمين.\n\n`+
`القاعدة الأساسية: كن مساعدًا عمليًا ودقيقًا، واستفد من كل البيانات الحالية التي أرسلها التطبيق وكل محتوى المرفق في الطلب، مع الحفاظ على حدود الأدوات والصلاحيات السابقة.\n\n`+
`<student_data>${JSON.stringify(context)}</student_data>`;
}

function fileBlock(file) {
  if (!file) return null;
  const data = file.buffer.toString('base64');
  if (file.mimetype === 'application/pdf') {
    return { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data } };
  }
  return { type: 'image', source: { type: 'base64', media_type: file.mimetype, data } };
}


app.post('/api/support/tickets', ticketUpload.single('image'), (req, res) => {
  try {
    const session = verifySession(getBearer(req));
    if (!session) return res.status(401).json({ error: 'جلسة الدعم غير صالحة' });
    const subject = cleanText(req.body?.subject, 120);
    const details = cleanText(req.body?.details, 5000);
    if (!subject || !details) return res.status(400).json({ error: 'عنوان المشكلة والتفاصيل مطلوبان.' });
    const id = crypto.randomUUID();
    const ticketNumber = makeTicketNumber();
    let attachment = null;
    if (req.file) {
      const filename = `${id}.${safeFileExt(req.file.mimetype)}`;
      fs.writeFileSync(path.join(SUPPORT_ATTACHMENTS_DIR, filename), req.file.buffer);
      attachment = { filename, mimeType: req.file.mimetype, size: req.file.size };
    }
    supportTicketsStore[id] = {
      id, ticketNumber, studentId: session.sub, subject, details,
      status: 'قيد المعالجة', priority: 'عادية', attachment,
      clientVersion: cleanText(req.body?.clientVersion, 40) || 'غير معروف',
      page: cleanText(req.body?.page, 80) || 'settings',
      createdAt: Date.now(), updatedAt: Date.now()
    };
    saveSupportTickets();
    return res.json({ ok: true, ticket: { id, ticketNumber, subject, details, status: 'قيد المعالجة', attachment: !!attachment, createdAt: supportTicketsStore[id].createdAt } });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'تعذر حفظ تذكرة الدعم' });
  }
});

app.get('/api/support/tickets', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'جلسة الدعم غير صالحة' });
  const tickets = Object.values(supportTicketsStore)
    .filter(t => t.studentId === session.sub)
    .sort((a,b) => b.createdAt - a.createdAt)
    .slice(0, 50)
    .map(({id,ticketNumber,subject,details,status,priority,attachment,createdAt,updatedAt}) => ({id,ticketNumber,subject,details,status,priority,attachment:!!attachment,createdAt,updatedAt}));
  return res.json({ tickets });
});

app.get('/api/support/tickets/:id/attachment', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'جلسة الدعم غير صالحة' });
  const ticket = ticketFor(cleanText(req.params.id, 80));
  if (!ticket || ticket.studentId !== session.sub || !ticket.attachment) return res.status(404).json({ error: 'المرفق غير موجود' });
  return res.type(ticket.attachment.mimeType).sendFile(path.resolve(path.join(SUPPORT_ATTACHMENTS_DIR, ticket.attachment.filename)));
});

app.post('/api/assistant', upload.single('file'), async (req, res) => {
  try {
    const session = verifySession(getBearer(req));
    if (!session) return res.status(401).json({ error: 'جلسة المساعد غير صالحة أو منتهية' });

    const message = cleanText(req.body?.message, 6000);
    const context = JSON.parse(req.body?.context || '{}');
    if (context.studentId !== session.sub) return res.status(403).json({ error: 'هوية الطالب لا تطابق الجلسة الحالية' });
    if (!message && !req.file) return res.status(400).json({ error: 'اكتب طلبك أو أرفق ملفًا' });

    const content = [];
    const attachment = fileBlock(req.file);
    if (attachment) content.push(attachment);
    content.push({ type: 'text', text: message || 'اشرح لي المرفق، لخّصه، واستخرج أهم النقاط والواجبات منه.' });

    const response = await anthropic.messages.create({
      model: MODEL,
      max_tokens: 1800,
      system: buildSystem(context),
      tools,
      tool_choice: { type: 'auto' },
      messages: [{ role: 'user', content }]
    });

    const textParts = response.content.filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
    const toolUse = response.content.find(b => b.type === 'tool_use');

    if (toolUse) {
      if (toolUse.name === 'delete_task' || toolUse.name === 'delete_note') {
        return res.json({ reply: textParts || 'هذا الإجراء يحتاج تأكيدك قبل الحذف.', confirmation: { type: toolUse.name, ...toolUse.input } });
      }
      return res.json({ reply: textParts || 'تمام، بنفذها لك الآن.', action: { type: toolUse.name, ...toolUse.input } });
    }

    return res.json({ reply: textParts || 'أكيد 👍 قل لي وش تبغى أسوي.' });
  } catch (error) {
    console.error(error);
    const message = error?.message || 'تعذر تشغيل المساعد';
    return res.status(500).json({ error: message });
  }
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'الملف المرفق أكبر من الحد المسموح.' });
  if (err?.message) return res.status(400).json({ error: err.message });
  return res.status(500).json({ error: 'خطأ غير متوقع في السيرفر' });
});

app.listen(PORT, () => console.log(`Mahami Claude server running on http://localhost:${PORT} using ${MODEL}`));
