const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const JWT_SECRET = process.env.JWT_SECRET;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('sslmode=require') ? undefined : { rejectUnauthorized: false },
  max: Number(process.env.DB_POOL_MAX || 5),
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 8000
});

const DEFAULT_CATEGORIES = [
  ['Culture générale','🧠'],['Histoire','📜'],['Science','🔬'],['Sport','⚽'],
  ['Géographie','🌍'],['Musique','🎵'],['Technologie','💻'],['Haïti','🇭🇹']
];
const SETTINGS_DEFAULTS = { timerPerQuestion: 15, questionsPerQuiz: 5 };
let initPromise;
let bootstrapCache = { at: 0, data: null };
const rateBuckets = new Map();

function json(res,status,data){res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify(data));}
function cors(req,res){
  const configured=(process.env.CORS_ORIGIN||'*').split(',').map(x=>x.trim()).filter(Boolean);
  const origin=req.headers.origin;
  const allow=configured.includes('*')?'*':(origin&&configured.includes(origin)?origin:configured[0]||'*');
  res.setHeader('Access-Control-Allow-Origin',allow); res.setHeader('Vary','Origin');
  res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization, X-Client-Version, X-Quiz-Id');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Cache-Control','no-store');
}
function body(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>8e6){reject(Object.assign(new Error('Payload too large'),{status:413}));req.destroy();}});req.on('end',()=>{try{resolve(s?JSON.parse(s):{});}catch{reject(Object.assign(new Error('JSON invalide'),{status:400}));}});req.on('error',reject);});}
async function query(sql,args=[]){return pool.query(sql,args);}
function fail(message,status){throw Object.assign(new Error(message),{status});}
function clientIp(req){return String(req.headers['x-forwarded-for']||req.socket?.remoteAddress||'unknown').split(',')[0].trim();}
function rateLimit(req,key,limit,windowMs){
  const k=key+':'+clientIp(req), now=Date.now(); let b=rateBuckets.get(k);
  if(!b||now>b.reset){b={count:0,reset:now+windowMs};rateBuckets.set(k,b)}
  b.count++; if(b.count>limit)fail('Trop de tentatives. Réessaie plus tard.',429);
}

async function init(){
  if(initPromise)return initPromise;
  initPromise=(async()=>{
    if(!process.env.DATABASE_URL)fail('DATABASE_URL manquant',500);
    if(!JWT_SECRET)fail('JWT_SECRET manquant',500);
    const statements=[
      `CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY,pseudo TEXT NOT NULL,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin','owner')),verified BOOLEAN NOT NULL DEFAULT FALSE,banned BOOLEAN NOT NULL DEFAULT FALSE,coins INTEGER NOT NULL DEFAULT 0,points INTEGER NOT NULL DEFAULT 0,quiz_count INTEGER NOT NULL DEFAULT 0,total_correct INTEGER NOT NULL DEFAULT 0,total_answered INTEGER NOT NULL DEFAULT 0,streak INTEGER NOT NULL DEFAULT 0,best_streak INTEGER NOT NULL DEFAULT 0,last_play_date TEXT NOT NULL DEFAULT '',state JSONB NOT NULL DEFAULT '{}'::jsonb,last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
      `CREATE TABLE IF NOT EXISTS categories (id BIGSERIAL PRIMARY KEY,name TEXT UNIQUE NOT NULL,icon TEXT NOT NULL DEFAULT '📚',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
      `CREATE TABLE IF NOT EXISTS questions (id BIGSERIAL PRIMARY KEY,category TEXT NOT NULL,question TEXT NOT NULL,answers JSONB NOT NULL,correct INTEGER NOT NULL CHECK(correct BETWEEN 0 AND 3),explanation TEXT NOT NULL DEFAULT '',difficulty TEXT NOT NULL DEFAULT 'Moyen',knowledge_key TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(category,question))`,
      `CREATE TABLE IF NOT EXISTS quiz_results (id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,category TEXT NOT NULL,score INTEGER NOT NULL,total INTEGER NOT NULL,points INTEGER NOT NULL DEFAULT 0,accuracy INTEGER NOT NULL DEFAULT 0,duration_seconds INTEGER NOT NULL DEFAULT 0,answers JSONB NOT NULL DEFAULT '[]'::jsonb,client_quiz_id TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
      `CREATE UNIQUE INDEX IF NOT EXISTS uq_quiz_client ON quiz_results(user_id,client_quiz_id) WHERE client_quiz_id IS NOT NULL`,
      `CREATE TABLE IF NOT EXISTS audit_logs (id BIGSERIAL PRIMARY KEY,actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,action TEXT NOT NULL,target_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,details JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
      `CREATE TABLE IF NOT EXISTS auth_codes (id BIGSERIAL PRIMARY KEY,email TEXT NOT NULL,kind TEXT NOT NULL,code_hash TEXT NOT NULL,challenge_id TEXT,expires_at TIMESTAMPTZ NOT NULL,used BOOLEAN NOT NULL DEFAULT FALSE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
      `CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY,value JSONB NOT NULL)`,
      `CREATE INDEX IF NOT EXISTS idx_users_last_seen ON users(last_seen_at)`,
      `CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)`,
      `CREATE INDEX IF NOT EXISTS idx_questions_category ON questions(category)`,
      `CREATE INDEX IF NOT EXISTS idx_quiz_user ON quiz_results(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_auth_codes_challenge ON auth_codes(challenge_id)`
    ];
    for(const s of statements)await query(s);
    // Safe migrations for an already-created database.
    await query(`ALTER TABLE quiz_results ADD COLUMN IF NOT EXISTS client_quiz_id TEXT`);
    await query(`ALTER TABLE auth_codes ADD COLUMN IF NOT EXISTS challenge_id TEXT`);
    for(const [name,icon] of DEFAULT_CATEGORIES)await query('INSERT INTO categories(name,icon) VALUES($1,$2) ON CONFLICT(name) DO NOTHING',[name,icon]);
    await query(`INSERT INTO app_settings(key,value) VALUES('quiz', $1) ON CONFLICT(key) DO NOTHING`,[JSON.stringify(SETTINGS_DEFAULTS)]);
    const ownerId=process.env.ADMIN_ID||'brainmaster_owner';
    const email=(process.env.ADMIN_EMAIL||'').trim().toLowerCase();
    const pass=process.env.ADMIN_PASSWORD||'';
    if(!email||!pass)fail('ADMIN_EMAIL et ADMIN_PASSWORD sont requis',500);
    const hash=await bcrypt.hash(pass,12);
    await query(`INSERT INTO users(pseudo,email,password_hash,role,verified) VALUES($1,$2,$3,'owner',TRUE) ON CONFLICT(email) DO UPDATE SET pseudo=$1,role='owner',verified=TRUE,updated_at=NOW()`,[ownerId,email,hash]);
  })();
  return initPromise;
}
function tokenFor(user){return jwt.sign({sub:String(user.id),role:user.role,email:user.email},JWT_SECRET,{expiresIn:'7d'});}
async function auth(req){
  const h=req.headers.authorization||''; if(!h.startsWith('Bearer '))fail('Authentification requise',401);
  let p;try{p=jwt.verify(h.slice(7),JWT_SECRET)}catch{fail('Token invalide ou expiré',401)}
  const r=await query('SELECT * FROM users WHERE id=$1',[p.sub]); const u=r.rows[0]; if(!u)fail('Utilisateur introuvable',401); if(u.banned)fail('Compte suspendu',403);
  await query('UPDATE users SET last_seen_at=NOW(),updated_at=NOW() WHERE id=$1',[u.id]); return u;
}
function adminOnly(u){if(!['admin','owner'].includes(u.role))fail('Accès admin refusé',403)}
function ownerOnly(u){if(u.role!=='owner')fail('Seul le propriétaire peut gérer les administrateurs',403)}
function cleanUser(u){const active=(Date.now()-new Date(u.last_seen_at).getTime())<5*60*1000;return {id:u.id,pseudo:u.pseudo,email:u.email,role:u.role,verified:u.verified,banned:u.banned,coins:u.coins,points:u.points,quizCount:u.quiz_count,totalCorrect:u.total_correct,totalAnswered:u.total_answered,streak:u.streak,bestStreak:u.best_streak,lastPlayDate:u.last_play_date,lastSeenAt:u.last_seen_at,active,createdAt:u.created_at};}
function mailer(){const {SMTP_HOST,SMTP_USER,SMTP_PASS}=process.env;if(!SMTP_HOST||!SMTP_USER||!SMTP_PASS)return null;return nodemailer.createTransport({host:SMTP_HOST,port:Number(process.env.SMTP_PORT||465),secure:String(process.env.SMTP_SECURE||'true')==='true',auth:{user:SMTP_USER,pass:SMTP_PASS}})}
async function sendCode(email,code,subject){const t=mailer();if(!t)return false;await t.sendMail({from:process.env.SMTP_FROM||process.env.SMTP_USER,to:email,subject,html:`<div style="font-family:Arial"><h2>🧠 BrainMaster</h2><p>Ton code de sécurité :</p><p style="font-size:30px;font-weight:800;letter-spacing:8px">${code}</p><p>Valide pendant 10 minutes.</p></div>`});return true}
function randomId(){return require('crypto').randomBytes(18).toString('hex')}
async function createCode(email,kind,challengeId=null){const code=String(Math.floor(100000+Math.random()*900000));const hash=await bcrypt.hash(code,10);await query('UPDATE auth_codes SET used=TRUE WHERE email=$1 AND kind=$2 AND used=FALSE',[email,kind]);await query('INSERT INTO auth_codes(email,kind,code_hash,challenge_id,expires_at) VALUES($1,$2,$3,$4,NOW()+INTERVAL \'10 minutes\')',[email,kind,hash,challengeId]);return code}
async function consumeCode(email,kind,code,challengeId=null){const args=[email,kind];let sql='SELECT * FROM auth_codes WHERE email=$1 AND kind=$2 AND used=FALSE AND expires_at>NOW()';if(challengeId){sql+=' AND challenge_id=$3';args.push(challengeId)}sql+=' ORDER BY id DESC LIMIT 1';const r=await query(sql,args);if(!r.rows[0]||!(await bcrypt.compare(String(code),r.rows[0].code_hash)))fail('Code incorrect ou expiré',400);await query('UPDATE auth_codes SET used=TRUE WHERE id=$1',[r.rows[0].id]);return r.rows[0];}
async function getSettings(){const r=await query("SELECT value FROM app_settings WHERE key='quiz'");return {...SETTINGS_DEFAULTS,...(r.rows[0]?.value||{})}}
async function getBootstrap(){if(bootstrapCache.data&&Date.now()-bootstrapCache.at<15000)return bootstrapCache.data;const [cats,qs,settings]=await Promise.all([query('SELECT name,icon FROM categories ORDER BY id'),query('SELECT id,category,question,answers,correct,explanation,difficulty,knowledge_key AS "knowledgeKey" FROM questions ORDER BY id'),getSettings()]);const data={categories:cats.rows,settings,questions:qs.rows};bootstrapCache={at:Date.now(),data};return data}

async function route(req,res){
  await init(); const url=new URL(req.url,'http://localhost'); const path=url.pathname.replace(/\/+$/,'')||'/'; const method=req.method;
  if(method==='GET'&&path==='/')return json(res,200,{ok:true,name:'BrainMaster API',version:'1.1.0',health:'/api/health'});
  if(method==='GET'&&path==='/api')return json(res,200,{ok:true,name:'BrainMaster API',health:'/api/health'});
  if(method==='GET'&&path==='/api/health')return json(res,200,{ok:true,service:'BrainMaster API',time:new Date().toISOString()});
  if(method==='GET'&&path==='/api/bootstrap')return json(res,200,await getBootstrap());

  if(method==='POST'&&path==='/api/auth/register'){
    rateLimit(req,'register',10,15*60*1000);const b=await body(req),pseudo=String(b.pseudo||'').trim(),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');
    if(pseudo.length<2||pseudo.length>40||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<8)fail('Données de compte invalides',400);
    if((await query('SELECT id FROM users WHERE email=$1',[email])).rows[0])fail('Email déjà utilisé',409);
    const hash=await bcrypt.hash(password,12);await query('INSERT INTO users(pseudo,email,password_hash,verified) VALUES($1,$2,$3,FALSE)',[pseudo,email,hash]);const code=await createCode(email,'email_verify');const sent=await sendCode(email,code,'✉️ BrainMaster — Vérification email');return json(res,201,{ok:true,requiresVerification:true,sent,devCode:sent?undefined:code});
  }
  if(method==='POST'&&path==='/api/auth/verify-email'){
    rateLimit(req,'verify-email',20,15*60*1000);const b=await body(req),email=String(b.email||'').trim().toLowerCase();await consumeCode(email,'email_verify',b.code);const r=await query('UPDATE users SET verified=TRUE,last_seen_at=NOW(),updated_at=NOW() WHERE email=$1 RETURNING *',[email]);if(!r.rows[0])fail('Utilisateur introuvable',404);return json(res,200,{token:tokenFor(r.rows[0]),user:cleanUser(r.rows[0])});
  }
  if(method==='POST'&&path==='/api/auth/resend-verification'){
    rateLimit(req,'resend-verification',5,15*60*1000);const b=await body(req),email=String(b.email||'').trim().toLowerCase();const u=(await query('SELECT * FROM users WHERE email=$1',[email])).rows[0];if(!u)fail('Utilisateur introuvable',404);if(u.verified)return json(res,200,{ok:true});const code=await createCode(email,'email_verify');const sent=await sendCode(email,code,'✉️ BrainMaster — Nouveau code');return json(res,200,{ok:true,sent,devCode:sent?undefined:code});
  }
  if(method==='POST'&&path==='/api/auth/login'){
    rateLimit(req,'login',20,15*60*1000);const b=await body(req),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');const u=(await query('SELECT * FROM users WHERE email=$1',[email])).rows[0];if(!u||!(await bcrypt.compare(password,u.password_hash)))fail('Email ou mot de passe incorrect',401);if(u.banned)fail('Compte suspendu',403);if(!u.verified)return json(res,403,{error:'Email non vérifié',requiresVerification:true});await query('UPDATE users SET last_seen_at=NOW() WHERE id=$1',[u.id]);return json(res,200,{token:tokenFor(u),user:cleanUser(u)});
  }
  if(method==='POST'&&path==='/api/auth/forgot-password'){
    rateLimit(req,'forgot',5,15*60*1000);const b=await body(req),email=String(b.email||'').trim().toLowerCase();const u=(await query('SELECT id FROM users WHERE email=$1',[email])).rows[0];if(u){const code=await createCode(email,'password_reset');await sendCode(email,code,'🔐 BrainMaster — Réinitialisation');}return json(res,200,{ok:true});
  }
  if(method==='POST'&&path==='/api/auth/reset-password'){
    rateLimit(req,'reset',10,15*60*1000);const b=await body(req),email=String(b.email||'').trim().toLowerCase();await consumeCode(email,'password_reset',b.code);if(String(b.password||'').length<8)fail('Mot de passe trop court',400);const hash=await bcrypt.hash(String(b.password),12);await query('UPDATE users SET password_hash=$1,updated_at=NOW() WHERE email=$2',[hash,email]);return json(res,200,{ok:true});
  }

  if(method==='POST'&&path==='/api/admin/request-otp'){
    rateLimit(req,'admin-login',8,15*60*1000);const b=await body(req),id=String(b.id||'').trim(),password=String(b.password||'');
    const r=await query('SELECT * FROM users WHERE (LOWER(email)=LOWER($1) OR LOWER(pseudo)=LOWER($1)) AND role IN (\'admin\',\'owner\') LIMIT 1',[id]);const u=r.rows[0];if(!u||!(await bcrypt.compare(password,u.password_hash)))fail('Identifiants admin incorrects',401);const challengeId=randomId(),code=await createCode(u.email,'admin_login',challengeId),sent=await sendCode(u.email,code,'🛡️ BrainMaster — Code Admin');return json(res,200,{ok:true,challengeId,emailMasked:u.email.replace(/^(.{2}).*(@.*)$/,'$1••••$2'),sent,devCode:sent?undefined:code});
  }
  if(method==='POST'&&path==='/api/admin/verify-otp'){
    rateLimit(req,'admin-otp',10,15*60*1000);const b=await body(req),challengeId=String(b.challengeId||'').trim();if(!challengeId)fail('Challenge admin manquant',400);const r=await query('SELECT email FROM auth_codes WHERE challenge_id=$1 AND kind=\'admin_login\' ORDER BY id DESC LIMIT 1',[challengeId]);if(!r.rows[0])fail('Session OTP introuvable ou expirée',400);await consumeCode(r.rows[0].email,'admin_login',b.code,challengeId);const u=(await query('SELECT * FROM users WHERE email=$1',[r.rows[0].email])).rows[0];if(!u||!['admin','owner'].includes(u.role))fail('Compte admin introuvable',403);return json(res,200,{token:tokenFor(u),user:cleanUser(u)});
  }

  const u=await auth(req);
  if(method==='GET'&&path==='/api/me')return json(res,200,{user:cleanUser(u),state:u.state||{}});
  if(method==='PUT'&&path==='/api/me/state'){const b=await body(req);await query('UPDATE users SET state=$1,updated_at=NOW(),last_seen_at=NOW() WHERE id=$2',[JSON.stringify(b.state||{}),u.id]);return json(res,200,{ok:true});}
  if(method==='POST'&&path==='/api/quiz/complete'){
    const b=await body(req),score=Math.max(0,Number(b.score||0)),total=Math.max(0,Number(b.total||0)),points=Math.max(0,Number(b.points||0)),accuracy=Math.max(0,Math.min(100,Number(b.accuracy||0))),duration=Math.max(0,Number(b.durationSeconds||0)),clientQuizId=String(b.clientQuizId||req.headers['x-quiz-id']||'').slice(0,120)||null;
    if(total<1||total>100||score>total)fail('Résultat de quiz invalide',400);
    const client=await query('SELECT id FROM quiz_results WHERE user_id=$1 AND client_quiz_id=$2',[u.id,clientQuizId]);if(clientQuizId&&client.rows[0])return json(res,200,{ok:true,duplicate:true});
    await query('INSERT INTO quiz_results(user_id,category,score,total,points,accuracy,duration_seconds,answers,client_quiz_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[u.id,String(b.category||'').slice(0,120),score,total,points,accuracy,duration,JSON.stringify(Array.isArray(b.answers)?b.answers:[]),clientQuizId]);
    await query('UPDATE users SET quiz_count=quiz_count+1,total_correct=total_correct+$1,total_answered=total_answered+$2,points=points+$3,updated_at=NOW(),last_seen_at=NOW() WHERE id=$4',[score,total,points,u.id]);return json(res,200,{ok:true});
  }

  if(path==='/api/admin/password'&&method==='POST'){adminOnly(u);const b=await body(req);if(!(await bcrypt.compare(String(b.currentPassword||''),u.password_hash)))fail('Mot de passe actuel incorrect',400);if(String(b.newPassword||'').length<8)fail('Nouveau mot de passe trop court',400);const hash=await bcrypt.hash(String(b.newPassword),12);await query('UPDATE users SET password_hash=$1,updated_at=NOW() WHERE id=$2',[hash,u.id]);return json(res,200,{ok:true});}
  if(path==='/api/admin/stats'&&method==='GET'){adminOnly(u);const [a,b,c,d]=await Promise.all([query('SELECT COUNT(*)::int n FROM categories'),query('SELECT COUNT(*)::int n FROM questions'),query('SELECT COUNT(*)::int n FROM users'),query('SELECT COUNT(*)::int n FROM quiz_results')]);return json(res,200,{categories:a.rows[0].n,questions:b.rows[0].n,users:c.rows[0].n,quizzes:d.rows[0].n});}
  if(path==='/api/admin/users'&&method==='GET'){
    adminOnly(u);const page=Math.max(1,Number(url.searchParams.get('page')||1)),limit=Math.min(200,Math.max(1,Number(url.searchParams.get('limit')||100))),offset=(page-1)*limit;const r=await query('SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2',[limit,offset]);const count=await query('SELECT COUNT(*)::int n FROM users');return json(res,200,{users:r.rows.map(cleanUser),page,limit,total:count.rows[0].n});
  }
  if(path.startsWith('/api/admin/users/')&&method==='PATCH'){
    adminOnly(u);ownerOnly(u);const id=path.split('/').pop(),b=await body(req),role=String(b.role||'user');if(!['user','admin'].includes(role))fail('Rôle invalide',400);const target=(await query('SELECT * FROM users WHERE id=$1',[id])).rows[0];if(!target)fail('Utilisateur introuvable',404);if(target.role==='owner')fail('Le owner ne peut pas être modifié ici',403);await query('UPDATE users SET role=$1,updated_at=NOW() WHERE id=$2',[role,id]);await query('INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES($1,$2,$3,$4)',[u.id,role==='admin'?'PROMOTE_ADMIN':'DEMOTE_ADMIN',id,JSON.stringify({role})]);return json(res,200,{ok:true,user:cleanUser((await query('SELECT * FROM users WHERE id=$1',[id])).rows[0])});
  }
  if(path.startsWith('/api/admin/users/')&&method==='DELETE'){
    adminOnly(u);ownerOnly(u);const id=path.split('/').pop();if(String(id)===String(u.id))fail('Impossible de supprimer ton propre compte',400);const target=(await query('SELECT * FROM users WHERE id=$1',[id])).rows[0];if(!target)fail('Utilisateur introuvable',404);if(target.role==='owner')fail('Impossible de supprimer le owner',403);await query('DELETE FROM users WHERE id=$1',[id]);return json(res,200,{ok:true});
  }
  if(path==='/api/admin/active-users'&&method==='GET'){adminOnly(u);const r=await query('SELECT * FROM users ORDER BY last_seen_at DESC LIMIT 500');return json(res,200,{users:r.rows.map(cleanUser)});}
  if(path==='/api/admin/data'&&method==='GET'){adminOnly(u);return json(res,200,await getBootstrap());}
  if(path==='/api/admin/data'&&method==='PUT'){
    adminOnly(u);const b=await body(req);
    if(Array.isArray(b.categories))for(const c of b.categories)if(c?.name)await query('INSERT INTO categories(name,icon) VALUES($1,$2) ON CONFLICT(name) DO UPDATE SET icon=EXCLUDED.icon',[String(c.name).slice(0,120),String(c.icon||'📚').slice(0,8)]);
    if(b.settings){const settings={timerPerQuestion:Math.min(60,Math.max(5,Number(b.settings.timerPerQuestion||15))),questionsPerQuiz:Math.min(30,Math.max(5,Number(b.settings.questionsPerQuiz||5)))};await query(`INSERT INTO app_settings(key,value) VALUES('quiz',$1) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`,[JSON.stringify(settings)]);}
    if(Array.isArray(b.questions)){
      for(const q of b.questions){if(!q?.category||!q?.question||!Array.isArray(q.answers)||q.answers.length!==4||!Number.isInteger(Number(q.correct))||Number(q.correct)<0||Number(q.correct)>3)continue;
        await query(`INSERT INTO questions(category,question,answers,correct,explanation,difficulty,knowledge_key) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(category,question) DO UPDATE SET answers=EXCLUDED.answers,correct=EXCLUDED.correct,explanation=EXCLUDED.explanation,difficulty=EXCLUDED.difficulty,knowledge_key=EXCLUDED.knowledge_key,updated_at=NOW()`,[String(q.category).slice(0,120),String(q.question).slice(0,1000),JSON.stringify(q.answers),Number(q.correct),String(q.explanation||'').slice(0,2000),String(q.difficulty||'Moyen').slice(0,30),String(q.knowledgeKey||'').slice(0,500)||null]);
      }
    }
    bootstrapCache={at:0,data:null};return json(res,200,{ok:true});
  }
  return json(res,404,{error:'Route introuvable',path});
}

module.exports=async function handler(req,res){cors(req,res);if(req.method==='OPTIONS')return json(res,204,{});try{await route(req,res)}catch(e){console.error(e);json(res,e.status||500,{error:e.message||'Erreur serveur'})}};
