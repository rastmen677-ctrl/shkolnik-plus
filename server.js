require('dotenv').config();
const express=require('express'),path=require('path'),fs=require('fs'),crypto=require('crypto');
const bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),multer=require('multer'),cookieParser=require('cookie-parser');
const {DatabaseSync}=require('node:sqlite');   // встроенная в Node 22.5+ SQLite, без нативных модулей
const {ADMIN_LOGIN='admin',ADMIN_PASSWORD,PAYMENT_DETAILS='',PORT=3000}=process.env;
const MIN=parseInt(process.env.MIN_DEPOSIT,10)||10;
if(!ADMIN_PASSWORD||ADMIN_PASSWORD==='CHANGE_ME'){console.error('Задайте ADMIN_PASSWORD в .env (см. .env.example)');process.exit(1)}
let SECRET=process.env.JWT_SECRET;
if(!SECRET||SECRET==='CHANGE_ME'){SECRET=crypto.randomBytes(32).toString('hex');console.warn('JWT_SECRET не задан: сессии сбросятся при перезапуске')}

const db=new DatabaseSync(process.env.DB_FILE||path.join(__dirname,'data.db'));
db.exec('PRAGMA journal_mode=WAL;PRAGMA foreign_keys=ON;');
let depth=0;   // транзакции с поддержкой вложенности (SAVEPOINT)
const tx=fn=>(...a)=>{const n=depth++;db.exec(n?`SAVEPOINT s${n}`:'BEGIN IMMEDIATE');
  try{const r=fn(...a);db.exec(n?`RELEASE s${n}`:'COMMIT');return r}
  catch(e){db.exec(n?`ROLLBACK TO s${n};RELEASE s${n}`:'ROLLBACK');throw e}finally{depth--}};
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0),blocked INTEGER NOT NULL DEFAULT 0,ai_access INTEGER NOT NULL DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS deposits(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id),amount INTEGER NOT NULL CHECK(amount>0),transfer_at TEXT,payment_comment TEXT,proof_file TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',idem_key TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,reviewed_at TEXT,reviewed_by TEXT,rejection_reason TEXT,UNIQUE(user_id,idem_key));
CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,type TEXT NOT NULL,amount INTEGER NOT NULL,balance_before INTEGER NOT NULL,balance_after INTEGER NOT NULL,reference_id TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS admin_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,admin_id TEXT NOT NULL,action TEXT NOT NULL,deposit_id INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,text TEXT NOT NULL,read INTEGER NOT NULL DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,title TEXT,subject TEXT,budget INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);`);
try{db.exec('ALTER TABLE users ADD COLUMN ai_access INTEGER NOT NULL DEFAULT 0')}catch{}
for(const c of['service TEXT','description TEXT'])try{db.exec('ALTER TABLE orders ADD COLUMN '+c)}catch{}

const bad=(res,m,c=400)=>res.status(c).json({error:m});
const AI_PRICE=3999;const money=k=>k%100?(k/100).toFixed(2):String(k/100);
const aiReply=v=>/задач|реши|\d/i.test(v)?'Давай разберём по шагам:\n1) Выпиши, что дано и что нужно найти.\n2) Вспомни подходящую формулу или правило.\n3) Подставь значения и посчитай.\n4) Проверь ответ.\nПришли условие — разберём вместе, чтобы ты понял решение.':/контрольн|подготов/i.test(v)?'План подготовки: повтори теорию, реши 5–7 типовых задач, отметь ошибки и перерешай их. Какая тема?':'Объясню простыми словами: сначала главная идея, затем пример. Напиши тему — начнём!';
const notify=(uid,text)=>db.prepare('INSERT INTO notifications(user_id,text) VALUES(?,?)').run(uid,text);
const getPD=()=>{const r=db.prepare("SELECT value FROM settings WHERE key='payment_details'").get();return r?r.value:(PAYMENT_DETAILS==='CHANGE_ME'?'':PAYMENT_DETAILS)};
// Единственное место, где меняется баланс. Вызывать только на сервере, внутри транзакции.
const move=tx((uid,type,amount,ref)=>{
  const u=db.prepare('SELECT balance FROM users WHERE id=?').get(uid),after=u.balance+amount;
  if(after<0)throw new Error('NSF');
  db.prepare('UPDATE users SET balance=? WHERE id=?').run(after,uid);
  return db.prepare('INSERT INTO transactions(user_id,type,amount,balance_before,balance_after,reference_id) VALUES(?,?,?,?,?,?)').run(uid,type,amount,u.balance,after,ref).lastInsertRowid;
});

const app=express();
app.disable('x-powered-by');
if(process.env.NODE_ENV==='production')app.set('trust proxy',1);   // за Caddy/nginx: реальные IP для ограничения попыток
app.use((q,r,n)=>{r.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin'});n()});
app.use(express.json({limit:'20kb'}));app.use(cookieParser());
const ck={httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production'};
const sign=(o,exp)=>jwt.sign(o,SECRET,{expiresIn:exp});
const hits=new Map();
const limit=(max,ms)=>(req,res,next)=>{const k=req.ip+req.path,n=Date.now(),a=(hits.get(k)||[]).filter(t=>n-t<ms);if(a.length>=max)return bad(res,'Слишком много попыток, подождите',429);a.push(n);hits.set(k,a);next()};
const sha=s=>crypto.createHash('sha256').update(String(s)).digest();
const eq=(a,b)=>crypto.timingSafeEqual(sha(a),sha(b));

function user(req,res,next){let u=null;try{u=db.prepare('SELECT * FROM users WHERE id=?').get(jwt.verify(req.cookies.sess,SECRET).uid)}catch{}
  if(!u||u.blocked)return bad(res,'Требуется вход',401);req.user=u;next()}
function admin(req,res,next){let a=null;try{a=jwt.verify(req.cookies.adm,SECRET).admin}catch{}
  if(!a)return bad(res,'Требуется вход администратора',401);req.admin=a;next()}
function either(req,res,next){let a=null;try{a=jwt.verify(req.cookies.adm,SECRET).admin}catch{}
  if(a){req.admin=a;return next()}user(req,res,next)}

// ---------- пользователи ----------
app.post('/api/register',limit(10,6e5),(req,res)=>{
  const {username,email,password}=req.body||{};
  if(!/^[\wа-яёіїєґ.-]{3,24}$/i.test(username||''))return bad(res,'Имя: 3–24 символа (буквы, цифры, _ . -)');
  if(!/^\S+@\S+\.\S+$/.test(email||''))return bad(res,'Неверный email');
  if(typeof password!=='string'||password.length<8)return bad(res,'Пароль — минимум 8 символов');
  try{const r=db.prepare('INSERT INTO users(username,email,password_hash) VALUES(?,?,?)').run(username,email.toLowerCase(),bcrypt.hashSync(password,10));
    res.cookie('sess',sign({uid:r.lastInsertRowid},'7d'),{...ck,maxAge:7*864e5}).json({ok:1})}
  catch{bad(res,'Имя или email уже заняты')}});
app.post('/api/login',limit(10,6e5),(req,res)=>{
  const {username,password}=req.body||{},n=String(username||'');
  const u=db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(n,n.toLowerCase());
  if(!u||u.blocked||!bcrypt.compareSync(String(password||''),u.password_hash))return bad(res,'Неверный логин или пароль',401);
  res.cookie('sess',sign({uid:u.id},'7d'),{...ck,maxAge:7*864e5}).json({ok:1})});
app.post('/api/logout',(q,res)=>res.clearCookie('sess',ck).json({ok:1}));
app.get('/api/me',(req,res)=>{try{const u=db.prepare('SELECT * FROM users WHERE id=?').get(jwt.verify(req.cookies.sess,SECRET).uid);
  if(u&&!u.blocked)return res.json({user:u.username,balance:u.balance,min:MIN,ai:!!u.ai_access,ai_price:AI_PRICE})}catch{}res.json({user:null,min:MIN})});
app.get('/api/balance',user,(req,res)=>res.json({balance:req.user.balance}));
app.get('/api/transactions',user,(req,res)=>res.json(db.prepare("SELECT t.id,t.type,t.amount,t.balance_before,t.balance_after,t.reference_id,t.created_at,o.service AS note FROM transactions t LEFT JOIN orders o ON t.reference_id='order:'||o.id WHERE t.user_id=? ORDER BY t.id DESC LIMIT 200").all(req.user.id)));
app.get('/api/payment-details',user,(req,res)=>res.json({details:getPD()}));
app.get('/api/notifications',user,(req,res)=>res.json(db.prepare('SELECT id,text,read,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50').all(req.user.id)));
app.post('/api/notifications/read',user,(req,res)=>{db.prepare('UPDATE notifications SET read=1 WHERE user_id=?').run(req.user.id);res.json({ok:1})});

// ---------- AI Помощник (платно, 39.99 грн, проверка доступа на сервере) ----------
app.post('/api/ai/buy',user,(req,res)=>{try{tx(()=>{
  if(db.prepare('SELECT ai_access FROM users WHERE id=?').get(req.user.id).ai_access)throw new Error('HAS');
  move(req.user.id,'ai_access',-AI_PRICE,'ai');db.prepare('UPDATE users SET ai_access=1 WHERE id=?').run(req.user.id);
  notify(req.user.id,'🟢 AI Помощник подключён!')})();res.json({ok:1})}
  catch(e){e.message==='NSF'?bad(res,'Недостаточно средств — пополните баланс',402):e.message==='HAS'?bad(res,'Доступ уже куплен',409):bad(res,'Ошибка',500)}});
app.post('/api/ai/ask',user,(req,res)=>{if(!req.user.ai_access)return bad(res,'AI Помощник доступен за 39.99 грн',402);
  const q=String((req.body||{}).message||'').trim().slice(0,2000);if(!q)return bad(res,'Пустой вопрос');res.json({reply:aiReply(q)})}); // сюда можно подключить реальную модель

// ---------- заказы (оплата с баланса) ----------
const SERVICES=[   // каталог и цены (грн) — только на сервере; цена заказа считается здесь, а не на клиенте
 {id:'hw',icon:'📝',name:'Помощь с домашним заданием',tiers:[['Простое задание',10],['Среднее задание',25],['Сложное задание',50]]},
 {id:'task',icon:'🧮',name:'Решение задачи',tiers:[['Одна простая задача',10],['Несколько задач',30],['Сложная / олимпиадная',60]]},
 {id:'explain',icon:'📚',name:'Объяснение темы',tiers:[['Короткое объяснение',10],['Подробно, с примерами',25],['Разбор темы целиком',50]]},
 {id:'pres',icon:'📊',name:'Презентация',tiers:[['До 5 слайдов',10],['До 10 слайдов',30],['До 20 слайдов',60]]},
 {id:'essay',icon:'📖',name:'Реферат',tiers:[['1–2 страницы',10],['5–7 страниц',40],['10+ страниц',80]]},
 {id:'design',icon:'🎨',name:'Оформление работы',tiers:[['Простое оформление',10],['Титульный лист и оформление',20],['Полное оформление',40]]},
 {id:'code',icon:'💻',name:'Помощь с программированием',tiers:[['Небольшая правка / вопрос',10],['Задание целиком',40],['Мини-проект',90]]},
 {id:'project',icon:'🔬',name:'Помощь с проектом',tiers:[['Консультация',10],['Часть проекта',60],['Проект целиком',120]]}];
app.get('/api/services',(q,res)=>res.json(SERVICES));
app.post('/api/orders',user,(req,res)=>{
  const b=req.body||{},sv=SERVICES.find(x=>x.id===b.service),ti=Number(b.tier);
  if(!sv||!Number.isInteger(ti)||!sv.tiers[ti])return bad(res,'Выберите услугу и вариант');
  const title=String(b.title||'').trim();if(!title)return bad(res,'Укажите название');
  const price=sv.tiers[ti][1]*100;   // копейки
  try{const id=tx(()=>{
    const id=db.prepare('INSERT INTO orders(user_id,title,subject,budget,service,description) VALUES(?,?,?,?,?,?)').run(req.user.id,title.slice(0,200),String(b.subject||'').slice(0,50),price,sv.name+' — '+sv.tiers[ti][0],String(b.description||'').slice(0,3000)).lastInsertRowid;
    move(req.user.id,'order_payment',-price,'order:'+id);return id})();
    res.json({id,price:price/100})}
  catch(e){e.message==='NSF'?bad(res,'Недостаточно средств — пополните баланс',402):bad(res,'Ошибка',500)}});

// ---------- пополнения ----------
const UP=path.join(__dirname,'uploads');fs.mkdirSync(UP,{recursive:true});   // вне public — прямой ссылки нет
const EXT={'image/png':'.png','image/jpeg':'.jpg','image/webp':'.webp'};
const upload=multer({storage:multer.diskStorage({destination:UP,filename:(q,f,cb)=>cb(null,crypto.randomBytes(16).toString('hex')+EXT[f.mimetype])}),
  limits:{fileSize:5*1024*1024,files:1},fileFilter:(q,f,cb)=>EXT[f.mimetype]?cb(null,true):cb(new Error('Только PNG, JPG или WEBP'))});
const isImg=f=>{const b=Buffer.alloc(12),fd=fs.openSync(f.path,'r');fs.readSync(fd,b,0,12,0);fs.closeSync(fd);
  return (b[0]==0x89&&b.toString('latin1',1,4)==='PNG')||(b[0]==0xFF&&b[1]==0xD8&&b[2]==0xFF)||(b.toString('latin1',0,4)==='RIFF'&&b.toString('latin1',8,12)==='WEBP')};
app.post('/api/deposits',user,limit(15,6e5),upload.single('proof'),(req,res)=>{
  const f=req.file,rm=()=>f&&fs.unlink(f.path,()=>{});
  const uah=Number(req.body.amount),amount=Math.round(uah*100),key=String(req.body.idem_key||'').slice(0,64);
  if(f&&!isImg(f)){rm();return bad(res,'Файл не является изображением')}
  if(!(uah>0)||Math.abs(uah*100-amount)>1e-6||amount<MIN*100||amount>10000000){rm();return bad(res,`Минимальная сумма — ${MIN} грн`)}
  if(!key){rm();return bad(res,'Нет ключа запроса')}
  const dup=db.prepare('SELECT id FROM deposits WHERE user_id=? AND idem_key=?').get(req.user.id,key);
  if(dup){rm();return res.json({id:dup.id,duplicate:true})}                      // защита от повторной отправки
  if(db.prepare("SELECT COUNT(*) c FROM deposits WHERE user_id=? AND status='pending'").get(req.user.id).c>=5){rm();return bad(res,'Слишком много заявок на проверке')}
  const id=tx(()=>{
    const id=db.prepare('INSERT INTO deposits(user_id,amount,transfer_at,payment_comment,proof_file,idem_key) VALUES(?,?,?,?,?,?)')
      .run(req.user.id,amount,String(req.body.transfer_at||'').slice(0,40),String(req.body.comment||'').slice(0,500),f?f.filename:'',key).lastInsertRowid;
    notify(req.user.id,'🟡 Заявка на пополнение отправлена и ожидает проверки.');return id})();
  res.json({id})});
const DEP='SELECT d.id,d.user_id,u.username,d.amount,d.transfer_at,d.payment_comment,d.status,d.created_at,d.reviewed_at,d.reviewed_by,d.rejection_reason,(length(d.proof_file)>0) AS has_proof,u.balance AS user_balance FROM deposits d JOIN users u ON u.id=d.user_id';
app.get('/api/deposits',either,(req,res)=>{   // админ — все заявки, пользователь — только свои
  const st=['pending','approved','rejected'].includes(req.query.status)?req.query.status:null,w=[],a=[];
  if(!req.admin){w.push('d.user_id=?');a.push(req.user.id)}if(st){w.push('d.status=?');a.push(st)}
  res.json(db.prepare(DEP+(w.length?' WHERE '+w.join(' AND '):'')+' ORDER BY d.id DESC LIMIT 500').all(...a))});
app.get('/api/deposits/:id',either,(req,res)=>{const d=db.prepare(DEP+' WHERE d.id=?').get(req.params.id);
  if(!d||(!req.admin&&d.user_id!==req.user.id))return bad(res,'Не найдено',404);res.json(d)});
app.get('/api/deposits/:id/proof',either,(req,res)=>{const d=db.prepare('SELECT user_id,proof_file FROM deposits WHERE id=?').get(req.params.id);
  if(!d||(!req.admin&&d.user_id!==req.user.id))return bad(res,'Не найдено',404);
  if(!d.proof_file)return bad(res,'Скриншот не приложен',404);
  res.set('Cache-Control','private, no-store');res.sendFile(path.join(UP,d.proof_file))});

// ---------- админ ----------
app.post('/api/admin/login',limit(5,6e5),(req,res)=>{
  const {login,password}=req.body||{};
  if(!(eq(login,ADMIN_LOGIN)&eq(password,ADMIN_PASSWORD)))return bad(res,'Неверный логин или пароль',401);
  db.prepare('INSERT INTO admin_logs(admin_id,action) VALUES(?,?)').run(ADMIN_LOGIN,'login');
  res.cookie('adm',sign({admin:ADMIN_LOGIN},'8h'),{...ck,maxAge:8*36e5}).json({ok:1})});
app.post('/api/admin/logout',(q,res)=>res.clearCookie('adm',ck).json({ok:1}));
app.get('/api/admin/me',admin,(req,res)=>res.json({admin:req.admin}));
const review=(req,res,status)=>{
  const reason=String((req.body||{}).reason||'').trim().slice(0,300);
  if(status==='rejected'&&reason.length<3)return bad(res,'Укажите причину отклонения');
  const r=tx(()=>{
    const d=db.prepare('SELECT * FROM deposits WHERE id=?').get(req.params.id);if(!d)return{e:'Не найдено',c:404};
    // атомарно: только pending -> approved/rejected, поэтому второй раз подтвердить нельзя
    const up=db.prepare("UPDATE deposits SET status=?,reviewed_at=CURRENT_TIMESTAMP,reviewed_by=?,rejection_reason=? WHERE id=? AND status='pending'").run(status,req.admin,status==='rejected'?reason:null,d.id);
    if(!up.changes)return{e:'Заявка уже обработана',c:409};
    if(status==='approved'){move(d.user_id,'deposit',d.amount,'deposit:'+d.id);notify(d.user_id,`🟢 Ваше пополнение на ${money(d.amount)} грн успешно подтверждено. Средства зачислены на баланс.`)}
    else notify(d.user_id,`🔴 Заявка на пополнение отклонена. Причина: ${reason}`);
    db.prepare('INSERT INTO admin_logs(admin_id,action,deposit_id) VALUES(?,?,?)').run(req.admin,status==='approved'?'approve':'reject',d.id);
    return{ok:1}})();
  r.e?bad(res,r.e,r.c):res.json(r)};
app.post('/api/admin/deposits/:id/approve',admin,(q,r)=>review(q,r,'approved'));
app.post('/api/admin/deposits/:id/reject',admin,(q,r)=>review(q,r,'rejected'));
app.get('/api/admin/transactions',admin,(q,res)=>res.json(db.prepare('SELECT t.*,u.username FROM transactions t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 500').all()));
app.get('/api/admin/logs',admin,(q,res)=>res.json(db.prepare('SELECT * FROM admin_logs ORDER BY id DESC LIMIT 500').all()));
app.get('/api/admin/settings',admin,(q,res)=>res.json({payment_details:getPD()}));
app.post('/api/admin/settings',admin,(req,res)=>{
  db.prepare("INSERT INTO settings(key,value) VALUES('payment_details',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(String((req.body||{}).payment_details||'').slice(0,2000));
  db.prepare('INSERT INTO admin_logs(admin_id,action) VALUES(?,?)').run(req.admin,'update_payment_details');res.json({ok:1})});

app.get('/admin.html',(q,r)=>r.redirect('/admin'));
app.use(express.static(path.join(__dirname,'public')));
app.get('/admin',(q,r)=>r.sendFile(path.join(__dirname,'public','admin.html')));
app.use((e,req,res,next)=>{res.status(400).json({error:e.code==='LIMIT_FILE_SIZE'?'Файл больше 5 МБ':e.message||'Ошибка'})});
app.listen(PORT,()=>console.log('Школьник+: http://localhost:'+PORT));
