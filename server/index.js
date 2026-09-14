import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import Database from 'better-sqlite3';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import {fileURLToPath} from 'url';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const PORT=process.env.PORT||3000;
const SECRET=process.env.JWT_SECRET;
if(!SECRET || SECRET.length<32) throw new Error('Set a strong JWT_SECRET (32+ chars).');

const dataDir=path.join(__dirname,'data'); fs.mkdirSync(dataDir,{recursive:true});
const uploadDir=path.join(__dirname,'../uploads'); fs.mkdirSync(uploadDir,{recursive:true});
const db=new Database(path.join(dataDir,'site.sqlite'));
db.pragma('journal_mode=WAL');
db.exec(`CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS songs(id INTEGER PRIMARY KEY, title TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, artist TEXT NOT NULL, genre TEXT, year INTEGER, duration TEXT, cover TEXT, audio TEXT, description TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);

const adminExists=db.prepare('SELECT id FROM admins WHERE username=?').get('admin');
if(!adminExists){
  const hash=bcrypt.hashSync(process.env.ADMIN_PASSWORD||'CHANGE_ME',12);
  db.prepare('INSERT INTO admins(username,password_hash) VALUES(?,?)').run('admin',hash);
  console.log('Admin initialized. Change ADMIN_PASSWORD before production.');
}

app.use(helmet({crossOriginResourcePolicy:{policy:'cross-origin'}}));
app.use(compression());
app.use(express.json({limit:'100kb'}));
app.use(cors({origin:process.env.NODE_ENV==='production'?process.env.SITE_URL:true,credentials:true}));
app.use('/uploads',express.static(uploadDir,{maxAge:'7d',dotfiles:'deny'}));
const authLimit=rateLimit({windowMs:15*60*1000,max:8,standardHeaders:true,legacyHeaders:false});
const apiLimit=rateLimit({windowMs:60*1000,max:120,standardHeaders:true,legacyHeaders:false});

function auth(req,res,next){
  const h=req.headers.authorization||'';
  const token=h.startsWith('Bearer ')?h.slice(7):null;
  if(!token) return res.status(401).json({error:'unauthorized'});
  try{req.user=jwt.verify(token,SECRET);next()}catch{return res.status(401).json({error:'invalid_token'})}
}
function slugify(s){return s.toString().trim().toLowerCase().replace(/[^\p{L}\p{N}]+/gu,'-').replace(/(^-|-$)/g,'')+'-'+Date.now()}
const storage=multer.diskStorage({destination:uploadDir,filename:(req,file,cb)=>cb(null,Date.now()+'-'+Math.random().toString(36).slice(2)+path.extname(file.originalname).toLowerCase())});
const upload=multer({storage,limits:{fileSize:80*1024*1024},fileFilter:(req,file,cb)=>{
  const okAudio=['audio/mpeg','audio/mp4','audio/wav','audio/ogg','audio/x-m4a'].includes(file.mimetype);
  const okImage=['image/jpeg','image/png','image/webp'].includes(file.mimetype);
  cb(null,okAudio||okImage);
}});

app.post('/api/auth/login',authLimit,(req,res)=>{
  const {username,password}=req.body||{};
  const admin=db.prepare('SELECT * FROM admins WHERE username=?').get(username||'');
  if(!admin||!bcrypt.compareSync(password||'',admin.password_hash)) return res.status(401).json({error:'نام کاربری یا رمز عبور نادرست است'});
  const token=jwt.sign({id:admin.id,username:admin.username},SECRET,{expiresIn:'2h'});
  res.json({token});
});

app.get('/api/songs',apiLimit,(req,res)=>{
  const q=(req.query.q||'').trim(); const genre=(req.query.genre||'').trim();
  let rows=db.prepare(`SELECT * FROM songs WHERE (?='' OR title LIKE ? OR artist LIKE ?) AND (?='' OR genre=?) ORDER BY id DESC`).all(q,`%${q}%`,`%${q}%`,genre,genre);
  res.json(rows);
});
app.get('/api/songs/:slug',(req,res)=>{
  const row=db.prepare('SELECT * FROM songs WHERE slug=?').get(req.params.slug);
  if(!row)return res.status(404).json({error:'not_found'}); res.json(row);
});
app.post('/api/songs',auth,upload.fields([{name:'audio',maxCount:1},{name:'cover',maxCount:1}]),(req,res)=>{
  const {title,artist,genre,year,duration,description}=req.body;
  if(!title||!artist)return res.status(400).json({error:'title_and_artist_required'});
  const audio=req.files?.audio?.[0]?.filename||null, cover=req.files?.cover?.[0]?.filename||null;
  const slug=slugify(title);
  const info=db.prepare(`INSERT INTO songs(title,slug,artist,genre,year,duration,cover,audio,description) VALUES(?,?,?,?,?,?,?,?,?)`).run(title,slug,artist,genre||'',year||null,duration||'',cover,audio,description||'');
  res.status(201).json(db.prepare('SELECT * FROM songs WHERE id=?').get(info.lastInsertRowid));
});
app.put('/api/songs/:id',auth,upload.fields([{name:'audio',maxCount:1},{name:'cover',maxCount:1}]),(req,res)=>{
  const old=db.prepare('SELECT * FROM songs WHERE id=?').get(req.params.id);
  if(!old)return res.status(404).json({error:'not_found'});
  const b=req.body; const audio=req.files?.audio?.[0]?.filename||old.audio; const cover=req.files?.cover?.[0]?.filename||old.cover;
  db.prepare(`UPDATE songs SET title=?,artist=?,genre=?,year=?,duration=?,cover=?,audio=?,description=? WHERE id=?`).run(b.title||old.title,b.artist||old.artist,b.genre||'',b.year||null,b.duration||'',cover,audio,b.description||'',old.id);
  res.json(db.prepare('SELECT * FROM songs WHERE id=?').get(old.id));
});
app.delete('/api/songs/:id',auth,(req,res)=>{const r=db.prepare('DELETE FROM songs WHERE id=?').run(req.params.id);res.json({ok:r.changes>0})});

app.get('/robots.txt',(req,res)=>{res.type('text/plain').send(`User-agent: *\nAllow: /\nDisallow: /admin\nSitemap: ${(process.env.SITE_URL||'http://localhost:'+PORT)}/sitemap.xml`)});
app.get('/sitemap.xml',(req,res)=>{
  const base=process.env.SITE_URL||`http://localhost:${PORT}`;
  const rows=db.prepare('SELECT slug,created_at FROM songs ORDER BY id DESC').all();
  const urls=[`${base}/`,'/songs'].map(x=>x.startsWith('http')?x:base+x).concat(rows.map(r=>`${base}/song/${encodeURIComponent(r.slug)}`));
  res.type('application/xml').send('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+urls.map(u=>`<url><loc>${u}</loc></url>`).join('')+'</urlset>');
});

const client=path.join(__dirname,'../client/dist');
if(fs.existsSync(client)){app.use(express.static(client));app.get('*',(req,res)=>res.sendFile(path.join(client,'index.html')))}
app.listen(PORT,()=>console.log(`KING TATALOO running on :${PORT}`));
