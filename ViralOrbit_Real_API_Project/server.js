require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const axios = require("axios");
const FormData = require("form-data");
const { google } = require("googleapis");
const OpenAI = require("openai");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_LONG_RANDOM_SECRET";
const ENC_KEY_RAW = process.env.ENCRYPTION_KEY || "CHANGE_THIS_32_BYTE_SECRET_KEY_123";
const ENC_KEY = crypto.createHash("sha256").update(ENC_KEY_RAW).digest();
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const uploadDir = path.join(__dirname, "uploads");
if(!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, {recursive:true});

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => {
    const safe = file.originalname.replace(/[^\w.\-]+/g, "_");
    cb(null, Date.now() + "_" + safe);
  }
});
const upload = multer({ storage, limits: { fileSize: 1024 * 1024 * 1024 * 2 } }); // 2GB demo limit

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN || "*"}));
app.use(express.json({ limit: "25mb" }));
app.use("/uploads", express.static(uploadDir));
app.use(express.static(path.join(__dirname, "public")));

const db = new Database(path.join(__dirname, "viralorbit.db"));
db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS platform_credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  platform TEXT UNIQUE NOT NULL,
  encrypted_json TEXT NOT NULL,
  iv TEXT NOT NULL,
  auth_tag TEXT NOT NULL,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS videos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  description TEXT,
  hashtags TEXT,
  filename TEXT NOT NULL,
  public_url TEXT,
  mime_type TEXT,
  size INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS publish_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  video_id INTEGER,
  platform TEXT,
  status TEXT,
  response_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  detail TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

function audit(action, detail=""){
  db.prepare("INSERT INTO audit_logs(action, detail) VALUES(?,?)").run(action, detail);
}

function encryptObject(obj){
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(obj), "utf8"), cipher.final()]);
  return { encrypted_json: encrypted.toString("base64"), iv: iv.toString("base64"), auth_tag: cipher.getAuthTag().toString("base64") };
}
function decryptObject(row){
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, Buffer.from(row.iv, "base64"));
  decipher.setAuthTag(Buffer.from(row.auth_tag, "base64"));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(row.encrypted_json, "base64")), decipher.final()]);
  return JSON.parse(decrypted.toString("utf8"));
}
function getCred(platform){
  const row = db.prepare("SELECT * FROM platform_credentials WHERE platform=?").get(platform);
  if(!row) throw new Error(`No saved credentials for ${platform}`);
  return decryptObject(row);
}
function auth(req, res, next){
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if(!token) return res.status(401).json({ok:false,error:"Login required"});
  try{ req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch{ return res.status(401).json({ok:false,error:"Invalid or expired session"}); }
}

async function ensureDefaultAdmin(){
  const username = process.env.ADMIN_USER || "admin";
  const password = process.env.ADMIN_PASS || "123456";
  const found = db.prepare("SELECT id FROM admins WHERE username=?").get(username);
  if(!found){
    const hash = await bcrypt.hash(password, 12);
    db.prepare("INSERT INTO admins(username,password_hash) VALUES(?,?)").run(username, hash);
    console.log(`Default admin created: ${username} / ${password}`);
  }
}
ensureDefaultAdmin();

app.post("/api/auth/login", async (req,res)=>{
  const { username, password } = req.body || {};
  const user = db.prepare("SELECT * FROM admins WHERE username=?").get(username || "");
  if(!user) { audit("login_failed", username || ""); return res.status(401).json({ok:false,error:"Invalid username or password"}); }
  const ok = await bcrypt.compare(password || "", user.password_hash);
  if(!ok){ audit("login_failed", username || ""); return res.status(401).json({ok:false,error:"Invalid username or password"}); }
  const token = jwt.sign({id:user.id, username:user.username}, JWT_SECRET, {expiresIn:"8h"});
  audit("login_success", username);
  res.json({ok:true,token});
});

app.post("/api/platforms/save", auth, (req,res)=>{
  const { platform, credentials } = req.body || {};
  const allowed = ["youtube","facebook","instagram","tiktok","openai"];
  if(!allowed.includes(platform)) return res.status(400).json({ok:false,error:"Invalid platform"});
  if(!credentials || typeof credentials !== "object") return res.status(400).json({ok:false,error:"Missing credentials"});
  const enc = encryptObject(credentials);
  db.prepare(`
    INSERT INTO platform_credentials(platform, encrypted_json, iv, auth_tag, updated_at)
    VALUES(@platform, @encrypted_json, @iv, @auth_tag, CURRENT_TIMESTAMP)
    ON CONFLICT(platform) DO UPDATE SET encrypted_json=excluded.encrypted_json, iv=excluded.iv, auth_tag=excluded.auth_tag, updated_at=CURRENT_TIMESTAMP
  `).run({platform, ...enc});
  audit("platform_save", platform);
  res.json({ok:true,message:`${platform} credentials encrypted and saved`});
});

app.post("/api/platforms/test", auth, async (req,res)=>{
  try{
    const { platform } = req.body || {};
    const cred = getCred(platform);
    if(platform === "youtube" && !cred.refresh_token) return res.status(400).json({ok:false,error:"YouTube needs OAuth refresh_token, client_id, client_secret"});
    if(platform === "facebook" && !cred.page_access_token) return res.status(400).json({ok:false,error:"Facebook needs page_access_token and page_id"});
    if(platform === "instagram" && (!cred.access_token || !cred.ig_user_id)) return res.status(400).json({ok:false,error:"Instagram needs access_token and ig_user_id"});
    if(platform === "tiktok" && !cred.access_token) return res.status(400).json({ok:false,error:"TikTok needs access_token and approved app"});
    audit("platform_test", platform);
    res.json({ok:true,message:`${platform} credential format ok ✅`});
  }catch(e){ res.status(400).json({ok:false,error:e.message}); }
});

app.post("/api/videos/upload", auth, upload.single("video"), (req,res)=>{
  if(!req.file) return res.status(400).json({ok:false,error:"No video file uploaded"});
  const { title="", description="", hashtags="" } = req.body || {};
  const publicUrl = `${BASE_URL}/uploads/${req.file.filename}`;
  const info = db.prepare(`
    INSERT INTO videos(title,description,hashtags,filename,public_url,mime_type,size)
    VALUES(?,?,?,?,?,?,?)
  `).run(title, description, hashtags, req.file.filename, publicUrl, req.file.mimetype, req.file.size);
  audit("video_upload", req.file.filename);
  res.json({ok:true,video:{id:info.lastInsertRowid,title,description,hashtags,url:publicUrl,filename:req.file.filename}});
});

async function publishYouTube(video, meta){
  const c = getCred("youtube");
  const oauth2Client = new google.auth.OAuth2(c.client_id, c.client_secret, c.redirect_uri || "http://localhost:3000/oauth2callback");
  oauth2Client.setCredentials({ refresh_token: c.refresh_token });
  const youtube = google.youtube({ version:"v3", auth: oauth2Client });
  const filePath = path.join(uploadDir, video.filename);
  const response = await youtube.videos.insert({
    part: ["snippet","status"],
    requestBody: {
      snippet: { title: meta.title || video.title || "ViralOrbit Upload", description: meta.description || video.description || "", tags: (meta.hashtags || video.hashtags || "").replace(/#/g,"").split(/\s+/).filter(Boolean) },
      status: { privacyStatus: meta.privacyStatus || "private" }
    },
    media: { body: fs.createReadStream(filePath) }
  });
  return response.data;
}

async function publishFacebook(video, meta){
  const c = getCred("facebook");
  const filePath = path.join(uploadDir, video.filename);
  const form = new FormData();
  form.append("source", fs.createReadStream(filePath));
  form.append("description", `${meta.title || video.title || ""}\n\n${meta.description || video.description || ""}\n${meta.hashtags || video.hashtags || ""}`);
  form.append("access_token", c.page_access_token);
  const url = `https://graph.facebook.com/v19.0/${c.page_id}/videos`;
  const { data } = await axios.post(url, form, { headers: form.getHeaders(), maxBodyLength: Infinity, maxContentLength: Infinity });
  return data;
}

async function publishInstagram(video, meta){
  const c = getCred("instagram");
  // Instagram reels publishing requires a public video URL accessible by Meta.
  const videoUrl = meta.videoUrl || video.public_url;
  const caption = `${meta.title || video.title || ""}\n${meta.description || video.description || ""}\n${meta.hashtags || video.hashtags || ""}`;
  const createUrl = `https://graph.facebook.com/v19.0/${c.ig_user_id}/media`;
  const create = await axios.post(createUrl, null, { params: { media_type:"REELS", video_url: videoUrl, caption, access_token: c.access_token }});
  const creationId = create.data.id;
  // In production you should poll container status before publish.
  await new Promise(r => setTimeout(r, 5000));
  const publishUrl = `https://graph.facebook.com/v19.0/${c.ig_user_id}/media_publish`;
  const publish = await axios.post(publishUrl, null, { params: { creation_id: creationId, access_token: c.access_token }});
  return publish.data;
}

async function publishTikTok(video, meta){
  const c = getCred("tiktok");
  // TikTok direct post/upload requires app approval and exact required scopes.
  // PULL_FROM_URL requires your video URL from a verified domain/prefix.
  const videoUrl = meta.videoUrl || video.public_url;
  const initUrl = "https://open.tiktokapis.com/v2/post/publish/video/init/";
  const body = {
    post_info: {
      title: meta.title || video.title || "ViralOrbit Upload",
      privacy_level: meta.privacy_level || "SELF_ONLY",
      disable_duet: false,
      disable_comment: false,
      disable_stitch: false
    },
    source_info: {
      source: "PULL_FROM_URL",
      video_url: videoUrl
    }
  };
  const { data } = await axios.post(initUrl, body, { headers: { Authorization:`Bearer ${c.access_token}`, "Content-Type":"application/json; charset=UTF-8" }});
  return data;
}

app.post("/api/publish", auth, async (req,res)=>{
  const { videoId, platforms=[], meta={} } = req.body || {};
  const video = db.prepare("SELECT * FROM videos WHERE id=?").get(videoId);
  if(!video) return res.status(404).json({ok:false,error:"Video not found. Upload video first."});
  const results = [];
  for(const platform of platforms){
    try{
      let out;
      if(platform === "youtube") out = await publishYouTube(video, meta);
      else if(platform === "facebook") out = await publishFacebook(video, meta);
      else if(platform === "instagram") out = await publishInstagram(video, meta);
      else if(platform === "tiktok") out = await publishTikTok(video, meta);
      else throw new Error("Unknown platform");
      results.push({platform, ok:true, response:out});
      db.prepare("INSERT INTO publish_results(video_id,platform,status,response_json) VALUES(?,?,?,?)").run(video.id, platform, "success", JSON.stringify(out));
    }catch(e){
      results.push({platform, ok:false, error:e.message});
      db.prepare("INSERT INTO publish_results(video_id,platform,status,response_json) VALUES(?,?,?,?)").run(video.id, platform, "failed", JSON.stringify({error:e.message}));
    }
  }
  res.json({ok:true,results});
});

app.post("/api/ai/generate", auth, async (req,res)=>{
  const { type, videoName } = req.body || {};
  try{
    const c = (()=>{ try{return getCred("openai")}catch{return {api_key:process.env.OPENAI_API_KEY}} })();
    if(!c.api_key) throw new Error("OPENAI_API_KEY missing");
    const client = new OpenAI({ apiKey: c.api_key });
    const promptMap = {
      title:`Write ONE viral social media video title for: ${videoName}. Bengali or English. Return only title.`,
      description:`Write a short viral social media description under 120 words for: ${videoName}. Return only description.`,
      hashtags:`Give 12 popular hashtags for: ${videoName}. Return only hashtags separated by spaces.`
    };
    const completion = await client.chat.completions.create({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      messages: [{role:"user", content: promptMap[type] || promptMap.title}],
      max_tokens: 220
    });
    res.json({ok:true,text:completion.choices[0].message.content.trim()});
  }catch(e){
    // Fallback so app still works
    const name = videoName || "ViralOrbit Video";
    if(type === "title") return res.json({ok:true,text:`🔥 ${name} | ViralOrbit Trending Upload`});
    if(type === "description") return res.json({ok:true,text:`Watch this amazing video on ViralOrbit. Like, comment, share, and follow for more trending content.`});
    if(type === "hashtags") return res.json({ok:true,text:"#viral #trending #viralorbit #shorts #reels #fyp #bangladesh #youtube #facebook #instagram"});
    res.status(400).json({ok:false,error:e.message});
  }
});

app.get("/api/platforms/status", auth, (req,res)=>{
  const rows = db.prepare("SELECT platform, updated_at FROM platform_credentials").all();
  res.json({ok:true,platforms:rows});
});
app.get("/health", (_,res)=>res.json({ok:true,status:"ViralOrbit real API backend running"}));

app.listen(PORT, ()=>console.log(`ViralOrbit real API backend running at ${BASE_URL}`));
