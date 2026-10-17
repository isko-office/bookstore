// =====================================================================
// server.js - Kitab Evi (BookStore) backend
// Texnologiyalar: Node.js, Express, MySQL (Alwaysdata), bcrypt
//
// Üç fənnin kodda harada göründüyü:
//   Bulud          -> mühit dəyişənləri (process.env), Render + Alwaysdata, proxy ayarı
//   Kriptoqrafiya  -> bcrypt (duz + hash), təhlükəsiz session cookie, HTTPS
//   İTİS (ISO 27001) -> audit_logs (loglama), rollar (giriş nəzarəti), rate limit
// =====================================================================

// Lokalda .env faylından oxumaq üçün (npm i dotenv). Render-də lazım deyil.
try { require("dotenv").config(); } catch (e) { /* dotenv qurulmayıbsa keçirik */ }

const path = require("path");
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const session = require("express-session");
const rateLimit = require("express-rate-limit");

const isProd = process.env.NODE_ENV === "production";
const PORT = process.env.PORT || 3000;
const BCRYPT_ROUNDS = 12; // nə qədər böyükdürsə, hash o qədər yavaş (hücumçu üçün baha)

// Canlı mühitdə session açarı mütləq təyin olunmalıdır
if (isProd && !process.env.SESSION_SECRET) {
  console.error("XƏTA: SESSION_SECRET mühit dəyişəni təyin edilməyib.");
  process.exit(1);
}

// ---------------------------------------------------------------------
// 1. VERİLƏNLƏR BAZASI (Alwaysdata MySQL)
// Giriş məlumatları kodda yox, mühit dəyişənlərindədir (Render -> Environment).
// ---------------------------------------------------------------------
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit: 5, // pulsuz planda bağlantı limiti kiçikdir
  // Bağlantını şifrələmək üçün DB_SSL=true yazın (Alwaysdata-nın dəstəyini yoxlayın)
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: true } : undefined
});

// ---------------------------------------------------------------------
// 2. AUDİT LOG (ISO/IEC 27001:2022, A.8.15 Logging)
// Hər təhlükəsizlik hadisəsi audit_logs cədvəlinə yazılır.
// Şifrə heç vaxt loga yazılmır.
// ---------------------------------------------------------------------
async function writeLog(userId, username, action, req) {
  try {
    await pool.execute(
      "INSERT INTO audit_logs (user_id, username, action, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)",
      [
        userId || null,
        username ? String(username).slice(0, 30) : null,
        action,
        req.ip || null, // req.ip: Express-in "trust proxy" ilə təyin etdiyi IP (başlığı əllə oxumuruq, çünki saxtalaşdırıla bilər)
        (req.get("user-agent") || "").slice(0, 255)
      ]
    );
  } catch (err) {
    // Log yazıla bilməsə də, istifadəçinin sorğusu çökməsin
    console.error("Audit log yazıla bilmədi:", err.code || err.message);
  }
}

// ---------------------------------------------------------------------
// 3. EXPRESS AYARLARI
// ---------------------------------------------------------------------
const app = express();

// Render sorğuları öz proxy-si ilə yönləndirir. Bu ayar real istifadəçi IP-sini
// (req.ip) və HTTPS-i düzgün tanımaq üçündür. IP səhv görünsə, 1 əvəzinə 2 yoxlayın.
app.set("trust proxy", 1);

// Helmet: təhlükəsizlik başlıqları (clickjacking, MIME sniffing və s. qarşı)
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        // Səhifələrimizdə inline <script> var, ona görə 'unsafe-inline' lazımdır.
        // Təkmilləşdirmə: skriptləri ayrı .js fayllara çıxarıb bunu silmək olar.
        "script-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:", "https://covers.openlibrary.org", "https://archive.org", "https://*.archive.org"],
        // Lokalda (http) bu direktiv CSS-i pozur, ona görə yalnız canlıda aktivdir
        "upgrade-insecure-requests": isProd ? [] : null
      }
    }
  })
);

app.use(express.json({ limit: "10kb" })); // böyük sorğuların qarşısını alır

// Session: giriş edən istifadəçini yadda saxlayır
// Qeyd: MemoryStore yalnız demo üçündür (server yenidən başlayanda sessiyalar silinir).
app.use(
  session({
    name: "kitabevi.sid",
    secret: process.env.SESSION_SECRET || "yalniz-lokal-test-ucun",
    resave: false,
    saveUninitialized: false,
    rolling: true, // fəaliyyət olduqca müddət uzanır
    cookie: {
      httpOnly: true,           // JavaScript cookie-ni oxuya bilməz (XSS-dən qorunma)
      secure: isProd,           // canlıda yalnız HTTPS üzərindən göndərilir
      sameSite: "lax",          // başqa saytdan gələn sorğularda cookie göndərilmir (CSRF azaldır)
      maxAge: 30 * 60 * 1000    // 30 dəqiqə
    }
  })
);

// ---------------------------------------------------------------------
// 4. YARDIMÇI FUNKSİYALAR
// ---------------------------------------------------------------------
const USERNAME_RE = /^[A-Za-z0-9_.-]{3,30}$/;

// bcrypt yalnız ilk 72 baytı nəzərə alır, ona görə yuxarı həddi 72 qoyuruq
function isValidPassword(p) {
  return typeof p === "string" && p.length >= 8 && Buffer.byteLength(p, "utf8") <= 72;
}

// Mövcud olmayan istifadəçi üçün də bcrypt müqayisəsi aparılır ki,
// cavab vaxtına görə "belə istifadəçi var/yoxdur" bilinməsin.
const DUMMY_HASH = bcrypt.hashSync("vaxt-bərabərləşdirmə", BCRYPT_ROUNDS);

// Brute-force qoruması: yalnız UĞURSUZ cəhdlər sayılır (15 dəqiqədə 10)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  handler: async (req, res) => {
    const name = req.body && typeof req.body.username === "string" ? req.body.username : null;
    await writeLog(null, name, "RATE_LIMITED", req);
    res.status(429).json({ message: "Çox sayda uğursuz cəhd. 15 dəqiqə sonra yenidən cəhd edin." });
  }
});

// Giriş tələb edən səhifələr üçün: giriş yoxdursa login səhifəsinə yönləndirir
function requirePageLogin(req, res, next) {
  if (req.session.userId) return next();
  res.redirect("/login.html");
}

// Yalnız admin üçün API: giriş yoxdursa 401, admin deyilsə 403 (və loga yazılır)
async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ message: "Əvvəlcə daxil olun." });
  if (req.session.role !== "admin") {
    await writeLog(req.session.userId, req.session.username, "ACCESS_DENIED", req);
    return res.status(403).json({ message: "Bu əməliyyat üçün icazəniz yoxdur." });
  }
  next();
}

// ---------------------------------------------------------------------
// 5. MARŞRUTLAR
// ---------------------------------------------------------------------

// ----- Qeydiyyat -----
app.post("/register", authLimiter, async (req, res) => {
  const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
  const password = req.body.password;

  // Server tərəfində yoxlama (brauzerdəki yoxlamaya etibar etmirik)
  if (!USERNAME_RE.test(username) || !isValidPassword(password)) {
    await writeLog(null, username, "REGISTER_FAILED", req);
    return res.status(400).json({
      message: "İstifadəçi adı 3-30 simvol (hərf, rəqəm, _ . -), şifrə isə 8-72 simvol olmalıdır."
    });
  }

  try {
    // Şifrə duz (salt) ilə hash-lənir; bazaya yalnız hash yazılır
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // "?" yerhesablayıcıları = Prepared Statement (SQL Injection-a qarşı)
    // Rol həmişə "user" olur. Admin rolunu yalnız baza administratoru verə bilər.
    const [result] = await pool.execute(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
      [username, hash]
    );

    await writeLog(result.insertId, username, "REGISTER_SUCCESS", req);
    res.status(201).json({ message: "Qeydiyyat uğurludur." });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      await writeLog(null, username, "REGISTER_FAILED", req);
      return res.status(409).json({ message: "Bu istifadəçi adı artıq mövcuddur." });
    }
    console.error("Qeydiyyat xətası:", err.code || err.message);
    res.status(500).json({ message: "Server xətası. Bir az sonra yenidən cəhd edin." });
  }
});

// ----- Giriş -----
app.post("/login", authLimiter, async (req, res) => {
  const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";

  try {
    const [rows] = await pool.execute(
      "SELECT id, username, password_hash, role FROM users WHERE username = ?",
      [username]
    );
    const user = rows[0];

    // İstifadəçi tapılmasa da müqayisə aparılır (vaxt fərqi olmasın)
    const match = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);

    if (!user || !match) {
      await writeLog(user ? user.id : null, username, "LOGIN_FAILED", req);
      // Hər iki halda eyni mesaj: hansının səhv olduğunu hücumçuya bildirmirik
      return res.status(401).json({ message: "İstifadəçi adı və ya şifrə yanlışdır." });
    }

    // Yeni session ID yaradırıq (session fixation hücumuna qarşı)
    req.session.regenerate(async (err) => {
      if (err) {
        console.error("Session xətası:", err.message);
        return res.status(500).json({ message: "Server xətası. Bir az sonra yenidən cəhd edin." });
      }
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;
      await writeLog(user.id, user.username, "LOGIN_SUCCESS", req);
      res.json({ message: "Giriş uğurludur." });
    });
  } catch (err) {
    console.error("Giriş xətası:", err.code || err.message);
    res.status(500).json({ message: "Server xətası. Bir az sonra yenidən cəhd edin." });
  }
});

// ----- Çıxış -----
app.get("/logout", (req, res) => {
  const { userId, username } = req.session;
  req.session.destroy(async () => {
    if (userId) await writeLog(userId, username, "LOGOUT", req);
    res.clearCookie("kitabevi.sid");
    res.redirect("/index.html");
  });
});

// ----- Audit loglara baxış (yalnız admin) -----
app.get("/api/audit-logs", requireAdmin, async (req, res) => {
  // limit yoxlanılmış tam ədəddir (1-500), ona görə birbaşa sorğuya yazmaq təhlükəsizdir
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
  try {
    const [rows] = await pool.query(
      `SELECT id, user_id, username, action, ip_address, created_at
         FROM audit_logs ORDER BY id DESC LIMIT ${limit}`
    );
    res.json(rows);
  } catch (err) {
    console.error("Log oxuma xətası:", err.code || err.message);
    res.status(500).json({ message: "Server xətası." }); // daxili xəta mətnini istifadəçiyə vermirik
  }
});

// ----- Qorunan səhifə: kataloq yalnız giriş etmiş istifadəçiyə açıqdır -----
// DİQQƏT: bu marşrut express.static-dən ƏVVƏL yazılmalıdır, yoxsa fayl hamıya açıq olar.
app.get("/bookstore.html", requirePageLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "bookstore.html"));
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ message: "Daxil olmamısınız." });
  res.json({ username: req.session.username, role: req.session.role });
});

// ----- Qalan statik fayllar (index, login, register, style.css) -----
app.use(express.static(path.join(__dirname, "public")));

// Səhv JSON göndərilərsə və ya gözlənilməz xəta olarsa
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ message: "Yanlış sorğu formatı." });
  }
  console.error("Gözlənilməz xəta:", err.message);
  res.status(500).json({ message: "Server xətası." });
});

// ---------------------------------------------------------------------
// 6. SERVERİ İŞƏ SALIRIQ (əvvəl bazaya qoşulmanı yoxlayırıq)
// ---------------------------------------------------------------------
pool
  .query("SELECT 1")
  .then(() => {
    app.listen(PORT, () => console.log("Kitab Evi " + PORT + " portunda işləyir."));
  })
  .catch((err) => {
    console.error("Bazaya qoşulmaq mümkün olmadı:", err.code || err.message);
    process.exit(1);
  });
