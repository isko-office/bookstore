// =====================================================================
// server.js - Kitab Evi (BookStore) backend
// Texnologiyalar: Node.js, Express, MySQL (Alwaysdata), bcrypt
//
// Üç fənnin kodda harada göründüyü:
//   Bulud          -> mühit dəyişənləri (process.env), Render + Alwaysdata, proxy ayarı
//   Kriptoqrafiya  -> bcrypt (duz + hash), təhlükəsiz session cookie, HTTPS
//   İTİS (ISO 27001) -> audit_logs (loglama), rollar (giriş nəzarəti),
//                       şifrə siyasəti, giriş cəhdlərinin məhdudlaşdırılması
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
// Hadisələr: REGISTER_SUCCESS, REGISTER_FAILED, LOGIN_SUCCESS, LOGIN_FAILED,
//            ACCOUNT_BLOCKED, LOGOUT, RATE_LIMITED, ACCESS_DENIED
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
// (req.ip) və HTTPS-i düzgün tanımaq üçündür.
// DİQQƏT: IP-əsaslı bloklama bu dəyərə güvənir. audit_logs-da bütün IP-lər eyni görünürsə
// (proxy IP-si), 1 əvəzinə 2 yoxlayın, yoxsa bir istifadəçinin bloklanması hamını bloklaya bilər.
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
        // Kitab üz qabıqları Open Library-dən gəlir (archive.org-a yönləndirilə bilir)
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
// 4. İSTİFADƏÇİ ADI VƏ ŞİFRƏ SİYASƏTİ (ISO/IEC 27001:2022, A.5.17)
// Qaydalar register.html-dəki qaydalarla EYNİDİR. Brauzerdəki yoxlama yalnız
// rahatlıq üçündür, əsl yoxlama burada, serverdə aparılır.
// ---------------------------------------------------------------------
const USERNAME_RE = /^[A-Za-z0-9_.-]{3,30}$/;

// ---- BEGIN PASSWORD POLICY ----
// Xüsusi simvollar: ! @ # $ % ^ & * ( ) _ + - = [ ] { } ; ' : " \ | , . < > / ? ~ `
const PASSWORD_RULES = [
  { re: /^[\x20-\x7E]{8,64}$/, text: "8-64 simvol olmalıdır (yalnız latın hərfləri, rəqəmlər və ASCII simvollar)" },
  { re: /[a-z]/, text: "ən azı 1 kiçik hərf (a-z)" },
  { re: /[A-Z]/, text: "ən azı 1 böyük hərf (A-Z)" },
  { re: /[0-9]/, text: "ən azı 1 rəqəm (0-9)" },
  { re: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/, text: "ən azı 1 xüsusi simvol (! @ # $ % ^ & * ...)" }
];

// Şifrə uyğun deyilsə pozulan qaydaların mətnini qaytarır, uyğundursa boş massiv
function passwordProblems(password) {
  if (typeof password !== "string") return [PASSWORD_RULES[0].text];
  return PASSWORD_RULES.filter((rule) => !rule.re.test(password)).map((rule) => rule.text);
}
// ---- END PASSWORD POLICY ----

// Mövcud olmayan istifadəçi üçün də bcrypt müqayisəsi aparılır ki,
// cavab vaxtına görə "belə istifadəçi var/yoxdur" bilinməsin.
const DUMMY_HASH = bcrypt.hashSync("vaxt-bərabərləşdirmə", BCRYPT_ROUNDS);

// ---------------------------------------------------------------------
// 5. GİRİŞ CƏHDLƏRİNİN MƏHDUDLAŞDIRILMASI (Brute-force qoruması)
// Qayda: ardıcıl 3 yanlış şifrə -> həmin IP və həmin istifadəçi adı 5 dəqiqə bloklanır.
// Sayğaclar iki açar üzrə aparılır: IP ünvanı və istifadəçi adı. Hər hansı biri
// bloklanıbsa giriş cəhdi qəbul edilmir. İstifadəçi adı olmayan hesablar üçün də
// eyni qayda işləyir (belə hesabın mövcud olub-olmadığı bilinmir).
// Diqqət: sayğaclar server yaddaşındadır, server yenidən başlayanda sıfırlanır
// və yalnız tək server nüsxəsi üçün işləyir (demo üçün kifayətdir).
// ---------------------------------------------------------------------
// ---- BEGIN LOCKOUT ----
const MAX_ATTEMPTS = 3;                    // ardıcıl yanlış cəhd limiti
const LOCK_MS = 5 * 60 * 1000;             // bloklanma müddəti: 5 dəqiqə
const FAIL_WINDOW_MS = 15 * 60 * 1000;     // bu müddətdə yeni cəhd olmazsa sayğac sıfırlanır

const attempts = new Map(); // açar -> { count, blockedUntil, lastFail }

function lockKeys(req, username) {
  const keys = ["ip:" + req.ip];
  if (username) keys.push("user:" + username.toLowerCase());
  return keys;
}

// Açarlardan hər hansı biri bloklanıbsa, qalan millisaniyəni qaytarır (yoxdursa 0)
function getBlockedMs(keys) {
  const now = Date.now();
  let ms = 0;
  for (const key of keys) {
    const entry = attempts.get(key);
    if (entry && entry.blockedUntil > now) ms = Math.max(ms, entry.blockedUntil - now);
  }
  return ms;
}

// Uğursuz cəhdi sayır. Qaytarır: { blocked: bu cəhdlə bloklandımı, remaining: qalan cəhd }
function registerFailure(keys) {
  const now = Date.now();
  let worst = 0;
  let blocked = false;
  for (const key of keys) {
    let entry = attempts.get(key);
    const blockExpired = entry && entry.blockedUntil && entry.blockedUntil <= now;
    const stale = entry && now - entry.lastFail > FAIL_WINDOW_MS;
    if (!entry || blockExpired || stale) entry = { count: 0, blockedUntil: 0, lastFail: now };

    entry.count += 1;
    entry.lastFail = now;
    if (entry.count >= MAX_ATTEMPTS) {
      entry.blockedUntil = now + LOCK_MS;
      blocked = true;
    }
    attempts.set(key, entry);
    worst = Math.max(worst, entry.count);
  }
  return { blocked, remaining: Math.max(MAX_ATTEMPTS - worst, 0) };
}

// Düzgün giriş olduqda sayğacları sıfırlayır
function clearFailures(keys) {
  keys.forEach((key) => attempts.delete(key));
}

// Köhnəlmiş qeydləri vaxtaşırı təmizləyirik (yaddaş dolmasın)
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of attempts) {
    if (entry.blockedUntil <= now && now - entry.lastFail > FAIL_WINDOW_MS) attempts.delete(key);
  }
}, 10 * 60 * 1000).unref();
// ---- END LOCKOUT ----

// 429 cavabı: neçə dəqiqə qaldığını bildirir
function sendBlocked(res, ms) {
  const seconds = Math.ceil(ms / 1000);
  const minutes = Math.ceil(ms / 60000);
  res.set("Retry-After", String(seconds));
  return res.status(429).json({
    message: "Çox sayda yanlış cəhd. " + minutes + " dəqiqə sonra yenidən cəhd edin.",
    retryAfterSeconds: seconds
  });
}

// Qeydiyyat üçün ümumi limit: yalnız UĞURSUZ sorğular sayılır (15 dəqiqədə 10)
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

// ---------------------------------------------------------------------
// 6. GİRİŞ NƏZARƏTİ (middleware)
// ---------------------------------------------------------------------
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
// 7. MARŞRUTLAR
// ---------------------------------------------------------------------

// ----- Qeydiyyat -----
app.post("/register", authLimiter, async (req, res) => {
  const body = req.body || {};
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const password = body.password;

  // Server tərəfində yoxlama (brauzerdəki yoxlamaya etibar etmirik)
  if (!USERNAME_RE.test(username)) {
    await writeLog(null, username, "REGISTER_FAILED", req);
    return res.status(400).json({
      message: "İstifadəçi adı 3-30 simvol olmalıdır (hərf, rəqəm, _ . - istifadə oluna bilər)."
    });
  }

  const problems = passwordProblems(password);
  if (problems.length > 0) {
    await writeLog(null, username, "REGISTER_FAILED", req);
    return res.status(400).json({
      message: "Şifrə tələblərə uyğun deyil: " + problems.join("; ") + ".",
      problems
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
app.post("/login", async (req, res) => {
  const body = req.body || {};
  const username = typeof body.username === "string" ? body.username.trim().slice(0, 30) : "";
  const password = typeof body.password === "string" ? body.password : "";

  // 1) Bloklanıbsa, şifrəni yoxlamadan 429 qaytarırıq.
  // Bloklanma zamanı təkrar cəhdlər loga yazılmır (jurnalın dolmasının qarşısını almaq üçün).
  const keys = lockKeys(req, username);
  const blockedMs = getBlockedMs(keys);
  if (blockedMs > 0) return sendBlocked(res, blockedMs);

  try {
    const [rows] = await pool.execute(
      "SELECT id, username, password_hash, role FROM users WHERE username = ?",
      [username]
    );
    const user = rows[0];

    // İstifadəçi tapılmasa da müqayisə aparılır (vaxt fərqi olmasın)
    const match = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);

    // 2) Uğursuz giriş
    if (!user || !match) {
      await writeLog(user ? user.id : null, username, "LOGIN_FAILED", req);

      const { blocked, remaining } = registerFailure(keys);
      if (blocked) {
        await writeLog(user ? user.id : null, username, "ACCOUNT_BLOCKED", req);
        return sendBlocked(res, LOCK_MS);
      }
      // Hər iki halda (yanlış ad / yanlış şifrə) eyni mesaj: hansının səhv olduğunu bildirmirik
      return res.status(401).json({
        message: "İstifadəçi adı və ya şifrə yanlışdır. Qalan cəhd: " + remaining,
        remainingAttempts: remaining
      });
    }

    // 3) Uğurlu giriş: sayğacları sıfırlayırıq
    clearFailures(keys);

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

// ----- Cari istifadəçi (kataloq səhifəsindəki profil üçün) -----
app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ message: "Daxil olmamısınız." });
  res.json({ username: req.session.username, role: req.session.role });
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
// 8. SERVERİ İŞƏ SALIRIQ (əvvəl bazaya qoşulmanı yoxlayırıq)
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
