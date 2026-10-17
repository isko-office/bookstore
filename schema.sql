-- =====================================================================
-- schema.sql - Kitab Evi (BookStore)
-- Alwaysdata-da: əvvəlcə öz bazanızı yaradın/seçin, sonra phpMyAdmin-də
-- həmin bazanı açıb "Import" (və ya SQL) bölməsindən bu faylı işə salın.
-- (CREATE DATABASE yazmırıq, çünki Alwaysdata baza adını özü prefikslə verir.)
-- =====================================================================

-- 1. İstifadəçilər cədvəli
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  -- UNIQUE: eyni ad iki dəfə qeydiyyatdan keçə bilməz.
  -- Standart collation hərf böyüklüyünə həssas deyil: "Ali" və "ali" eyni sayılır.
  username      VARCHAR(30)  NOT NULL UNIQUE,
  -- bcrypt hash-i həmişə 60 simvoldur. Şifrənin özü HEÇ VAXT saxlanılmır.
  password_hash CHAR(60)     NOT NULL,
  -- Rol: qeydiyyatda həmişə "user". "admin" yalnız bazadan əllə verilir.
  role          ENUM('user', 'admin') NOT NULL DEFAULT 'user',
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Təhlükəsizlik audit jurnalı (ISO/IEC 27001:2022, A.8.15)
CREATE TABLE IF NOT EXISTS audit_logs (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  -- İstifadəçi tanınmırsa NULL. İstifadəçi silinərsə log qalır (ON DELETE SET NULL).
  user_id     INT UNSIGNED NULL,
  username    VARCHAR(30)  NULL,   -- daxil edilən ad (tanınmayan adlar da qeyd olunur)
  -- LOGIN_SUCCESS, LOGIN_FAILED, REGISTER_SUCCESS, REGISTER_FAILED,
  -- LOGOUT, RATE_LIMITED, ACCESS_DENIED
  action      VARCHAR(30)  NOT NULL,
  ip_address  VARCHAR(45)  NULL,   -- IPv6 ünvanı 45 simvola qədər ola bilər
  user_agent  VARCHAR(255) NULL,   -- brauzer/cihaz məlumatı
  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_audit_created (created_at),
  INDEX idx_audit_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =====================================================================
-- ADMİN YARATMAQ (bir dəfə):
-- 1) Saytda adi qeydiyyatdan keçin (məs. istifadəçi adı: admin_ali)
-- 2) Sonra bu sorğunu işə salın (öz adınızı yazın):
--
-- UPDATE users SET role = 'admin' WHERE username = 'admin_ali';
--
-- ADMİN ÜÇÜN FAYDALI SORĞULAR (hesabat ekran görüntüləri üçün):
--
-- Son 20 hadisə:
-- SELECT id, username, action, ip_address, created_at
--   FROM audit_logs ORDER BY id DESC LIMIT 20;
--
-- Eyni IP-dən uğursuz giriş cəhdlərinin sayı (brute-force əlaməti):
-- SELECT ip_address, COUNT(*) AS cehd_sayi
--   FROM audit_logs WHERE action = 'LOGIN_FAILED'
--   GROUP BY ip_address ORDER BY cehd_sayi DESC;
--
-- Şifrənin açıq yazılmadığını göstərmək üçün:
-- SELECT username, password_hash FROM users;
-- =====================================================================
