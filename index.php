<?php
/* ============================================================
   UTS Kriptografi — Single File Application
   Oleh: Yogiswara Putra Rainanda
   Berisi: FPB, Enkripsi/Dekripsi, Simulasi RSA, Digital Signature,
           SSL Generator, XOR Cipher, SHA-256 Hash Generator
   ============================================================ */

session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// ── Routing: tentukan halaman aktif ──────────────────────────
$page = $_GET['page'] ?? 'home';
$allowed_pages = ['home','fpb','kripto','rsa','verifikator','ssl','xor','sha256'];
if (!in_array($page, $allowed_pages)) $page = 'home';

// ============================================================
// LOGIC: FPB (Algoritma Euclidean)
// ============================================================
function euclideanGCD($a, $b) {
    $steps = [];
    $original_a = $a;
    $original_b = $b;
    if ($a <= 0 || $b <= 0) {
        return ['gcd' => null, 'steps' => [], 'error' => 'Masukkan bilangan bulat positif!'];
    }
    if ($a < $b) {
        [$a, $b] = [$b, $a];
        $steps[] = "Menukar posisi: a = {$a}, b = {$b}";
    }
    $steps[] = "Memulai Algoritma Euclidean untuk GCD({$original_a}, {$original_b}):";
    while ($b != 0) {
        $q = floor($a / $b);
        $r = $a % $b;
        $steps[] = "{$a} = {$q} × {$b} + {$r}";
        $a = $b;
        $b = $r;
    }
    $steps[] = "✅ FPB = {$a}";
    return ['gcd' => $a, 'steps' => $steps, 'error' => null];
}

$fpb_result = null;
$fpb_angka1 = '';
$fpb_angka2 = '';
if ($page === 'fpb' && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['hitung'])) {
    $fpb_angka1 = intval($_POST['angka1'] ?? 0);
    $fpb_angka2 = intval($_POST['angka2'] ?? 0);
    $fpb_result = euclideanGCD($fpb_angka1, $fpb_angka2);
}

// ============================================================
// LOGIC: Caesar & Vigenère Cipher
// ============================================================
function caesar_cipher(string $text, int $key, bool $is_encrypt): string {
    $key = (($key % 26) + 26) % 26;
    if (!$is_encrypt) $key = (26 - $key) % 26;
    $result = '';
    for ($i = 0; $i < strlen($text); $i++) {
        $char = $text[$i];
        if (ctype_alpha($char)) {
            $base   = ctype_upper($char) ? ord('A') : ord('a');
            $result .= chr(($key + ord($char) - $base) % 26 + $base);
        } else {
            $result .= $char;
        }
    }
    return $result;
}

function vigenere_cipher(string $text, string $key, bool $is_encrypt): string {
    if (empty($key)) return $text;
    $clean_key = strtoupper(preg_replace('/[^A-Za-z]/', '', $key));
    if (empty($clean_key)) return $text;
    $result  = '';
    $key_len = strlen($clean_key);
    $key_idx = 0;
    for ($i = 0; $i < strlen($text); $i++) {
        $char = $text[$i];
        if (ctype_alpha($char)) {
            $base  = ctype_upper($char) ? ord('A') : ord('a');
            $shift = ord($clean_key[$key_idx % $key_len]) - ord('A');
            if (!$is_encrypt) $shift = (26 - $shift) % 26;
            $result  .= chr(($shift + ord($char) - $base) % 26 + $base);
            $key_idx++;
        } else {
            $result .= $char;
        }
    }
    return $result;
}

$kripto_output    = '';
$kripto_input     = '';
$kripto_operation = 'encrypt';
$kripto_algorithm = 'caesar';
$kripto_caesar_key  = 3;
$kripto_vigenere_key = '';
$kripto_error     = '';

if ($page === 'kripto' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $kripto_input        = $_POST['message']     ?? '';
    $kripto_operation    = $_POST['operation']   ?? 'encrypt';
    $kripto_algorithm    = $_POST['algorithm']   ?? 'caesar';
    $kripto_caesar_key   = (int)($_POST['caesar_key'] ?? 3);
    $kripto_vigenere_key = trim($_POST['vigenere_key'] ?? '');
    $is_encrypt = ($kripto_operation === 'encrypt');
    if (empty($kripto_input)) {
        $kripto_error = 'Masukkan pesan terlebih dahulu.';
    } elseif ($kripto_algorithm === 'caesar') {
        if ($kripto_caesar_key < 1 || $kripto_caesar_key > 25) {
            $kripto_error = 'Key Caesar harus antara 1 – 25.';
        } else {
            $kripto_output = caesar_cipher($kripto_input, $kripto_caesar_key, $is_encrypt);
        }
    } elseif ($kripto_algorithm === 'vigenere') {
        if (empty($kripto_vigenere_key) || !ctype_alpha(str_replace(' ', '', $kripto_vigenere_key))) {
            $kripto_error = 'Key Vigenère harus berisi huruf saja (minimal 1 karakter).';
        } else {
            $kripto_output = vigenere_cipher($kripto_input, $kripto_vigenere_key, $is_encrypt);
        }
    }
}

// ============================================================
// LOGIC: Simulasi RSA
// ============================================================
$rsa_error = '';
$rsa_pesanBob = '';
$rsa_cipherBase64 = '';
$rsa_pesanDekripsi = '';

if ($page === 'rsa') {
    if (isset($_POST['regenerate'])) {
        unset($_SESSION['alice_private'], $_SESSION['alice_public']);
        header("Location: uts_kripto.php?page=rsa");
        exit;
    }

    if (!isset($_SESSION['alice_private']) || !isset($_SESSION['alice_public'])) {
        $rsa_config = [
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "config" => "C:/laragon/bin/php/php-8.1.10-Win32-vs16-x64/extras/ssl/openssl.cnf"
        ];
        $res = openssl_pkey_new($rsa_config);
        if ($res === false) {
            $rsa_error = "Gagal membuat kunci RSA: " . openssl_error_string();
        } else {
            openssl_pkey_export($res, $privateKeyAlice, null, $rsa_config);
            $details = openssl_pkey_get_details($res);
            $publicKeyAlice = $details["key"];
            $_SESSION['alice_private'] = $privateKeyAlice;
            $_SESSION['alice_public']  = $publicKeyAlice;
        }
    } else {
        $privateKeyAlice = $_SESSION['alice_private'];
        $publicKeyAlice  = $_SESSION['alice_public'];
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pesan_bob'])) {
        $rsa_pesanBob = trim($_POST['pesan_bob']);
        if ($rsa_pesanBob === '') {
            $rsa_error = 'Pesan tidak boleh kosong.';
        } else {
            $encrypted = null;
            if (!openssl_public_encrypt($rsa_pesanBob, $encrypted, $publicKeyAlice)) {
                $rsa_error = 'Enkripsi gagal: ' . openssl_error_string();
            } else {
                $rsa_cipherBase64 = base64_encode($encrypted);
                $decrypted = null;
                if (!openssl_private_decrypt(base64_decode($rsa_cipherBase64), $decrypted, $privateKeyAlice)) {
                    $rsa_error = 'Dekripsi gagal: ' . openssl_error_string();
                } else {
                    $rsa_pesanDekripsi = $decrypted;
                }
            }
        }
    }
}

// ============================================================
// LOGIC: Verifikator Dokumen (HMAC-SHA256)
// ============================================================
$verif_message = '';
$verif_signed_document = '';
$verif_verification_result = '';

if ($page === 'verifikator') {
    if (!isset($_SESSION['key'])) $_SESSION['key'] = '';

    if (isset($_POST['generate_key'])) {
        $_SESSION['key'] = bin2hex(random_bytes(16));
        $verif_message = "Key baru telah dibuat.";
    }

    if (isset($_POST['sign'])) {
        $key    = $_SESSION['key'];
        $dokumen = trim($_POST['dokumen']);
        if (!empty($key) && !empty($dokumen)) {
            $signature = hash_hmac('sha256', $dokumen, $key);
            $verif_signed_document = $dokumen . '--' . $signature;
            $verif_message = "Dokumen berhasil ditandatangani.";
        } else {
            $verif_message = "Key atau isi dokumen kosong. Generate key terlebih dahulu.";
        }
    }

    if (isset($_POST['verify'])) {
        $key = $_SESSION['key'];
        $signed_input = trim($_POST['signed_document']);
        if (!empty($key) && !empty($signed_input)) {
            $parts = explode('--', $signed_input);
            if (count($parts) === 2) {
                $dokumen = $parts[0];
                $received_sig = $parts[1];
                $calc_sig = hash_hmac('sha256', $dokumen, $key);
                if (hash_equals($calc_sig, $received_sig)) {
                    $verif_verification_result = '<div class="verification-result result-valid">✅ DOKUMEN VALID — Keaslian terkonfirmasi</div>';
                } else {
                    $verif_verification_result = '<div class="verification-result result-invalid">❌ DOKUMEN TIDAK VALID / TELAH DIMODIFIKASI</div>';
                }
            } else {
                $verif_message = "Format dokumen tidak sesuai (harus berisi '--' pemisah).";
            }
        } else {
            $verif_message = "Key atau dokumen ditandatangani kosong.";
        }
    }
}

// ============================================================
// LOGIC: SSL Certificate Generator
// ============================================================
$ssl_privateKey  = '';
$ssl_certificate = '';
$ssl_error       = '';

if ($page === 'ssl') {
    $possibleCnf = [
        'C:/laragon/bin/php/php-8.1.10-Win32-vs16-x64/extras/ssl/openssl.cnf',
        'C:/laragon/bin/php/php-8.3.30-Win32-vs16-x64/extras/ssl/openssl.cnf',
        'C:/xampp/apache/conf/openssl.cnf',
        'C:/xampp/php/extras/ssl/openssl.cnf',
    ];
    $opensslCnf = null;
    foreach ($possibleCnf as $path) {
        if (file_exists($path)) { $opensslCnf = $path; break; }
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $ssl_country  = strtoupper(trim($_POST['country']  ?? 'ID'));
        $ssl_state    = trim($_POST['state']               ?? '');
        $ssl_locality = trim($_POST['locality']            ?? '');
        $ssl_org      = trim($_POST['org']                 ?? '');
        $ssl_cn       = trim($_POST['cn']                  ?? '');

        if (empty($ssl_state) || empty($ssl_locality) || empty($ssl_org) || empty($ssl_cn)) {
            $ssl_error = 'Semua field wajib diisi sebelum membuat sertifikat.';
        } elseif (strlen($ssl_country) !== 2) {
            $ssl_error = 'Kode negara (Country) harus 2 huruf, contoh: ID';
        } elseif (!extension_loaded('openssl')) {
            $ssl_error = 'Ekstensi PHP OpenSSL tidak aktif.';
        } else {
            $config = ['digest_alg' => 'sha256', 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
            if ($opensslCnf !== null) $config['config'] = $opensslCnf;
            while (openssl_error_string() !== false);
            $pkeyResource = openssl_pkey_new($config);
            if ($pkeyResource === false) {
                $ssl_error = "Gagal membuat keypair RSA. Error: " . (openssl_error_string() ?: 'unknown');
            } else {
                openssl_pkey_export($pkeyResource, $privateKeyPem, null, $config);
                $dn = [
                    'countryName'         => $ssl_country,
                    'stateOrProvinceName' => $ssl_state,
                    'localityName'        => $ssl_locality,
                    'organizationName'    => $ssl_org,
                    'commonName'          => $ssl_cn,
                ];
                $csr = openssl_csr_new($dn, $pkeyResource, $config);
                if ($csr === false) {
                    $ssl_error = "Gagal membuat CSR.";
                } else {
                    $x509 = openssl_csr_sign($csr, null, $pkeyResource, 365, $config, (int)(microtime(true) * 1000));
                    if ($x509 === false) {
                        $ssl_error = "Gagal sign sertifikat.";
                    } else {
                        openssl_x509_export($x509, $certPem);
                        $ssl_privateKey  = $privateKeyPem;
                        $ssl_certificate = $certPem;
                    }
                }
            }
        }
    }
}

// ============================================================
// LOGIC: XOR Cipher
// ============================================================
function xor_cipher_fn(string $text, string $key): string {
    if (empty($key)) return $text;
    $result  = '';
    $key_len = strlen($key);
    for ($i = 0; $i < strlen($text); $i++) {
        $result .= chr(ord($text[$i]) ^ ord($key[$i % $key_len]));
    }
    return $result;
}
function to_binary(string $str): string {
    $bits = '';
    for ($i = 0; $i < strlen($str); $i++) {
        $bits .= str_pad(decbin(ord($str[$i])), 8, '0', STR_PAD_LEFT);
        if ($i < strlen($str) - 1) $bits .= ' ';
    }
    return $bits;
}
function to_hex(string $str): string { return strtoupper(bin2hex($str)); }

$xor_input_text = '';
$xor_key        = '';
$xor_output     = '';
$xor_output_hex = '';
$xor_input_bin  = '';
$xor_key_bin    = '';
$xor_output_bin = '';
$xor_operation  = 'encrypt';
$xor_error      = '';

if ($page === 'xor' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $xor_input_text = $_POST['message']   ?? '';
    $xor_key        = $_POST['key']       ?? '';
    $xor_operation  = $_POST['operation'] ?? 'encrypt';
    if (empty($xor_input_text)) {
        $xor_error = 'Masukkan teks terlebih dahulu.';
    } elseif (empty($xor_key)) {
        $xor_error = 'Masukkan kunci XOR terlebih dahulu.';
    } else {
        $xor_output     = xor_cipher_fn($xor_input_text, $xor_key);
        $xor_output_hex = to_hex($xor_output);
        $xor_input_bin  = to_binary($xor_input_text);
        $xor_key_bin    = to_binary($xor_key);
        $xor_output_bin = to_binary($xor_output);
    }
}

// ============================================================
// LOGIC: SHA-256 Hash Generator
// ============================================================
$sha_input_text   = '';
$sha_hash_result  = '';
$sha_hash_upper   = '';
$sha_hash_groups  = [];
$sha_error        = '';
$sha_compare_text = '';
$sha_compare_result = null;
$sha_hash_info    = [];

if ($page === 'sha256' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $sha_action       = $_POST['action']       ?? 'hash';
    $sha_input_text   = $_POST['message']      ?? '';
    $sha_compare_text = $_POST['compare_hash'] ?? '';

    if ($sha_action === 'hash') {
        if (empty($sha_input_text)) {
            $sha_error = 'Masukkan teks yang ingin di-hash.';
        } else {
            $sha_hash_result = hash('sha256', $sha_input_text);
            $sha_hash_upper  = strtoupper($sha_hash_result);
            $sha_hash_groups = str_split($sha_hash_result, 8);
            $sha_hash_info = [
                'md5'    => hash('md5',    $sha_input_text),
                'sha1'   => hash('sha1',   $sha_input_text),
                'sha512' => hash('sha512', $sha_input_text),
            ];
        }
    } elseif ($sha_action === 'compare') {
        if (empty($sha_input_text) || empty($sha_compare_text)) {
            $sha_error = 'Isi teks dan hash pembanding.';
        } else {
            $sha_hash_result    = hash('sha256', $sha_input_text);
            $sha_compare_result = hash_equals($sha_hash_result, strtolower(trim($sha_compare_text)));
            $sha_hash_groups    = str_split($sha_hash_result, 8);
        }
    }
}

// ============================================================
// HELPER: Navbar builder
// ============================================================
function navItem(string $p, string $current, string $icon, string $label): string {
    $active = ($p === $current) ? ' active' : '';
    return '<a href="uts_kripto.php?page=' . $p . '" class="dropdown-item' . $active . '" role="menuitem">' . $icon . ' ' . $label . '</a>';
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CryptoLab UTS — <?= match($page) {
    'home'       => 'Dashboard',
    'fpb'        => 'Kalkulator FPB',
    'kripto'     => 'Enkripsi & Dekripsi',
    'rsa'        => 'Simulasi RSA',
    'verifikator'=> 'Digital Signature',
    'ssl'        => 'SSL Generator',
    'xor'        => 'XOR Cipher',
    'sha256'     => 'SHA-256',
    default      => 'CryptoLab'
  } ?></title>
  <meta name="description" content="Laboratorium Kriptografi UTS — FPB, Caesar, Vigenère, RSA, HMAC, SSL, XOR, SHA-256">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
<style>
/* ============================================================
   UTS Kriptografi — Unified Stylesheet
   ============================================================ */
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

:root {
  --bg-deep:    #050d1a;
  --bg-mid:     #0f172a;
  --bg-card:    rgba(255,255,255,0.04);
  --border:     rgba(59,130,246,0.15);
  --blue:       #3b82f6;
  --cyan:       #06b6d4;
  --text-main:  #e2e8f0;
  --text-muted: #64748b;
  --text-sub:   #94a3b8;
  --grad:       linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%);
}

html { scroll-behavior: smooth; }

body {
  font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
  background: linear-gradient(135deg, #050d1a 0%, #0f172a 50%, #061224 100%);
  min-height: 100vh;
  color: var(--text-main);
}

/* ── Navbar ─────────────────────────────────────────────── */
.navbar {
  background: rgba(5,13,26,0.97);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--border);
  padding: 0.85rem 2rem;
  position: sticky;
  top: 0;
  z-index: 100;
}
.nav-container {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
}
.logo {
  font-size: 1.45rem;
  font-weight: 800;
  background: var(--grad);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  text-decoration: none;
  white-space: nowrap;
  flex-shrink: 0;
}
.nav-dropdown { position: relative; flex-shrink: 0; }
.dropdown-trigger {
  display: flex; align-items: center; gap: 0.45rem;
  padding: 0.5rem 1.1rem;
  background: var(--grad);
  color: white; border: none; border-radius: 25px;
  font-size: 0.9rem; font-weight: 600; cursor: pointer;
  white-space: nowrap; transition: opacity .25s, transform .2s, box-shadow .25s;
  box-shadow: 0 2px 10px rgba(59,130,246,0.4);
  font-family: inherit;
}
.dropdown-trigger:hover { opacity: 0.9; transform: translateY(-1px); box-shadow: 0 4px 16px rgba(59,130,246,0.55); }
.dropdown-trigger .caret {
  display: inline-block; width: 0; height: 0;
  border-left: 5px solid transparent; border-right: 5px solid transparent; border-top: 5px solid white;
  transition: transform 0.3s cubic-bezier(0.23,1,0.32,1); flex-shrink: 0;
}
.dropdown-trigger.open .caret { transform: rotate(180deg); }
.dropdown-menu {
  position: absolute; top: calc(100% + 10px); right: 0;
  min-width: 230px; background: #0a1628;
  border: 1px solid rgba(59,130,246,0.2); border-radius: 16px;
  box-shadow: 0 12px 40px rgba(0,0,0,0.6);
  padding: 0.5rem; opacity: 0; pointer-events: none;
  transform: translateY(-8px) scale(0.97); transform-origin: top right;
  transition: opacity .22s ease, transform .22s cubic-bezier(0.23,1,0.32,1); z-index: 999;
}
.dropdown-menu.open { opacity: 1; pointer-events: auto; transform: translateY(0) scale(1); }
.dropdown-item {
  display: flex; align-items: center; gap: 0.65rem;
  padding: 0.65rem 1rem; border-radius: 10px;
  text-decoration: none; color: var(--text-muted);
  font-size: 0.9rem; font-weight: 500;
  transition: background .18s, color .18s, transform .15s; outline: none;
}
.dropdown-item:hover, .dropdown-item:focus-visible {
  background: var(--grad); color: white; transform: translateX(3px);
}
.dropdown-item.active { background: rgba(59,130,246,0.12); color: #60a5fa; font-weight: 600; }
.dropdown-divider { height: 1px; background: rgba(59,130,246,0.12); margin: 0.35rem 0.5rem; }

/* ── Footer ─────────────────────────────────────────────── */
footer {
  text-align: center; padding: 2rem; color: var(--text-muted);
  background: rgba(0,0,0,0.25); border-top: 1px solid var(--border); margin-top: 3rem;
  font-size: 0.82rem;
}

/* ── Page Wrapper ───────────────────────────────────────── */
.container { max-width: 1200px; margin: 0 auto; padding: 3rem 2rem; }
.wrapper { max-width: 860px; margin: 0 auto; padding: 3rem 1.5rem; }
.wrapper-sm { max-width: 640px; margin: 0 auto; padding: 2.5rem 1.5rem; }
.wrapper-wide { max-width: 1100px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }

/* ── Card ───────────────────────────────────────────────── */
.card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 22px; padding: 2.5rem 2rem; box-shadow: 0 20px 60px rgba(0,0,0,0.4);
  animation: slide-up 0.4s ease-out both;
}
@keyframes slide-up {
  from { opacity: 0; transform: translateY(20px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* ── Page Header ────────────────────────────────────────── */
.page-header { text-align: center; margin-bottom: 2.5rem; }
.page-header h1 {
  font-size: 2.4rem; font-weight: 800;
  background: linear-gradient(135deg, #fff 0%, #60a5fa 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
  margin-bottom: 0.6rem;
}
.page-header .tagline { color: var(--text-muted); font-size: 1rem; line-height: 1.6; }
.header-icon {
  font-size: 3.5rem; margin-bottom: 1rem; display: inline-block;
  filter: drop-shadow(0 0 24px rgba(59,130,246,0.7));
}

/* ── Form Elements ──────────────────────────────────────── */
.form-group { display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 1.2rem; }
.form-label {
  font-size: 0.85rem; font-weight: 600; color: var(--text-sub);
  text-transform: uppercase; letter-spacing: 0.04em; display: flex; align-items: center; gap: 6px;
}
.form-textarea, .form-input, .ssl-input {
  background: rgba(0,0,0,0.35); border: 1.5px solid var(--border); border-radius: 12px;
  padding: 0.85rem 1rem; color: var(--text-main); font-family: 'Fira Code', monospace;
  font-size: 0.9rem; width: 100%; resize: vertical;
  transition: border-color .25s, box-shadow .25s; outline: none;
}
.form-textarea:focus, .form-input:focus, .ssl-input:focus {
  border-color: var(--blue); box-shadow: 0 0 0 3px rgba(59,130,246,0.15);
}
.form-input { font-family: 'Inter', sans-serif; }
.char-count { font-size: 0.75rem; color: #475569; text-align: right; }
.input-hint { font-size: 0.75rem; color: #475569; margin-top: 0.2rem; }

/* ── Buttons ────────────────────────────────────────────── */
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  padding: 0.75rem 1.8rem; border: none; border-radius: 12px; font-weight: 700;
  font-size: 0.95rem; cursor: pointer; transition: all 0.2s; font-family: 'Inter', sans-serif;
}
.btn-primary {
  background: var(--grad); color: white;
  box-shadow: 0 4px 16px rgba(59,130,246,0.4);
}
.btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(59,130,246,0.55); }
.btn-secondary {
  background: rgba(100,116,139,0.15); color: var(--text-sub);
  border: 1px solid rgba(100,116,139,0.3);
}
.btn-secondary:hover { background: rgba(100,116,139,0.3); }
.btn-encrypt {
  background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); color: white;
  box-shadow: 0 4px 14px rgba(59,130,246,0.35); flex: 1;
}
.btn-encrypt:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(59,130,246,0.5); }
.btn-decrypt {
  background: linear-gradient(135deg, #06b6d4 0%, #0ea5e9 100%); color: white;
  box-shadow: 0 4px 14px rgba(6,182,212,0.35); flex: 1;
}
.btn-decrypt:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(6,182,212,0.5); }
.btn-wide { width: 100%; }

/* ── Alert / Error ──────────────────────────────────────── */
.alert-error {
  display: flex; align-items: center; gap: 10px; padding: 0.85rem 1.2rem;
  border-radius: 12px; background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.25);
  color: #fca5a5; margin-top: 1.2rem; font-size: 0.9rem;
}
.alert-success {
  background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.25); color: #6ee7b7;
  padding: 0.8rem 1.2rem; border-radius: 12px; margin-bottom: 1.2rem; font-size: 0.9rem;
}

/* ── Copy Button ────────────────────────────────────────── */
.copy-btn {
  background: rgba(59,130,246,0.08); border: 1.5px solid rgba(59,130,246,0.2);
  padding: 5px 14px; border-radius: 8px; cursor: pointer; color: #60a5fa;
  font-size: 0.78rem; font-family: 'Inter', sans-serif; transition: all .2s;
}
.copy-btn:hover { background: rgba(59,130,246,0.18); border-color: var(--blue); }

/* ── Divider ────────────────────────────────────────────── */
.divider { border: none; height: 1px; background: var(--border); margin: 1.5rem 0; }

/* ============================================================
   HOME — Dashboard
   ============================================================ */
.hero { text-align: center; color: white; margin-bottom: 3rem; }
.hero h1 { font-size: 2.6rem; margin-bottom: 1rem; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); font-weight: 800; }
.hero p { font-size: 1.1rem; color: var(--text-sub); }
.projects-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.8rem;
}
.project-card {
  background: rgba(255,255,255,0.04); border: 1px solid var(--border);
  border-radius: 20px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.3);
  transition: transform .3s, box-shadow .3s, border-color .3s; text-decoration: none; color: inherit; display: block;
}
.project-card:hover { transform: translateY(-10px); box-shadow: 0 30px 60px rgba(59,130,246,0.25); border-color: rgba(59,130,246,0.5); }
.card-header { padding: 2rem; text-align: center; background: linear-gradient(135deg, rgba(59,130,246,0.1), rgba(6,182,212,0.07)); }
.card-icon { font-size: 3.5rem; margin-bottom: 1rem; }
.card-header h2 { color: var(--text-main); }
.card-body { padding: 1.5rem; color: var(--text-sub); }
.card-body p { margin-bottom: 1rem; line-height: 1.6; }
.card-tags { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; }
.tag { background: rgba(59,130,246,0.1); border: 1px solid rgba(59,130,246,0.2); padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.73rem; color: #60a5fa; }
.btn-card { display: inline-block; margin-top: 1rem; padding: 0.55rem 1.4rem; background: var(--grad); color: white; border-radius: 25px; text-decoration: none; font-weight: 600; font-size: 0.9rem; box-shadow: 0 4px 12px rgba(59,130,246,0.35); }

/* ============================================================
   FPB
   ============================================================ */
.fpb-value { font-size: 48px; font-weight: 800; color: var(--blue); text-align: center; margin: 0.5rem 0; font-family: 'Fira Code', monospace; }
.fpb-status { text-align: center; padding: 0.75rem; border-radius: 8px; font-weight: 600; margin-top: 0.75rem; }
.fpb-status.prime { background: rgba(16,185,129,0.12); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.3); }
.fpb-status.not-prime { background: rgba(239,68,68,0.12); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); }
.fpb-steps { margin-top: 1rem; padding: 1rem; background: rgba(0,0,0,0.2); border-radius: 8px; font-family: 'Fira Code', monospace; font-size: 0.85rem; color: var(--text-sub); border: 1px solid var(--border); }
.fpb-steps pre { white-space: pre-wrap; }
.fpb-result { margin-top: 1.5rem; padding: 1.5rem; background: rgba(59,130,246,0.06); border-radius: 12px; border-left: 4px solid var(--blue); }
.fpb-result h3 { color: var(--text-main); margin-bottom: 1rem; }
.example-btns { margin-top: 1.5rem; padding-top: 1.2rem; border-top: 1px solid var(--border); }
.example-btns h4 { color: var(--text-muted); margin-bottom: 0.75rem; font-size: 0.88rem; }
.example-btns button {
  padding: 0.4rem 0.9rem; background: rgba(59,130,246,0.08); border: 1px solid rgba(59,130,246,0.2);
  border-radius: 8px; cursor: pointer; margin-right: 0.6rem; margin-bottom: 0.6rem; color: #60a5fa;
  font-size: 0.82rem; font-family: 'Inter', sans-serif; transition: background .2s;
}
.example-btns button:hover { background: rgba(59,130,246,0.2); }
.num-row { display: flex; gap: 1rem; }
.num-row .form-group { flex: 1; }
.fpb-btn-row { display: flex; gap: 0.75rem; margin-top: 1rem; }

/* ============================================================
   KRIPTO (Caesar / Vigenère)
   ============================================================ */
.site-header { text-align: center; margin-bottom: 1.8rem; }
.site-header h1 { font-size: 1.9rem; background: var(--grad); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin-bottom: 6px; }
.section-label { font-size: 0.78rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.75rem; }
.radio-group { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.radio-card { display: flex; flex-direction: column; gap: 4px; padding: 1.1rem 1.3rem; background: rgba(59,130,246,0.04); border: 1.5px solid var(--border); border-radius: 12px; cursor: pointer; transition: all .2s; }
.radio-card.active { border-color: var(--blue); background: rgba(59,130,246,0.12); }
.algo-icon { font-size: 1.5rem; }
.algo-name { font-weight: 600; color: var(--text-main); }
.algo-desc { font-size: 0.78rem; color: var(--text-muted); }
.number-input-wrap { display: flex; align-items: center; border: 1.5px solid var(--border); border-radius: 12px; overflow: hidden; }
.num-btn { background: rgba(59,130,246,0.08); border: none; padding: 0 18px; height: 46px; cursor: pointer; font-size: 1.3rem; color: #60a5fa; }
.num-btn:hover { background: rgba(59,130,246,0.18); }
.number-input { border: none !important; text-align: center; width: 80px; background: transparent; color: var(--text-main); font-family: 'Inter', sans-serif; }
.action-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1.5rem; }
.result-section { margin-top: 1.5rem; }
.result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
.result-badge { font-size: 0.78rem; font-weight: 600; padding: 5px 16px; border-radius: 50px; }
.badge-encrypt { background: rgba(59,130,246,0.15); color: #60a5fa; }
.badge-decrypt { background: rgba(6,182,212,0.15); color: #22d3ee; }
.result-text { background: rgba(0,0,0,0.3); border: 1.5px solid var(--border); border-radius: 12px; padding: 1.1rem 1.2rem; font-family: 'Fira Code', monospace; white-space: pre-wrap; word-break: break-word; color: var(--text-sub); line-height: 1.7; }
.info-section { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-top: 2rem; }
.info-card { background: rgba(255,255,255,0.03); border: 1.5px solid rgba(59,130,246,0.1); border-radius: 16px; padding: 1.2rem; text-align: center; transition: border-color .25s, transform .25s; }
.info-card:hover { border-color: rgba(59,130,246,0.35); transform: translateY(-3px); }
.info-card h3, .info-card h4 { font-size: 0.88rem; color: var(--text-main); margin-bottom: 6px; }
.info-card p { font-size: 0.8rem; color: var(--text-muted); }
.info-icon { font-size: 1.8rem; margin-bottom: 0.5rem; }

/* ============================================================
   RSA
   ============================================================ */
.steps-list { display: flex; flex-direction: column; gap: 12px; }
.step-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 20px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.3); animation: slide-up .4s ease-out both; }
.step-header { display: flex; align-items: center; gap: 14px; padding: 1.1rem 1.5rem; color: white; }
.step-alice .step-header { background: linear-gradient(135deg, #1d4ed8 0%, #3b82f6 100%); }
.step-bob   .step-header { background: linear-gradient(135deg, #0369a1 0%, #0ea5e9 100%); }
.step-dec   .step-header { background: linear-gradient(135deg, #047857 0%, #10b981 100%); }
.step-num { width: 32px; height: 32px; border-radius: 50%; background: rgba(255,255,255,0.25); display: flex; align-items: center; justify-content: center; font-size: 0.85rem; font-weight: 800; flex-shrink: 0; }
.step-avatar { font-size: 1.5rem; }
.step-title h2 { font-size: 1rem; font-weight: 700; }
.step-title small { font-size: 0.78rem; opacity: 0.85; }
.step-body { padding: 1.4rem 1.5rem; }
.field { margin-bottom: 1rem; }
.field-label { display: block; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; color: var(--blue); margin-bottom: 6px; }
.field-value { background: rgba(0,0,0,0.2); border: 1.5px solid var(--border); border-radius: 10px; padding: 12px 14px; font-family: 'Courier New', monospace; font-size: 0.78rem; word-break: break-all; white-space: pre-wrap; line-height: 1.55; max-height: 160px; overflow-y: auto; color: var(--text-sub); }
.field-value.cipher { background: rgba(59,130,246,0.06); border-color: var(--blue); color: #93c5fd; }
.field-value.highlight { background: rgba(16,185,129,0.08); border-color: #10b981; color: #6ee7b7; font-size: 1rem; font-weight: 600; max-height: none; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 0.72rem; font-weight: 700; margin-left: 6px; vertical-align: middle; }
.badge-pub { background: rgba(59,130,246,0.15); color: #60a5fa; }
.badge-ok  { background: rgba(16,185,129,0.15); color: #6ee7b7; }
.flow-arrow { text-align: center; font-size: 1.6rem; color: rgba(59,130,246,0.5); margin: 4px 0; }
.rsa-input { width: 100%; padding: 0.75rem 0.9rem; border: 1.5px solid rgba(59,130,246,0.2); border-radius: 10px; color: var(--text-main); background: rgba(0,0,0,0.3); transition: all .2s; outline: none; font-family: 'Inter', sans-serif; font-size: 1rem; margin-bottom: 0.75rem; }
.rsa-input:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(59,130,246,0.2); }
.error-msg { color: #f87171; font-size: 0.85rem; font-weight: 600; margin-top: 8px; }
details { background: rgba(59,130,246,0.05); border: 1px solid var(--border); border-radius: 10px; padding: 12px 16px; margin-top: 1.2rem; }
summary { font-weight: 600; color: #60a5fa; cursor: pointer; outline: none; }

/* ============================================================
   VERIFIKATOR
   ============================================================ */
.verif-wrapper { max-width: 780px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }
.verif-header { text-align: center; color: white; margin-bottom: 2.5rem; }
.verif-header h1 { font-size: 2.2rem; font-weight: 700; margin-bottom: 0.5rem; }
.verif-header p { font-size: 1rem; color: var(--text-sub); }
.verif-step { background: var(--bg-card); border: 1px solid var(--border); border-radius: 20px; padding: 1.8rem 2rem; margin-bottom: 1.5rem; box-shadow: 0 10px 30px rgba(0,0,0,0.25); }
.verif-step-title { display: flex; align-items: center; gap: 0.8rem; margin-bottom: 1.2rem; padding-bottom: 0.8rem; border-bottom: 2px solid var(--border); }
.verif-num { width: 36px; height: 36px; border-radius: 50%; background: var(--grad); color: white; font-weight: 700; font-size: 1rem; display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 2px 8px rgba(59,130,246,0.4); }
.verif-step-title h3 { font-size: 1.05rem; font-weight: 600; color: var(--text-main); }
.verif-textarea { width: 100%; padding: 0.75rem 1rem; border: 2px solid rgba(59,130,246,0.18); border-radius: 12px; color: var(--text-main); background: rgba(0,0,0,0.25); font-size: 0.9rem; font-family: 'Inter', sans-serif; resize: vertical; outline: none; transition: border-color .2s, box-shadow .2s; box-sizing: border-box; }
.verif-textarea:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(59,130,246,0.18); }
.verif-textarea.readonly { background: rgba(0,0,0,0.3); color: var(--text-muted); font-family: 'Fira Code', monospace; font-size: 0.83rem; }
.key-display { background: rgba(0,0,0,0.25); border: 2px dashed rgba(59,130,246,0.25); border-radius: 12px; padding: 0.85rem 1rem; font-family: 'Fira Code', monospace; font-size: 0.85rem; color: var(--text-muted); word-break: break-all; margin-top: 0.75rem; }
.key-display.empty { color: #334155; font-style: italic; }
.verif-result { margin-top: 1rem; padding: 1rem 1.2rem; border-radius: 12px; font-size: 1.05rem; font-weight: 600; text-align: center; }
.result-valid { background: rgba(16,185,129,0.1); border: 2px solid rgba(16,185,129,0.35); color: #6ee7b7; }
.result-invalid { background: rgba(239,68,68,0.1); border: 2px solid rgba(239,68,68,0.35); color: #fca5a5; }
.out-label { font-size: 0.8rem; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: .04em; margin-bottom: 0.4rem; margin-top: 0.8rem; display: block; }
.mt-2 { margin-top: 0.75rem; }

/* ============================================================
   SSL
   ============================================================ */
.ssl-hero { text-align: center; color: white; padding: 3rem 1rem 2rem; }
.ssl-hero h1 { font-size: 2.4rem; font-weight: 700; margin-bottom: 0.5rem; }
.ssl-hero p  { font-size: 1rem; color: var(--text-sub); }
.ssl-main { max-width: 1100px; margin: 0 auto; padding: 0 1.5rem 4rem; display: grid; grid-template-columns: 360px 1fr; gap: 1.5rem; align-items: start; }
.ssl-form-panel { background: var(--bg-card); border: 1px solid rgba(59,130,246,0.2); border-radius: 20px; padding: 2rem 1.8rem; box-shadow: 0 20px 50px rgba(0,0,0,0.3); position: sticky; top: 80px; animation: slide-up .4s ease-out both; }
.form-panel-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.8rem; padding-bottom: 1rem; border-bottom: 2px solid var(--border); }
.form-panel-header h2 { font-size: 1.15rem; font-weight: 700; color: var(--text-main); margin-bottom: 2px; }
.form-panel-header p  { font-size: 0.8rem; color: var(--text-muted); }
.panel-icon { width: 44px; height: 44px; background: var(--grad); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.3rem; flex-shrink: 0; box-shadow: 0 4px 12px rgba(59,130,246,0.4); }
.ssl-field-group { margin-bottom: 1.1rem; }
.ssl-label { display: block; font-size: 0.8rem; font-weight: 600; color: var(--text-sub); margin-bottom: 0.4rem; text-transform: uppercase; letter-spacing: .04em; }
.ssl-input { font-family: 'Inter', sans-serif; }
.ssl-input::placeholder { color: #334155; }
.ssl-error-box { display: flex; align-items: flex-start; gap: .6rem; background: rgba(239,68,68,0.1); border: 2px solid rgba(239,68,68,0.3); color: #fca5a5; padding: .8rem 1rem; border-radius: 12px; margin-bottom: 1.2rem; font-size: .85rem; line-height: 1.5; }
.btn-ssl-generate { width: 100%; padding: .9rem; background: var(--grad); color: white; border: none; border-radius: 25px; font-size: .95rem; font-weight: 700; cursor: pointer; transition: opacity .2s, transform .15s, box-shadow .2s; margin-top: .5rem; box-shadow: 0 4px 16px rgba(59,130,246,0.4); font-family: 'Inter', sans-serif; }
.btn-ssl-generate:hover { opacity: .9; transform: translateY(-2px); box-shadow: 0 8px 24px rgba(59,130,246,0.55); }
.ssl-output-panel { background: #050d1a; border: 1px solid var(--border); border-radius: 20px; box-shadow: 0 20px 50px rgba(0,0,0,0.4); overflow: hidden; min-height: 480px; display: flex; flex-direction: column; animation: slide-up .4s ease-out .08s both; }
.terminal-bar { background: #0a1628; padding: .7rem 1.1rem; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border); flex-shrink: 0; }
.terminal-dots { display: flex; gap: 6px; align-items: center; }
.dot { width: 12px; height: 12px; border-radius: 50%; }
.dot-red { background: #ff5f57; } .dot-yellow { background: #febc2e; } .dot-green { background: #28c840; }
.terminal-title { font-family: 'Fira Code', monospace; font-size: .75rem; color: #334155; }
.terminal-body { flex: 1; padding: 1.8rem; display: flex; flex-direction: column; }
.terminal-ready { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; gap: 1rem; }
.ready-icon { width: 80px; height: 80px; background: rgba(59,130,246,0.12); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2.2rem; border: 2px solid rgba(59,130,246,0.3); }
.terminal-ready h3 { font-size: 1.4rem; font-weight: 700; color: var(--text-main); }
.terminal-ready p  { font-size: .88rem; line-height: 1.7; max-width: 340px; color: #475569; }
.output-section { margin-bottom: 1.5rem; }
.output-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: .65rem; }
.output-badge { display: inline-flex; align-items: center; gap: .4rem; font-family: 'Fira Code', monospace; font-size: .7rem; font-weight: 600; letter-spacing: .08em; padding: .28rem .75rem; border-radius: 6px; }
.badge-key  { background: rgba(59,130,246,0.15); color: #60a5fa; border: 1px solid rgba(59,130,246,0.3); }
.badge-cert { background: rgba(6,182,212,0.15); color: #22d3ee; border: 1px solid rgba(6,182,212,0.3); }
.copy-btn-dark { background: rgba(255,255,255,0.05); border: 1px solid rgba(59,130,246,0.15); color: #64748b; border-radius: 8px; padding: .28rem .75rem; font-size: .78rem; cursor: pointer; transition: all .2s; font-family: 'Inter', sans-serif; }
.copy-btn-dark:hover { background: rgba(59,130,246,0.15); border-color: var(--blue); color: #60a5fa; }
.cert-output-area { width: 100%; background: #020b18; border: 1px solid rgba(59,130,246,0.12); border-radius: 10px; padding: .9rem 1.1rem; font-family: 'Fira Code', monospace; font-size: .75rem; line-height: 1.6; resize: vertical; color: #60a5fa; }
.cert-output-area.key-color { color: #38bdf8; }
.ssl-success-bar { display: flex; align-items: center; gap: .6rem; background: rgba(59,130,246,0.12); border: 1px solid rgba(59,130,246,0.3); color: #93c5fd; padding: .8rem 1.1rem; border-radius: 10px; font-size: .88rem; margin-bottom: 1.2rem; }
.cert-chips { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: 1.3rem; }
.cert-chip { display: flex; flex-direction: column; background: rgba(59,130,246,0.06); border: 1px solid rgba(59,130,246,0.12); border-radius: 10px; padding: .45rem .8rem; min-width: 90px; }
.chip-label { font-size: .62rem; font-weight: 700; text-transform: uppercase; letter-spacing: .07em; color: #334155; }
.chip-val   { font-size: .82rem; font-weight: 600; color: #93c5fd; margin-top: 2px; word-break: break-all; }

/* ============================================================
   XOR Cipher
   ============================================================ */
.theory-card { background: rgba(59,130,246,0.04); border: 1px solid var(--border); border-radius: 20px; padding: 2rem; margin-bottom: 2rem; }
.theory-card h3 { font-size: 1.1rem; font-weight: 700; color: var(--text-main); margin-bottom: .8rem; }
.theory-card p  { color: var(--text-muted); line-height: 1.7; margin-bottom: 1.2rem; }
.theory-card code { background: rgba(59,130,246,0.12); color: #60a5fa; padding: .15rem .4rem; border-radius: 5px; font-family: 'Fira Code', monospace; font-size: .9em; }
.truth-table { display: flex; align-items: flex-start; gap: 2rem; flex-wrap: wrap; }
.truth-table table { border-collapse: collapse; font-family: 'Fira Code', monospace; font-size: .95rem; }
.truth-table th { background: rgba(59,130,246,0.15); color: #60a5fa; padding: .5rem 1.2rem; border: 1px solid rgba(59,130,246,0.2); font-weight: 600; }
.truth-table td { padding: .45rem 1.2rem; border: 1px solid rgba(255,255,255,0.06); text-align: center; color: var(--text-sub); }
.xor-result { color: #38bdf8 !important; font-weight: 700; }
.formula { color: var(--text-muted); font-size: .95rem; line-height: 2; }
.main-card { background: rgba(255,255,255,0.03); border: 1px solid rgba(59,130,246,0.12); border-radius: 24px; padding: 2.5rem; margin-bottom: 2rem; }
.op-tabs { display: flex; gap: .5rem; margin-bottom: 2rem; background: rgba(0,0,0,0.35); padding: .35rem; border-radius: 14px; width: fit-content; }
.op-tab { padding: .6rem 1.8rem; border: none; border-radius: 10px; cursor: pointer; font-size: .95rem; font-weight: 600; font-family: 'Inter', sans-serif; transition: all .25s; color: var(--text-muted); background: transparent; }
.op-tab.active { background: var(--grad); color: white; box-shadow: 0 4px 16px rgba(59,130,246,0.4); }
.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
.results-section { margin-top: 2rem; display: flex; flex-direction: column; gap: 1.5rem; }
.result-title { display: flex; align-items: center; gap: 1rem; }
.badge-green { background: rgba(34,197,94,0.18); color: #4ade80; border: 1px solid rgba(34,197,94,0.3); display: inline-flex; align-items: center; padding: .4rem 1.2rem; border-radius: 20px; font-size: .88rem; font-weight: 700; }
.badge-blue  { background: rgba(59,130,246,0.18); color: #60a5fa; border: 1px solid rgba(59,130,246,0.3); display: inline-flex; align-items: center; padding: .4rem 1.2rem; border-radius: 20px; font-size: .88rem; font-weight: 700; }
.result-block { background: rgba(0,0,0,0.35); border: 1px solid rgba(59,130,246,0.1); border-radius: 14px; overflow: hidden; }
.result-block-header { display: flex; justify-content: space-between; align-items: center; padding: .75rem 1.2rem; background: rgba(59,130,246,0.04); border-bottom: 1px solid rgba(59,130,246,0.08); }
.result-block-label { font-size: .8rem; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: .05em; }
.mono-output { font-family: 'Fira Code', monospace; font-size: .85rem; color: #60a5fa; padding: 1rem 1.2rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; line-height: 1.8; }
.hex-style { color: #38bdf8; letter-spacing: .12em; }
.binary-vis { background: rgba(0,0,0,0.4); border: 1px solid var(--border); border-radius: 14px; padding: 1.5rem; }
.binary-vis h3 { font-size: 1rem; font-weight: 700; color: var(--text-main); margin-bottom: 1.2rem; }
.bin-grid { display: flex; flex-direction: column; gap: 1.5rem; }
.bin-row-group { display: flex; flex-direction: column; gap: .4rem; }
.bin-label { font-size: .82rem; color: var(--text-muted); font-family: 'Fira Code', monospace; }
.bin-label code { color: #60a5fa; }
.result-label { color: #4ade80; }
.result-label code { color: #4ade80; }
.bin-bits { display: flex; gap: 3px; flex-wrap: wrap; }
.bit { width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: .9rem; font-weight: 700; transition: all .3s; }
.bit-p    { background: rgba(59,130,246,0.18); color: #60a5fa; border: 1px solid rgba(59,130,246,0.3); }
.bit-k    { background: rgba(6,182,212,0.18);  color: #22d3ee; border: 1px solid rgba(6,182,212,0.3); }
.bit-zero { background: rgba(75,85,99,0.4);    color: #64748b; border: 1px solid rgba(255,255,255,0.08); }
.bit-one  { background: rgba(34,197,94,0.2);   color: #4ade80; border: 1px solid rgba(34,197,94,0.3); }
.xor-line { font-size: .85rem; color: #334155; font-family: 'Fira Code', monospace; padding: .2rem 0; }
.more-chars { font-size: .82rem; color: #334155; text-align: center; padding: .5rem; border-top: 1px dashed rgba(59,130,246,0.1); margin-top: .5rem; }
.info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }

/* ============================================================
   SHA-256
   ============================================================ */
.stats-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
.stat-card { background: rgba(59,130,246,0.07); border: 1px solid rgba(59,130,246,0.2); border-radius: 16px; padding: 1.2rem; text-align: center; transition: border-color .25s, transform .25s; }
.stat-card:hover { border-color: rgba(59,130,246,0.4); transform: translateY(-3px); }
.stat-number { font-size: 2rem; font-weight: 800; color: var(--blue); font-family: 'Fira Code', monospace; }
.stat-number sup { font-size: 1rem; }
.stat-label  { font-size: .78rem; color: var(--text-muted); margin-top: .25rem; text-transform: uppercase; letter-spacing: .05em; }
.mode-tabs { display: flex; gap: .5rem; margin-bottom: 2rem; background: rgba(0,0,0,0.4); padding: .35rem; border-radius: 14px; width: fit-content; }
.mode-tab { padding: .6rem 1.8rem; border: none; border-radius: 10px; cursor: pointer; font-size: .92rem; font-weight: 600; font-family: 'Inter', sans-serif; transition: all .25s; color: var(--text-muted); background: transparent; }
.mode-tab.active { background: var(--grad); color: white; box-shadow: 0 4px 16px rgba(59,130,246,0.4); }
.mode-panel { display: none; }
.mode-panel.active { display: block; }
.textarea-footer { display: flex; justify-content: space-between; margin-top: .4rem; }
.byte-count { font-size: .75rem; color: #475569; }
.btn-generate { background: var(--grad); color: white; box-shadow: 0 4px 20px rgba(59,130,246,0.4); width: 100%; margin-top: .5rem; padding: .85rem; border: none; border-radius: 12px; font-size: 1rem; font-weight: 700; cursor: pointer; transition: all .25s; font-family: 'Inter', sans-serif; }
.btn-generate:hover { transform: translateY(-2px); box-shadow: 0 8px 28px rgba(59,130,246,0.55); }
.btn-compare { background: linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%); color: white; box-shadow: 0 4px 20px rgba(14,165,233,0.35); width: 100%; margin-top: .5rem; padding: .85rem; border: none; border-radius: 12px; font-size: 1rem; font-weight: 700; cursor: pointer; transition: all .25s; font-family: 'Inter', sans-serif; }
.btn-compare:hover { transform: translateY(-2px); }
.verify-result { display: flex; align-items: center; gap: 1.2rem; padding: 1.2rem 1.5rem; border-radius: 16px; }
.verify-ok   { background: rgba(34,197,94,0.12); border: 1px solid rgba(34,197,94,0.3); }
.verify-fail { background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.3); }
.verify-icon { font-size: 2.5rem; }
.verify-text strong { display: block; font-size: 1.1rem; font-weight: 700; color: var(--text-main); margin-bottom: .25rem; }
.verify-text p { color: var(--text-muted); font-size: .9rem; }
.hash-output-block { background: rgba(0,0,0,0.5); border: 1px solid rgba(59,130,246,0.25); border-radius: 18px; padding: 1.5rem; }
.hash-label { font-size: .78rem; font-weight: 700; color: var(--blue); text-transform: uppercase; letter-spacing: .08em; margin-bottom: 1rem; }
.hash-display { margin-bottom: 1rem; }
.hash-groups { display: flex; flex-wrap: wrap; gap: 4px; }
.hash-group { font-family: 'Fira Code', monospace; font-size: 1rem; font-weight: 600; padding: .3rem .5rem; border-radius: 8px; letter-spacing: .05em; cursor: default; transition: transform .15s; }
.hash-group:hover { transform: scale(1.05); }
.g0 { background: rgba(239,68,68,0.15);   color: #f87171; border: 1px solid rgba(239,68,68,0.2); }
.g1 { background: rgba(59,130,246,0.15);  color: #60a5fa; border: 1px solid rgba(59,130,246,0.2); }
.g2 { background: rgba(34,197,94,0.15);   color: #4ade80; border: 1px solid rgba(34,197,94,0.2); }
.g3 { background: rgba(6,182,212,0.15);   color: #22d3ee; border: 1px solid rgba(6,182,212,0.2); }
.g4 { background: rgba(167,139,250,0.15); color: #a78bfa; border: 1px solid rgba(167,139,250,0.2); }
.g5 { background: rgba(244,114,182,0.15); color: #f472b6; border: 1px solid rgba(244,114,182,0.2); }
.g6 { background: rgba(20,184,166,0.15);  color: #2dd4bf; border: 1px solid rgba(20,184,166,0.2); }
.g7 { background: rgba(14,165,233,0.15);  color: #38bdf8; border: 1px solid rgba(14,165,233,0.2); }
.hash-actions { display: flex; gap: .75rem; flex-wrap: wrap; margin-top: .75rem; }
.hash-visual { background: rgba(0,0,0,0.4); border: 1px solid rgba(59,130,246,0.1); border-radius: 16px; padding: 1.5rem; }
.hash-visual h3 { font-size: 1rem; font-weight: 700; color: var(--text-main); margin-bottom: .5rem; }
.vis-desc { color: var(--text-muted); font-size: .85rem; margin-bottom: 1.2rem; line-height: 1.5; }
.vis-blocks { display: grid; grid-template-columns: repeat(4, 1fr); gap: .75rem; }
.vis-block { border-radius: 12px; padding: .75rem; text-align: center; transition: transform .2s; }
.vis-block:hover { transform: scale(1.04); }
.vis-block-label { font-size: .7rem; text-transform: uppercase; letter-spacing: .1em; opacity: .7; margin-bottom: .4rem; }
.vis-block-hex { font-family: 'Fira Code', monospace; font-size: .85rem; font-weight: 700; word-break: break-all; letter-spacing: .05em; margin-bottom: .35rem; }
.vis-block-dec { font-size: .72rem; opacity: .6; font-family: 'Fira Code', monospace; }
.avalanche-demo { background: rgba(0,0,0,0.4); border: 1px solid rgba(59,130,246,0.1); border-radius: 16px; padding: 1.5rem; }
.avalanche-demo h3 { font-size: 1rem; font-weight: 700; color: var(--text-main); margin-bottom: .4rem; }
.avalanche-demo > p { color: var(--text-muted); font-size: .85rem; margin-bottom: 1.2rem; }
.avalanche-row { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
.av-item { flex: 1; min-width: 0; background: rgba(255,255,255,0.04); border-radius: 12px; padding: 1rem; }
.av-label { font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; color: #475569; margin-bottom: .5rem; }
.av-input { display: block; font-size: .82rem; color: var(--text-main); background: rgba(255,255,255,0.06); padding: .3rem .6rem; border-radius: 6px; margin-bottom: .6rem; }
.av-hash { font-family: 'Fira Code', monospace; font-size: .7rem; color: #4ade80; word-break: break-all; line-height: 1.6; }
.av-hash.different { color: #f87171; }
.av-arrow { font-size: 1.5rem; color: #475569; flex-shrink: 0; }
.diff-badge { margin-top: 1rem; display: inline-flex; align-items: center; background: rgba(59,130,246,0.15); border: 1px solid rgba(59,130,246,0.3); color: #60a5fa; padding: .4rem 1rem; border-radius: 20px; font-size: .82rem; font-weight: 700; }
.compare-table { background: rgba(0,0,0,0.4); border: 1px solid rgba(59,130,246,0.1); border-radius: 16px; padding: 1.5rem; overflow-x: auto; }
.compare-table h3 { font-size: 1rem; font-weight: 700; color: var(--text-main); margin-bottom: 1.2rem; }
.compare-table table { width: 100%; border-collapse: collapse; font-size: .82rem; }
.compare-table th { background: rgba(59,130,246,0.07); color: var(--text-muted); padding: .65rem .9rem; text-align: left; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid rgba(59,130,246,0.1); }
.compare-table td { padding: .65rem .9rem; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: middle; color: var(--text-sub); }
.row-current td { background: rgba(59,130,246,0.06); }
.row-current td:first-child { color: var(--blue); }
.hash-cell { font-family: 'Fira Code', monospace; font-size: .7rem; word-break: break-all; color: var(--text-muted); max-width: 300px; }
.hash-cell.small { font-size: .65rem; }
.len-badge { background: rgba(59,130,246,0.1); color: var(--text-muted); padding: .2rem .5rem; border-radius: 6px; font-size: .75rem; font-family: 'Fira Code', monospace; white-space: nowrap; }
.copy-btn-sm { background: transparent; border: 1px solid rgba(59,130,246,0.15); color: #475569; padding: .25rem .5rem; border-radius: 6px; cursor: pointer; font-size: .75rem; transition: all .2s; }
.copy-btn-sm:hover { border-color: var(--blue); color: #60a5fa; }

/* ── Responsive ─────────────────────────────────────────── */
@media (max-width: 1000px) { .ssl-main { grid-template-columns: 1fr; } .ssl-form-panel { position: static; } }
@media (max-width: 768px) {
  .navbar { padding: .75rem 1.2rem; }
  .dropdown-menu { right: 0; min-width: 200px; }
  .stats-row { grid-template-columns: repeat(2, 1fr); }
  .form-grid { grid-template-columns: 1fr; }
  .action-row { grid-template-columns: 1fr; }
  .info-section { grid-template-columns: 1fr; }
  .radio-group { grid-template-columns: 1fr; }
  .vis-blocks { grid-template-columns: repeat(2, 1fr); }
  .avalanche-row { flex-direction: column; }
  .av-arrow { transform: rotate(90deg); }
  .bit { width: 24px; height: 24px; font-size: .8rem; }
}
@media (max-width: 480px) {
  .logo { font-size: 1.2rem; }
  .dropdown-trigger { font-size: .85rem; padding: .45rem .9rem; }
  .page-header h1 { font-size: 1.8rem; }
  .hero h1 { font-size: 1.9rem; }
}
</style>
</head>
<body>

<!-- ── Navbar ─────────────────────────────────────────────── -->
<nav class="navbar" role="navigation" aria-label="Main navigation">
  <div class="nav-container">
    <a href="uts_kripto.php" class="logo">🔬 CryptoLab</a>
    <div class="nav-dropdown">
      <button id="tools-dropdown-trigger" class="dropdown-trigger"
              aria-haspopup="true" aria-expanded="false" aria-controls="tools-dropdown-menu">
        🔧 Pilih Alat <span class="caret"></span>
      </button>
      <div id="tools-dropdown-menu" class="dropdown-menu" role="menu">
        <?= navItem('home',        $page, '🏠', 'Beranda') ?>
        <div class="dropdown-divider"></div>
        <?= navItem('fpb',         $page, '🔢', 'FPB Calculator') ?>
        <?= navItem('kripto',      $page, '🔐', 'Enkripsi & Dekripsi') ?>
        <?= navItem('rsa',         $page, '🛡️', 'Simulasi RSA') ?>
        <?= navItem('verifikator', $page, '📝', 'Digital Signature') ?>
        <?= navItem('ssl',         $page, '🔏', 'SSL Generator') ?>
        <?= navItem('xor',         $page, '⊕', 'XOR Cipher') ?>
        <?= navItem('sha256',      $page, '🔑', 'SHA-256') ?>
      </div>
    </div>
  </div>
</nav>

<!-- ============================================================
     HOME
     ============================================================ -->
<?php if ($page === 'home'): ?>
<div class="container">
  <div class="hero">
    <h1>🔬 Laboratorium Kriptografi & Matematika</h1>
    <p>Kumpulan alat bantu untuk pembelajaran kriptografi dan algoritma matematika — UTS Kriptografi</p>
  </div>
  <div class="projects-grid">
    <a href="uts_kripto.php?page=fpb" class="project-card">
      <div class="card-header"><div class="card-icon">🔢</div><h2>Kalkulator FPB</h2></div>
      <div class="card-body">
        <p>Menghitung Faktor Persekutuan Terbesar (FPB) menggunakan <strong>Algoritma Euclidean</strong> dengan langkah-langkah detail.</p>
        <div class="card-tags"><span class="tag">Algoritma Euclidean</span><span class="tag">Matematika</span><span class="tag">FPB</span></div>
        <span class="btn-card">Hitung Sekarang →</span>
      </div>
    </a>
    <a href="uts_kripto.php?page=kripto" class="project-card">
      <div class="card-header"><div class="card-icon">🔐</div><h2>Enkripsi & Dekripsi</h2></div>
      <div class="card-body">
        <p>Mengenkripsi dan mendekripsi pesan menggunakan <strong>Caesar Cipher</strong> dan <strong>Vigenère Cipher</strong>.</p>
        <div class="card-tags"><span class="tag">Caesar Cipher</span><span class="tag">Vigenère Cipher</span><span class="tag">Kriptografi</span></div>
        <span class="btn-card">Coba Sekarang →</span>
      </div>
    </a>
    <a href="uts_kripto.php?page=rsa" class="project-card">
      <div class="card-header"><div class="card-icon">🛡️</div><h2>Simulasi RSA</h2></div>
      <div class="card-body">
        <p>Simulasi pengiriman pesan terenkripsi menggunakan <strong>RSA 2048-bit</strong> antara Alice (penerima) dan Bob (pengirim).</p>
        <div class="card-tags"><span class="tag">RSA</span><span class="tag">Asimetris</span><span class="tag">OpenSSL</span></div>
        <span class="btn-card">Lihat Simulasi →</span>
      </div>
    </a>
    <a href="uts_kripto.php?page=verifikator" class="project-card">
      <div class="card-header"><div class="card-icon">📝</div><h2>Digital Signature</h2></div>
      <div class="card-body">
        <p>Menandatangani dan memverifikasi keaslian dokumen menggunakan <strong>HMAC-SHA256</strong> untuk memastikan integritas data.</p>
        <div class="card-tags"><span class="tag">HMAC</span><span class="tag">SHA-256</span><span class="tag">Integritas</span></div>
        <span class="btn-card">Coba Sekarang →</span>
      </div>
    </a>
    <a href="uts_kripto.php?page=ssl" class="project-card">
      <div class="card-header"><div class="card-icon">🔏</div><h2>SSL Certificate Generator</h2></div>
      <div class="card-body">
        <p>Membuat <strong>Private Key RSA-2048</strong> dan <strong>Sertifikat SSL Self-Signed (X.509)</strong> berbasis OpenSSL.</p>
        <div class="card-tags"><span class="tag">RSA-2048</span><span class="tag">X.509</span><span class="tag">OpenSSL</span><span class="tag">TLS/SSL</span></div>
        <span class="btn-card">Buat Sertifikat →</span>
      </div>
    </a>
    <a href="uts_kripto.php?page=xor" class="project-card">
      <div class="card-header"><div class="card-icon">⊕</div><h2>XOR Cipher</h2></div>
      <div class="card-body">
        <p>Enkripsi &amp; dekripsi teks menggunakan <strong>XOR Cipher</strong> dengan visualisasi <strong>Biner</strong> dan <strong>Hexadecimal</strong>.</p>
        <div class="card-tags"><span class="tag">XOR</span><span class="tag">Bin2Hex</span><span class="tag">Bitwise</span></div>
        <span class="btn-card">Enkripsi Sekarang →</span>
      </div>
    </a>
    <a href="uts_kripto.php?page=sha256" class="project-card">
      <div class="card-header"><div class="card-icon">🔑</div><h2>SHA-256 Hash Generator</h2></div>
      <div class="card-body">
        <p>Menghasilkan <strong>SHA-256 cryptographic hash</strong> 256-bit dengan visualisasi blok, efek avalanche, dan perbandingan algoritma hash.</p>
        <div class="card-tags"><span class="tag">SHA-256</span><span class="tag">Hashing</span><span class="tag">One-Way</span></div>
        <span class="btn-card">Generate Hash →</span>
      </div>
    </a>
  </div>
</div>

<!-- ============================================================
     FPB
     ============================================================ -->
<?php elseif ($page === 'fpb'): ?>
<div class="wrapper-sm">
  <div class="card">
    <div class="site-header">
      <div class="header-icon">🔢</div>
      <h1 style="font-size:1.9rem;background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">Kalkulator FPB</h1>
      <p class="tagline" style="margin-top:.3rem;">Algoritma Euclidean — langkah demi langkah</p>
    </div>
    <div class="alert-success" style="font-size:.88rem;">📚 Masukkan dua bilangan bulat positif untuk menghitung FPB menggunakan Algoritma Euclidean.</div>
    <form method="POST" action="uts_kripto.php?page=fpb" id="fpb-form">
      <div class="num-row">
        <div class="form-group">
          <label class="form-label" for="angka1">📊 Angka 1 (Nilai A)</label>
          <input type="number" id="angka1" name="angka1" class="form-input" required min="1" placeholder="Bilangan bulat positif"
                 value="<?= htmlspecialchars($fpb_angka1 ?: '') ?>" style="font-family:'Inter',sans-serif;">
        </div>
        <div class="form-group">
          <label class="form-label" for="angka2">📊 Angka 2 (Nilai B)</label>
          <input type="number" id="angka2" name="angka2" class="form-input" required min="1" placeholder="Bilangan bulat positif"
                 value="<?= htmlspecialchars($fpb_angka2 ?: '') ?>" style="font-family:'Inter',sans-serif;">
        </div>
      </div>
      <div class="fpb-btn-row">
        <button type="submit" name="hitung" class="btn btn-primary">🔍 Hitung FPB</button>
        <button type="button" onclick="resetFPB()" class="btn btn-secondary">🔄 Reset</button>
      </div>
    </form>

    <?php if ($fpb_result): ?>
      <?php if ($fpb_result['error']): ?>
        <div class="alert-error"><span>⚠️</span> <?= htmlspecialchars($fpb_result['error']) ?></div>
      <?php else: ?>
        <div class="fpb-result">
          <h3>📈 Hasil Perhitungan</h3>
          <div class="fpb-value"><?= $fpb_result['gcd'] ?></div>
          <?php $isPrime = ($fpb_result['gcd'] == 1); ?>
          <div class="fpb-status <?= $isPrime ? 'prime' : 'not-prime' ?>">
            <?= $isPrime ? 'RELATIF PRIMA' : 'TIDAK RELATIF PRIMA' ?>
            <br><small><?= $isPrime ? '(FPB = 1 — Kedua bilangan saling prima)' : '(FPB > 1 — Kedua bilangan tidak saling prima)' ?></small>
          </div>
          <div class="fpb-steps">
            <strong>📝 Langkah-langkah Algoritma Euclidean:</strong>
            <pre><?= implode("\n", array_map('htmlspecialchars', $fpb_result['steps'])) ?></pre>
          </div>
          <div style="margin-top:12px;font-size:.8rem;color:#64748b;text-align:center;">
            <strong>Verifikasi:</strong>
            <?= $fpb_angka1 ?> ÷ <?= $fpb_result['gcd'] ?> = <?= $fpb_angka1/$fpb_result['gcd'] ?>,
            <?= $fpb_angka2 ?> ÷ <?= $fpb_result['gcd'] ?> = <?= $fpb_angka2/$fpb_result['gcd'] ?>
          </div>
        </div>
      <?php endif; ?>
    <?php endif; ?>

    <div class="example-btns">
      <h4>💡 Contoh Cepat:</h4>
      <button onclick="setFPB(48,18)">48 dan 18</button>
      <button onclick="setFPB(56,98)">56 dan 98</button>
      <button onclick="setFPB(17,13)">17 dan 13 (Prima)</button>
      <button onclick="setFPB(100,75)">100 dan 75</button>
    </div>
  </div>
</div>

<!-- ============================================================
     KRIPTO (Caesar / Vigenère)
     ============================================================ -->
<?php elseif ($page === 'kripto'): ?>
<div class="wrapper">
  <div class="card">
    <div class="site-header">
      <h1>🔐 Enkripsi & Dekripsi</h1>
      <p class="tagline">Caesar Cipher | Vigenère Cipher</p>
    </div>

    <section class="algo-selector" aria-labelledby="algo-label">
      <p class="section-label" id="algo-label">Pilih Algoritma</p>
      <div class="radio-group" id="algo-group">
        <label class="radio-card <?= ($kripto_algorithm === 'caesar') ? 'active' : '' ?>">
          <input type="radio" name="algorithm_radio" value="caesar" <?= ($kripto_algorithm === 'caesar') ? 'checked' : '' ?> style="display:none">
          <span class="algo-icon">🔤</span>
          <span class="algo-name">Caesar Cipher</span>
          <span class="algo-desc">Pergeseran sederhana A–Z</span>
        </label>
        <label class="radio-card <?= ($kripto_algorithm === 'vigenere') ? 'active' : '' ?>">
          <input type="radio" name="algorithm_radio" value="vigenere" <?= ($kripto_algorithm === 'vigenere') ? 'checked' : '' ?> style="display:none">
          <span class="algo-icon">🔑</span>
          <span class="algo-name">Vigenère Cipher</span>
          <span class="algo-desc">Kunci berupa kata/frasa</span>
        </label>
      </div>
    </section>

    <hr class="divider">

    <form method="POST" action="uts_kripto.php?page=kripto" id="crypto-form">
      <input type="hidden" name="algorithm" id="algorithm-hidden" value="<?= htmlspecialchars($kripto_algorithm) ?>">
      <input type="hidden" name="operation" id="operation-hidden" value="<?= htmlspecialchars($kripto_operation) ?>">

      <div class="form-group">
        <label class="form-label" for="message">✉️ Pesan</label>
        <textarea id="message" name="message" class="form-textarea" placeholder="Ketik pesan di sini…" rows="5" required><?= htmlspecialchars($kripto_input) ?></textarea>
        <span class="char-count"><span id="char-count">0</span> karakter</span>
      </div>

      <div class="form-group key-field" id="caesar-key-group" style="<?= ($kripto_algorithm === 'vigenere') ? 'display:none' : '' ?>">
        <label class="form-label" for="caesar_key">🔢 Key (Pergeseran)</label>
        <div class="number-input-wrap">
          <button type="button" class="num-btn" id="btn-minus">−</button>
          <input type="number" id="caesar_key" name="caesar_key" class="form-input number-input" value="<?= (int)$kripto_caesar_key ?>" min="1" max="25">
          <button type="button" class="num-btn" id="btn-plus">+</button>
        </div>
        <p class="input-hint">Rentang: 1 – 25</p>
      </div>

      <div class="form-group key-field" id="vigenere-key-group" style="<?= ($kripto_algorithm === 'caesar') ? 'display:none' : '' ?>">
        <label class="form-label" for="vigenere_key">🗝️ Key (Kata/Frasa)</label>
        <input type="text" id="vigenere_key" name="vigenere_key" class="form-input" placeholder="Contoh: SECRET" value="<?= htmlspecialchars($kripto_vigenere_key) ?>">
        <p class="input-hint">Hanya huruf (spasi diabaikan)</p>
      </div>

      <div class="action-row">
        <button type="submit" class="btn btn-encrypt" onclick="setOperation('encrypt')">🔒 Enkripsi</button>
        <button type="submit" class="btn btn-decrypt" onclick="setOperation('decrypt')">🔓 Dekripsi</button>
      </div>
    </form>

    <?php if ($kripto_error): ?>
    <div class="alert-error" id="error-box"><span>⚠️</span> <?= htmlspecialchars($kripto_error) ?></div>
    <?php endif; ?>

    <?php if ($kripto_output !== '' && !$kripto_error): ?>
    <section class="result-section" id="result-section">
      <div class="result-header">
        <span class="result-badge <?= $kripto_operation === 'encrypt' ? 'badge-encrypt' : 'badge-decrypt' ?>">
          <?= $kripto_operation === 'encrypt' ? '🔒 Hasil Enkripsi' : '🔓 Hasil Dekripsi' ?>
        </span>
        <button type="button" class="copy-btn" onclick="copyResult()">📋 Salin</button>
      </div>
      <pre class="result-text" id="result-text"><?= htmlspecialchars($kripto_output) ?></pre>
    </section>
    <?php endif; ?>
  </div>

  <section class="info-section" aria-label="Informasi algoritma">
    <div class="info-card"><h3>Caesar Cipher</h3><p>Setiap huruf digeser sebanyak n posisi dalam alfabet.</p></div>
    <div class="info-card"><h3>Vigenère Cipher</h3><p>Menggunakan kata kunci sebagai urutan pergeseran.</p></div>
    <div class="info-card"><h3>Validasi Input</h3><p>Hanya huruf A–Z yang dienkripsi. Spasi, angka, dan simbol dibiarkan.</p></div>
  </section>
</div>

<!-- ============================================================
     RSA
     ============================================================ -->
<?php elseif ($page === 'rsa'): ?>
<div class="wrapper">
  <div class="page-header">
    <h1>🛡️ Simulasi Kirim Surat RSA</h1>
    <p class="tagline">Percakapan satu arah: Bob mengenkripsi pesan, Alice mendekripsinya</p>
  </div>

  <?php if ($rsa_error && !isset($publicKeyAlice)): ?>
    <div class="alert-error"><span>⚠️</span> <?= htmlspecialchars($rsa_error) ?></div>
  <?php else: ?>
  <div class="steps-list">
    <!-- Step 1: Alice Public Key -->
    <div class="step-card step-alice">
      <div class="step-header">
        <div class="step-num">1</div>
        <div class="step-avatar">👩</div>
        <div class="step-title">
          <h2>Public Key Alice <span class="badge badge-pub">Dipublikasikan</span></h2>
          <small>Kunci publik ini bisa dilihat siapa saja, termasuk Bob.</small>
        </div>
      </div>
      <div class="step-body">
        <div class="field">
          <span class="field-label">🔓 Public Key Alice</span>
          <div class="field-value"><?= htmlspecialchars($publicKeyAlice ?? '') ?></div>
          <button type="button" class="copy-btn" style="margin-top:.5rem;" onclick="copyRSA(this, <?= htmlspecialchars(json_encode($publicKeyAlice ?? '')) ?>)">📋 Salin Public Key</button>
        </div>
        <form method="post" action="uts_kripto.php?page=rsa" style="margin-top:1rem;border-top:1px solid var(--border);padding-top:1rem;">
          <button type="submit" name="regenerate" value="1" class="btn btn-secondary">🔄 Generate Ulang Kunci RSA</button>
        </form>
      </div>
    </div>

    <div class="flow-arrow">↓</div>

    <!-- Step 2: Bob encrypt -->
    <div class="step-card step-bob">
      <div class="step-header">
        <div class="step-num">2</div>
        <div class="step-avatar">👨</div>
        <div class="step-title">
          <h2>Bob Menulis Pesan Rahasia</h2>
          <small>Bob akan mengenkripsi pesannya menggunakan Public Key Alice.</small>
        </div>
      </div>
      <div class="step-body">
        <form method="post" action="uts_kripto.php?page=rsa">
          <div class="field">
            <label for="pesan_bob" class="field-label">📝 Pesan Asli (Plaintext)</label>
            <input type="text" id="pesan_bob" name="pesan_bob" class="rsa-input"
                   placeholder="Masukkan pesan, misal: Rahasia Negara X"
                   value="<?= htmlspecialchars($rsa_pesanBob) ?>" required>
          </div>
          <button type="submit" class="btn btn-primary">🔒 Enkripsi &amp; Kirim ke Alice</button>
          <?php if ($rsa_error): ?><div class="error-msg">⚠️ <?= htmlspecialchars($rsa_error) ?></div><?php endif; ?>
        </form>
      </div>
    </div>

    <?php if ($rsa_cipherBase64 !== ''): ?>
    <div class="flow-arrow">↓</div>

    <!-- Step 3: Ciphertext -->
    <div class="step-card step-bob">
      <div class="step-header">
        <div class="step-num">3</div>
        <div class="step-avatar">📨</div>
        <div class="step-title">
          <h2>Ciphertext yang Dikirim Bob</h2>
          <small>Ini adalah data acak yang tidak bisa dibaca tanpa Private Key.</small>
        </div>
      </div>
      <div class="step-body">
        <div class="field">
          <span class="field-label">🔒 Hasil Enkripsi (Base64)</span>
          <div class="field-value cipher"><?= htmlspecialchars($rsa_cipherBase64) ?></div>
          <button type="button" class="copy-btn" style="margin-top:.5rem;" onclick="copyRSA(this, <?= htmlspecialchars(json_encode($rsa_cipherBase64)) ?>)">📋 Salin Ciphertext</button>
        </div>
      </div>
    </div>

    <div class="flow-arrow">↓</div>

    <!-- Step 4: Alice decrypt -->
    <div class="step-card step-dec">
      <div class="step-header">
        <div class="step-num">4</div>
        <div class="step-avatar">👩</div>
        <div class="step-title">
          <h2>Alice Membaca Pesan <span class="badge badge-ok">Sukses</span></h2>
          <small>Alice mendekripsi ciphertext menggunakan Private Key-nya sendiri.</small>
        </div>
      </div>
      <div class="step-body">
        <div class="field">
          <span class="field-label">📬 Pesan Asli Berhasil Didekripsi</span>
          <div class="field-value highlight"><?= htmlspecialchars($rsa_pesanDekripsi) ?></div>
        </div>
        <p style="font-size:.82rem;margin-top:.5rem;color:#475569;">✅ Integritas terjaga — Hanya Alice (pemilik private key) yang bisa membaca pesan ini.</p>
      </div>
    </div>
    <?php endif; ?>

    <details>
      <summary>🔑 Lihat Private Key Alice (rahasia, hanya simulasi)</summary>
      <div class="field" style="margin-top:.75rem;">
        <div class="field-value"><?= htmlspecialchars($privateKeyAlice ?? '') ?></div>
        <button type="button" class="copy-btn" style="margin-top:.5rem;" onclick="copyRSA(this, <?= htmlspecialchars(json_encode($privateKeyAlice ?? '')) ?>)">📋 Salin Private Key</button>
      </div>
    </details>
  </div>
  <?php endif; ?>
</div>

<!-- ============================================================
     VERIFIKATOR
     ============================================================ -->
<?php elseif ($page === 'verifikator'): ?>
<div class="verif-wrapper">
  <div class="verif-header">
    <h1>📝 Verifikator Dokumen</h1>
    <p>Tanda tangani dan verifikasi keaslian dokumen menggunakan HMAC-SHA256</p>
  </div>

  <?php if (!empty($verif_message)): ?>
    <div class="alert-success">ℹ️ <?= htmlspecialchars($verif_message) ?></div>
  <?php endif; ?>

  <!-- Step 1 -->
  <div class="verif-step">
    <div class="verif-step-title">
      <div class="verif-num">1</div>
      <h3>🔑 Generate Key HMAC</h3>
    </div>
    <form method="post" action="uts_kripto.php?page=verifikator">
      <button type="submit" name="generate_key" class="btn btn-primary">🔑 Buat Key Baru</button>
    </form>
    <span class="out-label">Key Saat Ini:</span>
    <div class="key-display <?= empty($_SESSION['key']) ? 'empty' : '' ?>">
      <?= $_SESSION['key'] ? htmlspecialchars($_SESSION['key']) : '(belum ada — klik Buat Key Baru)' ?>
    </div>
  </div>

  <!-- Step 2 -->
  <div class="verif-step">
    <div class="verif-step-title">
      <div class="verif-num">2</div>
      <h3>✍️ Tanda Tangani Dokumen</h3>
    </div>
    <form method="post" action="uts_kripto.php?page=verifikator">
      <label class="form-label" for="dokumen">Isi Dokumen</label>
      <textarea id="dokumen" name="dokumen" rows="4" class="verif-textarea" placeholder="Masukkan teks dokumen yang ingin ditandatangani..."></textarea>
      <div class="mt-2">
        <button type="submit" name="sign" class="btn btn-primary">✍️ Tanda Tangani</button>
      </div>
    </form>
    <?php if (!empty($verif_signed_document)): ?>
      <span class="out-label">Dokumen Tertandatangani (salin untuk verifikasi):</span>
      <textarea readonly rows="3" class="verif-textarea readonly"><?= htmlspecialchars($verif_signed_document) ?></textarea>
    <?php endif; ?>
  </div>

  <!-- Step 3 -->
  <div class="verif-step">
    <div class="verif-step-title">
      <div class="verif-num">3</div>
      <h3>🔍 Verifikasi Keaslian</h3>
    </div>
    <form method="post" action="uts_kripto.php?page=verifikator">
      <label class="form-label" for="signed_document">Tempelkan Dokumen Tertandatangani</label>
      <small style="color:#94a3b8;display:block;margin-bottom:.4rem;">Format: <code style="background:rgba(59,130,246,0.12);color:#60a5fa;padding:.1rem .4rem;border-radius:4px;">DOKUMEN--SIGNATURE</code></small>
      <textarea id="signed_document" name="signed_document" rows="4" class="verif-textarea" placeholder="Contoh: Transfer ke Budi: Rp 100.000--abc123..."></textarea>
      <div class="mt-2">
        <button type="submit" name="verify" class="btn btn-primary">🔍 Verifikasi</button>
      </div>
    </form>
    <?php if (!empty($verif_verification_result)) echo $verif_verification_result; ?>
  </div>
</div>

<!-- ============================================================
     SSL GENERATOR
     ============================================================ -->
<?php elseif ($page === 'ssl'): ?>
<div class="ssl-hero">
  <h1>SSL Certificate Generator</h1>
  <p>Hasilkan RSA Private Key &amp; Sertifikat X.509 Self-Signed berbasis OpenSSL.</p>
</div>

<div class="ssl-main">
  <!-- LEFT: Form -->
  <div class="ssl-form-panel">
    <div class="form-panel-header">
      <div>
        <h2>CSR Identity</h2>
        <p>Input data sertifikat SSL</p>
      </div>
      <div class="panel-icon">🔏</div>
    </div>

    <?php if (!empty($ssl_error)): ?>
    <div class="ssl-error-box"><span>⚠️</span> <span><?= htmlspecialchars($ssl_error) ?></span></div>
    <?php endif; ?>

    <form method="post" action="uts_kripto.php?page=ssl" id="ssl-form" novalidate>
      <div class="ssl-field-group">
        <label class="ssl-label" for="country">Country Code</label>
        <input type="text" id="country" name="country" class="ssl-input form-input" maxlength="2"
               value="<?= htmlspecialchars($_POST['country'] ?? 'ID') ?>" placeholder="ID" required>
      </div>
      <div class="ssl-field-group">
        <label class="ssl-label" for="state">State / Province</label>
        <input type="text" id="state" name="state" class="ssl-input form-input"
               value="<?= htmlspecialchars($_POST['state'] ?? '') ?>" placeholder="Jawa Barat" required>
      </div>
      <div class="ssl-field-group">
        <label class="ssl-label" for="locality">Locality / City</label>
        <input type="text" id="locality" name="locality" class="ssl-input form-input"
               value="<?= htmlspecialchars($_POST['locality'] ?? '') ?>" placeholder="Bandung" required>
      </div>
      <div class="ssl-field-group">
        <label class="ssl-label" for="org">Organization Name</label>
        <input type="text" id="org" name="org" class="ssl-input form-input"
               value="<?= htmlspecialchars($_POST['org'] ?? '') ?>" placeholder="Universitas / Company" required>
      </div>
      <div class="ssl-field-group">
        <label class="ssl-label" for="cn">Common Name / Domain</label>
        <input type="text" id="cn" name="cn" class="ssl-input form-input"
               value="<?= htmlspecialchars($_POST['cn'] ?? '') ?>" placeholder="www.example.com" required>
      </div>
      <button type="submit" class="btn-ssl-generate" id="btn-generate">Generate SSL Certificate</button>
    </form>
  </div>

  <!-- RIGHT: Output Panel -->
  <div class="ssl-output-panel">
    <div class="terminal-bar">
      <div class="terminal-dots">
        <span class="dot dot-red"></span><span class="dot dot-yellow"></span><span class="dot dot-green"></span>
      </div>
      <span class="terminal-title">SSL Certificate Output</span>
      <span></span>
    </div>
    <div class="terminal-body">
      <?php if (empty($ssl_privateKey)): ?>
      <div class="terminal-ready">
        <div class="ready-icon">🔐</div>
        <h3>Ready to Generate</h3>
        <p>Isi seluruh identitas sertifikat pada form sebelah kiri lalu tekan tombol Generate untuk membuat RSA Private Key dan SSL Certificate berbasis OpenSSL.</p>
      </div>
      <?php else: ?>
      <div class="ssl-success-bar"><span>✅</span><span>Sertifikat berhasil dibuat menggunakan RSA-2048 &amp; SHA-256. Berlaku 365 hari.</span></div>
      <div class="cert-chips">
        <div class="cert-chip"><span class="chip-label">Country</span><span class="chip-val"><?= htmlspecialchars(strtoupper($_POST['country'] ?? '')) ?></span></div>
        <div class="cert-chip"><span class="chip-label">State</span><span class="chip-val"><?= htmlspecialchars($_POST['state'] ?? '') ?></span></div>
        <div class="cert-chip"><span class="chip-label">Locality</span><span class="chip-val"><?= htmlspecialchars($_POST['locality'] ?? '') ?></span></div>
        <div class="cert-chip"><span class="chip-label">Organization</span><span class="chip-val"><?= htmlspecialchars($_POST['org'] ?? '') ?></span></div>
        <div class="cert-chip" style="flex:1;min-width:180px;"><span class="chip-label">Common Name</span><span class="chip-val"><?= htmlspecialchars($_POST['cn'] ?? '') ?></span></div>
      </div>
      <div class="output-section">
        <div class="output-header">
          <span class="output-badge badge-key">🔑 PRIVATE KEY — RSA 2048-bit</span>
          <button class="copy-btn-dark" onclick="copySSLText('pkey-out', this)">📋 Copy</button>
        </div>
        <textarea id="pkey-out" class="cert-output-area key-color" rows="12" readonly><?= htmlspecialchars($ssl_privateKey) ?></textarea>
      </div>
      <div class="output-section">
        <div class="output-header">
          <span class="output-badge badge-cert">📜 SSL CERTIFICATE — X.509</span>
          <button class="copy-btn-dark" onclick="copySSLText('cert-out', this)">📋 Copy</button>
        </div>
        <textarea id="cert-out" class="cert-output-area" rows="14" readonly><?= htmlspecialchars($ssl_certificate) ?></textarea>
      </div>
      <?php endif; ?>
    </div>
  </div>
</div>

<!-- ============================================================
     XOR CIPHER
     ============================================================ -->
<?php elseif ($page === 'xor'): ?>
<div class="wrapper">
  <div class="page-header">
    <div class="header-icon">⊕</div>
    <h1>XOR Cipher</h1>
    <p class="tagline">Enkripsi &amp; Dekripsi dengan visualisasi <strong>Biner</strong> dan <strong>Hexadecimal</strong></p>
  </div>

  <div class="theory-card">
    <h3>📖 Cara Kerja XOR Cipher</h3>
    <p>XOR (Exclusive OR) adalah operasi bitwise yang menghasilkan <code>1</code> bila kedua bit berbeda, dan <code>0</code> bila sama. Karena bersifat <em>reversible</em>, operasi enkripsi dan dekripsi menggunakan fungsi yang <strong>identik</strong>.</p>
    <div class="truth-table">
      <table>
        <thead><tr><th>A</th><th>B</th><th>A ⊕ B</th></tr></thead>
        <tbody>
          <tr><td>0</td><td>0</td><td class="xor-result">0</td></tr>
          <tr><td>0</td><td>1</td><td class="xor-result">1</td></tr>
          <tr><td>1</td><td>0</td><td class="xor-result">1</td></tr>
          <tr><td>1</td><td>1</td><td class="xor-result">0</td></tr>
        </tbody>
      </table>
      <p class="formula">🔑 Formula: <code>C = P ⊕ K</code> &nbsp;|&nbsp; <code>P = C ⊕ K</code></p>
    </div>
  </div>

  <div class="main-card">
    <div class="op-tabs">
      <button class="op-tab <?= $xor_operation === 'encrypt' ? 'active' : '' ?>" data-op="encrypt" id="tab-encrypt">🔒 Enkripsi</button>
      <button class="op-tab <?= $xor_operation === 'decrypt' ? 'active' : '' ?>" data-op="decrypt" id="tab-decrypt">🔓 Dekripsi</button>
    </div>

    <form method="POST" action="uts_kripto.php?page=xor" id="xor-form">
      <input type="hidden" name="operation" id="operation-hidden" value="<?= htmlspecialchars($xor_operation) ?>">
      <div class="form-grid">
        <div class="form-group">
          <label class="form-label" for="message">
            <?= $xor_operation === 'encrypt' ? '✉️ Plaintext' : '🔢 Ciphertext (Hex)' ?>
          </label>
          <textarea id="message" name="message" class="form-textarea" rows="5"
            placeholder="<?= $xor_operation === 'encrypt' ? 'Ketik teks yang ingin dienkripsi…' : 'Tempel ciphertext hex di sini…' ?>"
            required><?= htmlspecialchars($xor_input_text) ?></textarea>
          <span class="char-count"><span id="char-count">0</span> karakter</span>
        </div>
        <div class="form-group">
          <label class="form-label" for="key">🔑 Kunci XOR</label>
          <input type="text" id="key" name="key" class="form-input"
            placeholder="Masukkan kunci (contoh: SECRET)"
            value="<?= htmlspecialchars($xor_key) ?>">
          <p class="input-hint">Kunci akan berulang (cycling key) bila lebih pendek dari teks</p>
        </div>
      </div>
      <div class="action-row" style="display:flex;gap:1rem;flex-wrap:wrap;">
        <button type="submit" class="btn btn-primary" id="submit-btn">
          <?= $xor_operation === 'encrypt' ? '🔒 Enkripsi Sekarang' : '🔓 Dekripsi Sekarang' ?>
        </button>
        <button type="button" class="btn btn-secondary" onclick="resetXOR()">↺ Reset</button>
      </div>
    </form>

    <?php if ($xor_error): ?>
    <div class="alert-error"><span>⚠️</span> <?= htmlspecialchars($xor_error) ?></div>
    <?php endif; ?>

    <?php if ($xor_output !== '' && !$xor_error): ?>
    <div class="results-section" id="results">
      <div class="result-title">
        <span class="<?= $xor_operation === 'encrypt' ? 'badge-green' : 'badge-blue' ?>">
          <?= $xor_operation === 'encrypt' ? '🔒 Hasil Enkripsi' : '🔓 Hasil Dekripsi' ?>
        </span>
      </div>
      <div class="result-block">
        <div class="result-block-header">
          <span class="result-block-label">🔢 Output (Hexadecimal)</span>
          <button class="copy-btn" onclick="copyXOR('hex-output')">📋 Salin</button>
        </div>
        <pre class="mono-output hex-style" id="hex-output"><?= htmlspecialchars($xor_output_hex) ?></pre>
      </div>
      <div class="binary-vis">
        <h3>🔬 Visualisasi Biner (karakter pertama)</h3>
        <div class="bin-grid">
          <?php
          $vis_len = min(strlen($xor_input_text), 4);
          for ($i = 0; $i < $vis_len; $i++):
            $p_char = $xor_input_text[$i];
            $k_char = $xor_key[$i % strlen($xor_key)];
            $c_char = $xor_output[$i];
            $p_bits = str_pad(decbin(ord($p_char)), 8, '0', STR_PAD_LEFT);
            $k_bits = str_pad(decbin(ord($k_char)), 8, '0', STR_PAD_LEFT);
            $c_bits = str_pad(decbin(ord($c_char)), 8, '0', STR_PAD_LEFT);
          ?>
          <div class="bin-row-group">
            <div class="bin-label">Teks[<?= $i ?>] = <code><?= htmlspecialchars($p_char) ?></code> (<?= ord($p_char) ?>)</div>
            <div class="bin-bits"><?php for($b=0;$b<8;$b++) echo '<span class="bit bit-p">'.$p_bits[$b].'</span>'; ?></div>
            <div class="bin-label">Key[<?= $i % strlen($xor_key) ?>] = <code><?= htmlspecialchars($k_char) ?></code> (<?= ord($k_char) ?>)</div>
            <div class="bin-bits"><?php for($b=0;$b<8;$b++) echo '<span class="bit bit-k">'.$k_bits[$b].'</span>'; ?></div>
            <div class="xor-line"><span>⊕ XOR</span></div>
            <div class="bin-bits result-bits">
              <?php for($b=0;$b<8;$b++) { $m = ($p_bits[$b] === $k_bits[$b]) ? 'bit-zero' : 'bit-one'; echo '<span class="bit '.$m.'">'.$c_bits[$b].'</span>'; } ?>
            </div>
            <div class="bin-label result-label">Cipher[<?= $i ?>] = <code>0x<?= strtoupper(dechex(ord($c_char))) ?></code> (<?= ord($c_char) ?>)</div>
          </div>
          <?php endfor; ?>
          <?php if (strlen($xor_input_text) > 4): ?>
          <div class="more-chars">… dan <?= strlen($xor_input_text) - 4 ?> karakter lainnya</div>
          <?php endif; ?>
        </div>
      </div>
      <div class="result-block">
        <div class="result-block-header"><span class="result-block-label">🔵 Binary — Input</span><button class="copy-btn" onclick="copyXOR('bin-input')">📋</button></div>
        <pre class="mono-output" id="bin-input"><?= htmlspecialchars($xor_input_bin) ?></pre>
      </div>
      <div class="result-block">
        <div class="result-block-header"><span class="result-block-label">🟡 Binary — Kunci</span><button class="copy-btn" onclick="copyXOR('bin-key')">📋</button></div>
        <pre class="mono-output" id="bin-key"><?= htmlspecialchars($xor_key_bin) ?></pre>
      </div>
      <div class="result-block">
        <div class="result-block-header"><span class="result-block-label">🟢 Binary — Output</span><button class="copy-btn" onclick="copyXOR('bin-output')">📋</button></div>
        <pre class="mono-output" id="bin-output"><?= htmlspecialchars($xor_output_bin) ?></pre>
      </div>
    </div>
    <?php endif; ?>
  </div>

  <div class="info-grid">
    <div class="info-card"><div class="info-icon">⚡</div><h4>Sangat Cepat</h4><p>XOR adalah operasi CPU level paling dasar — digunakan dalam AES, stream cipher, dll.</p></div>
    <div class="info-card"><div class="info-icon">🔄</div><h4>Self-Inverse</h4><p>Enkripsi dan dekripsi menggunakan fungsi yang sama persis. Terapkan dua kali → kembali ke semula.</p></div>
    <div class="info-card"><div class="info-icon">⚠️</div><h4>Peringatan Keamanan</h4><p>XOR sederhana mudah dipecahkan bila kunci lebih pendek dari pesan. Gunakan OTP untuk keamanan penuh.</p></div>
    <div class="info-card"><div class="info-icon">🔢</div><h4>Bin ↔ Hex</h4><p>Setiap byte output ditampilkan dalam biner (8-bit) dan hexadecimal (2 digit) untuk analisis mendalam.</p></div>
  </div>
</div>

<!-- ============================================================
     SHA-256
     ============================================================ -->
<?php elseif ($page === 'sha256'): ?>
<div class="wrapper">
  <div class="page-header">
    <div class="header-icon">🔑</div>
    <h1>SHA-256 Hash Generator</h1>
    <p class="tagline">Menghasilkan <strong>256-bit cryptographic hash</strong> yang unik dan tidak dapat dibalik</p>
  </div>

  <div class="stats-row">
    <div class="stat-card"><div class="stat-number">256</div><div class="stat-label">bit output</div></div>
    <div class="stat-card"><div class="stat-number">64</div><div class="stat-label">karakter hex</div></div>
    <div class="stat-card"><div class="stat-number">2<sup>256</sup></div><div class="stat-label">kemungkinan hash</div></div>
    <div class="stat-card"><div class="stat-number">∞</div><div class="stat-label">panjang input</div></div>
  </div>

  <div class="main-card">
    <div class="mode-tabs">
      <button class="mode-tab active" data-mode="hash" id="tab-hash"># Generate Hash</button>
      <button class="mode-tab" data-mode="compare" id="tab-compare">⚖️ Verifikasi Hash</button>
    </div>

    <form method="POST" action="uts_kripto.php?page=sha256" id="sha-form">
      <input type="hidden" name="action" id="action-hidden" value="<?= htmlspecialchars($_POST['action'] ?? 'hash') ?>">

      <div id="hash-mode" class="mode-panel <?= (($_POST['action'] ?? 'hash') !== 'compare') ? 'active' : '' ?>">
        <div class="form-group">
          <label class="form-label" for="message">📝 Teks / Data Input</label>
          <textarea id="message" name="message" class="form-textarea" rows="6"
            placeholder="Masukkan teks, password, dokumen, atau data apapun…"><?= htmlspecialchars($sha_input_text) ?></textarea>
          <div class="textarea-footer">
            <span class="char-count"><span id="char-count">0</span> karakter</span>
            <span class="byte-count" id="byte-display"></span>
          </div>
        </div>
        <button type="submit" class="btn-generate" id="btn-generate">🔑 Generate Hash</button>
      </div>

      <div id="compare-mode" class="mode-panel <?= (($_POST['action'] ?? 'hash') === 'compare') ? 'active' : '' ?>">
        <div class="form-group">
          <label class="form-label" for="message-cmp">📝 Teks / Data</label>
          <textarea id="message-cmp" class="form-textarea" rows="4" placeholder="Masukkan teks yang ingin diverifikasi…"></textarea>
        </div>
        <div class="form-group">
          <label class="form-label" for="compare_hash">🔍 Hash Pembanding (SHA-256)</label>
          <input type="text" id="compare_hash" name="compare_hash" class="form-input"
            placeholder="Tempelkan hash SHA-256 di sini (64 karakter hex)…"
            value="<?= htmlspecialchars($sha_compare_text) ?>">
        </div>
        <button type="submit" class="btn-compare" id="btn-compare">⚖️ Verifikasi Sekarang</button>
      </div>
    </form>

    <?php if ($sha_error): ?>
    <div class="alert-error"><span>⚠️</span> <?= htmlspecialchars($sha_error) ?></div>
    <?php endif; ?>

    <?php if ($sha_hash_result && !$sha_error): ?>
    <div class="results-section">
      <?php if ($sha_compare_result !== null): ?>
      <div class="verify-result <?= $sha_compare_result ? 'verify-ok' : 'verify-fail' ?>">
        <div class="verify-icon"><?= $sha_compare_result ? '✅' : '❌' ?></div>
        <div class="verify-text">
          <strong><?= $sha_compare_result ? 'Hash Cocok!' : 'Hash Tidak Cocok!' ?></strong>
          <p><?= $sha_compare_result ? 'Data identik — integritas terkonfirmasi.' : 'Data berbeda atau hash salah.' ?></p>
        </div>
      </div>
      <?php endif; ?>

      <div class="hash-output-block">
        <div class="hash-label">SHA-256 Hash</div>
        <div class="hash-display">
          <div class="hash-groups" id="hash-groups">
            <?php foreach ($sha_hash_groups as $idx => $group): ?>
            <span class="hash-group g<?= $idx % 8 ?>" title="Bytes <?= $idx*4+1 ?>–<?= $idx*4+4 ?>"><?= $group ?></span>
            <?php endforeach; ?>
          </div>
        </div>
        <div class="hash-actions">
          <button class="copy-btn" onclick="copySHA('hash-full')">📋 Salin Hash</button>
          <button class="copy-btn" onclick="copyHashUppercase()">📋 Salin UPPERCASE</button>
        </div>
        <input type="hidden" id="hash-full" value="<?= htmlspecialchars($sha_hash_result) ?>">
        <input type="hidden" id="hash-upper-val" value="<?= htmlspecialchars($sha_hash_upper) ?>">
      </div>

      <div class="hash-visual">
        <h3>🎨 Visualisasi Hash (8 blok × 32-bit)</h3>
        <p class="vis-desc">SHA-256 menghasilkan 8 word 32-bit. Setiap blok berwarna berbeda untuk identifikasi:</p>
        <div class="vis-blocks">
          <?php foreach ($sha_hash_groups as $idx => $group): ?>
          <div class="vis-block g<?= $idx % 8 ?>">
            <div class="vis-block-label">W<?= $idx + 1 ?></div>
            <div class="vis-block-hex"><?= strtoupper($group) ?></div>
            <div class="vis-block-dec"><?= hexdec($group) ?></div>
          </div>
          <?php endforeach; ?>
        </div>
      </div>

      <div class="avalanche-demo">
        <h3>🌊 Efek Avalanche</h3>
        <p>Perubahan 1 karakter → hash berubah total (~50% bit berbeda)</p>
        <div class="avalanche-row">
          <div class="av-item">
            <div class="av-label">Input Asli</div>
            <code class="av-input"><?= htmlspecialchars(mb_substr($sha_input_text, 0, 30)) ?><?= mb_strlen($sha_input_text) > 30 ? '…' : '' ?></code>
            <div class="av-hash"><?= strtoupper($sha_hash_result) ?></div>
          </div>
          <?php if (!empty($sha_input_text)):
            $mod_text = $sha_input_text;
            if (strlen($mod_text) > 0) $mod_text[0] = chr(ord($mod_text[0]) + 1);
            $mod_hash = hash('sha256', $mod_text);
            $diff_count = 0;
            for ($i = 0; $i < 64; $i++) if ($sha_hash_result[$i] !== $mod_hash[$i]) $diff_count++;
          ?>
          <div class="av-arrow">→</div>
          <div class="av-item">
            <div class="av-label">Input +1 karakter pertama</div>
            <code class="av-input"><?= htmlspecialchars(mb_substr($mod_text, 0, 30)) ?><?= mb_strlen($mod_text) > 30 ? '…' : '' ?></code>
            <div class="av-hash different"><?= strtoupper($mod_hash) ?></div>
          </div>
          <?php endif; ?>
        </div>
        <?php if (!empty($sha_input_text)): ?>
        <div class="diff-badge"><?= $diff_count ?>/64 karakter hex berbeda (<?= round($diff_count/64*100) ?>%)</div>
        <?php endif; ?>
      </div>

      <?php if (!empty($sha_hash_info)): ?>
      <div class="compare-table">
        <h3>📊 Perbandingan Algoritma Hash</h3>
        <table>
          <thead><tr><th>Algoritma</th><th>Panjang</th><th>Hash Value</th><th></th></tr></thead>
          <tbody>
            <tr class="row-current">
              <td><strong>SHA-256</strong> ✓</td>
              <td><span class="len-badge">64 hex</span></td>
              <td class="hash-cell"><?= strtoupper($sha_hash_result) ?></td>
              <td><button class="copy-btn-sm" onclick="navigator.clipboard.writeText('<?= $sha_hash_result ?>')">📋</button></td>
            </tr>
            <tr>
              <td>MD5</td>
              <td><span class="len-badge">32 hex</span></td>
              <td class="hash-cell"><?= strtoupper($sha_hash_info['md5']) ?></td>
              <td><button class="copy-btn-sm" onclick="navigator.clipboard.writeText('<?= $sha_hash_info['md5'] ?>')">📋</button></td>
            </tr>
            <tr>
              <td>SHA-1</td>
              <td><span class="len-badge">40 hex</span></td>
              <td class="hash-cell"><?= strtoupper($sha_hash_info['sha1']) ?></td>
              <td><button class="copy-btn-sm" onclick="navigator.clipboard.writeText('<?= $sha_hash_info['sha1'] ?>')">📋</button></td>
            </tr>
            <tr>
              <td>SHA-512</td>
              <td><span class="len-badge">128 hex</span></td>
              <td class="hash-cell small"><?= strtoupper($sha_hash_info['sha512']) ?></td>
              <td><button class="copy-btn-sm" onclick="navigator.clipboard.writeText('<?= $sha_hash_info['sha512'] ?>')">📋</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <?php endif; ?>
    </div>
    <?php endif; ?>
  </div>

  <div class="info-grid">
    <div class="info-card"><div class="info-icon">🔒</div><h4>One-Way Function</h4><p>Hash tidak bisa dikembalikan ke teks aslinya (preimage resistance).</p></div>
    <div class="info-card"><div class="info-icon">☄️</div><h4>Collision Resistant</h4><p>Mustahil mencari dua input berbeda yang menghasilkan hash yang sama.</p></div>
    <div class="info-card"><div class="info-icon">🌊</div><h4>Efek Avalanche</h4><p>Perubahan 1-bit pada input mengubah ~50% bit pada output.</p></div>
    <div class="info-card"><div class="info-icon">🏭</div><h4>Digunakan Everywhere</h4><p>Bitcoin, TLS/SSL, Git commits, password storage, digital signatures.</p></div>
  </div>
</div>
<?php endif; ?>

<!-- ── Footer ─────────────────────────────────────────────── -->
<footer>
  <p>Copyright &copy; <?= date('Y') ?> — Dibuat oleh Yogiswara Putra Rainanda</p>
  <p style="margin-top:.4rem;">Mata Kuliah: Kriptografi &nbsp;•&nbsp; UTS Single File Application</p>
</footer>

<!-- ============================================================
     JAVASCRIPT — Semua logika interaktif dalam satu blok
     ============================================================ -->
<script>
/* ── Dropdown Navbar ─────────────────────────────────────── */
(function () {
  'use strict';
  const trigger = document.getElementById('tools-dropdown-trigger');
  const menu    = document.getElementById('tools-dropdown-menu');
  if (!trigger || !menu) return;
  function open()  { trigger.classList.add('open'); trigger.setAttribute('aria-expanded','true');  menu.classList.add('open'); }
  function close() { trigger.classList.remove('open'); trigger.setAttribute('aria-expanded','false'); menu.classList.remove('open'); }
  function toggle(){ menu.classList.contains('open') ? close() : open(); }
  trigger.addEventListener('click', e => { e.stopPropagation(); toggle(); });
  document.addEventListener('click', e => { if (!trigger.contains(e.target) && !menu.contains(e.target)) close(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') { close(); trigger.focus(); } });
  menu.addEventListener('keydown', e => {
    const items = Array.from(menu.querySelectorAll('.dropdown-item'));
    const idx   = items.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); items[(idx+1)%items.length].focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); items[(idx-1+items.length)%items.length].focus(); }
  });
})();

/* ── FPB helpers ─────────────────────────────────────────── */
function setFPB(a, b) {
  const a1 = document.getElementById('angka1');
  const a2 = document.getElementById('angka2');
  if (a1) a1.value = a;
  if (a2) a2.value = b;
}
function resetFPB() {
  const a1 = document.getElementById('angka1');
  const a2 = document.getElementById('angka2');
  if (a1) a1.value = '';
  if (a2) a2.value = '';
  window.location.href = 'uts_kripto.php?page=fpb';
}

/* ── Caesar / Vigenère helpers ───────────────────────────── */
(function () {
  const radioCards   = document.querySelectorAll('.radio-card');
  const radioInputs  = document.querySelectorAll('input[name="algorithm_radio"]');
  const algoHidden   = document.getElementById('algorithm-hidden');
  const caesarGroup  = document.getElementById('caesar-key-group');
  const vigenereGroup= document.getElementById('vigenere-key-group');

  function switchAlgorithm(value) {
    if (!algoHidden) return;
    algoHidden.value = value;
    radioCards.forEach(c => c.classList.remove('active'));
    radioInputs.forEach(r => {
      if (r.value === value) { r.checked = true; r.closest('.radio-card').classList.add('active'); }
    });
    if (caesarGroup)  caesarGroup.style.display  = value === 'caesar'   ? '' : 'none';
    if (vigenereGroup) vigenereGroup.style.display = value === 'vigenere' ? '' : 'none';
  }

  radioCards.forEach(card => {
    card.addEventListener('click', () => {
      const val = card.querySelector('input[type="radio"]').value;
      switchAlgorithm(val);
    });
  });

  // Char counter
  const ta   = document.getElementById('message');
  const cc   = document.getElementById('char-count');
  if (ta && cc) { ta.addEventListener('input', () => cc.textContent = ta.value.length); cc.textContent = ta.value.length; }

  // Number stepper
  const keyInput = document.getElementById('caesar_key');
  const btnMinus = document.getElementById('btn-minus');
  const btnPlus  = document.getElementById('btn-plus');
  if (btnMinus && btnPlus && keyInput) {
    btnMinus.addEventListener('click', () => { let v = parseInt(keyInput.value,10); if (v > 1)  keyInput.value = v-1; });
    btnPlus.addEventListener('click',  () => { let v = parseInt(keyInput.value,10); if (v < 25) keyInput.value = v+1; });
  }

  // Operation flag
  const opHidden = document.getElementById('operation-hidden');
  window.setOperation = function(op) { if (opHidden) opHidden.value = op; };

  // Copy result
  window.copyResult = function() {
    const text = document.getElementById('result-text');
    const btn  = document.querySelector('.copy-btn');
    if (!text || !btn) return;
    navigator.clipboard.writeText(text.textContent.trim()).then(() => {
      btn.textContent = '✅ Disalin!';
      setTimeout(() => btn.textContent = '📋 Salin', 2000);
    });
  };

  // Auto-dismiss error
  const eb = document.getElementById('error-box');
  if (eb) { setTimeout(() => { eb.style.opacity='0'; setTimeout(() => eb.remove(), 500); }, 4000); }
})();

/* ── RSA helpers ─────────────────────────────────────────── */
function copyRSA(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✅ Tersalin!';
    setTimeout(() => btn.textContent = orig, 1800);
  });
}

/* ── SSL helpers ─────────────────────────────────────────── */
function copySSLText(id, btn) {
  const el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.value).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✅ Tersalin!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2200);
  });
}
(function () {
  const form = document.getElementById('ssl-form');
  const btn  = document.getElementById('btn-generate');
  if (form && btn) {
    form.addEventListener('submit', () => {
      btn.disabled = true;
      btn.textContent = '⏳ Memproses...';
    });
  }
})();

/* ── XOR helpers ─────────────────────────────────────────── */
(function () {
  const tabs     = document.querySelectorAll('.op-tab');
  const opHidden = document.getElementById('operation-hidden');
  const msgArea  = document.getElementById('message');
  const submitBtn= document.getElementById('submit-btn');

  tabs.forEach(tab => {
    tab.addEventListener('click', function () {
      tabs.forEach(t => t.classList.remove('active'));
      this.classList.add('active');
      const op = this.dataset.op;
      if (opHidden) opHidden.value = op;
      if (submitBtn) submitBtn.textContent = op === 'encrypt' ? '🔒 Enkripsi Sekarang' : '🔓 Dekripsi Sekarang';
      const msgLabel = document.querySelector('label[for="message"]');
      if (msgLabel) msgLabel.textContent = op === 'encrypt' ? '✉️ Plaintext' : '🔢 Ciphertext (Hex)';
      if (msgArea) msgArea.placeholder = op === 'encrypt' ? 'Ketik teks yang ingin dienkripsi…' : 'Tempel ciphertext hex di sini…';
    });
  });

  const charCountEl = document.getElementById('char-count');
  function updateXORCount() { if (msgArea && charCountEl) charCountEl.textContent = msgArea.value.length; }
  if (msgArea) { msgArea.addEventListener('input', updateXORCount); updateXORCount(); }

  window.copyXOR = function (id) {
    const el = document.getElementById(id);
    if (!el) return;
    const text = el.value !== undefined ? el.value : el.innerText;
    navigator.clipboard.writeText(text).then(() => {
      document.querySelectorAll('.copy-btn').forEach(btn => {
        if (btn.getAttribute('onclick') && btn.getAttribute('onclick').includes(id)) {
          const orig = btn.textContent;
          btn.textContent = '✅ Tersalin!';
          setTimeout(() => btn.textContent = orig, 1800);
        }
      });
    });
  };

  window.resetXOR = function () {
    const form = document.getElementById('xor-form');
    if (form) form.reset();
    if (charCountEl) charCountEl.textContent = '0';
  };

  const results = document.getElementById('results');
  if (results) setTimeout(() => results.scrollIntoView({ behavior: 'smooth', block: 'start' }), 200);
})();

/* ── SHA-256 helpers ─────────────────────────────────────── */
(function () {
  const modeTabs   = document.querySelectorAll('.mode-tab');
  const panels     = document.querySelectorAll('.mode-panel');
  const actionHid  = document.getElementById('action-hidden');
  const msgHash    = document.getElementById('message');
  const msgCmp     = document.getElementById('message-cmp');

  modeTabs.forEach(tab => {
    tab.addEventListener('click', function () {
      modeTabs.forEach(t => t.classList.remove('active'));
      this.classList.add('active');
      const mode = this.dataset.mode;
      panels.forEach(p => p.classList.remove('active'));
      const panel = document.getElementById(mode + '-mode');
      if (panel) panel.classList.add('active');
      if (actionHid) actionHid.value = mode;
      if (mode === 'compare' && msgHash && msgCmp) {
        msgCmp.value = msgHash.value;
        msgCmp.name  = 'message';
        if (msgHash) msgHash.removeAttribute('name');
      } else if (mode === 'hash') {
        if (msgCmp)  msgCmp.removeAttribute('name');
        if (msgHash) msgHash.name = 'message';
      }
    });
  });

  const shaCC  = document.getElementById('char-count');
  const byteD  = document.getElementById('byte-display');
  function updateSHACount() {
    const len = msgHash ? msgHash.value.length : 0;
    if (shaCC) shaCC.textContent = len;
    if (byteD && msgHash) {
      const bytes = new TextEncoder().encode(msgHash.value).length;
      byteD.textContent = bytes !== len ? `(${bytes} bytes)` : '';
    }
  }
  if (msgHash) { msgHash.addEventListener('input', updateSHACount); updateSHACount(); }

  window.copySHA = function (id) {
    const el = document.getElementById(id);
    if (!el) return;
    const text = el.value !== undefined ? el.value : el.innerText.trim();
    navigator.clipboard.writeText(text);
  };

  window.copyHashUppercase = function () {
    const el = document.getElementById('hash-upper-val');
    if (!el) return;
    navigator.clipboard.writeText(el.value);
  };

  const rs = document.querySelector('.results-section');
  if (rs) setTimeout(() => rs.scrollIntoView({ behavior: 'smooth', block: 'start' }), 200);

  document.querySelectorAll('.copy-btn-sm').forEach(btn => {
    btn.addEventListener('click', function () {
      const orig = this.textContent;
      this.textContent = '✅';
      setTimeout(() => this.textContent = orig, 1500);
    });
  });
})();
</script>
</body>
</html>
