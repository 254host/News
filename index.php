<?php
declare(strict_types=1);

/* ==========================================================================
   QuickAds Production Suite — public marketplace (index.php)
   Requires PHP 8.2+, ext-openssl, ext-fileinfo.
   ========================================================================== */

const APP_SECRET     = 'REPLACE_WITH_A_LONG_RANDOM_STRING_AT_LEAST_32_CHARS';
const ADSENSE_CLIENT = '';                 // e.g. 'ca-pub-1234567890123456'; empty disables ad slots
const CURRENCY_LABEL = 'KSh';
const SITE_NAME      = 'QuickAds';
const DB_FILE        = __DIR__ . '/ads.json';
const UPLOAD_DIR     = __DIR__ . '/uploads';
const MAX_IMAGE_BYTES = 2 * 1024 * 1024;

const TAXONOMY = [
    'Electronics' => ['Phones' => [], 'Laptops' => [], 'Cameras' => [], 'Audio' => [], 'Other' => []],
    'Vehicles'    => ['Cars' => [], 'Motorcycles' => [], 'Bicycles' => [], 'Parts' => [], 'Other' => []],
    'Property'    => ['For Sale' => [], 'For Rent' => [], 'Land' => [], 'Commercial' => [], 'Other' => []],
    'Jobs'        => ['Full-time' => [], 'Part-time' => [], 'Freelance' => [], 'Internship' => [], 'Other' => []],
    'Services'    => ['Repairs' => [], 'Cleaning' => [], 'Tutoring' => [], 'Design' => [], 'Other' => []],
    'Other'       => ['Other' => []],
];

/* ---------- Bootstrap / self-initialisation ---------- */

function bootstrap(): void
{
    if (!is_dir(UPLOAD_DIR)) {
        mkdir(UPLOAD_DIR, 0755, true);
    }
    if (!file_exists(DB_FILE)) {
        file_put_contents(DB_FILE, '[]', LOCK_EX);
    }
}
bootstrap();

/* ---------- Ledger I/O ---------- */

function load_ads(): array
{
    $raw = is_file(DB_FILE) ? (string) file_get_contents(DB_FILE) : '[]';
    $data = json_decode($raw, true);
    return is_array($data) ? array_values($data) : [];
}

function save_ads(array $ads): bool
{
    $tmp = DB_FILE . '.' . bin2hex(random_bytes(4)) . '.tmp';
    $json = json_encode(array_values($ads), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false || file_put_contents($tmp, $json, LOCK_EX) === false) {
        return false;
    }
    return rename($tmp, DB_FILE);
}

function new_id(): string
{
    return date('YmdHis') . '_' . bin2hex(random_bytes(8));
}

/* ---------- Recursive taxonomy validation ---------- */

function tax_has_path(array $tree, array $path): bool
{
    if ($path === []) {
        return true;
    }
    $head = array_shift($path);
    if (!array_key_exists($head, $tree)) {
        return false;
    }
    return tax_has_path($tree[$head], $path);
}

function tax_children(array $tree, array $path): array
{
    $node = TAXONOMY;
    foreach ($path as $p) {
        if (!isset($node[$p])) {
            return [];
        }
        $node = $node[$p];
    }
    return array_keys($node);
}

/* ---------- Security helpers ---------- */

function encrypt_contact(string $plain): string
{
    $key = hash('sha256', APP_SECRET, true);
    $iv  = random_bytes(16);
    $cipher = openssl_encrypt($plain, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $cipher);
}

function decrypt_contact(string $payload): string
{
    $raw = base64_decode($payload, true);
    if ($raw === false || strlen($raw) <= 16) {
        return '';
    }
    $key = hash('sha256', APP_SECRET, true);
    $plain = openssl_decrypt(substr($raw, 16), 'aes-256-cbc', $key, OPENSSL_RAW_DATA, substr($raw, 0, 16));
    return $plain === false ? '' : $plain;
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_valid(?string $token): bool
{
    return is_string($token) && isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token);
}

function clean_text(string $s, int $max): string
{
    $s = trim(strip_tags($s));
    $s = preg_replace('/[^\P{C}\n\t]/u', '', $s) ?? '';
    return mb_substr($s, 0, $max);
}

function flash(?string $set = null): ?string
{
    if ($set !== null) {
        $_SESSION['flash'] = $set;
        return null;
    }
    $msg = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return $msg;
}

function format_price(string $raw): string
{
    $num = (float) preg_replace('/[^\d.]/', '', $raw);
    return CURRENCY_LABEL . ' ' . number_format($num, 2);
}

/* ---------- Media firewall ---------- */

function handle_upload(array $file): string
{
    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        return '';
    }
    if ($file['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name'])) {
        throw new RuntimeException('The image could not be uploaded. Try again.');
    }
    if ($file['size'] > MAX_IMAGE_BYTES) {
        throw new RuntimeException('Images must be 2 MB or smaller.');
    }
    $mime = mime_content_type($file['tmp_name']);
    $ext = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp'][$mime] ?? null;
    if ($ext === null) {
        throw new RuntimeException('Only JPG, PNG, or WebP images are accepted.');
    }
    $name = bin2hex(random_bytes(16)) . '.' . $ext;
    if (!move_uploaded_file($file['tmp_name'], UPLOAD_DIR . '/' . $name)) {
        throw new RuntimeException('The image could not be saved. Try again.');
    }
    return 'uploads/' . $name;
}

/* ---------- Controllers ---------- */

function handle_post(): void
{
    if (!csrf_valid($_POST['csrf'] ?? null)) {
        flash('Your session expired. Please try again.');
        return;
    }

    $action = $_POST['action'] ?? '';

    if ($action === 'submit') {
        $title = clean_text((string) ($_POST['title'] ?? ''), 120);
        $desc  = clean_text((string) ($_POST['description'] ?? ''), 2000);
        $cat   = (string) ($_POST['category'] ?? '');
        $sub   = (string) ($_POST['subcategory'] ?? '');
        $price = (string) ($_POST['price'] ?? '');
        $contact = clean_text((string) ($_POST['contact'] ?? ''), 120);

        try {
            if ($title === '' || $desc === '' || $contact === '') {
                throw new RuntimeException('Title, description, and contact are required.');
            }
            if (!tax_has_path(TAXONOMY, [$cat, $sub])) {
                throw new RuntimeException('Choose a valid category and subcategory.');
            }
            if (!is_numeric(preg_replace('/[,\s]/', '', $price))) {
                throw new RuntimeException('Enter a valid price.');
            }
            $image = handle_upload($_FILES['image'] ?? ['error' => UPLOAD_ERR_NO_FILE]);
        } catch (RuntimeException $e) {
            flash($e->getMessage());
            return;
        }

        $ads = load_ads();
        $ads[] = [
            'id'          => new_id(),
            'title'       => $title,
            'category'    => $cat,
            'subcategory' => $sub,
            'price'       => format_price($price),
            'description' => $desc,
            'contact'     => encrypt_contact($contact),
            'image'       => $image,
            'status'      => 'pending',
            'pinned'      => false,
            'date'        => date('Y-m-d H:i'),
        ];
        flash(save_ads($ads)
            ? 'Thanks. Your listing is live after review.'
            : 'Could not save your listing. Please try again.');
        return;
    }

    if ($action === 'message') {
        $id    = (string) ($_POST['id'] ?? '');
        $name  = clean_text((string) ($_POST['name'] ?? ''), 80);
        $email = filter_var(trim((string) ($_POST['email'] ?? '')), FILTER_VALIDATE_EMAIL);
        $body  = clean_text((string) ($_POST['body'] ?? ''), 1000);

        if ($name === '' || $email === false || $body === '') {
            flash('Please fill in your name, a valid email, and a message.');
            return;
        }
        $ad = null;
        foreach (load_ads() as $item) {
            if ($item['id'] === $id && $item['status'] === 'approved') {
                $ad = $item;
                break;
            }
        }
        if ($ad === null) {
            flash('This listing is no longer available.');
            return;
        }
        $sellerAddr = decrypt_contact($ad['contact']);
        if (filter_var($sellerAddr, FILTER_VALIDATE_EMAIL) === false) {
            flash('The seller cannot be reached by email for this listing.');
            return;
        }
        $subject = 'QuickAds enquiry: ' . mb_substr($ad['title'], 0, 80);
        $message = "You have a new enquiry about your listing.\n\n"
                 . "From: {$name}\n\n{$body}\n\n"
                 . "Reply directly to this email to respond to the buyer.";
        $headers = "From: " . SITE_NAME . " <no-reply@" . ($_SERVER['HTTP_HOST'] ?? 'localhost') . ">\r\n"
                 . "Reply-To: {$name} <{$email}>\r\n"
                 . "Content-Type: text/plain; charset=UTF-8";
        flash(mail($sellerAddr, $subject, $message, $headers)
            ? 'Your message was sent to the seller.'
            : 'Your message could not be sent right now.');
        return;
    }
}

/* ---------- Request routing ---------- */

session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    handle_post();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'), true, 303);
    exit;
}

$query    = trim((string) ($_GET['q'] ?? ''));
$catFilter = (string) ($_GET['category'] ?? '');
$subFilter = (string) ($_GET['subcategory'] ?? '');

$listings = array_filter(load_ads(), static function (array $ad) use ($query, $catFilter, $subFilter): bool {
    if (($ad['status'] ?? '') !== 'approved') {
        return false;
    }
    if ($catFilter !== '' && $ad['category'] !== $catFilter) {
        return false;
    }
    if ($subFilter !== '' && $ad['subcategory'] !== $subFilter) {
        return false;
    }
    if ($query !== '') {
        $haystack = mb_strtolower($ad['title'] . ' ' . $ad['description']);
        foreach (preg_split('/\s+/', mb_strtolower($query)) ?: [] as $word) {
            if ($word !== '' && !str_contains($haystack, $word)) {
                return false;
            }
        }
    }
    return true;
});

usort($listings, static function (array $a, array $b): int {
    return [$b['pinned'] ? 1 : 0, $b['date']] <=> [$a['pinned'] ? 1 : 0, $a['date']];
});

$notice = flash();
$token  = csrf_token();
$adsOn  = ADSENSE_CLIENT !== '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars(SITE_NAME) ?> — Local classifieds</title>
<?php if ($adsOn): ?>
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=<?= htmlspecialchars(ADSENSE_CLIENT) ?>" crossorigin="anonymous"></script>
<?php endif; ?>
<style>
:root {
  --paper: #FAF8F3;
  --ink: #1C2B27;
  --moss: #2F5D50;
  --rule: #D9D4C7;
  --marigold: #E3A72F;
  --muted: #6B6F68;
  --danger: #9B2C2C;
  --radius: 4px;
  font-family: "Iowan Old Style", Georgia, "Times New Roman", serif;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--paper); color: var(--ink); line-height: 1.55; }
a { color: var(--moss); }
header { border-bottom: 2px solid var(--ink); padding: 1.25rem 1rem; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 1rem; }
header .wrap { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: baseline; gap: .75rem; }
h1 { font-size: clamp(1.6rem, 3vw, 2.2rem); margin: 0; letter-spacing: -.01em; }
.tagline { color: var(--muted); font-style: italic; }
.notice { background: #EFEBDD; border-left: 4px solid var(--moss); padding: .75rem 1rem; margin: 1rem 0; }
.toolbar { display: grid; gap: .75rem; grid-template-columns: 2fr 1fr 1fr auto; margin: 1.5rem 0; align-items: end; }
label { display: block; font-size: .85rem; color: var(--muted); margin-bottom: .25rem; }
input, select, textarea, button {
  font: inherit; width: 100%; padding: .55rem .65rem; border: 1px solid var(--rule);
  border-radius: var(--radius); background: #fff; color: var(--ink);
}
textarea { min-height: 7rem; resize: vertical; }
button, .btn {
  background: var(--ink); color: var(--paper); border: none; cursor: pointer; width: auto;
  padding: .6rem 1.1rem; text-decoration: none; display: inline-block; border-radius: var(--radius);
}
button:focus-visible, a:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible {
  outline: 3px solid var(--marigold); outline-offset: 2px;
}
.layout { display: grid; grid-template-columns: minmax(0, 1fr) 260px; gap: 1.5rem; }
.grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); }
.card { background: #fff; border: 1px solid var(--rule); border-radius: var(--radius); overflow: hidden; display: flex; flex-direction: column; }
.card.pinned { border-color: var(--marigold); box-shadow: inset 0 3px 0 var(--marigold); }
.card img { width: 100%; height: 160px; object-fit: cover; display: block; background: #EFEBDD; }
.card .body { padding: .85rem; display: flex; flex-direction: column; gap: .4rem; flex: 1; }
.card h2 { font-size: 1.05rem; margin: 0; }
.price { font-weight: bold; color: var(--moss); }
.meta { font-size: .8rem; color: var(--muted); }
.desc { font-size: .92rem; margin: 0; overflow-wrap: anywhere; }
.card details summary { cursor: pointer; color: var(--moss); font-size: .9rem; }
.card details form { display: grid; gap: .5rem; margin-top: .5rem; }
.sidebar { display: flex; flex-direction: column; gap: 1rem; }
.panel { background: #fff; border: 1px solid var(--rule); border-radius: var(--radius); padding: 1rem; }
.panel h2 { font-size: 1.05rem; margin-top: 0; }
.ad-row { margin: 1rem 0; min-height: 90px; }
.ad-slot { min-height: 250px; }
.empty { padding: 2rem; text-align: center; color: var(--muted); border: 1px dashed var(--rule); border-radius: var(--radius); }
footer { margin-top: 3rem; border-top: 1px solid var(--rule); padding: 1rem 0; color: var(--muted); font-size: .85rem; }
@media (max-width: 900px) {
  .toolbar { grid-template-columns: 1fr 1fr; }
  .layout { grid-template-columns: 1fr; }
  .sidebar { order: 2; }
}
@media (max-width: 520px) {
  .toolbar { grid-template-columns: 1fr; }
  .grid { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
</style>
</head>
<body>
<header>
  <div class="wrap">
    <h1><?= htmlspecialchars(SITE_NAME) ?></h1>
    <span class="tagline">Buy, sell, hire, and rent near you.</span>
  </div>
</header>

<main class="wrap">
  <?php if ($notice): ?>
    <div class="notice" role="status"><?= htmlspecialchars($notice) ?></div>
  <?php endif; ?>

  <form class="toolbar" method="get" action="">
    <div>
      <label for="q">Search</label>
      <input id="q" name="q" type="search" value="<?= htmlspecialchars($query) ?>" placeholder="Keywords in title or description">
    </div>
    <div>
      <label for="filter-cat">Category</label>
      <select id="filter-cat" name="category">
        <option value="">All categories</option>
        <?php foreach (array_keys(TAXONOMY) as $c): ?>
          <option value="<?= htmlspecialchars($c) ?>" <?= $c === $catFilter ? 'selected' : '' ?>><?= htmlspecialchars($c) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <div>
      <label for="filter-sub">Subcategory</label>
      <select id="filter-sub" name="subcategory" data-selected="<?= htmlspecialchars($subFilter) ?>">
        <option value="">All subcategories</option>
      </select>
    </div>
    <div><button type="submit">Apply</button></div>
  </form>

  <div class="layout">
    <section aria-label="Listings">
      <?php if ($adsOn): ?>
        <div class="ad-row"><ins class="adsbygoogle" style="display:block" data-ad-client="<?= htmlspecialchars(ADSENSE_CLIENT) ?>" data-ad-format="horizontal" data-full-width-responsive="true"></ins><script>(adsbygoogle = window.adsbygoogle || []).push({});</script></div>
      <?php endif; ?>

      <?php if ($listings === []): ?>
        <div class="empty">No listings match. Try different keywords or post the first one.</div>
      <?php else: ?>
        <div class="grid">
        <?php $i = 0; foreach ($listings as $ad): $i++; ?>
          <article class="card<?= $ad['pinned'] ? ' pinned' : '' ?>">
            <?php if ($ad['image'] !== ''): ?>
              <img src="<?= htmlspecialchars($ad['image']) ?>" alt="<?= htmlspecialchars($ad['title']) ?>" loading="lazy">
            <?php endif; ?>
            <div class="body">
              <?php if ($ad['pinned']): ?><span class="meta">Featured</span><?php endif; ?>
              <h2><?= htmlspecialchars($ad['title']) ?></h2>
              <div class="price"><?= htmlspecialchars($ad['price']) ?></div>
              <div class="meta"><?= htmlspecialchars($ad['category']) ?> · <?= htmlspecialchars($ad['subcategory']) ?> · <?= htmlspecialchars($ad['date']) ?></div>
              <p class="desc"><?= nl2br(htmlspecialchars($ad['description'])) ?></p>
              <details>
                <summary>Message seller</summary>
                <form method="post" action="">
                  <input type="hidden" name="csrf" value="<?= htmlspecialchars($token) ?>">
                  <input type="hidden" name="action" value="message">
                  <input type="hidden" name="id" value="<?= htmlspecialchars($ad['id']) ?>">
                  <input name="name" placeholder="Your name" maxlength="80" required aria-label="Your name">
                  <input name="email" type="email" placeholder="Your email" maxlength="120" required aria-label="Your email">
                  <textarea name="body" placeholder="Your message" maxlength="1000" required aria-label="Message"></textarea>
                  <button type="submit">Send message</button>
                </form>
              </details>
            </div>
          </article>
          <?php if ($adsOn && $i % 6 === 0): ?>
            <div class="ad-row" style="grid-column: 1 / -1"><ins class="adsbygoogle" style="display:block" data-ad-client="<?= htmlspecialchars(ADSENSE_CLIENT) ?>" data-ad-format="fluid" data-ad-layout-key="-fb+5w+4e-db+86" data-full-width-responsive="true"></ins><script>(adsbygoogle = window.adsbygoogle || []).push({});</script></div>
          <?php endif; ?>
        <?php endforeach; ?>
        </div>
      <?php endif; ?>
    </section>

    <aside class="sidebar" aria-label="Post and sponsors">
      <section class="panel" id="post">
        <h2>Post a listing</h2>
        <form method="post" action="#post" enctype="multipart/form-data">
          <input type="hidden" name="csrf" value="<?= htmlspecialchars($token) ?>">
          <input type="hidden" name="action" value="submit">
          <label for="title">Title</label>
          <input id="title" name="title" maxlength="120" required>
          <label for="category" style="margin-top:.6rem">Category</label>
          <select id="category" name="category" required>
            <option value="">Choose…</option>
            <?php foreach (array_keys(TAXONOMY) as $c): ?>
              <option value="<?= htmlspecialchars($c) ?>"><?= htmlspecialchars($c) ?></option>
            <?php endforeach; ?>
          </select>
          <label for="subcategory" style="margin-top:.6rem">Subcategory</label>
          <select id="subcategory" name="subcategory" required>
            <option value="">Choose a category first</option>
          </select>
          <label for="price" style="margin-top:.6rem">Price (<?= htmlspecialchars(CURRENCY_LABEL) ?>)</label>
          <input id="price" name="price" inputmode="decimal" required>
          <label for="description" style="margin-top:.6rem">Description</label>
          <textarea id="description" name="description" maxlength="2000" required></textarea>
          <label for="contact" style="margin-top:.6rem">Your contact email</label>
          <input id="contact" name="contact" type="email" maxlength="120" required>
          <label for="i
