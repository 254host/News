<?php
declare(strict_types=1);

/* ==========================================================================
   QuickAds Production Suite — admin controller (admin.php)
   Set ADMIN_PASSWORD_HASH with:  php -r "echo password_hash('your-password', PASSWORD_DEFAULT);"
   ========================================================================== */

const ADMIN_PASSWORD_HASH = '$2y$10$REPLACE_WITH_OUTPUT_OF_PASSWORD_HASH_COMMAND_000000000000';
const SITE_NAME = 'QuickAds';
const DB_FILE   = __DIR__ . '/ads.json';
const UPLOAD_DIR = __DIR__ . '/uploads';

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

/* ---------- Security helpers ---------- */

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

function is_logged_in(): bool
{
    return ($_SESSION['admin'] ?? false) === true
        && isset($_SESSION['admin_ip'])
        && $_SESSION['admin_ip'] === ($_SERVER['REMOTE_ADDR'] ?? '');
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

function delete_upload(string $relative): void
{
    if ($relative === '' || !str_starts_with($relative, 'uploads/')) {
        return;
    }
    $file = __DIR__ . '/' . basename($relative);
    $realDir = realpath(UPLOAD_DIR);
    $realFile = realpath(UPLOAD_DIR . '/' . basename($relative));
    if ($realDir !== false && $realFile !== false && str_starts_with($realFile, $realDir . DIRECTORY_SEPARATOR) && is_file($realFile)) {
        unlink($realFile);
    }
}

/* ---------- Session ---------- */

session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
    'cookie_secure'   => !empty($_SERVER['HTTPS']),
]);

/* ---------- Logout ---------- */

if (($_GET['action'] ?? '') === 'logout') {
    $_SESSION = [];
    session_destroy();
    header('Location: admin.php', true, 303);
    exit;
}

/* ---------- Login ---------- */

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
    if (!csrf_valid($_POST['csrf'] ?? null)) {
        flash('Session expired. Try again.');
    } elseif (password_verify((string) ($_POST['password'] ?? ''), ADMIN_PASSWORD_HASH)) {
        session_regenerate_id(true);
        $_SESSION['admin'] = true;
        $_SESSION['admin_ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    } else {
        usleep(400000); // slow brute-force attempts
        flash('Incorrect password.');
    }
    header('Location: admin.php', true, 303);
    exit;
}

if (!is_logged_in()) {
    $token = csrf_token();
    $notice = flash();
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?= htmlspecialchars(SITE_NAME) ?> admin — sign in</title>
<style>
:root { --ink:#1C2B27; --paper:#FAF8F3; --rule:#D9D4C7; --danger:#9B2C2C; --moss:#2F5D50; font-family: Georgia, serif; }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:grid; place-items:center; background:var(--paper); color:var(--ink); padding:1rem; }
form { width:min(360px,100%); background:#fff; border:1px solid var(--rule); padding:1.5rem; border-radius:4px; display:grid; gap:.75rem; }
h1 { font-size:1.4rem; margin:0; }
input, button { font:inherit; padding:.6rem; border-radius:4px; border:1px solid var(--rule); width:100%; }
button { background:var(--ink); color:var(--paper); border:none; cursor:pointer; }
button:focus-visible, input:focus-visible { outline:3px solid #E3A72F; outline-offset:2px; }
.err { color: var(--danger); font-size:.9rem; }
@media (prefers-reduced-motion: reduce) { * { transition:none !important; } }
</style>
</head>
<body>
<form method="post" action="admin.php">
  <h1><?= htmlspecialchars(SITE_NAME) ?> admin</h1>
  <?php if ($notice): ?><p class="err" role="alert"><?= htmlspecialchars($notice) ?></p><?php endif; ?>
  <input type="hidden" name="csrf" value="<?= htmlspecialchars($token) ?>">
  <input type="hidden" name="action" value="login">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" required autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
</body>
</html>
<?php
    exit;
}

/* ---------- Moderation actions (GET with CSRF token) ---------- */

$action = (string) ($_GET['action'] ?? '');
if (in_array($action, ['approve', 'pin', 'delete'], true)) {
    if (!csrf_valid($_GET['csrf'] ?? null)) {
        flash('Action rejected: session token mismatch.');
    } else {
        $id = (string) ($_GET['id'] ?? '');
        $ads = load_ads();
        $found = false;
        foreach ($ads as $key => $ad) {
            if (($ad['id'] ?? '') !== $id) {
                continue;
            }
            $found = true;
            if ($action === 'approve') {
                $ads[$key]['status'] = 'approved';
                flash('Listing approved.');
            } elseif ($action === 'pin') {
                if (($ad['status'] ?? '') !== 'approved') {
                    flash('Approve the listing before pinning it.');
                    break;
                }
                $ads[$key]['pinned'] = !($ad['pinned'] ?? false);
                flash($ads[$key]['pinned'] ? 'Listing pinned to the top.' : 'Listing unpinned.');
            } else {
                delete_upload((string) ($ad['image'] ?? ''));
                unset($ads[$key]);
                $ads = array_values($ads);
                flash('Listing and image deleted.');
            }
            break;
        }
        if (!$found) {
            flash('Listing not found.');
        } elseif (!save_ads($ads)) {
            flash('Could not write the ledger. Check file permissions.');
        }
    }
    header('Location: admin.php', true, 303);
    exit;
}

/* ---------- Dashboard data ---------- */

$ads = load_ads();
$pending  = array_values(array_filter($ads, static fn($a) => ($a['status'] ?? '') === 'pending'));
$approved = array_values(array_filter($ads, static fn($a) => ($a['status'] ?? '') === 'approved'));
$pinned   = array_values(array_filter($approved, static fn($a) => !empty($a['pinned'])));
$token    = csrf_token();
$notice   = flash();

$byDate = static fn(array $a, array $b): int => strcmp($b['date'] ?? '', $a['date'] ?? '');
usort($pending, $byDate);
usort($pinned, $byDate);

function render_rows(array $items, bool $showApprove, string $token): void
{
    if ($items === []) {
        echo '<tr><td colspan="6" class="muted">None.</td></tr>';
        return;
    }
    foreach ($items as $ad) {
        $id = htmlspecialchars($ad['id']);
        $tok = htmlspecialchars($token);
        echo '<tr>';
        echo '<td>' . htmlspecialchars($ad['title']) . '</td>';
        echo '<td>' . htmlspecialchars($ad['category']) . ' / ' . htmlspecialchars($ad['subcategory']) . '</td>';
        echo '<td>' . htmlspecialchars($ad['price']) . '</td>';
        echo '<td>' . htmlspecialchars($ad['date']) . '</td>';
        echo '<td>' . (!empty($ad['image']) ? '<a href="' . htmlspecialchars($ad['image']) . '" target="_blank" rel="noopener">View</a>' : '—') . '</td>';
        echo '<td class="actions">';
        if ($showApprove) {
            echo '<a class="btn ok" href="?action=approve&amp;id=' . $id . '&amp;csrf=' . $tok . '">Approve</a>';
        } else {
            echo '<a class="btn" href="?action=pin&amp;id=' . $id . '&amp;csrf=' . $tok . '">' . (!empty($ad['pinned']) ? 'Unpin' : 'Pin') . '</a>';
        }
        echo '<a class="btn danger" href="?action=delete&amp;id=' . $id . '&amp;csrf=' . $tok . '" onclick="return confirm(\'Delete this listing and its image permanently?\')">Delete</a>';
        echo '</td></tr>';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?= htmlspecialchars(SITE_NAME) ?> admin</title>
<style>
:root { --ink:#1C2B27; --paper:#FAF8F3; --rule:#D9D4C7; --moss:#2F5D50; --marigold:#E3A72F; --danger:#9B2C2C; --muted:#6B6F68; font-family: Georgia, serif; }
* { box-sizing: border-box; }
body { margin:0; background:var(--paper); color:var(--ink); line-height:1.5; }
header { border-bottom:2px solid var(--ink); padding:1rem; display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:.5rem; }
header h1 { margin:0; font-size:1.4rem; }
main { max-width:1100px; margin:0 auto; padding:1rem; display:grid; gap:1.5rem; }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:.75rem; }
.stat { background:#fff; border:1px solid var(--rule); border-radius:4px; padding:1rem; }
.stat strong { display:block; font-size:1.8rem; }
.muted { color:var(--muted); font-size:.9rem; }
.notice { background:#EFEBDD; border-left:4px solid var(--moss); padding:.7rem 1rem; }
section { background:#fff; border:1px solid var(--rule); border-radius:4px; padding:1rem; overflow-x:auto; }
h2 { font-size:1.1rem; margin-top:0; }
table { width:100%; border-collapse:collapse; font-size:.92rem; min-width:620px; }
th, td { text-align:left; padding:.55rem .5rem; border-bottom:1px solid var(--rule); vertical-align:top; }
th { font-size:.8rem; color:var(--muted); font-weight:normal; text-transform:none; }
.actions { white-space:nowrap; }
.btn { display:inline-block; padding:.35rem .65rem; border:1px solid var(--ink); border-radius:4px; color:var(--ink); text-decoration:none; font-size:.85rem; margin-right:.3rem; }
.btn.ok { background:var(--moss); border-color:var(--moss); color:#fff; }
.btn.danger { border-color:var(--danger); color:var(--danger); }
.btn:focus-visible, header a:focus-visible { outline:3px solid var(--marigold); outline-offset:2px; }
header a { color:var(--ink); }
@media (prefers-reduced-motion: reduce) { * { transition:none !important; } }
</style>
</head>
<body>
<header>
  <h1><?= htmlspecialchars(SITE_NAME) ?> · Operations</h1>
  <a href="admin.php?action=logout">Sign out</a>
</header>
<main>
  <?php if ($notice): ?><div class="notice" role="status"><?= htmlspecialchars($notice) ?></div><?php endif; ?>

  <div class="stats">
    <div class="stat"><span class="muted">Total listings</span><strong><?= count($ads) ?></strong></div>
    <div class="stat"><span class="muted">Awaiting review</span><strong><?= count($pending) ?></strong></div>
    <div class="stat"><span class="muted">Live</span><strong><?= count($approved) ?></strong></div>
    <div class="stat"><span class="muted">Pinned</span><strong><?= count($pinned) ?></strong></div>
  </div>

  <section aria-labelledby="pending-h">
    <h2 id="pending-h">Pending review</h2>
    <table>
      <thead><tr><th>Title</th><th>Category</th><th>Price</th><th>Submitted</th><th>Image</th><th>Actions</th></tr></thead>
      <tbody><?php render_rows($pending, true, $token); ?></tbody>
    </table>
  </section>

  <section aria-labelledby="pinned-h">
    <h2 id="pinned-h">Pinned listings</h2>
    <table>
      <thead><tr><th>Title</th><th>Category</th><th>Price</th><th>Submitted</th><th>Image</th><th>Actions</th></tr></thead>
      <tbody><?php render_rows($pinned, false, $token); ?></tbody>
    </table>
  </section>

  <section aria-labelledby="live-h">
    <h2 id="live-h">Live listings</h2>
    <table>
      <thead><tr><th>Title</th><th>Category</th><th>Price</th><th>Submitted</th><th>Image</th><th>Actions</th></tr></thead>
      <tbody><?php
        $live = array_values(array_filter($approved, static fn($a) => empty($a['pinned'])));
        usort($live, $byDate);
        render_rows($live, false, $token);
      ?></tbody>
    </table>
  </section>
</main>
</body>
</html>
