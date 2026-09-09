<?php
/**
 * SecureFlat CMS v1.1.1 — Flat-File CMS с усиленной защитой и поддержкой CSS-фреймворков
 * Исправление: Добавлена обработка ошибок установки, фоллбэк хеширования и проверка прав.
 */

declare(strict_types=1);

define('SF_VERSION', '1.2.0');
define('SF_DATA', __DIR__ . '/sf_data');
define('SF_PAGES', SF_DATA . '/pages');
define('SF_UPLOADS', SF_DATA . '/uploads');
define('SF_THEMES', SF_DATA . '/themes');
define('SF_CONFIG', SF_DATA . '/config.json');
define('SF_USERS', SF_DATA . '/users.json');
define('SF_LOG', SF_DATA . '/log.json');
define('SF_RATE', SF_DATA . '/rate_limit.json');

error_reporting(0);
ini_set('display_errors', '0');
mb_internal_encoding('UTF-8');

function sf_start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) return;
    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || 
                (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    session_start([
        'cookie_httponly'  => true,
        'cookie_secure'    => $is_https,
        'cookie_samesite'  => 'Strict',
        'use_strict_mode'  => true,
        'use_only_cookies' => true,
        'name'             => 'SF_SID',
    ]);
}

function sf_csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function sf_verify_csrf(): bool
{
    $token = $_POST['csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    return hash_equals((string)($_SESSION['csrf'] ?? ''), (string)$token);
}

function sf_csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . htmlspecialchars(sf_csrf_token(), ENT_QUOTES, 'UTF-8') . '">';
}

function sf_clean_html(string $html): string
{
    $dangerous_tags = 'script|style|iframe|object|embed|form|input|textarea|select|button|link|meta|base|svg|math';
    $html = preg_replace('#<(' . $dangerous_tags . ')[^>]*>.*?</\1>#is', '', $html);
    $html = preg_replace('#<(' . $dangerous_tags . ')[^>]*/?>#is', '', $html);
    $html = preg_replace('/\bon[a-z]+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]*)/i', '', $html);
    $html = preg_replace('#(href|src|action)\s*=\s*["\']?\s*(javascript|vbscript|data)\s*:[^"\'>\s]*["\']?#i', '$1="#"', $html);
    $allowed_tags = '<p><br><h1><h2><h3><h4><h5><h6><strong><em><u><s><del><a><img><ul><ol><li><blockquote><pre><code><hr><div><span><table><thead><tbody><tr><th><td><figure><figcaption><sub><sup><mark>';
    $html = strip_tags($html, $allowed_tags);
    $allowed_attrs = ['href', 'src', 'alt', 'title', 'class', 'id', 'width', 'height', 'target', 'rel', 'style'];
    $html = preg_replace_callback('#<(\w+)([^>]*)>#', function($m) use ($allowed_attrs) {
        $tag = strtolower($m[1]);
        $attrs_str = $m[2];
        $clean_attrs = '';
        if (preg_match_all('#(\w[\w-]*)\s*=\s*("([^"]*)"|\'([^\']*)\'|(\S+))#', $attrs_str, $attrs, PREG_SET_ORDER)) {
            foreach ($attrs as $a) {
                $name = strtolower($a[1]);
                $val  = $a[3] ?? $a[4] ?? $a[5] ?? '';
                if (in_array($name, $allowed_attrs, true) && !str_starts_with($name, 'on')) {
                    if (in_array($name, ['href', 'src'], true) && preg_match('/^(javascript|vbscript|data):/i', trim($val))) {
                        continue;
                    }
                    $clean_attrs .= ' ' . $name . '="' . htmlspecialchars($val, ENT_QUOTES, 'UTF-8') . '"';
                }
            }
        }
        return "<{$tag}{$clean_attrs}>";
    }, $html);
    return $html;
}

function sf_secure_path(string $base, string $relative): string|false
{
    $relative = str_replace(["\0", '\\'], ['', '/'], $relative);
    $relative = ltrim($relative, '/');
    if (str_contains($relative, '../') || str_contains($relative, '..')) return false;
    $base_real = realpath($base);
    if ($base_real === false) return false;
    $full = $base_real . DIRECTORY_SEPARATOR . $relative;
    $real = realpath($full);
    if ($real === false) {
        $dir_real = realpath(dirname($full));
        if ($dir_real === false || !str_starts_with($dir_real, $base_real)) return false;
        return $full;
    }
    if (!str_starts_with($real, $base_real . DIRECTORY_SEPARATOR) && $real !== $base_real) return false;
    return $real;
}

function sf_json_save(string $path, mixed $data): bool
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0755, true)) return false;
    }
    $tmp = $path . '.tmp.' . bin2hex(random_bytes(4));
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    if (file_put_contents($tmp, $json, LOCK_EX) === false) return false;
    return rename($tmp, $path);
}

function sf_json_load(string $path, mixed $default = null): mixed
{
    if (!file_exists($path)) return $default;
    $data = json_decode(file_get_contents($path), true);
    return json_last_error() === JSON_ERROR_NONE ? ($data ?? $default) : $default;
}

function sf_rate_check(string $key, int $max = 5, int $window = 900): bool
{
    $rates = sf_json_load(SF_RATE, []);
    $now = time();
    $entry = $rates[$key] ?? ['count' => 0, 'start' => $now];
    if ($now - $entry['start'] > $window) $entry = ['count' => 0, 'start' => $now];
    if ($entry['count'] >= $max) {
        sf_json_save(SF_RATE, $rates);
        return false;
    }
    $entry['count']++;
    $rates[$key] = $entry;
    sf_json_save(SF_RATE, $rates);
    return true;
}

function sf_rate_reset(string $key): void
{
    $rates = sf_json_load(SF_RATE, []);
    unset($rates[$key]);
    sf_json_save(SF_RATE, $rates);
}

function sf_slug(string $text): string
{
    $text = mb_strtolower($text, 'UTF-8');
    $map = ['а'=>'a','б'=>'b','в'=>'v','г'=>'g','д'=>'d','е'=>'e','ё'=>'yo','ж'=>'zh','з'=>'z','и'=>'i','й'=>'y','к'=>'k','л'=>'l','м'=>'m','н'=>'n','о'=>'o','п'=>'p','р'=>'r','с'=>'s','т'=>'t','у'=>'u','ф'=>'f','х'=>'kh','ц'=>'ts','ч'=>'ch','ш'=>'sh','щ'=>'sch','ъ'=>'','ы'=>'y','ь'=>'','э'=>'e','ю'=>'yu','я'=>'ya'];
    $text = strtr($text, $map);
    $text = preg_replace('/[^a-z0-9\s-]/', '', $text);
    $text = preg_replace('/[\s-]+/', '-', trim($text));
    return substr($text, 0, 80) ?: 'page-' . bin2hex(random_bytes(3));
}

function sf_redirect(string $url): never
{
    header('Location: ' . $url);
    exit;
}

function sf_msg(string $text, string $type = 'ok'): void
{
    $_SESSION['flash'] = ['text' => $text, 'type' => $type];
}

function sf_get_msg(): ?array
{
    $msg = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return $msg;
}

function sf_log(string $action, string $detail = ''): void
{
    $log = sf_json_load(SF_LOG, []);
    $log[] = ['time' => date('Y-m-d H:i:s'), 'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown', 'action' => $action, 'detail' => $detail];
    if (count($log) > 500) $log = array_slice($log, -500);
    sf_json_save(SF_LOG, $log);
}

function sf_installed(): bool
{
    return file_exists(SF_CONFIG) && (sf_json_load(SF_CONFIG)['installed'] ?? false);
}

function sf_config(): array
{
    return sf_json_load(SF_CONFIG, [
        'site_name' => 'SecureFlat CMS',
        'site_desc' => '',
        'footer' => '© ' . date('Y'),
        'menu' => [],
        'custom_css' => '',
        'disable_def_css' => false,
        'active_theme' => 'default',
        'installed' => false,
    ]);
}

function sf_save_config(array $cfg): bool
{
    return sf_json_save(SF_CONFIG, $cfg);
}

function sf_pages(): array
{
    $pages = [];
    if (!is_dir(SF_PAGES)) return $pages;
    $files = glob(SF_PAGES . '/*.json');
    if (!$files) return $pages;
    foreach ($files as $f) {
        $p = sf_json_load($f);
        if ($p) $pages[$p['slug']] = $p;
    }
    uasort($pages, fn($a, $b) => ($a['sort'] ?? 999) <=> ($b['sort'] ?? 999));
    return $pages;
}

function sf_page(string $slug): ?array
{
    $slug = sf_slug($slug);
    $path = SF_PAGES . '/' . $slug . '.json';
    if (!file_exists($path)) return null;
    return sf_json_load($path);
}

function sf_save_page(array $page): bool
{
    $new_slug = sf_slug($page['slug'] ?: $page['title']);
    $old_slug = $page['_old_slug'] ?? '';
    if ($old_slug !== $new_slug && file_exists(SF_PAGES . '/' . $new_slug . '.json')) {
        sf_msg('Страница с таким URL уже существует.', 'err');
        return false;
    }
    $page['slug'] = $new_slug;
    $page['updated_at'] = date('Y-m-d H:i:s');
    if (empty($page['created_at'])) $page['created_at'] = $page['updated_at'];
    $page['content'] = sf_clean_html($page['content'] ?? '');
    $page['title'] = htmlspecialchars(strip_tags($page['title'] ?? ''), ENT_QUOTES, 'UTF-8');
    $page['meta_desc'] = htmlspecialchars(strip_tags($page['meta_desc'] ?? ''), ENT_QUOTES, 'UTF-8');
    $page['status'] = in_array($page['status'] ?? 'published', ['published', 'draft'], true) ? $page['status'] : 'published';
    $page['sort'] = (int)($page['sort'] ?? 0);
    unset($page['_old_slug']);
    return sf_json_save(SF_PAGES . '/' . $page['slug'] . '.json', $page);
}

function sf_delete_page(string $slug): bool
{
    $slug = sf_slug($slug);
    $path = SF_PAGES . '/' . $slug . '.json';
    if (file_exists($path)) {
        unlink($path);
        $cfg = sf_config();
        $cfg['menu'] = array_values(array_filter($cfg['menu'] ?? [], fn($s) => $s !== $slug));
        sf_save_config($cfg);
        return true;
    }
    return false;
}

function sf_uploads_list(): array
{
    $files = [];
    if (!is_dir(SF_UPLOADS)) return $files;
    $items = scandir(SF_UPLOADS);
    if (!$items) return $files;
    foreach ($items as $f) {
        if ($f[0] === '.') continue;
        $path = SF_UPLOADS . '/' . $f;
        if (!is_file($path)) continue;
        $files[] = ['name' => $f, 'size' => filesize($path), 'time' => date('Y-m-d H:i', filemtime($path)), 'url' => '?file=' . urlencode($f)];
    }
    usort($files, fn($a, $b) => $b['time'] <=> $a['time']);
    return $files;
}

function sf_is_admin(): bool
{
    if (empty($_SESSION['sf_admin'])) return false;
    $current_ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (isset($_SESSION['sf_ip']) && $_SESSION['sf_ip'] !== $current_ip) {
        sf_logout();
        return false;
    }
    return true;
}

function sf_login(string $pass): bool
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (!sf_rate_check('login_' . $ip, 5, 900)) {
        sf_msg('Слишком много попыток. Подождите 15 минут.', 'err');
        return false;
    }
    $users = sf_json_load(SF_USERS, []);
    $hash = $users['admin']['hash'] ?? '';
    if (password_verify($pass, $hash)) {
        sf_rate_reset('login_' . $ip);
        session_regenerate_id(true);
        $_SESSION['sf_admin'] = true;
        $_SESSION['sf_ip'] = $ip;
        sf_log('login', 'success');
        return true;
    }
    sf_log('login', 'failed from ' . $ip);
    sf_msg('Неверный пароль.', 'err');
    return false;
}

function sf_logout(): void
{
    sf_log('logout');
    $_SESSION = [];
    session_destroy();
}

function sf_install(string $password): bool
{
    if (sf_installed()) return false;
    foreach ([SF_DATA, SF_PAGES, SF_UPLOADS, SF_THEMES] as $d) {
        if (!is_dir($d)) {
            if (!mkdir($d, 0755, true)) {
                sf_msg('Нет прав на создание папки ' . basename($d), 'err');
                return false;
            }
        }
        if (!is_writable($d)) {
            sf_msg('Папка ' . basename($d) . ' недоступна для записи.', 'err');
            return false;
        }
    }
    $htaccess = SF_DATA . '/.htaccess';
    if (!file_exists($htaccess)) {
        file_put_contents($htaccess, "Deny from all\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\nOptions -Indexes\n");
    }
    file_put_contents(SF_DATA . '/index.html', '');
    file_put_contents(SF_PAGES . '/index.html', '');
    file_put_contents(SF_UPLOADS . '/index.html', '');
    file_put_contents(SF_THEMES . '/index.html', '');
    
    $default_theme_dir = SF_THEMES . '/default';
    if (!is_dir($default_theme_dir)) mkdir($default_theme_dir, 0755, true);
    file_put_contents($default_theme_dir . '/main.html', sf_get_default_theme());
    
    $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    $hash = password_hash($password, $algo);
    if (!$hash || !sf_json_save(SF_USERS, ['admin' => ['hash' => $hash]])) {
        sf_msg('Ошибка сохранения пользователей.', 'err');
        return false;
    }
    if (!sf_save_config([
        'site_name' => 'Мой сайт',
        'site_desc' => 'Сайт на SecureFlat CMS',
        'footer' => '© ' . date('Y') . ' Мой сайт',
        'menu' => ['home'],
        'custom_css' => '',
        'disable_def_css' => false,
        'active_theme' => 'default',
        'installed' => true,
    ])) {
        sf_msg('Ошибка сохранения конфигурации.', 'err');
        return false;
    }
    if (!sf_save_page([
        'slug' => 'home', 'title' => 'Главная', 'sort' => 0, 'status' => 'published',
        'content' => '<h1>Добро пожаловать!</h1><p>Это ваш новый сайт на <strong>SecureFlat CMS</strong>.</p>',
        'meta_desc' => 'Главная страница',
    ])) {
        sf_msg('Ошибка создания главной страницы.', 'err');
        return false;
    }
    sf_log('install');
    return true;
}

function sf_get_default_theme(): string
{
    return <<<'HTML'
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{page_title}} — {{site_name}}</title>
    <meta name="description" content="{{meta_desc}}">
    {{custom_css_link}}
    {{def_css}}
</head>
<body>
    <header style="background:#fff;border-bottom:1px solid #e5e7eb;padding:16px 0;">
        <div style="max-width:800px;margin:0 auto;padding:0 20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
            <a href="?" style="font-size:20px;font-weight:700;color:#1a1a2e;text-decoration:none;">{{site_name}}</a>
            <nav>
                {{menu}}
                <a href="?admin" style="color:#9ca3af;font-size:12px;margin-left:20px;" title="Админ-панель">⚙</a>
            </nav>
        </div>
    </header>
    <main style="padding:40px 20px;max-width:800px;margin:0 auto;">
        {{content}}
    </main>
    <footer style="text-align:center;padding:30px;color:#9ca3af;font-size:13px;border-top:1px solid #e5e7eb;margin-top:40px;">
        {{footer}} · <span style="font-size:11px;color:#ccc">SecureFlat CMS v{{version}}</span>
    </footer>
</body>
</html>
HTML;
}

function sf_get_themes(): array
{
    $themes = [];
    if (!is_dir(SF_THEMES)) return $themes;
    foreach (scandir(SF_THEMES) as $dir) {
        if ($dir[0] === '.' || !is_dir(SF_THEMES . '/' . $dir)) continue;
        if (file_exists(SF_THEMES . '/' . $dir . '/main.html')) {
            $themes[] = $dir;
        }
    }
    return $themes;
}

function sf_load_theme(string $theme_name): string
{
    $path = SF_THEMES . '/' . $theme_name . '/main.html';
    if (!file_exists($path)) $path = SF_THEMES . '/default/main.html';
    return file_get_contents($path);
}

function sf_render_template(string $template, array $vars): string
{
    foreach ($vars as $key => $value) {
        $template = str_replace('{{' . $key . '}}', $value, $template);
    }
    return $template;
}

function sf_serve_file(): void
{
    $name = $_GET['file'] ?? '';
    $path = sf_secure_path(SF_UPLOADS, $name);
    if (!$path || !is_file($path)) {
        http_response_code(404);
        exit('404 Not Found');
    }
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($path) ?: 'application/octet-stream';
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($path));
    header('Cache-Control: public, max-age=86400');
    header('X-Content-Type-Options: nosniff');
    header('Content-Disposition: inline; filename="' . basename($path) . '"');
    readfile($path);
    exit;
}

function sf_handle_post(): void
{
    $action = $_POST['action'] ?? '';
    if ($action === 'install') {
        $pass = $_POST['password'] ?? '';
        $pass2 = $_POST['password2'] ?? '';
        if (mb_strlen($pass) < 8) { sf_msg('Пароль минимум 8 символов.', 'err'); return; }
        if ($pass !== $pass2) { sf_msg('Пароли не совпадают.', 'err'); return; }
        if (sf_install($pass)) {
            if (sf_login($pass)) {
                sf_redirect('?admin');
            } else {
                sf_msg('Установка прошла успешно. Пожалуйста, войдите.', 'err');
                sf_redirect('?admin');
            }
        }
        return;
    }
    if ($action === 'login') {
        if (!sf_verify_csrf()) { sf_msg('Ошибка CSRF.', 'err'); return; }
        if (sf_login($_POST['password'] ?? '')) sf_redirect('?admin');
        return;
    }
    if (!sf_is_admin()) { sf_redirect('?admin'); }
    if (!sf_verify_csrf()) { sf_msg('Ошибка CSRF-токена.', 'err'); return; }
    
    switch ($action) {
        case 'save_page':
            $old_slug = $_POST['old_slug'] ?? '';
            $page = [
                '_old_slug' => $old_slug,
                'slug' => $_POST['slug'] ?: $_POST['title'],
                'title' => $_POST['title'] ?? '',
                'content' => $_POST['content'] ?? '',
                'meta_desc' => $_POST['meta_desc'] ?? '',
                'status' => $_POST['status'] ?? 'published',
                'sort' => (int)($_POST['sort'] ?? 0),
            ];
            if (empty($page['title'])) { sf_msg('Заголовок обязателен.', 'err'); return; }
            if ($old_slug) {
                $old = sf_page($old_slug);
                if ($old) $page['created_at'] = $old['created_at'];
            }
            if (sf_save_page($page)) {
                $new_slug = $page['slug'];
                if ($old_slug && $old_slug !== $new_slug) {
                    $old_path = SF_PAGES . '/' . $old_slug . '.json';
                    if (file_exists($old_path)) unlink($old_path);
                    $cfg = sf_config();
                    $cfg['menu'] = array_map(fn($s) => $s === $old_slug ? $new_slug : $s, $cfg['menu'] ?? []);
                    sf_save_config($cfg);
                }
                if (!$old_slug && $page['status'] === 'published') {
                    $cfg = sf_config();
                    if (!in_array($new_slug, $cfg['menu'] ?? [], true)) {
                        $cfg['menu'][] = $new_slug;
                        sf_save_config($cfg);
                    }
                }
                sf_log('save_page', $new_slug);
                sf_msg('Страница сохранена.');
                sf_redirect('?admin=edit&slug=' . urlencode($new_slug));
            }
            break;
        case 'delete_page':
            $slug = $_POST['slug'] ?? '';
            if ($slug === 'home') { sf_msg('Нельзя удалить главную страницу.', 'err'); return; }
            sf_delete_page($slug);
            sf_log('delete_page', $slug);
            sf_msg('Страница удалена.');
            sf_redirect('?admin');
            break;
        case 'upload':
            $file = $_FILES['file'] ?? null;
            if (!$file || $file['error'] !== UPLOAD_ERR_OK) { sf_msg('Ошибка загрузки файла.', 'err'); return; }
            if ($file['size'] > 10 * 1024 * 1024) { sf_msg('Файл слишком большой (макс. 10 МБ).', 'err'); return; }
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $mime = $finfo->file($file['tmp_name']);
            $allowed = ['image/jpeg','image/png','image/gif','image/webp','image/svg+xml','application/pdf'];
            if (!in_array($mime, $allowed, true)) { sf_msg('Запрещённый тип файла.', 'err'); return; }
            if ($mime === 'image/svg+xml') {
                $svg = file_get_contents($file['tmp_name']);
                if (preg_match('/<script/i', $svg) || preg_match('/\bon[a-z]+\s*=/i', $svg)) {
                    sf_msg('SVG содержит опасный код.', 'err'); return;
                }
            }
            $ext = match($mime) {
                'image/jpeg' => 'jpg', 'image/png' => 'png', 'image/gif' => 'gif',
                'image/webp' => 'webp', 'image/svg+xml' => 'svg', 'application/pdf' => 'pdf',
                default => 'bin'
            };
            $new_name = bin2hex(random_bytes(8)) . '.' . $ext;
            if (!move_uploaded_file($file['tmp_name'], SF_UPLOADS . '/' . $new_name)) {
                sf_msg('Не удалось сохранить файл.', 'err');
                return;
            }
            sf_log('upload', $new_name);
            if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
                header('Content-Type: application/json');
                echo json_encode(['ok' => true, 'url' => '?file=' . urlencode($new_name), 'name' => $new_name]);
                exit;
            }
            sf_msg('Файл загружен: ' . $new_name);
            sf_redirect('?admin=files');
            break;
        case 'delete_file':
            $name = $_POST['name'] ?? '';
            $path = sf_secure_path(SF_UPLOADS, $name);
            if ($path && is_file($path)) {
                unlink($path);
                sf_log('delete_file', $name);
                sf_msg('Файл удалён.');
            }
            sf_redirect('?admin=files');
            break;
        case 'save_settings':
            $cfg = sf_config();
            $cfg['site_name'] = htmlspecialchars(strip_tags($_POST['site_name'] ?? ''), ENT_QUOTES, 'UTF-8');
            $cfg['site_desc'] = htmlspecialchars(strip_tags($_POST['site_desc'] ?? ''), ENT_QUOTES, 'UTF-8');
            $cfg['footer'] = htmlspecialchars(strip_tags($_POST['footer'] ?? ''), ENT_QUOTES, 'UTF-8');
            $cfg['custom_css'] = filter_var($_POST['custom_css'] ?? '', FILTER_VALIDATE_URL) ?: '';
            $cfg['disable_def_css'] = isset($_POST['disable_def_css']);
            $cfg['active_theme'] = preg_replace('/[^a-z0-9_-]/', '', $_POST['active_theme'] ?? 'default');
            $menu_order = $_POST['menu_order'] ?? '';
            if ($menu_order) $cfg['menu'] = array_filter(array_map('trim', explode(',', $menu_order)));
            sf_save_config($cfg);
            $new_pass = $_POST['new_password'] ?? '';
            if (mb_strlen($new_pass) >= 8) {
                $users = sf_json_load(SF_USERS, []);
                $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
                $users['admin']['hash'] = password_hash($new_pass, $algo);
                sf_json_save(SF_USERS, $users);
                sf_msg('Настройки и пароль сохранены.');
            } else {
                sf_msg('Настройки сохранены.');
            }
            sf_log('save_settings');
            sf_redirect('?admin=settings');
            break;
        case 'save_theme':
            $theme_name = preg_replace('/[^a-z0-9_-]/', '', $_POST['theme_name'] ?? '');
            $theme_html = $_POST['theme_html'] ?? '';
            if (empty($theme_name)) { sf_msg('Имя шаблона обязательно.', 'err'); return; }
            $theme_dir = SF_THEMES . '/' . $theme_name;
            if (!is_dir($theme_dir)) mkdir($theme_dir, 0755, true);
            if (file_put_contents($theme_dir . '/main.html', $theme_html) === false) {
                sf_msg('Ошибка сохранения шаблона.', 'err');
                return;
            }
            sf_log('save_theme', $theme_name);
            sf_msg('Шаблон сохранён.');
            sf_redirect('?admin=themes&edit=' . urlencode($theme_name));
            break;
        case 'delete_theme':
            $theme_name = preg_replace('/[^a-z0-9_-]/', '', $_POST['theme_name'] ?? '');
            if ($theme_name === 'default') { sf_msg('Нельзя удалить базовый шаблон.', 'err'); return; }
            $theme_dir = SF_THEMES . '/' . $theme_name;
            if (is_dir($theme_dir)) {
                array_map('unlink', glob($theme_dir . '/*'));
                rmdir($theme_dir);
                sf_log('delete_theme', $theme_name);
                sf_msg('Шаблон удалён.');
            }
            sf_redirect('?admin=themes');
            break;
        case 'menu_toggle':
            $slug = $_POST['slug'] ?? '';
            $cfg = sf_config();
            $menu = $cfg['menu'] ?? [];
            if (in_array($slug, $menu, true)) {
                $menu = array_values(array_filter($menu, fn($s) => $s !== $slug));
            } else {
                $menu[] = $slug;
            }
            $cfg['menu'] = $menu;
            sf_save_config($cfg);
            sf_redirect('?admin');
            break;
    }
}

function sf_handle_get(): void
{
    if (($_GET['action'] ?? '') === 'logout' && sf_is_admin()) {
        sf_logout();
        sf_redirect('?admin');
    }
}

function sf_html_head(string $title, bool $admin = false): string
{
    $t = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $html = "<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"UTF-8\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>{$t} — SecureFlat CMS</title>
<style>" . sf_admin_css() . "</style></head><body>";
    return $html;
}

function sf_admin_css(): string
{
    return "
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#1a1a2e;line-height:1.7;background:#fafafa}
a{color:#2563eb;text-decoration:none}a:hover{text-decoration:underline}
.flash{padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:14px}
.flash.ok{background:#d1fae5;color:#065f46;border:1px solid #6ee7b7}
.flash.err{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}
.btn{display:inline-block;padding:8px 18px;border-radius:6px;border:none;cursor:pointer;font-size:14px;font-weight:500;transition:.2s}
.btn-primary{background:#2563eb;color:#fff}.btn-primary:hover{background:#1d4ed8;text-decoration:none}
.btn-danger{background:#dc2626;color:#fff}.btn-danger:hover{background:#b91c1c;text-decoration:none}
.btn-sm{padding:5px 12px;font-size:12px}
.btn-outline{background:transparent;border:1px solid #d1d5db;color:#374151}.btn-outline:hover{background:#f3f4f6;text-decoration:none}
input[type=text],input[type=password],input[type=number],input[type=url],textarea,select{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:6px;font-size:14px;font-family:inherit}
input:focus,textarea:focus,select:focus{outline:none;border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.1)}
label{display:block;font-weight:600;margin-bottom:4px;font-size:13px;color:#374151}
.form-group{margin-bottom:16px}
table{width:100%;border-collapse:collapse}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #e5e7eb}
th{font-size:12px;text-transform:uppercase;color:#6b7280;background:#f9fafb}
h1,h2,h3{margin-bottom:12px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:20px;margin-bottom:16px}
.admin-wrap{display:flex;min-height:100vh}
.sidebar{width:240px;background:#1e293b;color:#e2e8f0;padding:20px 0;flex-shrink:0;position:fixed;top:0;left:0;bottom:0;overflow-y:auto;z-index:100}
.sidebar .logo{color:#fff;font-size:18px;padding:0 20px 20px;border-bottom:1px solid #334155;margin-bottom:10px;display:block}
.sidebar a{display:block;padding:10px 20px;color:#94a3b8;font-size:14px;transition:.15s}
.sidebar a:hover,.sidebar a.active{background:#334155;color:#fff;text-decoration:none}
.admin-main{margin-left:240px;flex:1;padding:24px 32px;background:#f8fafc;min-height:100vh}
.admin-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.editor-toolbar{display:flex;flex-wrap:wrap;gap:4px;padding:8px;background:#f1f5f9;border:1px solid #d1d5db;border-bottom:none;border-radius:8px 8px 0 0}
.editor-toolbar button{padding:6px 10px;border:1px solid transparent;background:none;cursor:pointer;border-radius:4px;font-size:13px;color:#374151}
.editor-toolbar button:hover{background:#e2e8f0}
.editor-area{min-height:350px;padding:16px;border:1px solid #d1d5db;border-radius:0 0 8px 8px;background:#fff;outline:none;line-height:1.7;overflow-y:auto}
.editor-area:focus{border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.1)}
.editor-area img{max-width:100%;height:auto}
.upload-zone{border:2px dashed #d1d5db;border-radius:10px;padding:40px;text-align:center;color:#6b7280;cursor:pointer;transition:.2s}
.upload-zone:hover,.upload-zone.dragover{border-color:#2563eb;background:#eff6ff;color:#2563eb}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.badge-green{background:#d1fae5;color:#065f46}.badge-yellow{background:#fef3c7;color:#92400e}
.code-editor{font-family:'Courier New',monospace;font-size:13px;line-height:1.5;min-height:500px;tab-size:4}
@media(max-width:768px){
  .sidebar{position:static;width:100%;display:flex;flex-wrap:wrap;padding:10px}
  .sidebar .logo{padding:5px 10px;border:none;margin:0}
  .sidebar a{padding:8px 12px;font-size:13px}
  .admin-main{margin-left:0;padding:16px}
}
";
}

function sf_flash_html(): string
{
    $msg = sf_get_msg();
    if (!$msg) return '';
    $t = htmlspecialchars($msg['text'], ENT_QUOTES, 'UTF-8');
    $c = $msg['type'] === 'err' ? 'err' : 'ok';
    return "<div class=\"flash {$c}\">{$t}</div>";
}

function sf_render_public(): void
{
    $cfg = sf_config();
    $slug = sf_slug($_GET['page'] ?? 'home');
    $page = sf_page($slug);
    if (!$page || $page['status'] !== 'published') {
        http_response_code(404);
        $page = ['title' => '404', 'content' => '<h1>Страница не найдена</h1><p><a href="?">На главную</a></p>', 'meta_desc' => ''];
    }
    $theme = sf_load_theme($cfg['active_theme'] ?? 'default');
    $menu_html = '';
    foreach ($cfg['menu'] ?? [] as $ms) {
        $mp = sf_page($ms);
        if ($mp) {
            $active = $ms === $slug ? ' style="color:#2563eb;font-weight:600"' : '';
            $menu_html .= '<a href="?page=' . urlencode($ms) . '"' . $active . '>' . htmlspecialchars($mp['title']) . '</a> ';
        }
    }
    $custom_css_link = '';
    if (!empty($cfg['custom_css'])) {
        $custom_css_link = '<link rel="stylesheet" href="' . htmlspecialchars($cfg['custom_css'], ENT_QUOTES, 'UTF-8') . '">';
    }
    $def_css = '';
    if (!$cfg['disable_def_css']) {
        $def_css = '<style>' . sf_public_css() . '</style>';
    }
    $output = sf_render_template($theme, [
        'site_name' => htmlspecialchars($cfg['site_name'], ENT_QUOTES, 'UTF-8'),
        'site_desc' => htmlspecialchars($cfg['site_desc'], ENT_QUOTES, 'UTF-8'),
        'footer' => $cfg['footer'] ?? '',
        'page_title' => htmlspecialchars($page['title'], ENT_QUOTES, 'UTF-8'),
        'meta_desc' => htmlspecialchars($page['meta_desc'] ?? '', ENT_QUOTES, 'UTF-8'),
        'content' => $page['content'],
        'menu' => $menu_html,
        'custom_css_link' => $custom_css_link,
        'def_css' => $def_css,
        'version' => SF_VERSION,
    ]);
    echo $output;
}

function sf_public_css(): string
{
    return "
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#1a1a2e;line-height:1.7;background:#fafafa}
a{color:#2563eb;text-decoration:none}a:hover{text-decoration:underline}
main img{max-width:100%;height:auto;border-radius:8px}
main h1{font-size:2em;margin-bottom:16px}main h2{font-size:1.5em;margin:24px 0 12px}
main blockquote{border-left:4px solid #2563eb;padding:8px 16px;margin:16px 0;background:#eff6ff;border-radius:0 6px 6px 0}
main pre{background:#1e293b;color:#e2e8f0;padding:16px;border-radius:8px;overflow-x:auto;margin:16px 0}
main code{background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:0.9em}
main pre code{background:none;padding:0}
";
}

function sf_admin_sidebar(string $active = ''): string
{
    $links = ['' => '📄 Страницы', 'files' => '📁 Файлы', 'themes' => '🎨 Шаблоны', 'settings' => '⚙ Настройки'];
    $h = '<aside class="sidebar"><a href="?admin" class="logo">SecureFlat v' . SF_VERSION . '</a>';
    foreach ($links as $k => $v) {
        $cls = $active === $k ? ' class="active"' : '';
        $url = $k === '' ? '?admin' : '?admin=' . $k;
        $h .= "<a href=\"{$url}\"{$cls}>{$v}</a>";
    }
    $h .= '<a href="?action=logout" style="margin-top:20px;border-top:1px solid #334155">🚪 Выход</a></aside>';
    return $h;
}

function sf_render_login(): void
{
    echo sf_html_head('Вход', true);
    echo '<div style="display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f1f5f9">';
    echo '<div class="card" style="width:100%;max-width:380px">';
    echo '<h2 style="text-align:center;margin-bottom:20px">Вход в админку</h2>';
    echo sf_flash_html();
    echo '<form method="post"><input type="hidden" name="action" value="login">' . sf_csrf_field();
    echo '<div class="form-group"><label>Пароль</label><input type="password" name="password" required autofocus></div>';
    echo '<button class="btn btn-primary" style="width:100%">Войти</button></form>';
    echo '<p style="text-align:center;margin-top:12px"><a href="?">← На сайт</a></p>';
    echo '</div></div></body></html>';
}

function sf_render_install(): void
{
    echo sf_html_head('Установка', true);
    echo '<div style="display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f1f5f9">';
    echo '<div class="card" style="width:100%;max-width:420px">';
    echo '<h2 style="text-align:center;margin-bottom:8px">Установка SecureFlat CMS</h2>';
    echo '<p style="text-align:center;color:#6b7280;margin-bottom:20px;font-size:14px">Придумайте пароль администратора (мин. 8 символов)</p>';
    echo sf_flash_html();
    echo '<form method="post"><input type="hidden" name="action" value="install">';
    echo '<div class="form-group"><label>Пароль</label><input type="password" name="password" required autofocus></div>';
    echo '<div class="form-group"><label>Повторите пароль</label><input type="password" name="password2" required></div>';
    echo '<button class="btn btn-primary" style="width:100%">Установить</button></form>';
    echo '</div></div></body></html>';
}

function sf_render_admin_dashboard(): void
{
    $cfg = sf_config();
    $pages = sf_pages();
    echo sf_html_head('Админка', true);
    echo '<div class="admin-wrap">' . sf_admin_sidebar('');
    echo '<div class="admin-main">';
    echo '<div class="admin-top"><h1>Страницы</h1><a href="?admin=edit" class="btn btn-primary">+ Новая страница</a></div>';
    echo sf_flash_html();
    if (empty($pages)) {
        echo '<div class="card"><p style="color:#6b7280;text-align:center">Страниц пока нет. <a href="?admin=edit">Создайте первую!</a></p></div>';
    } else {
        echo '<div class="card" style="padding:0;overflow-x:auto"><table>';
        echo '<tr><th>Заголовок</th><th>URL</th><th>Статус</th><th>Меню</th><th>Обновлена</th><th></th></tr>';
        foreach ($pages as $p) {
            $title = htmlspecialchars($p['title']);
            $slug = htmlspecialchars($p['slug']);
            $status = $p['status'] === 'published' ? '<span class="badge badge-green">Опублик.</span>' : '<span class="badge badge-yellow">Черновик</span>';
            $in_menu = in_array($p['slug'], $cfg['menu'] ?? [], true);
            $menu_btn = '<form method="post" style="display:inline"><input type="hidden" name="action" value="menu_toggle">' . sf_csrf_field() . '<input type="hidden" name="slug" value="' . $slug . '"><button class="btn btn-sm ' . ($in_menu ? 'btn-primary' : 'btn-outline') . '">' . ($in_menu ? '✓ В меню' : '+ В меню') . '</button></form>';
            $upd = htmlspecialchars($p['updated_at'] ?? '');
            echo "<tr><td><a href=\"?admin=edit&slug={$slug}\"><strong>{$title}</strong></a></td><td><code style=\"font-size:12px;background:#f1f5f9;padding:2px 6px;border-radius:4px\">{$slug}</code></td><td>{$status}</td><td>{$menu_btn}</td><td style=\"font-size:12px;color:#6b7280\">{$upd}</td><td><a href=\"?page={$slug}\" class=\"btn btn-sm btn-outline\" target=\"_blank\" rel=\"noopener\">👁</a></td></tr>";
        }
        echo '</table></div>';
    }
    echo '</div></div></body></html>';
}

function sf_render_editor(): void
{
    $slug = $_GET['slug'] ?? '';
    $page = $slug ? sf_page($slug) : null;
    $is_new = !$page;
    $title = $page['title'] ?? '';
    $content = $page['content'] ?? '';
    $meta_desc = $page['meta_desc'] ?? '';
    $status = $page['status'] ?? 'published';
    $sort = $page['sort'] ?? 0;
    $old_slug = $page['slug'] ?? '';
    echo sf_html_head($is_new ? 'Новая страница' : 'Редактор: ' . $title, true);
    echo '<div class="admin-wrap">' . sf_admin_sidebar('');
    echo '<div class="admin-main">';
    echo '<div class="admin-top"><h1>' . ($is_new ? 'Новая страница' : 'Редактирование') . '</h1><a href="?admin" class="btn btn-outline">← К списку</a></div>';
    echo sf_flash_html();
    echo '<form method="post" id="pageForm"><input type="hidden" name="action" value="save_page">' . sf_csrf_field();
    echo '<input type="hidden" name="old_slug" value="' . htmlspecialchars($old_slug) . '">';
    echo '<div style="display:grid;grid-template-columns:1fr 280px;gap:20px">';
    echo '<div>';
    echo '<div class="form-group"><label>Заголовок</label><input type="text" name="title" id="pageTitle" value="' . htmlspecialchars($title) . '" required></div>';
    echo '<div class="form-group"><label>URL (Slug)</label><input type="text" name="slug" id="pageSlug" value="' . htmlspecialchars($old_slug) . '" placeholder="авто-генерация"></div>';
    echo '<label>Контент</label>';
    echo '<div class="editor-toolbar" id="toolbar">';
    $btns = [['b','<b>B</b>','bold'],['i','<i>I</i>','italic'],['u','<u>U</u>','underline'],['s','<s>S</s>','strikeThrough'],['|'],['h1','H1','formatBlock:H1'],['h2','H2','formatBlock:H2'],['h3','H3','formatBlock:H3'],['p','¶','formatBlock:P'],['|'],['ul','• Список','insertUnorderedList'],['ol','1. Список','insertOrderedList'],['|'],['link','🔗','createLink'],['img','🖼','insertImage'],['quote','❝','formatBlock:BLOCKQUOTE'],['code','&lt;/&gt;','formatBlock:PRE'],['hr','—','insertHorizontalRule'],['|'],['undo','↩','undo'],['redo','↪','redo'],['clear','✕','removeFormat']];
    foreach ($btns as $b) {
        if ($b[0] === '|') { echo '<span style="width:1px;background:#d1d5db;margin:0 4px"></span>'; continue; }
        echo '<button type="button" data-cmd="' . htmlspecialchars($b[2]) . '" title="' . htmlspecialchars($b[0]) . '">' . $b[1] . '</button>';
    }
    echo '</div>';
    echo '<div class="editor-area" id="editor" contenteditable="true">' . $content . '</div>';
    echo '<input type="hidden" name="content" id="contentField"></div>';
    echo '<div><div class="card">';
    echo '<div class="form-group"><label>Статус</label><select name="status"><option value="published"' . ($status === 'published' ? ' selected' : '') . '>Опубликована</option><option value="draft"' . ($status === 'draft' ? ' selected' : '') . '>Черновик</option></select></div>';
    echo '<div class="form-group"><label>Порядок в меню</label><input type="number" name="sort" value="' . (int)$sort . '"></div>';
    echo '<div class="form-group"><label>Meta Description</label><textarea name="meta_desc" rows="3">' . htmlspecialchars($meta_desc) . '</textarea></div>';
    echo '<button type="submit" class="btn btn-primary" style="width:100%;margin-bottom:10px">💾 Сохранить</button>';
    if (!$is_new) {
        echo '<button type="button" class="btn btn-danger" style="width:100%" onclick="if(confirm(\'Удалить страницу?\')){document.getElementById(\'delForm\').submit()}">🗑 Удалить</button>';
    }
    echo '</div></div></form>';
    if (!$is_new) {
        echo '<form id="delForm" method="post" style="display:none"><input type="hidden" name="action" value="delete_page">' . sf_csrf_field() . '<input type="hidden" name="slug" value="' . htmlspecialchars($old_slug) . '"></form>';
    }
    $csrf_token = sf_csrf_token();
    echo <<<JS
<script>
const editor = document.getElementById("editor"), contentField = document.getElementById("contentField"), titleInp = document.getElementById("pageTitle"), slugInp = document.getElementById("pageSlug");
document.getElementById("toolbar").addEventListener("click", function(e){
  const btn = e.target.closest("button"); if(!btn) return; e.preventDefault();
  const cmd = btn.dataset.cmd;
  if(cmd.startsWith("formatBlock:")) document.execCommand("formatBlock", false, cmd.split(":")[1]);
  else if(cmd === "createLink"){ const u = prompt("URL:", "https://"); if(u) document.execCommand(cmd, false, u); }
  else if(cmd === "insertImage"){ const u = prompt("URL изображения:", ""); if(u) document.execCommand(cmd, false, u); }
  else document.execCommand(cmd, false, null);
  editor.focus();
});
document.getElementById("pageForm").addEventListener("submit", function(){ contentField.value = editor.innerHTML; });
titleInp.addEventListener("input", function(){ if(!slugInp.dataset.manual) slugInp.value = slugify(this.value); });
slugInp.addEventListener("input", function(){ this.dataset.manual = "1"; });
function slugify(s){ return s.toLowerCase().replace(/[а-яё]/gi, function(c){ var m={"а":"a","б":"b","в":"v","г":"g","д":"d","е":"e","ё":"yo","ж":"zh","з":"z","и":"i","й":"y","к":"k","л":"l","м":"m","н":"n","о":"o","п":"p","р":"r","с":"s","т":"t","у":"u","ф":"f","х":"kh","ц":"ts","ч":"ch","ш":"sh","щ":"sch","ъ":"","ы":"y","ь":"","э":"e","ю":"yu","я":"ya"}; return m[c]||c; }).replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"").substring(0,80); }
editor.addEventListener("dragover", function(e){ e.preventDefault(); });
editor.addEventListener("drop", function(e){ e.preventDefault(); const f = e.dataTransfer.files[0]; if(!f) return; uploadFile(f).then(url => { if(url) document.execCommand("insertImage", false, url); }); });
editor.addEventListener("paste", function(e){ const items = e.clipboardData?.items; if(!items) return; for(const item of items){ if(item.type.startsWith("image/")){ e.preventDefault(); uploadFile(item.getAsFile()).then(url => { if(url) document.execCommand("insertImage", false, url); }); break; } } });
function uploadFile(file){ const fd = new FormData(); fd.append("file", file); fd.append("action", "upload"); fd.append("csrf", "{$csrf_token}"); return fetch("?admin=files", { method: "POST", headers: {"X-Requested-With": "XMLHttpRequest"}, body: fd }).then(r => r.json()).then(d => { if(d.ok) return d.url; alert("Ошибка загрузки"); return null; }); }
</script>
JS;
    echo '</div></div></body></html>';
}

function sf_render_files(): void
{
    echo sf_html_head('Файлы', true);
    echo '<div class="admin-wrap">' . sf_admin_sidebar('files');
    echo '<div class="admin-main">';
    echo '<div class="admin-top"><h1>Файлы</h1></div>';
    echo sf_flash_html();
    echo '<div class="card"><form method="post" enctype="multipart/form-data" id="uploadForm"><input type="hidden" name="action" value="upload">' . sf_csrf_field() . '<div class="upload-zone" id="dropZone"><p>📎 Перетащите файл или нажмите</p><p style="font-size:12px;color:#9ca3af;margin-top:4px">JPG, PNG, GIF, WebP, SVG, PDF · макс. 10 МБ</p><input type="file" name="file" id="fileInput" style="display:none" accept="image/*,.pdf"></div></form></div>';
    $files = sf_uploads_list();
    if ($files) {
        echo '<div class="card" style="padding:0;overflow-x:auto"><table><tr><th>Превью</th><th>Имя / Ссылка</th><th>Размер</th><th>Дата</th><th></th></tr>';
        foreach ($files as $f) {
            $name = htmlspecialchars($f['name']);
            $url = htmlspecialchars($f['url']);
            $size = $f['size'] > 1024 ? round($f['size']/1024) . ' КБ' : $f['size'] . ' Б';
            $time = htmlspecialchars($f['time']);
            $preview = str_ends_with(strtolower($name), '.pdf') ? '📄' : "<img src=\"{$url}\" style=\"max-height:40px;border-radius:4px\">";
            echo "<tr><td>{$preview}</td><td><code style=\"font-size:12px\">{$name}</code><br><input type=\"text\" value=\"{$url}\" readonly onclick=\"this.select()\" style=\"font-size:11px;padding:3px 6px;width:200px;margin-top:4px\"></td><td>{$size}</td><td style=\"font-size:12px\">{$time}</td><td><form method=\"post\" style=\"display:inline\" onsubmit=\"return confirm('Удалить?')\"><input type=\"hidden\" name=\"action\" value=\"delete_file\">" . sf_csrf_field() . "<input type=\"hidden\" name=\"name\" value=\"{$name}\"><button class=\"btn btn-sm btn-danger\">✕</button></form></td></tr>";
        }
        echo '</table></div>';
    } else {
        echo '<div class="card"><p style="color:#6b7280;text-align:center">Файлов пока нет.</p></div>';
    }
    echo <<<JS
<script>
const dz = document.getElementById("dropZone"), fi = document.getElementById("fileInput"), uf = document.getElementById("uploadForm");
dz.addEventListener("click", () => fi.click());
dz.addEventListener("dragover", e => { e.preventDefault(); dz.classList.add("dragover"); });
dz.addEventListener("dragleave", () => dz.classList.remove("dragover"));
dz.addEventListener("drop", e => { e.preventDefault(); dz.classList.remove("dragover"); fi.files = e.dataTransfer.files; if(fi.files.length) uf.submit(); });
fi.addEventListener("change", () => { if(fi.files.length) uf.submit(); });
</script>
JS;
    echo '</div></div></body></html>';
}

function sf_render_themes(): void
{
    $cfg = sf_config();
    $themes = sf_get_themes();
    $edit_theme = $_GET['edit'] ?? '';
    
    echo sf_html_head('Шаблоны', true);
    echo '<div class="admin-wrap">' . sf_admin_sidebar('themes');
    echo '<div class="admin-main">';
    echo '<div class="admin-top"><h1>Шаблоны</h1></div>';
    echo sf_flash_html();
    
    if ($edit_theme) {
        $theme_path = SF_THEMES . '/' . $edit_theme . '/main.html';
        $theme_html = file_exists($theme_path) ? file_get_contents($theme_path) : '';
        
        echo '<div class="card">';
        echo '<h3 style="margin-bottom:12px">Редактирование шаблона: <code>' . htmlspecialchars($edit_theme) . '</code></h3>';
        echo '<p style="font-size:13px;color:#6b7280;margin-bottom:12px">Доступные переменные: <code>{{site_name}}</code>, <code>{{page_title}}</code>, <code>{{meta_desc}}</code>, <code>{{content}}</code>, <code>{{menu}}</code>, <code>{{footer}}</code>, <code>{{custom_css_link}}</code>, <code>{{def_css}}</code>, <code>{{version}}</code></p>';
        echo '<form method="post">';
        echo '<input type="hidden" name="action" value="save_theme">';
        echo '<input type="hidden" name="theme_name" value="' . htmlspecialchars($edit_theme) . '">';
        echo sf_csrf_field();
        echo '<textarea name="theme_html" class="code-editor" style="width:100%;min-height:500px;font-family:monospace;">' . htmlspecialchars($theme_html) . '</textarea>';
        echo '<div style="margin-top:12px"><button type="submit" class="btn btn-primary">💾 Сохранить шаблон</button> <a href="?admin=themes" class="btn btn-outline">Отмена</a></div>';
        echo '</form>';
        echo '</div>';
    } else {
        echo '<div class="card">';
        echo '<h3 style="margin-bottom:12px">Создать новый шаблон</h3>';
        echo '<form method="post">';
        echo '<input type="hidden" name="action" value="save_theme">';
        echo sf_csrf_field();
        echo '<div class="form-group"><label>Имя шаблона (латиница, цифры, дефис)</label><input type="text" name="theme_name" required pattern="[a-z0-9_-]+" placeholder="my-theme"></div>';
        echo '<div class="form-group"><label>HTML-код шаблона</label><textarea name="theme_html" class="code-editor" style="width:100%;min-height:400px;font-family:monospace;">' . htmlspecialchars(sf_get_default_theme()) . '</textarea></div>';
        echo '<button type="submit" class="btn btn-primary">Создать шаблон</button>';
        echo '</form>';
        echo '</div>';
        
        echo '<div class="card" style="padding:0;overflow-x:auto"><table>';
        echo '<tr><th>Шаблон</th><th>Статус</th><th>Действия</th></tr>';
        foreach ($themes as $theme) {
            $is_active = ($cfg['active_theme'] ?? 'default') === $theme;
            $status = $is_active ? '<span class="badge badge-green">Активен</span>' : '<span class="badge badge-yellow">Неактивен</span>';
            echo '<tr>';
            echo '<td><strong>' . htmlspecialchars($theme) . '</strong></td>';
            echo '<td>' . $status . '</td>';
            echo '<td>';
            echo '<a href="?admin=themes&edit=' . urlencode($theme) . '" class="btn btn-sm btn-outline">✏️ Редактировать</a> ';
            if (!$is_active && $theme !== 'default') {
                echo '<form method="post" style="display:inline"><input type="hidden" name="action" value="delete_theme"><input type="hidden" name="theme_name" value="' . htmlspecialchars($theme) . '">' . sf_csrf_field() . '<button class="btn btn-sm btn-danger" onclick="return confirm(\'Удалить шаблон?\')">🗑</button></form>';
            }
            echo '</td>';
            echo '</tr>';
        }
        echo '</table></div>';
    }
    
    echo '</div></div></body></html>';
}

function sf_render_settings(): void
{
    $cfg = sf_config();
    $themes = sf_get_themes();
    echo sf_html_head('Настройки', true);
    echo '<div class="admin-wrap">' . sf_admin_sidebar('settings');
    echo '<div class="admin-main">';
    echo '<div class="admin-top"><h1>Настройки</h1></div>';
    echo sf_flash_html();
    echo '<form method="post" class="card"><input type="hidden" name="action" value="save_settings">' . sf_csrf_field();
    echo '<div class="form-group"><label>Название сайта</label><input type="text" name="site_name" value="' . htmlspecialchars($cfg['site_name'] ?? '') . '"></div>';
    echo '<div class="form-group"><label>Описание сайта</label><input type="text" name="site_desc" value="' . htmlspecialchars($cfg['site_desc'] ?? '') . '"></div>';
    echo '<div class="form-group"><label>Подвал (footer)</label><input type="text" name="footer" value="' . htmlspecialchars($cfg['footer'] ?? '') . '"></div>';
    echo '<hr style="margin:20px 0;border:none;border-top:1px solid #e5e7eb">';
    echo '<h3 style="margin-bottom:12px">Внешний вид</h3>';
    echo '<div class="form-group"><label>Активный шаблон</label><select name="active_theme">';
    foreach ($themes as $theme) {
        $selected = ($cfg['active_theme'] ?? 'default') === $theme ? ' selected' : '';
        echo '<option value="' . htmlspecialchars($theme) . '"' . $selected . '>' . htmlspecialchars($theme) . '</option>';
    }
    echo '</select></div>';
    echo '<div class="form-group"><label>URL пользовательского CSS (Tailwind, Bootstrap и т.д.)</label><input type="url" name="custom_css" value="' . htmlspecialchars($cfg['custom_css'] ?? '') . '" placeholder="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css"></div>';
    echo '<div class="form-group" style="display:flex;align-items:center;gap:8px"><input type="checkbox" name="disable_def_css" id="disable_def_css" value="1" ' . (!empty($cfg['disable_def_css']) ? 'checked' : '') . ' style="width:auto"><label for="disable_def_css" style="margin:0;cursor:pointer">Отключить встроенные стили CMS</label></div>';
    echo '<hr style="margin:20px 0;border:none;border-top:1px solid #e5e7eb">';
    echo '<h3 style="margin-bottom:12px">Безопасность</h3>';
    echo '<div class="form-group"><label>Новый пароль (мин. 8 символов)</label><input type="password" name="new_password"></div>';
    echo '<button class="btn btn-primary">💾 Сохранить</button></form>';
    echo '<div class="card"><h3 style="margin-bottom:12px">Резервная копия</h3><p style="font-size:13px;color:#6b7280">Версия: <strong>' . SF_VERSION . '</strong> · PHP: ' . PHP_VERSION . '</p></div>';
    $log = sf_json_load(SF_LOG, []);
    if ($log) {
        echo '<div class="card"><h3 style="margin-bottom:12px">Журнал действий</h3><table><tr><th>Время</th><th>IP</th><th>Действие</th></tr>';
        foreach (array_slice(array_reverse($log), 0, 20) as $l) {
            echo '<tr><td style="font-size:12px">' . htmlspecialchars($l['time']) . '</td><td style="font-size:12px">' . htmlspecialchars($l['ip']) . '</td><td>' . htmlspecialchars($l['action']) . '</td></tr>';
        }
        echo '</table></div>';
    }
    echo '</div></div></body></html>';
}

try {
    sf_start_session();
    if (isset($_GET['file'])) sf_serve_file();
    if ($_SERVER['REQUEST_METHOD'] === 'POST') sf_handle_post();
    sf_handle_get();
    if (!sf_installed()) {
        sf_render_install();
        exit;
    }
    if (isset($_GET['admin'])) {
        if (!sf_is_admin()) {
            sf_render_login();
            exit;
        }
        $section = $_GET['admin'];
        match(true) {
            $section === 'edit' => sf_render_editor(),
            $section === 'files' => sf_render_files(),
            $section === 'themes' => sf_render_themes(),
            $section === 'settings' => sf_render_settings(),
            default => sf_render_admin_dashboard(),
        };
        exit;
    }
    sf_render_public();
} catch (Throwable $e) {
    http_response_code(500);
    echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Ошибка</title></head><body style="font-family:sans-serif;padding:40px;max-width:800px;margin:0 auto;background:#fee2e2;color:#991b1b">';
    echo '<h1>⚠️ Критическая ошибка</h1>';
    echo '<p><strong>Сообщение:</strong> ' . htmlspecialchars($e->getMessage()) . '</p>';
    echo '<p><strong>Файл:</strong> ' . htmlspecialchars($e->getFile()) . ' (строка ' . $e->getLine() . ')</p>';
    echo '</body></html>';
    exit;
}
