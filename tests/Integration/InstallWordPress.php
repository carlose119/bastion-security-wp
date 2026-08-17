<?php

declare(strict_types=1);

function fixtureCheck(bool $condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException($message);
    }
}

$root = realpath($argv[1] ?? '');
fixtureCheck($root !== false && is_file($root . '/wp-admin/install.php'), 'Invalid WordPress fixture root.');

$_SERVER['HTTP_HOST'] = 'bastion.test';
$_SERVER['REQUEST_METHOD'] = 'POST';
$_SERVER['REQUEST_URI'] = '/wp-admin/install.php?step=2';
$_GET = ['step' => '2'];
$_POST = [
    'weblog_title' => 'Bastion compatibility',
    'user_name' => 'admin',
    'admin_password' => 'bastion-fixture-password',
    'admin_password2' => 'bastion-fixture-password',
    'pw_weak' => '1',
    'admin_email' => 'admin@example.test',
    'blog_public' => '0',
    'Submit' => 'Install WordPress',
    'language' => '',
];
$_REQUEST = array_merge($_GET, $_POST);

ob_start();
try {
    require $root . '/wp-admin/install.php';
} finally {
    ob_end_clean();
}

global $wpdb;
fixtureCheck(is_blog_installed(), 'WordPress installation did not complete.');
fixtureCheck(get_option('blogname') === 'Bastion compatibility', 'WordPress installation did not persist its site title.');
fixtureCheck(get_user_by('login', 'admin') !== false, 'WordPress installation did not create its administrator.');
fixtureCheck($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->options)) === $wpdb->options, 'Options table is missing.');
fwrite(STDOUT, "BASTION_WP_INSTALL_OK: WordPress installed\n");
