<?php

declare(strict_types=1);

function check(bool $condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException($message);
    }
}

$mode = $argv[1] ?? '';
$root = realpath($argv[2] ?? '');
check(in_array($mode, ['install', 'verify', 'activate'], true), 'Invalid fixture lifecycle mode.');
check($root !== false && is_file($root . '/wp-load.php'), 'Invalid WordPress fixture root.');
$_SERVER['HTTP_HOST'] = 'bastion.test';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/';
define('WP_USE_THEMES', false);
if ($mode === 'install') {
    define('WP_INSTALLING', true);
}
require $root . '/wp-load.php';

if ($mode === 'install') {
    check(! is_blog_installed(), 'Fixture database is not empty.');
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    wp_install('Bastion compatibility', 'admin', 'admin@example.test', false, '', 'unused-password');
    exit(0);
}

global $wpdb;
check(is_blog_installed(), 'WordPress is not installed.');
check($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->options)) === $wpdb->options, 'Options table is missing.');
if ($mode === 'verify') {
    exit(0);
}

require_once ABSPATH . 'wp-admin/includes/plugin.php';
foreach (['woocommerce/woocommerce.php', 'bastion-security-wp/bastion-security-wp.php'] as $plugin) {
    $result = activate_plugin($plugin, '', false, true);
    check(! is_wp_error($result) && is_plugin_active($plugin), 'Could not activate ' . $plugin);
}
