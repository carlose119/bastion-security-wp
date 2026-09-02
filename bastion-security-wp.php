<?php
/**
 * Plugin Name:       Bastion Security WP
 * Description:       Defense-in-depth security diagnostics and reversible hardening tools for WordPress.
 * Version:           0.1.0
 * Requires at least: 6.8
 * Requires PHP:      8.1
 * Author:            Carlos Carrillo
 * License:           GPL-2.0-or-later
 * Text Domain:       bastion-security-wp
 */

declare(strict_types=1);

if (! defined('ABSPATH')) {
    exit;
}

$autoload = __DIR__ . '/vendor/autoload.php';

if (! is_readable($autoload)) {
    return;
}

require_once $autoload;

if (class_exists(\BastionSecurityWP\Bootstrap::class)) {
    \BastionSecurityWP\Bootstrap::boot();
}
