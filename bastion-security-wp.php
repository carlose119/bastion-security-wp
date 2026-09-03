<?php
/**
 * Plugin Name:       Bastion Security
 * Plugin URI:        https://github.com/carlose119/bastion-security-wp
 * Description:       Defense-in-depth security diagnostics and reversible hardening tools for WordPress.
 * Version:           0.2.0
 * Requires at least: 6.8
 * Requires PHP:      8.1
 * Author:            Carlos Carrillo
 * License:           GPL-2.0-or-later
 * Text Domain:       bastion-security
 */

declare(strict_types=1);

if (! defined('ABSPATH')) {
    exit;
}

$bastion_security_wp_autoload = __DIR__ . '/vendor/autoload.php';

if (! is_readable($bastion_security_wp_autoload)) {
    return;
}

require_once $bastion_security_wp_autoload;

if (class_exists(\BastionSecurityWP\Bootstrap::class)) {
    \BastionSecurityWP\Bootstrap::boot();
}
