<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use BastionSecurityWP\Admin\FileEditorAdmin;
use BastionSecurityWP\Admin\LoginProtectionAdmin;
use BastionSecurityWP\Admin\SecurityDashboard;
use BastionSecurityWP\Admin\SecurityHeadersAdmin;
use BastionSecurityWP\Security\FileEditorPolicy;
use BastionSecurityWP\Security\LoginProtectionPolicy;
use BastionSecurityWP\Security\SecurityHeadersPolicy;

final class Bootstrap
{
    private static bool $booted = false;

    private function __construct()
    {
    }

    public static function boot(): void
    {
        if (self::$booted) {
            return;
        }

        self::$booted = true;

        new DiagnosticRunner(new DiagnosticRegistry());

        if (! function_exists('get_option') || ! function_exists('is_multisite')) {
            return;
        }

        $fileEditorPolicy = new FileEditorPolicy();
        $fileEditorPolicy->enforce();
        $securityHeadersPolicy = new SecurityHeadersPolicy();
        $loginProtectionPolicy = new LoginProtectionPolicy();

        $siteHealth = new SiteHealthDiagnostics(
            fileEditorPolicy: $fileEditorPolicy,
            securityHeadersPolicy: $securityHeadersPolicy,
            loginProtectionPolicy: $loginProtectionPolicy,
        );

        if (function_exists('add_filter')) {
            \add_filter('site_status_tests', $siteHealth->register(...));
            \add_filter('wp_headers', $securityHeadersPolicy->apply(...));
            \add_filter('authenticate', $loginProtectionPolicy->filterAuthentication(...), 100, 3);
        }

        if (function_exists('add_action')) {
            $fileEditorAdmin = new FileEditorAdmin($fileEditorPolicy);
            $loginProtectionAdmin = new LoginProtectionAdmin($loginProtectionPolicy);
            $securityHeadersAdmin = new SecurityHeadersAdmin($securityHeadersPolicy);
            $dashboard = new SecurityDashboard($siteHealth, $fileEditorAdmin, $securityHeadersAdmin, $loginProtectionAdmin);
            \add_action('wp_login_failed', $loginProtectionPolicy->recordFailure(...), 10, 2);
            \add_action('wp_login', $loginProtectionPolicy->recordSuccess(...), 10, 2);
            \add_action('admin_menu', $dashboard->registerPage(...));
            \add_action('admin_post_' . FileEditorAdmin::POST_ACTION, $fileEditorAdmin->handleRequest(...));
            \add_action('admin_post_' . LoginProtectionAdmin::POST_ACTION, $loginProtectionAdmin->handleRequest(...));
            \add_action('admin_post_' . SecurityHeadersAdmin::POST_ACTION, $securityHeadersAdmin->handleRequest(...));
        }
    }
}
