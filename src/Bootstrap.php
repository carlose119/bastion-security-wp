<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use BastionSecurityWP\Admin\FileEditorAdmin;
use BastionSecurityWP\Admin\SecurityDashboard;
use BastionSecurityWP\Admin\SecurityHeadersAdmin;
use BastionSecurityWP\Security\FileEditorPolicy;
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

        $siteHealth = new SiteHealthDiagnostics(
            fileEditorPolicy: $fileEditorPolicy,
            securityHeadersPolicy: $securityHeadersPolicy,
        );

        if (function_exists('add_filter')) {
            \add_filter('site_status_tests', $siteHealth->register(...));
            \add_filter('wp_headers', $securityHeadersPolicy->apply(...));
        }

        if (function_exists('add_action')) {
            $fileEditorAdmin = new FileEditorAdmin($fileEditorPolicy);
            $securityHeadersAdmin = new SecurityHeadersAdmin($securityHeadersPolicy);
            $dashboard = new SecurityDashboard($siteHealth, $fileEditorAdmin, $securityHeadersAdmin);
            \add_action('admin_menu', $dashboard->registerPage(...));
            \add_action('admin_post_' . FileEditorAdmin::POST_ACTION, $fileEditorAdmin->handleRequest(...));
            \add_action('admin_post_' . SecurityHeadersAdmin::POST_ACTION, $securityHeadersAdmin->handleRequest(...));
        }
    }
}
