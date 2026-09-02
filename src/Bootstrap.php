<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use BastionSecurityWP\Admin\FileEditorAdmin;
use BastionSecurityWP\Admin\SecurityDashboard;
use BastionSecurityWP\Security\FileEditorPolicy;

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

        $siteHealth = new SiteHealthDiagnostics(fileEditorPolicy: $fileEditorPolicy);

        if (function_exists('add_filter')) {
            \add_filter('site_status_tests', $siteHealth->register(...));
        }

        if (function_exists('add_action')) {
            $fileEditorAdmin = new FileEditorAdmin($fileEditorPolicy);
            $dashboard = new SecurityDashboard($siteHealth, $fileEditorAdmin);
            \add_action('admin_menu', $dashboard->registerPage(...));
            \add_action('admin_post_' . FileEditorAdmin::POST_ACTION, $fileEditorAdmin->handleRequest(...));
        }
    }
}
