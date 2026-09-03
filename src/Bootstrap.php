<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use BastionSecurityWP\Admin\AdministratorAccountAlertAdmin;
use BastionSecurityWP\Admin\RestRouteControlsAdmin;
use BastionSecurityWP\Admin\FileEditorAdmin;
use BastionSecurityWP\Admin\LoginProtectionAdmin;
use BastionSecurityWP\Admin\PluginActivityAlertAdmin;
use BastionSecurityWP\Admin\SecurityDashboard;
use BastionSecurityWP\Admin\SecurityHeadersAdmin;
use BastionSecurityWP\Admin\XmlRpcPingbackAdmin;
use BastionSecurityWP\Security\AdministratorAccountAlertPolicy;
use BastionSecurityWP\Security\RestRouteControlsPolicy;
use BastionSecurityWP\Security\FileEditorPolicy;
use BastionSecurityWP\Security\LoginProtectionPolicy;
use BastionSecurityWP\Security\PluginActivityAlertPolicy;
use BastionSecurityWP\Security\SecurityHeadersPolicy;
use BastionSecurityWP\Security\XmlRpcPingbackPolicy;

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
        $pluginActivityAlertPolicy = new PluginActivityAlertPolicy();
        $administratorAccountAlertPolicy = new AdministratorAccountAlertPolicy();
        $xmlRpcPingbackPolicy = new XmlRpcPingbackPolicy();
        $restRouteControlsPolicy = new RestRouteControlsPolicy();
        $restRouteCatalog = new RestRouteCatalog();

        $siteHealth = new SiteHealthDiagnostics(
            fileEditorPolicy: $fileEditorPolicy,
            securityHeadersPolicy: $securityHeadersPolicy,
            loginProtectionPolicy: $loginProtectionPolicy,
            pluginActivityAlertPolicy: $pluginActivityAlertPolicy,
            administratorAccountAlertPolicy: $administratorAccountAlertPolicy,
            xmlRpcPingbackPolicy: $xmlRpcPingbackPolicy,
            restRouteControlsPolicy: $restRouteControlsPolicy,
        );

        if (function_exists('add_filter')) {
            \add_filter('site_status_tests', $siteHealth->register(...));
            \add_filter('wp_headers', $securityHeadersPolicy->apply(...));
            \add_filter('authenticate', $loginProtectionPolicy->filterAuthentication(...), 100, 3);
            \add_filter('xmlrpc_methods', $xmlRpcPingbackPolicy->filterMethods(...), PHP_INT_MAX, 1);
            \add_filter('wp_headers', $xmlRpcPingbackPolicy->filterHeaders(...), PHP_INT_MAX, 1);
            \add_filter('rest_request_before_callbacks', $restRouteControlsPolicy->filterRequest(...), PHP_INT_MAX, 3);
        }

        if (function_exists('add_action')) {
            $fileEditorAdmin = new FileEditorAdmin($fileEditorPolicy);
            $loginProtectionAdmin = new LoginProtectionAdmin($loginProtectionPolicy);
            $xmlRpcPingbackAdmin = new XmlRpcPingbackAdmin($xmlRpcPingbackPolicy);
            $restRouteControlsAdmin = new RestRouteControlsAdmin($restRouteControlsPolicy, $restRouteCatalog);
            $pluginActivityAlertAdmin = new PluginActivityAlertAdmin($pluginActivityAlertPolicy);
            $administratorAccountAlertAdmin = new AdministratorAccountAlertAdmin($administratorAccountAlertPolicy);
            $securityHeadersAdmin = new SecurityHeadersAdmin($securityHeadersPolicy);
            $dashboard = new SecurityDashboard($siteHealth, $fileEditorAdmin, $securityHeadersAdmin, $loginProtectionAdmin, $xmlRpcPingbackAdmin, $restRouteControlsAdmin, $pluginActivityAlertAdmin, $administratorAccountAlertAdmin);
            \add_action('wp_login_failed', $loginProtectionPolicy->recordFailure(...), 10, 2);
            \add_action('wp_login', $loginProtectionPolicy->recordSuccess(...), 10, 2);
            \add_action('upgrader_process_complete', $pluginActivityAlertPolicy->handleUpgraderProcessComplete(...), 10, 2);
            \add_action('activated_plugin', $pluginActivityAlertPolicy->handleActivatedPlugin(...), 10, 2);
            \add_action('add_user_role', $administratorAccountAlertPolicy->handleAddUserRole(...), 10, 2);
            \add_action('remove_user_role', $administratorAccountAlertPolicy->handleRemoveUserRole(...), 10, 2);
            \add_action('deleted_user', $administratorAccountAlertPolicy->handleDeletedUser(...), 10, 3);
            \add_action('admin_menu', $dashboard->registerPage(...));
            \add_action('admin_post_' . FileEditorAdmin::POST_ACTION, $fileEditorAdmin->handleRequest(...));
            \add_action('admin_post_' . LoginProtectionAdmin::POST_ACTION, $loginProtectionAdmin->handleRequest(...));
            \add_action('admin_post_' . XmlRpcPingbackAdmin::POST_ACTION, $xmlRpcPingbackAdmin->handleRequest(...));
            \add_action('admin_post_' . RestRouteControlsAdmin::POST_ACTION, $restRouteControlsAdmin->handleRequest(...));
            \add_action('admin_post_' . PluginActivityAlertAdmin::POST_ACTION, $pluginActivityAlertAdmin->handleRequest(...));
            \add_action('admin_post_' . AdministratorAccountAlertAdmin::POST_ACTION, $administratorAccountAlertAdmin->handleRequest(...));
            \add_action('admin_post_' . SecurityHeadersAdmin::POST_ACTION, $securityHeadersAdmin->handleRequest(...));
        }
    }
}
