<?php

declare(strict_types=1);

namespace BastionSecurityWP;

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

        if (function_exists('add_filter')) {
            $siteHealth = new SiteHealthDiagnostics();
            \add_filter('site_status_tests', $siteHealth->register(...));
        }
    }
}
