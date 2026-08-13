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

        // Integrations will consume these request-local services in later slices.
        new DiagnosticRunner(new DiagnosticRegistry());
    }
}
