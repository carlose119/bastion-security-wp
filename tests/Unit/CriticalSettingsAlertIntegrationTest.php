<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class CriticalSettingsAlertIntegrationTest extends TestCase
{
    public function testBootstrapWiresOnlySuccessfulLocalUrlUpdateHooksWithAllCallbackArguments(): void
    {
        $source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Bootstrap.php');

        self::assertStringContainsString('use BastionSecurityWP\\Admin\\CriticalSettingsAlertAdmin;', $source);
        self::assertStringContainsString('use BastionSecurityWP\\Security\\CriticalSettingsAlertPolicy;', $source);
        self::assertStringContainsString('$criticalSettingsAlertPolicy = new CriticalSettingsAlertPolicy();', $source);
        self::assertStringContainsString('$criticalSettingsAlertAdmin = new CriticalSettingsAlertAdmin($criticalSettingsAlertPolicy);', $source);
        self::assertStringContainsString("add_action('update_option_home', \$criticalSettingsAlertPolicy->onOptionUpdated(...), 10, 3)", $source);
        self::assertStringContainsString("add_action('update_option_siteurl', \$criticalSettingsAlertPolicy->onOptionUpdated(...), 10, 3)", $source);
        self::assertStringContainsString("add_action('admin_post_' . CriticalSettingsAlertAdmin::POST_ACTION, \$criticalSettingsAlertAdmin->handleRequest(...))", $source);
    }

    public function testBootstrapDoesNotAddUrlAlertsToSiteHealthDiagnostics(): void
    {
        $source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Bootstrap.php');

        self::assertStringNotContainsString('criticalSettingsAlertPolicy:', $source);
        self::assertStringNotContainsString('update_option_network_', $source);
        self::assertStringNotContainsString('switch_to_blog', $source);
    }
}
