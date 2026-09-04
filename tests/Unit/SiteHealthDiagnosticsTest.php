<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Admin\AdministratorAccountAlertAdmin;
    use BastionSecurityWP\Admin\RestRouteControlsAdmin;
use BastionSecurityWP\Admin\PluginActivityAlertAdmin;
use BastionSecurityWP\Admin\XmlRpcPingbackAdmin;
use BastionSecurityWP\Bootstrap;
use BastionSecurityWP\Security\AdministratorAccountAlertPolicy;
    use BastionSecurityWP\Security\RestRouteControlsPolicy;
use BastionSecurityWP\Security\FileEditorPolicy;
use BastionSecurityWP\Security\LoginProtectionPolicy;
use BastionSecurityWP\Security\PluginActivityAlertPolicy;
use BastionSecurityWP\Security\SecurityHeadersPolicy;
use BastionSecurityWP\Security\XmlRpcPingbackPolicy;
use BastionSecurityWP\SiteHealthDiagnostics;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class SiteHealthDiagnosticsTest extends TestCase
{
    /** @var array<string, mixed> */
    private array $values;

    protected function setUp(): void
    {
        $this->values = [
            'is_ssl' => true,
            'force_ssl_admin' => true,
            'disallow_file_edit' => true,
            'disallow_file_mods' => false,
            'wordpress_version' => '6.8.2',
            'php_version' => '8.4.1',
        ];
    }

    public function testBootDoesNotRequireWordPressHookFunctions(): void
    {
        self::assertFalse(function_exists('add_filter'));

        Bootstrap::boot();

        self::assertTrue(true);
    }

    public function testRegistrationPreservesCoreTestsAndHasStableUniqueOrder(): void
    {
        $tests = $this->diagnostics()->register([
            'direct' => ['wordpress_core' => ['test' => 'core_callback']],
            'async' => ['plugin_async' => ['test' => 'plugin_callback']],
        ]);

        self::assertSame([
            'wordpress_core',
            'bastion_security_wp_transport',
            'bastion_security_wp_file_editor',
            'bastion_security_wp_login_protection',
            'bastion_security_wp_xmlrpc_pingback_protection',
            'bastion_security_wp_rest_route_controls',
            'bastion_security_wp_plugin_activity_alerts',
            'bastion_security_wp_administrator_account_alerts',
            'bastion_security_wp_security_headers',
            'bastion_security_wp_file_modifications',
            'bastion_security_wp_runtime',
            'bastion_security_wp_plugin_update_compatibility',
            'bastion_security_wp_rest_surface_inventory',
        ], array_keys($tests['direct']));
        self::assertSame('plugin_callback', $tests['async']['plugin_async']['test']);
        self::assertCount(13, array_unique(array_keys($tests['direct'])));
    }

    public function testSharedReportListContainsExactlyTwelveBastionDiagnosticsInStableOrder(): void
    {
        $results = $this->diagnostics()->reports();

        self::assertCount(12, $results);
        self::assertSame([
            'bastion_security_wp_transport',
            'bastion_security_wp_file_editor',
            'bastion_security_wp_login_protection',
            'bastion_security_wp_xmlrpc_pingback_protection',
            'bastion_security_wp_rest_route_controls',
            'bastion_security_wp_plugin_activity_alerts',
            'bastion_security_wp_administrator_account_alerts',
            'bastion_security_wp_security_headers',
            'bastion_security_wp_file_modifications',
            'bastion_security_wp_runtime',
            'bastion_security_wp_plugin_update_compatibility',
            'bastion_security_wp_rest_surface_inventory',
        ], array_column($results, 'test'));
    }

    public function testResultsAreDeterministicAndUseSiteHealthShape(): void
    {
        $tests = $this->diagnostics()->register([])['direct'];
        $results = array_values(array_map(static fn (array $test): array => ($test['test'])(), $tests));

        self::assertSame([
            'bastion_security_wp_transport',
            'bastion_security_wp_file_editor',
            'bastion_security_wp_login_protection',
            'bastion_security_wp_xmlrpc_pingback_protection',
            'bastion_security_wp_rest_route_controls',
            'bastion_security_wp_plugin_activity_alerts',
            'bastion_security_wp_administrator_account_alerts',
            'bastion_security_wp_security_headers',
            'bastion_security_wp_file_modifications',
            'bastion_security_wp_runtime',
            'bastion_security_wp_plugin_update_compatibility',
            'bastion_security_wp_rest_surface_inventory',
        ], array_column($results, 'test'));
        self::assertSame(['good', 'good', 'recommended', 'recommended', 'recommended', 'recommended', 'recommended', 'recommended', 'good', 'good', 'recommended', 'recommended'], array_column($results, 'status'));
        self::assertSame(['label', 'status', 'badge', 'description', 'actions', 'test'], array_keys($results[0]));
        self::assertSame(['label' => 'Cerrojo Security Toolkit', 'color' => 'blue'], $results[0]['badge']);
        self::assertStringContainsString('Ownership:', $results[0]['description']);
        self::assertStringContainsString('Remediation:', $results[0]['actions']);
    }

    public function testFileEditorAndFileModificationSemanticsRemainSeparate(): void
    {
        $this->values['disallow_file_edit'] = false;
        $this->values['disallow_file_mods'] = true;
        $diagnostics = $this->diagnostics();

        self::assertSame('recommended', $diagnostics->fileEditor()['status']);
        self::assertStringContainsString('editor is available', $diagnostics->fileEditor()['description']);
        self::assertSame('recommended', $diagnostics->fileModifications()['status']);
        self::assertStringContainsString('prevent security updates', $diagnostics->fileModifications()['description']);
    }

    public function testFileEditorReportsExternalFalseConflictWithoutClaimingProtection(): void
    {
        $policy = new FileEditorPolicy(
            static fn (): bool => true,
            static fn (): bool => true,
            static fn (): bool => false,
            static fn (): array => ['defined' => true, 'value' => false],
            static fn (): bool => true,
        );
        $diagnostics = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            fileEditorPolicy: $policy,
        );

        $result = $diagnostics->fileEditor();

        self::assertSame('recommended', $result['status']);
        self::assertStringContainsString('editor is available', $result['description']);
        self::assertStringContainsString('defined outside Cerrojo', $result['description']);
        self::assertStringContainsString('will not override or remove', $result['actions']);
    }

    public function testLoginProtectionDiagnosticIsRecommendedWhenDisabledAndGoodWhenEnabledWithoutOverclaiming(): void
    {
        $disabled = $this->diagnostics()->loginProtection();
        self::assertSame('recommended', $disabled['status']);
        self::assertStringContainsString('disabled', $disabled['description']);
        self::assertStringContainsString('wp-login', $disabled['description']);
        self::assertStringContainsString('wp_authenticate()', $disabled['description']);
        self::assertStringContainsString('XML-RPC', $disabled['description']);
        self::assertStringContainsString('REST Application Passwords are not covered', $disabled['description']);
        self::assertStringContainsString('REMOTE_ADDR', $disabled['description']);
        self::assertStringContainsString('shared proxy', strtolower($disabled['description']));
        self::assertStringContainsString('transient', strtolower($disabled['description']));
        self::assertStringContainsString('race', strtolower($disabled['description']));
        self::assertStringContainsString('not WAF or DDoS protection', $disabled['description']);

        $enabledPolicy = new LoginProtectionPolicy(
            static fn (): int => 1000,
            static fn (): array => ['enabled' => true, 'generation' => 1],
        );
        $enabled = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            loginProtectionPolicy: $enabledPolicy,
        );
        self::assertSame('good', $enabled->loginProtection()['status']);
        self::assertStringContainsString('setting is enabled', $enabled->loginProtection()['description']);
        self::assertStringContainsString('does not guarantee', $enabled->loginProtection()['description']);
    }

    public function testXmlRpcPingbackDiagnosticUsesReadableSettingOnlyAndDoesNotOverclaimEnforcement(): void
    {
        $disabled = $this->diagnostics()->xmlRpcPingbackProtection();
        self::assertSame('recommended', $disabled['status']);
        self::assertStringContainsString('setting is disabled', $disabled['description']);

        $enabled = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            xmlRpcPingbackPolicy: new XmlRpcPingbackPolicy(static fn (): bool => true),
        );
        $result = $enabled->xmlRpcPingbackProtection();
        self::assertSame('good', $result['status']);
        self::assertStringContainsString('readable per-site', $result['description']);
        self::assertStringContainsString('pingback.ping', $result['description']);
        self::assertStringContainsString('pingback.extensions.getPingbacks', $result['description']);
        self::assertStringContainsString('later same-priority filters', $result['description']);
        self::assertStringContainsString('server, proxy, or CDN headers', $result['description']);
        self::assertStringContainsString('authenticated XML-RPC methods remain available', $result['description']);

        $unassessed = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            xmlRpcPingbackPolicy: new XmlRpcPingbackPolicy(static fn (): string => 'malformed'),
        );
        self::assertSame('recommended', $unassessed->xmlRpcPingbackProtection()['status']);
        self::assertStringContainsString('Not assessed', $unassessed->xmlRpcPingbackProtection()['description']);
    }

    public function testRestRouteControlsDiagnosticReportsOnlyReadableRuleCount(): void
    {
        $disabled = $this->diagnostics()->restRouteControls();
        self::assertSame('recommended', $disabled['status']);
        self::assertStringContainsString('0 selected REST route template rules', $disabled['description']);

        $enabled = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            restRouteControlsPolicy: new RestRouteControlsPolicy(static fn (): array => [
                'schema_version' => 1,
                    'rules' => [
                        ['method' => 'GET', 'route_pattern' => '/private-a'],
                        ['method' => 'POST', 'route_pattern' => '/private-b'],
                    ],
            ]),
        );
        $result = $enabled->restRouteControls();
        self::assertSame('good', $result['status']);
        self::assertStringContainsString('2 selected REST route template rules', $result['description']);
        self::assertStringNotContainsString('/private-a', $result['description']);
        self::assertStringNotContainsString('/private-b', $result['description']);
        self::assertStringContainsString('does not load the active catalog', $result['description']);

        $unassessed = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            restRouteControlsPolicy: new RestRouteControlsPolicy(static fn (): array => ['unexpected' => true]),
        );
        self::assertSame('recommended', $unassessed->restRouteControls()['status']);
        self::assertStringContainsString('Not assessed', $unassessed->restRouteControls()['description']);
    }

    public function testPluginActivityAlertDiagnosticReportsConfigurationWithoutClaimingDelivery(): void
    {
        $disabled = $this->diagnostics()->pluginActivityAlerts();
        self::assertSame('recommended', $disabled['status']);
        self::assertStringContainsString('disabled with 0 configured recipients', $disabled['description']);

        $policy = new PluginActivityAlertPolicy(
            static fn (): array => ['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            validateEmail: static fn (string $email): bool => true,
        );
        $diagnostics = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            pluginActivityAlertPolicy: $policy,
        );
        $result = $diagnostics->pluginActivityAlerts();

        self::assertSame('good', $result['status']);
        self::assertStringContainsString('enabled with 2 configured recipients', $result['description']);
        self::assertStringContainsString('attempt sends', $result['description']);
        self::assertStringContainsString('does not prove delivery', $result['description']);
        self::assertStringContainsString('Tools > Cerrojo Security Toolkit > Hardening', $result['actions']);
    }

    public function testAdministratorAccountAlertDiagnosticRequiresReadableEnabledConfigurationWithRecipients(): void
    {
        $unassessed = $this->diagnostics()->administratorAccountAlerts();
        self::assertSame('recommended', $unassessed['status']);
        self::assertStringContainsString('Not assessed', $unassessed['description']);
        self::assertStringContainsString('complete administrator-event capture', $unassessed['description']);

        $disabledPolicy = new AdministratorAccountAlertPolicy(
            static fn (): array => ['enabled' => false, 'recipients' => ['one@example.test']],
            validateEmail: static fn (string $email): bool => true,
        );
        $disabled = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            administratorAccountAlertPolicy: $disabledPolicy,
        );
        self::assertSame('recommended', $disabled->administratorAccountAlerts()['status']);
        self::assertStringContainsString('disabled with 1 configured recipient', $disabled->administratorAccountAlerts()['description']);

        $enabledPolicy = new AdministratorAccountAlertPolicy(
            static fn (): array => ['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            validateEmail: static fn (string $email): bool => true,
        );
        $enabled = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            administratorAccountAlertPolicy: $enabledPolicy,
        );
        $result = $enabled->administratorAccountAlerts();
        self::assertSame('good', $result['status']);
        self::assertStringContainsString('readable per-site', $result['description']);
        self::assertStringContainsString('enabled with 2 configured recipients', $result['description']);
        self::assertStringContainsString('does not prove wp_mail delivery', $result['description']);
        self::assertStringContainsString('complete event capture', $result['description']);
    }

    public function testSecurityHeaderDiagnosticReportsBaselineAndActiveGroupsWithoutClaimingDelivery(): void
    {
        $disabled = $this->diagnostics()->securityHeaders();
        self::assertSame('recommended', $disabled['status']);
        self::assertSame('Cerrojo: Security header preset', $disabled['label']);
        self::assertStringContainsString('baseline preference is disabled', $disabled['description']);
        self::assertStringContainsString('0 active optional groups (none)', $disabled['description']);

        $enabledPolicy = new SecurityHeadersPolicy(
            static fn (): bool => true,
            static fn (): bool => true,
            static fn (): array => ['resource_isolation', 'framing'],
        );
        $enabled = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            securityHeadersPolicy: $enabledPolicy,
        );
        $result = $enabled->securityHeaders();

        self::assertSame('good', $result['status']);
        self::assertStringContainsString('baseline preference is enabled', $result['description']);
        self::assertStringContainsString('2 active optional groups (framing, resource_isolation)', $result['description']);
        self::assertStringContainsString('configuration is not end-to-end delivery proof', $result['description']);
        self::assertStringContainsString('browser or CDN edge', $result['actions']);
        self::assertStringContainsString('per-site', $result['description']);
    }

    public function testOptionalGroupsAloneMakeTheDiagnosticConfiguredButNotProven(): void
    {
        $policy = new SecurityHeadersPolicy(
            static fn (): bool => false,
            static fn (): bool => true,
            static fn (): array => ['legacy_cross_domain'],
        );
        $diagnostics = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            securityHeadersPolicy: $policy,
        );

        $result = $diagnostics->securityHeaders();

        self::assertSame('good', $result['status']);
        self::assertStringContainsString('baseline preference is disabled', $result['description']);
        self::assertStringContainsString('1 active optional group (legacy_cross_domain)', $result['description']);
    }

    public function testBootstrapRegistersLoginProtectionHooksAtExactPrioritiesAndPreservesHeaderBehavior(): void
    {
        $source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Bootstrap.php');
        $policySource = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Security/SecurityHeadersPolicy.php');
        $xmlRpcSource = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Security/XmlRpcPingbackPolicy.php');

        self::assertStringContainsString("add_filter('authenticate', \$loginProtectionPolicy->filterAuthentication(...), 100, 3)", $source);
        self::assertStringContainsString("add_action('wp_login_failed', \$loginProtectionPolicy->recordFailure(...), 10, 2)", $source);
        self::assertStringContainsString("add_action('wp_login', \$loginProtectionPolicy->recordSuccess(...), 10, 2)", $source);
        self::assertStringContainsString("admin_post_' . LoginProtectionAdmin::POST_ACTION", $source);
        self::assertStringContainsString("admin_post_' . PluginActivityAlertAdmin::POST_ACTION", $source);
        self::assertStringContainsString("admin_post_' . XmlRpcPingbackAdmin::POST_ACTION", $source);
        self::assertStringContainsString("add_filter('xmlrpc_methods', \$xmlRpcPingbackPolicy->filterMethods(...), PHP_INT_MAX, 1)", $source);
        self::assertStringContainsString("add_filter('wp_headers', \$xmlRpcPingbackPolicy->filterHeaders(...), PHP_INT_MAX, 1)", $source);
        self::assertStringContainsString("add_filter('rest_request_before_callbacks', \$restRouteControlsPolicy->filterRequest(...), PHP_INT_MAX, 3)", $source);
        self::assertStringNotContainsString("add_filter('wp_is_application_passwords_available'", $source);
        self::assertStringNotContainsString("add_filter('rest_jsonp_enabled'", $source);
        self::assertStringContainsString("admin_post_' . RestRouteControlsAdmin::POST_ACTION", $source);
        self::assertStringContainsString("add_action('upgrader_process_complete', \$pluginActivityAlertPolicy->handleUpgraderProcessComplete(...), 10, 2)", $source);
        self::assertStringContainsString("add_action('activated_plugin', \$pluginActivityAlertPolicy->handleActivatedPlugin(...), 10, 2)", $source);
        self::assertStringContainsString("add_action('add_user_role', \$administratorAccountAlertPolicy->handleAddUserRole(...), 10, 2)", $source);
        self::assertStringContainsString("add_action('remove_user_role', \$administratorAccountAlertPolicy->handleRemoveUserRole(...), 10, 2)", $source);
        self::assertStringContainsString("add_action('deleted_user', \$administratorAccountAlertPolicy->handleDeletedUser(...), 10, 3)", $source);
        self::assertStringContainsString("admin_post_' . AdministratorAccountAlertAdmin::POST_ACTION", $source);
        self::assertStringNotContainsString("add_action('set_user_role'", $source);
        self::assertStringNotContainsString("add_action('user_register'", $source);
        self::assertStringNotContainsString("add_action('delete_user'", $source);
        self::assertStringContainsString("add_filter('wp_headers'", $source);
        self::assertStringNotContainsString('header(', $source . $policySource . $xmlRpcSource);
        self::assertStringNotContainsString('header_remove', $source . $xmlRpcSource);
        self::assertStringNotContainsString('send_headers', $source . $policySource . $xmlRpcSource);
        self::assertStringNotContainsString('switch_to_blog', $source . $xmlRpcSource);
    }

    public function testUnsupportedAndHostileRuntimeValuesAreNotCountedAsGoodOrReflected(): void
    {
        $this->values['wordpress_version'] = '<script>secret-token</script>';
        $this->values['php_version'] = '8.5.0';

        $result = $this->diagnostics()->runtime();

        self::assertSame('recommended', $result['status']);
        self::assertStringContainsString('Not assessed', $result['description']);
        self::assertStringContainsString('unavailable', $result['description']);
        self::assertStringNotContainsString('secret-token', $result['description']);
        self::assertStringNotContainsString('<script>', $result['description']);
    }

    public function testRuntimeVersionsAreEscapedAtPresentationTime(): void
    {
        $result = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => 'escaped[' . $value . ']',
        );

        self::assertStringContainsString('WordPress escaped[6.8.2] and PHP escaped[8.4.1]', $result->runtime()['description']);
    }

    public function testThrowingEscaperFailsOpenWithoutLeakingItsMessage(): void
    {
        $diagnostics = new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static function (string $value): never {
                throw new RuntimeException('secret-token');
            },
        );

        $result = $diagnostics->runtime();

        self::assertSame('recommended', $result['status']);
        self::assertStringContainsString('Not assessed', $result['description']);
        self::assertStringNotContainsString('secret-token', serialize($result));
    }

    public function testOneObservationFailureDoesNotStopOtherCallbacks(): void
    {
        $diagnostics = new SiteHealthDiagnostics(
            function (string $key): mixed {
                if ($key === 'is_ssl') {
                    throw new RuntimeException('secret-cookie-value');
                }

                return $this->values[$key];
            },
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
        );

        $transport = $diagnostics->transport();
        $editor = $diagnostics->fileEditor();

        self::assertSame('recommended', $transport['status']);
        self::assertStringContainsString('Not assessed', $transport['description']);
        self::assertStringNotContainsString('secret-cookie-value', serialize($transport));
        self::assertSame('good', $editor['status']);
        self::assertStringContainsString('editor is disabled', $editor['description']);
    }

    private function diagnostics(): SiteHealthDiagnostics
    {
        return new SiteHealthDiagnostics(
            fn (string $key): mixed => $this->values[$key],
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            securityHeadersPolicy: new SecurityHeadersPolicy(static fn (): bool => false, static fn (): bool => true),
            xmlRpcPingbackPolicy: new XmlRpcPingbackPolicy(static fn (): bool => false),
            restRouteControlsPolicy: new RestRouteControlsPolicy(static fn (): bool => false),
        );
    }
}
