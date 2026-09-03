<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Bootstrap;
use BastionSecurityWP\Security\FileEditorPolicy;
use BastionSecurityWP\Security\LoginProtectionPolicy;
use BastionSecurityWP\Security\SecurityHeadersPolicy;
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
            'bastion_security_wp_security_headers',
            'bastion_security_wp_file_modifications',
            'bastion_security_wp_runtime',
            'bastion_security_wp_plugin_update_compatibility',
            'bastion_security_wp_rest_surface_inventory',
        ], array_keys($tests['direct']));
        self::assertSame('plugin_callback', $tests['async']['plugin_async']['test']);
        self::assertCount(9, array_unique(array_keys($tests['direct'])));
    }

    public function testSharedReportListContainsExactlyEightBastionDiagnosticsInStableOrder(): void
    {
        $results = $this->diagnostics()->reports();

        self::assertCount(8, $results);
        self::assertSame([
            'bastion_security_wp_transport',
            'bastion_security_wp_file_editor',
            'bastion_security_wp_login_protection',
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
            'bastion_security_wp_security_headers',
            'bastion_security_wp_file_modifications',
            'bastion_security_wp_runtime',
            'bastion_security_wp_plugin_update_compatibility',
            'bastion_security_wp_rest_surface_inventory',
        ], array_column($results, 'test'));
        self::assertSame(['good', 'good', 'recommended', 'recommended', 'good', 'good', 'recommended', 'recommended'], array_column($results, 'status'));
        self::assertSame(['label', 'status', 'badge', 'description', 'actions', 'test'], array_keys($results[0]));
        self::assertSame(['label' => 'Bastion Security', 'color' => 'blue'], $results[0]['badge']);
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
        self::assertStringContainsString('defined outside Bastion', $result['description']);
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

    public function testSecurityHeaderDiagnosticReportsBaselineAndActiveGroupsWithoutClaimingDelivery(): void
    {
        $disabled = $this->diagnostics()->securityHeaders();
        self::assertSame('recommended', $disabled['status']);
        self::assertSame('Bastion: Security header preset', $disabled['label']);
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

        self::assertStringContainsString("add_filter('authenticate', \$loginProtectionPolicy->filterAuthentication(...), 100, 3)", $source);
        self::assertStringContainsString("add_action('wp_login_failed', \$loginProtectionPolicy->recordFailure(...), 10, 2)", $source);
        self::assertStringContainsString("add_action('wp_login', \$loginProtectionPolicy->recordSuccess(...), 10, 2)", $source);
        self::assertStringContainsString("admin_post_' . LoginProtectionAdmin::POST_ACTION", $source);
        self::assertStringContainsString("add_filter('wp_headers'", $source);
        self::assertStringNotContainsString('header(', $source . $policySource);
        self::assertStringNotContainsString('send_headers', $source . $policySource);
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
        );
    }
}
