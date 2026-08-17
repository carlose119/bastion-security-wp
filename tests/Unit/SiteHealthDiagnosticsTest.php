<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Bootstrap;
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
            'bastion_security_wp_file_modifications',
            'bastion_security_wp_runtime',
            'bastion_security_wp_rest_surface_inventory',
        ], array_keys($tests['direct']));
        self::assertSame('plugin_callback', $tests['async']['plugin_async']['test']);
        self::assertCount(6, array_unique(array_keys($tests['direct'])));
    }

    public function testResultsAreDeterministicAndUseSiteHealthShape(): void
    {
        $tests = $this->diagnostics()->register([])['direct'];
        $results = array_values(array_map(static fn (array $test): array => ($test['test'])(), $tests));

        self::assertSame([
            'bastion_security_wp_transport',
            'bastion_security_wp_file_editor',
            'bastion_security_wp_file_modifications',
            'bastion_security_wp_runtime',
            'bastion_security_wp_rest_surface_inventory',
        ], array_column($results, 'test'));
        self::assertSame(['good', 'good', 'good', 'good', 'recommended'], array_column($results, 'status'));
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
        );
    }
}
