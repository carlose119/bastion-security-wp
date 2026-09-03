<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\PluginUpdateCompatibility;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class PluginUpdateCompatibilityTest extends TestCase
{
    private const NOW = 1_700_000_000;

    public function testUnauthorizedSingleSiteAndMultisiteRequestsDoNotReadInventory(): void
    {
        $reads = 0;
        $single = $this->diagnostic(
            capabilities: static fn (string $capability): bool => false,
            transient: static function () use (&$reads): object {
                ++$reads;
                return new \stdClass();
            },
            plugins: static function () use (&$reads): array {
                ++$reads;
                return [];
            },
        );

        $singleResult = $single->report();
        self::assertSame('recommended', $singleResult['status']);
        self::assertStringContainsString('Not assessed', $singleResult['description']);
        self::assertSame(0, $reads);

        $multisite = $this->diagnostic(
            capabilities: static fn (string $capability): bool => $capability === 'update_plugins',
            multisite: true,
            transient: static function () use (&$reads): object {
                ++$reads;
                return new \stdClass();
            },
            plugins: static function () use (&$reads): array {
                ++$reads;
                return [];
            },
        );
        self::assertStringContainsString('Not assessed', $multisite->report()['description']);
        self::assertSame(0, $reads);
    }

    /** @dataProvider invalidCacheProvider */
    public function testMissingMalformedStaleAndFutureCachesAreNotAssessed(mixed $cache): void
    {
        $result = $this->diagnostic(transient: static fn (): mixed => $cache)->report();

        self::assertSame('recommended', $result['status']);
        self::assertStringContainsString('Not assessed', $result['description']);
        self::assertStringNotContainsString('Example Plugin', $result['description']);
    }

    /** @return iterable<string, array{mixed}> */
    public static function invalidCacheProvider(): iterable
    {
        yield 'missing' => [false];
        yield 'missing checked' => [(object) ['last_checked' => self::NOW, 'response' => [], 'no_update' => []]];
        yield 'malformed response' => [(object) ['last_checked' => self::NOW, 'checked' => [], 'response' => 'bad', 'no_update' => []]];
        yield 'stale' => [(object) ['last_checked' => self::NOW - 43_201, 'checked' => [], 'response' => [], 'no_update' => []]];
        yield 'future' => [(object) ['last_checked' => self::NOW + 301, 'checked' => [], 'response' => [], 'no_update' => []]];
    }

    public function testAcceptsArrayAndObjectCacheFormsAndReportsFreshEmptyResponseAsGood(): void
    {
        $array = $this->validCache(response: []);
        $object = (object) $array;
        $object->checked = (object) $array['checked'];
        $object->response = (object) [];
        $object->no_update = (object) [];

        foreach ([$array, $object] as $cache) {
            $result = $this->diagnostic(transient: static fn (): mixed => $cache)->report();
            self::assertSame('good', $result['status']);
            self::assertStringContainsString('no cached pending plugin updates', strtolower($result['description']));
            self::assertStringContainsString('cache age', strtolower($result['description']));
            self::assertStringContainsString('does not prove that a remote check succeeded', strtolower($result['description']));
        }
    }

    public function testInstalledVersionMismatchAndResponseNoUpdateConflictAreNotAssessed(): void
    {
        $mismatch = $this->validCache();
        $mismatch['checked']['example/example.php'] = '0.9.0';
        self::assertStringContainsString('Not assessed', $this->diagnostic(transient: static fn (): array => $mismatch)->report()['description']);

        $conflict = $this->validCache(response: ['example/example.php' => $this->target()]);
        $conflict['no_update']['example/example.php'] = $this->target();
        self::assertStringContainsString('Not assessed', $this->diagnostic(transient: static fn (): array => $conflict)->report()['description']);
    }

    /** @dataProvider classificationProvider */
    public function testClassifiesOnlyDeclaredTargetRequirements(
        array|object $target,
        string $classification,
        array $reasons,
    ): void {
        $cache = $this->validCache(response: ['example/example.php' => $target]);
        $result = $this->diagnostic(transient: static fn (): array => $cache)->report();
        $serialized = serialize($result);

        self::assertSame('recommended', $result['status']);
        self::assertStringContainsString($classification, $result['description']);
        foreach ($reasons as $reason) {
            self::assertStringContainsString($reason, $result['description']);
        }
    }

    /** @return iterable<string, array{array|object, string, list<string>}> */
    public static function classificationProvider(): iterable
    {
        yield 'met object' => [(object) self::target(), 'Declared requirements met', ['does not guarantee compatibility or absence of conflicts']];
        yield 'wordpress blocked' => [self::target(requires: '6.9'), 'Blocked by declared requirements', ['WordPress 6.9 minimum is not met']];
        yield 'php blocked' => [self::target(requiresPhp: '8.5'), 'Blocked by declared requirements', ['PHP 8.5 minimum is not met']];
        yield 'both blocked' => [self::target(requires: '6.9', requiresPhp: '8.5'), 'Blocked by declared requirements', ['WordPress 6.9 minimum is not met', 'PHP 8.5 minimum is not met']];
        yield 'missing minimum' => [self::target(requires: null), 'Compatibility unknown', ['minimum or tested-through metadata is missing or malformed']];
        yield 'malformed tested' => [self::target(tested: '<script>bad</script>'), 'Compatibility unknown', ['minimum or tested-through metadata is missing or malformed']];
        yield 'tested behind' => [self::target(tested: '6.7'), 'Compatibility unknown', ['newer than the publisher-tested-through WordPress version']];
    }

    public function testInstalledHeadersAreNeverUsedAsTargetRequirementFallbacks(): void
    {
        $cache = $this->validCache(response: ['example/example.php' => ['new_version' => '2.0.0']]);
        $plugins = $this->plugins();
        $plugins['example/example.php'] += ['RequiresWP' => '6.0', 'RequiresPHP' => '8.0', 'Tested' => '6.9'];

        $result = $this->diagnostic(
            transient: static fn (): array => $cache,
            plugins: static fn (): array => $plugins,
        )->report();

        self::assertStringContainsString('Compatibility unknown', $result['description']);
        self::assertStringContainsString('Declared minimum WordPress: unavailable', $result['description']);
    }

    public function testOrphansAreIgnoredAndRowsAreSortedThenLimitedDeterministically(): void
    {
        $plugins = [];
        $checked = [];
        $response = ['orphan/secret.php' => ['new_version' => '9.9', 'secret' => 'do-not-show']];
        for ($index = 0; $index < 52; ++$index) {
            $key = sprintf('plugin-%02d/plugin.php', $index);
            $name = $index === 0 ? 'Zulu' : sprintf('Plugin %02d', 51 - $index);
            $plugins[$key] = ['Name' => $name, 'Version' => '1.0.0'];
            $checked[$key] = '1.0.0';
            $response[$key] = $this->target(newVersion: '2.0.0');
        }
        $cache = [
            'last_checked' => self::NOW - 60,
            'checked' => $checked,
            'response' => $response,
            'no_update' => [],
        ];

        $result = $this->diagnostic(
            transient: static fn (): array => $cache,
            plugins: static fn (): array => $plugins,
        )->report();
        $description = $result['description'];

        self::assertStringContainsString('Total pending installed updates: 52. Shown: 50. Omitted: 2.', $description);
        self::assertSame(50, substr_count($description, 'Classification:'));
        self::assertTrue(strpos($description, 'Plugin 00') < strpos($description, 'Plugin 01'));
        self::assertStringNotContainsString('Zulu', $description);
        self::assertStringNotContainsString('orphan', $description);
        self::assertStringNotContainsString('do-not-show', $description);
    }

    public function testHostileMetadataIsEscapedBoundedAndUnsafeFieldsAreNeverRendered(): void
    {
        $target = $this->target();
        $target['new_version'] = '<img src=x onerror=alert(1)>' . str_repeat('x', 300);
        $target += [
            'package' => 'https://example.test/secret.zip',
            'url' => 'https://example.test/details',
            'callback' => 'secret_callback',
            'secret' => 'secret-token',
            'icons' => ['evil'],
        ];
        $cache = $this->validCache(response: ['example/example.php' => $target]);
        $plugins = $this->plugins();
        $plugins['example/example.php']['Name'] = '<script>alert(2)</script>';

        $serialized = serialize($this->diagnostic(
            transient: static fn (): array => $cache,
            plugins: static fn (): array => $plugins,
        )->report());

        self::assertStringNotContainsString('<script>', $serialized);
        self::assertStringNotContainsString('<img', $serialized);
        self::assertStringContainsString('&lt;script&gt;', $serialized);
        self::assertStringContainsString('&lt;img', $serialized);
        self::assertStringNotContainsString('secret.zip', $serialized);
        self::assertStringNotContainsString('details', $serialized);
        self::assertStringNotContainsString('secret_callback', $serialized);
        self::assertStringNotContainsString('secret-token', $serialized);
        self::assertLessThan(2_000, strlen($serialized));
    }

    public function testReaderExceptionsAndUnavailablePluginMetadataBecomeGenericNotAssessed(): void
    {
        $exception = $this->diagnostic(
            transient: static function (): never {
                throw new RuntimeException('secret exception');
            },
        )->report();
        $unavailable = $this->diagnostic(plugins: static fn () => null)->report();

        self::assertStringContainsString('Not assessed', $exception['description']);
        self::assertStringNotContainsString('secret exception', serialize($exception));
        self::assertStringContainsString('Not assessed', $unavailable['description']);
    }

    public function testSourceContainsOnlyReadOnlyUpdateInventoryOperations(): void
    {
        $source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/PluginUpdateCompatibility.php');

        self::assertStringContainsString("get_site_transient('update_plugins')", $source);
        self::assertStringContainsString("function_exists('get_plugins')", $source);
        self::assertStringContainsString("ABSPATH . 'wp-admin/includes/plugin.php'", $source);
        self::assertStringContainsString('is_readable($coreFile)', $source);
        self::assertStringContainsString('get_plugins()', $source);
        self::assertStringNotContainsString('wp_update_plugins', $source);
        self::assertDoesNotMatchRegularExpression('/wp_remote_|set_site_transient|set_transient|update_option|add_option|delete_option|plugins_api|upgrader|package\b|<button|href=|callback/i', $source);
    }

    public function testReadmeDocumentsDiagnosticBoundariesAndThreeStateSemantics(): void
    {
        $readme = (string) file_get_contents(dirname(__DIR__, 2) . '/README.md');

        self::assertStringContainsString('nine Bastion diagnostics', $readme);
        self::assertStringContainsString('Declared requirements met', $readme);
        self::assertStringContainsString('Blocked by declared requirements', $readme);
        self::assertStringContainsString('Compatibility unknown', $readme);
        self::assertStringContainsString('does not guarantee compatibility or absence of conflicts', $readme);
        self::assertStringContainsString('no more than 12 hours old', $readme);
        self::assertStringContainsString('limited to 50 displayed updates', $readme);
        self::assertStringContainsString('performs no network request', $readme);
        self::assertStringContainsString('provides no update button or action', $readme);
    }

    /** @return array<string, mixed> */
    private function validCache(array $response = []): array
    {
        return [
            'last_checked' => self::NOW - 60,
            'checked' => ['example/example.php' => '1.0.0'],
            'response' => $response,
            'no_update' => [],
        ];
    }

    /** @return array<string, array<string, string>> */
    private function plugins(): array
    {
        return ['example/example.php' => ['Name' => 'Example Plugin', 'Version' => '1.0.0']];
    }

    /** @return array<string, string> */
    private static function target(
        ?string $requires = '6.8',
        ?string $requiresPhp = '8.1',
        ?string $tested = '6.9',
        string $newVersion = '2.0.0',
    ): array {
        return array_filter([
            'new_version' => $newVersion,
            'requires' => $requires,
            'requires_php' => $requiresPhp,
            'tested' => $tested,
        ], static fn (mixed $value): bool => $value !== null);
    }

    private function diagnostic(
        ?callable $capabilities = null,
        bool $multisite = false,
        ?callable $transient = null,
        ?callable $plugins = null,
    ): PluginUpdateCompatibility {
        return new PluginUpdateCompatibility(
            $capabilities ?? static fn (string $capability): bool => in_array($capability, ['update_plugins', 'manage_network_plugins'], true),
            static fn (): bool => $multisite,
            $transient ?? fn (): array => $this->validCache(),
            $plugins ?? fn (): array => $this->plugins(),
            static fn (): int => self::NOW,
            static fn (): string => '6.8.2',
            static fn (): string => '8.4.1',
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
        );
    }
}
