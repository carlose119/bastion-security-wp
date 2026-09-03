<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\RestSurfaceInventory;
use BastionSecurityWP\SiteHealthDiagnostics;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class FaithfulRestServer
{
    protected array $namespaces = [];
    protected array $endpoints = [];
    protected array $route_options = [];
    public int $restEndpointFilterCalls = 0;

    public function registerRoute(string $namespace, string $route, array $handlers): void
    {
        $this->namespaces[$namespace][$route] = true;
        $this->endpoints[$route] = $handlers + ['namespace' => $namespace];
    }

    public function get_routes(): array
    {
        ++$this->restEndpointFilterCalls;
        foreach ($this->endpoints as $route => $handlers) {
            $this->route_options[$route] = ['namespace' => $handlers['namespace']];
        }

        return $this->endpoints;
    }

    public function get_route_options(string $route): ?array
    {
        return $this->route_options[$route] ?? null;
    }
}

if (! class_exists('WP_REST_Server', false)) {
    class_alias(FaithfulRestServer::class, 'WP_REST_Server');
}

final class RestSurfaceInventoryTest extends TestCase
{
    public function testTuplesAndMethodsAreNormalizedSortedEscapedAndAllowlisted(): void
    {
        $secretCallback = static fn (): string => 'secret-callback-result';
        $inventory = $this->inventory([
            'namespaces' => ['z/v1', '<script>alpha</script>', 'z/v1'],
            'routes' => [
                'z/v1' => [
                    '/z/v1/b' => [[
                        'methods' => ['post' => true, 'GET' => true, 'BAD METHOD' => true, 'secret-token' => false],
                        'callback' => $secretCallback,
                        'permission_callback' => 'secret-permission',
                        'args' => ['token' => 'secret-argument'],
                    ]],
                    '/z/v1/a' => [['methods' => 'patch, GET, bad method, PATCH']],
                ],
                '<script>alpha</script>' => [
                    '/<img src=x onerror=secret-route>' => [['methods' => ['DELETE' => true]]],
                ],
            ],
        ]);

        $result = $inventory->report();
        $serialized = serialize($result);

        self::assertSame('good', $result['status']);
        self::assertStringContainsString('&lt;script&gt;alpha&lt;/script&gt;', $result['description']);
        self::assertStringContainsString('/&lt;img src=x onerror=secret-route&gt;', $result['description']);
        self::assertStringContainsString('Methods: <code>GET, POST</code>', $result['description']);
        self::assertStringContainsString('Methods: <code>GET, PATCH</code>', $result['description']);
        self::assertLessThan(strpos($result['description'], '/z/v1/b'), strpos($result['description'], '/z/v1/a'));
        self::assertStringNotContainsString('secret-permission', $serialized);
        self::assertStringNotContainsString('secret-argument', $serialized);
        self::assertStringNotContainsString('secret-callback-result', $serialized);
        self::assertStringNotContainsString('BAD METHOD', $serialized);
    }

    public function testOutputLimitIsDeterministicAndReportsOnlyTheOmittedCount(): void
    {
        $routes = [];
        for ($index = 101; $index >= 0; --$index) {
            $routes[sprintf('/bulk/%03d', $index)] = [['methods' => ['GET' => true]]];
        }

        $description = $this->inventory([
            'namespaces' => ['bulk/v1'],
            'routes' => ['bulk/v1' => $routes],
        ])->report()['description'];

        self::assertStringContainsString('Showing 100 of 102 routes; 2 truncated.', $description);
        self::assertStringContainsString('/bulk/000', $description);
        self::assertStringContainsString('/bulk/099', $description);
        self::assertStringNotContainsString('/bulk/100', $description);
    }

    public function testUnavailableRegistryIsNotAssessedAndCannotInitializeRest(): void
    {
        $result = (new RestSurfaceInventory())->report();
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/RestSurfaceInventory.php');

        self::assertSame('recommended', $result['status']);
        self::assertStringContainsString('Not assessed', $result['description']);
        self::assertStringNotContainsString('rest_get_server', (string) $source);
        self::assertStringNotContainsString('->get_routes(', (string) $source);
    }

    public function testRealisticServerReadDoesNotFilterMaterializeOptionsOrInvokeCallbacks(): void
    {
        $calls = 0;
        $callback = static function () use (&$calls): void {
            ++$calls;
        };
        $server = new \WP_REST_Server();
        $server->registerRoute('custom/v1', '/custom/v1/item', [[
                'methods' => ['GET' => true],
                'callback' => $callback,
                'permission_callback' => $callback,
        ]]);
        $GLOBALS['wp_rest_server'] = $server;
        $optionsBefore = $server->get_route_options('/custom/v1/item');
        $filtersBefore = $server->restEndpointFilterCalls;

        try {
            $result = (new RestSurfaceInventory(null, static fn (string $value): string => $value))->report();
        } finally {
            unset($GLOBALS['wp_rest_server']);
        }

        self::assertSame('good', $result['status']);
        self::assertStringContainsString('Methods: <code>GET</code>', $result['description']);
        self::assertSame($filtersBefore, $server->restEndpointFilterCalls);
        self::assertSame($optionsBefore, $server->get_route_options('/custom/v1/item'));
        self::assertSame(0, $calls);
    }

    public function testReaderAndPresenterFailuresStayInsideInventoryAndOtherChecksRun(): void
    {
        $readerFailure = new RestSurfaceInventory(static function (): never {
            throw new RuntimeException('secret-reader');
        });
        $presenterFailure = new RestSurfaceInventory(
            static fn (): array => ['namespaces' => ['x/v1'], 'routes' => ['x/v1' => ['/x' => [['methods' => 'GET']]]]],
            static function (string $value): never {
                throw new RuntimeException('secret-presenter');
            },
        );
        $diagnostics = new SiteHealthDiagnostics(
            static fn (string $key): mixed => $key === 'disallow_file_edit',
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
            $readerFailure,
        );

        self::assertSame('recommended', $readerFailure->report()['status']);
        self::assertStringNotContainsString('secret-reader', serialize($readerFailure->report()));
        self::assertSame('recommended', $presenterFailure->report()['status']);
        self::assertStringNotContainsString('secret-presenter', serialize($presenterFailure->report()));
        self::assertSame('good', $diagnostics->fileEditor()['status']);
    }

    public function testInventoryRemainsPassiveAndRouteControlsAvoidInventoryAndAuthenticationCoupling(): void
    {
        $inventorySource = (string) file_get_contents(dirname(__DIR__, 2) . '/src/RestSurfaceInventory.php');
        $policySource = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Security/RestRouteControlsPolicy.php');
        $bootstrapSource = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Bootstrap.php');

        self::assertStringNotContainsString('->get_routes(', $inventorySource . $policySource);
        self::assertStringNotContainsString('rest_endpoints', $policySource . $bootstrapSource);
        self::assertStringContainsString("add_filter('rest_request_before_callbacks'", $bootstrapSource);
        self::assertStringNotContainsString('rest_authentication_errors', $policySource . $bootstrapSource);
        self::assertStringNotContainsString('wp_is_application_passwords_available', $policySource . $bootstrapSource);
        self::assertStringNotContainsString('rest_jsonp_enabled', $policySource . $bootstrapSource);
        self::assertStringNotContainsString('rest_pre_dispatch', $policySource . $bootstrapSource);
    }

    /** @param array<mixed> $registry */
    private function inventory(array $registry): RestSurfaceInventory
    {
        return new RestSurfaceInventory(
            static fn (): array => $registry,
            static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
        );
    }
}
