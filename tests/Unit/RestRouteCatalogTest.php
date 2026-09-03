<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\RestRouteCatalog;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class RestRouteCatalogTest extends TestCase
{
    public function testConstructionIsPassiveAndExplicitLoadDiscoversEffectiveRegistryWithoutCallbacks(): void
    {
        $reads = 0;
        $callbacks = 0;
        $server = new class($callbacks) {
            public function __construct(private int &$callbacks) {}
            public function get_routes(): array
            {
                return [
                    '/wp/v2/posts/(?P<id>[\\d]+)' => [
                        ['methods' => ['GET' => true], 'callback' => function (): void { ++$this->callbacks; }],
                        ['methods' => 'POST', 'permission_callback' => function (): void { ++$this->callbacks; }],
                    ],
                    '/vendor/v1/action' => ['methods' => ['DELETE' => true, 'OPTIONS' => true]],
                    '/' => ['methods' => 'OPTIONS'],
                ];
            }
            public function get_route_options(string $route): array { return ['namespace' => str_starts_with($route, '/wp/') ? 'wp/v2' : (str_starts_with($route, '/vendor/') ? 'vendor/v1' : '')]; }
        };
        $catalog = new RestRouteCatalog(static function () use (&$reads, $server): object { ++$reads; return $server; });
        self::assertSame(0, $reads);
        self::assertSame(0, $callbacks);

        $result = $catalog->load([
            ['method' => 'GET', 'route_pattern' => '/wp/v2/posts/(?P<id>[\\d]+)'],
            ['method' => 'PATCH', 'route_pattern' => '/gone/v1/item'],
        ]);

        self::assertTrue($result['available']);
        self::assertSame(1, $reads);
        self::assertSame(0, $callbacks);
        self::assertSame(['', 'vendor/v1', 'wp/v2'], array_column($result['groups'], 'namespace'));
        self::assertSame(['GET', 'HEAD', 'POST'], $result['groups'][2]['routes'][0]['methods']);
        self::assertSame(['DELETE'], $result['groups'][1]['routes'][0]['methods']);
        self::assertSame([], $result['groups'][0]['routes'][0]['methods']);
        self::assertSame([['method' => 'PATCH', 'route_pattern' => '/gone/v1/item', 'token' => RestRouteCatalog::token('PATCH', '/gone/v1/item')]], $result['stale']);
        self::assertSame(['namespaces' => 3, 'templates' => 3, 'pairs' => 4, 'selected' => 2, 'stale' => 1], $result['counts']);
    }

    public function testNormalizedMethodMapsExplicitHeadSortingAndMalformedIsolation(): void
    {
        $catalog = new RestRouteCatalog(static fn (): object => new class {
            public function get_routes(): array
            {
                return [
                    '/z/v1/b' => [['methods' => ['PATCH' => true, 'get' => true, 'POST' => false, 0 => 'PUT']]],
                    '/z/v1/a' => [['methods' => ['HEAD' => true]], ['broken' => true]],
                    7 => ['methods' => 'GET'],
                    '/broken[' => ['methods' => 'GET'],
                ];
            }
            public function get_route_options(string $route): array { return ['namespace' => 'z/v1']; }
        });
        $result = $catalog->load([]);
        self::assertTrue($result['available']);
        self::assertSame(['/z/v1/a', '/z/v1/b'], array_column($result['groups'][0]['routes'], 'route_pattern'));
        self::assertSame(['HEAD'], $result['groups'][0]['routes'][0]['methods']);
        self::assertSame(['GET', 'HEAD', 'PATCH'], $result['groups'][0]['routes'][1]['methods']);
    }

    public function testCatalogLevelFailuresAreUnavailableAndTokensAreCanonicalOpaqueRoundTrips(): void
    {
        $catalog = new RestRouteCatalog(static function (): never { throw new RuntimeException('private'); });
        $result = $catalog->load([]);
        self::assertFalse($result['available']);
        self::assertSame(['namespaces' => 0, 'templates' => 0, 'pairs' => 0, 'selected' => 0, 'stale' => 0], $result['counts']);

        $token = RestRouteCatalog::token('GET', '/Case/(?P<id>[\\d]+)');
        self::assertStringStartsWith('v1.', $token);
        self::assertStringNotContainsString('=', $token);
        self::assertSame(['method' => 'GET', 'route_pattern' => '/Case/(?P<id>[\\d]+)'], RestRouteCatalog::decodeToken($token));
        foreach (['', 'v2.AA', 'v1.AA=', 'v1.***', $token . 'A', 'v1.' . rtrim(strtr(base64_encode("GET\0/a\0b"), '+/', '-_'), '=')] as $invalid) {
            self::assertNull(RestRouteCatalog::decodeToken($invalid));
        }
    }
}
