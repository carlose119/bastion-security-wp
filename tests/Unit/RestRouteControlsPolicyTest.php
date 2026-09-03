<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Security\RestRouteControlsPolicy;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class RestRouteControlsRequest
{
    public function __construct(private readonly mixed $method, private readonly mixed $route) {}
    public function get_method(): mixed { return $this->method; }
    public function get_route(): mixed { return $this->route; }
}

final class RestRouteControlsPolicyTest extends TestCase
{
    public function testStateRequiresCanonicalPatternRulesAndMissingIsAssessedEmpty(): void
    {
        self::assertSame(['assessed' => true, 'rules' => []], (new RestRouteControlsPolicy(static fn (): bool => false))->state());

        $valid = ['schema_version' => 1, 'rules' => [
            ['method' => 'GET', 'route_pattern' => '/wp/v2/posts/(?P<id>[\\d]+)'],
            ['method' => 'DELETE', 'route_pattern' => '/wp/v2/posts/(?P<id>[\\d]+)'],
        ]];
        self::assertSame(['assessed' => true, 'rules' => $valid['rules']], (new RestRouteControlsPolicy(static fn (): array => $valid))->state());

        foreach ([
            [],
            ['rules' => [], 'schema_version' => 1],
            ['schema_version' => 2, 'rules' => []],
            ['schema_version' => 1, 'rules' => [['method' => 'get', 'route_pattern' => '/a']]],
            ['schema_version' => 1, 'rules' => [['method' => 'OPTIONS', 'route_pattern' => '/a']]],
            ['schema_version' => 1, 'rules' => [['method' => 'GET', 'route_pattern' => '/broken[']]],
            ['schema_version' => 1, 'rules' => [['method' => 'GET', 'route_pattern' => "/bad\0pattern"]]],
            ['schema_version' => 1, 'rules' => [
                ['method' => 'DELETE', 'route_pattern' => '/a'],
                ['method' => 'GET', 'route_pattern' => '/a'],
            ]],
        ] as $malformed) {
            self::assertSame(['assessed' => false, 'rules' => []], (new RestRouteControlsPolicy(static fn (): array => $malformed))->state());
        }
    }

    public function testCanonicalRulesPreservePatternBytesAndSortRouteThenMethod(): void
    {
        $policy = new RestRouteControlsPolicy();
        self::assertSame([
            ['method' => 'GET', 'route_pattern' => '/A/(?P<ID>[\\d]+)'],
            ['method' => 'HEAD', 'route_pattern' => '/A/(?P<ID>[\\d]+)'],
            ['method' => 'POST', 'route_pattern' => '/b'],
        ], $policy->canonicalRules([
            ['method' => 'post', 'route_pattern' => '/b'],
            ['method' => 'head', 'route_pattern' => '/A/(?P<ID>[\\d]+)'],
            ['method' => 'get', 'route_pattern' => '/A/(?P<ID>[\\d]+)'],
        ]));
    }

    public function testCanonicalRulesRejectInvalidShapePatternCompilationDuplicatesAndLimits(): void
    {
        $policy = new RestRouteControlsPolicy();
        $valid = ['method' => 'GET', 'route_pattern' => '/ok'];
        foreach ([
            'bad',
            [['route_pattern' => '/ok', 'method' => 'GET']],
            [['method' => 1, 'route_pattern' => '/ok']],
            [['method' => 'OPTIONS', 'route_pattern' => '/ok']],
            [['method' => 'GET', 'route_pattern' => 'relative']],
            [['method' => 'GET', 'route_pattern' => "/control\n"]],
            [['method' => 'GET', 'route_pattern' => '/delimiter@break']],
            [['method' => 'GET', 'route_pattern' => '/broken(']],
            [['method' => 'GET', 'route_pattern' => '/' . str_repeat('a', 2048)]],
            [$valid, $valid],
            array_fill(0, 101, $valid),
        ] as $invalid) {
            self::assertNull($policy->canonicalRules($invalid));
        }
    }

    public function testSaveCachesStateButAlwaysPerformsOneExactReadbackAfterWrite(): void
    {
        $stored = ['schema_version' => 1, 'rules' => [['method' => 'GET', 'route_pattern' => '/a']]];
        $reads = 0;
        $writes = 0;
        $policy = new RestRouteControlsPolicy(
            static function () use (&$stored, &$reads): mixed { ++$reads; return $stored; },
            static function (array $value) use (&$stored, &$writes): bool { ++$writes; $stored = $value; return true; },
        );

        self::assertSame($policy->state(), $policy->state());
        self::assertSame(1, $reads);
        self::assertSame('unchanged', $policy->saveRules([['method' => 'GET', 'route_pattern' => '/a']]));
        self::assertSame(1, $reads);
        self::assertSame('updated', $policy->saveRules([['method' => 'POST', 'route_pattern' => '/b']]));
        self::assertSame(2, $reads);
        self::assertSame(1, $writes);
        self::assertSame(['method' => 'POST', 'route_pattern' => '/b'], $policy->state()['rules'][0]);
    }

    public function testDynamicTemplatesUseAnchoredCaseInsensitiveWordPressMatching(): void
    {
        $errors = [];
        $policy = new RestRouteControlsPolicy(
            static fn (): array => ['schema_version' => 1, 'rules' => [
                ['method' => 'GET', 'route_pattern' => '/wp/v2/posts/(?P<id>[\\d]+)'],
                ['method' => 'HEAD', 'route_pattern' => '/wp/v2/posts/(?P<id>[\\d]+)'],
            ]],
            errorFactory: static function (string $code, string $message, array $data) use (&$errors): array {
                $errors[] = compact('code', 'message', 'data');
                return ['code' => $code, 'status' => $data['status']];
            },
            isError: static fn (mixed $value): bool => $value instanceof \stdClass,
        );

        foreach ([null, 'earlier-non-error'] as $response) {
            self::assertSame(
                ['code' => 'bastion_rest_route_disabled', 'status' => 403],
                $policy->filterRequest($response, ['callback' => 'ignored'], new RestRouteControlsRequest('GET', '/WP/v2/posts/42')),
            );
        }
        self::assertSame(['code' => 'bastion_rest_route_disabled', 'status' => 403], $policy->filterRequest(null, null, new RestRouteControlsRequest('HEAD', '/wp/v2/posts/7')));
        foreach ([
            new RestRouteControlsRequest('POST', '/wp/v2/posts/42'),
            new RestRouteControlsRequest('GET', '/wp/v2/posts/nope'),
            new RestRouteControlsRequest('GET', '/wp/v2/posts/42/extra'),
            new RestRouteControlsRequest('OPTIONS', '/wp/v2/posts/42'),
            new RestRouteControlsRequest('get', '/wp/v2/posts/42'),
        ] as $request) {
            self::assertNull($policy->filterRequest(null, null, $request));
        }
        self::assertSame('This REST route is disabled by site policy.', $errors[0]['message']);
    }

    public function testErrorsAndMalformedRequestsFailOpen(): void
    {
        $existing = new \stdClass();
        $policy = new RestRouteControlsPolicy(
            static function (): never { throw new RuntimeException('private'); },
            errorFactory: static function (): never { throw new RuntimeException('private'); },
            isError: static fn (mixed $value): bool => $value === $existing,
        );
        self::assertSame($existing, $policy->filterRequest($existing, null, new RestRouteControlsRequest('GET', '/a')));
        self::assertNull($policy->filterRequest(null, null, new RestRouteControlsRequest('GET', '/a')));
        self::assertNull($policy->filterRequest(null, null, new class {}));
    }
}
