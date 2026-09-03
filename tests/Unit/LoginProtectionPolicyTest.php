<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Security\LoginProtectionPolicy;
use PHPUnit\Framework\TestCase;

final class LoginProtectionPolicyTest extends TestCase
{
    public function testIdentityIsNormalizedHashedAndRawValueIsNeverUsedInTransientKey(): void
    {
        $harness = $this->harness();
        $policy = $harness['policy'];

        $policy->recordFailure('  AdMiN@Example.COM  ');

        self::assertCount(2, $harness['transients']);
        $identityKey = array_values(array_filter(array_keys($harness['transients']), static fn (string $key): bool => str_starts_with($key, 'bastion_lpu_')))[0];
        self::assertMatchesRegularExpression('/^bastion_lpu_1_[a-f0-9]{64}$/', $identityKey);
        self::assertStringNotContainsString('admin', $identityKey);
        self::assertSame(
            'bastion_lpu_1_' . hash_hmac('sha256', 'admin@example.com', 'test-auth-secret'),
            $identityKey,
        );
        self::assertStringNotContainsString('AdMiN', serialize($harness['transients']));
    }

    public function testPeerCanonicalizationSupportsIpv4Ipv6MappedAndRejectsInvalidOrMissingAddresses(): void
    {
        foreach ([
            '192.0.2.4' => '192.0.2.4',
            '2001:0db8:0:0:0:0:0:1' => '2001:db8::1',
            '::ffff:192.0.2.4' => '192.0.2.4',
        ] as $input => $canonical) {
            $harness = $this->harness(address: $input);
            $harness['policy']->recordFailure('');
            $expected = 'bastion_lpi_1_' . hash_hmac('sha256', $canonical, 'test-auth-secret');
            self::assertArrayHasKey($expected, $harness['transients']);
            self::assertTrue($harness['policy']->peerAvailable());
        }

        foreach (['not-an-ip', '', null] as $input) {
            $harness = $this->harness(address: $input);
            $harness['policy']->recordFailure('');
            self::assertSame([], $harness['transients']);
            self::assertFalse($harness['policy']->peerAvailable());
        }
    }

    public function testProductionAddressReaderUsesOnlyRemoteAddr(): void
    {
        $source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Security/LoginProtectionPolicy.php');

        self::assertStringContainsString("\$_SERVER['REMOTE_ADDR']", $source);
        self::assertStringNotContainsString('HTTP_X_FORWARDED_FOR', $source);
        self::assertStringNotContainsString('HTTP_FORWARDED', $source);
        self::assertStringNotContainsString('X-Forwarded-For', $source);
    }

    public function testIdentityThresholdsApplyExactProgressiveCooldownsAndWindowBoundary(): void
    {
        $harness = $this->harness(address: null);

        for ($index = 0; $index < 4; $index++) {
            $harness['policy']->recordFailure('user');
        }
        self::assertSame(0, $this->identityBucket($harness)['blocked_until']);

        $harness['policy']->recordFailure('user');
        self::assertSame(1060, $this->identityBucket($harness)['blocked_until']);

        $harness['now'] = 1060;
        for ($index = 0; $index < 3; $index++) {
            $harness['policy']->recordFailure('user');
        }
        self::assertSame(1360, $this->identityBucket($harness)['blocked_until']);

        $harness['now'] = 1360;
        for ($index = 0; $index < 4; $index++) {
            $harness['policy']->recordFailure('user');
        }
        $bucket = $this->identityBucket($harness);
        self::assertSame(2260, $bucket['blocked_until']);
        self::assertCount(12, $bucket['timestamps']);

        $harness['now'] = 1900;
        $harness['policy']->recordFailure('other');
        $harness['now'] = 2801;
        $harness['policy']->recordFailure('other');
        $other = $this->bucketFor($harness, 'bastion_lpu_1_' . hash_hmac('sha256', 'other', 'test-auth-secret'));
        self::assertSame([2801], $other['timestamps']);
    }

    public function testIpThresholdsApplyAtExactCountsAndHistoryIsCapped(): void
    {
        $harness = $this->harness(address: '192.0.2.10');

        for ($index = 0; $index < 49; $index++) {
            $harness['policy']->recordFailure('');
        }
        self::assertSame(0, $this->ipBucket($harness)['blocked_until']);
        $harness['policy']->recordFailure('');
        self::assertSame(1060, $this->ipBucket($harness)['blocked_until']);

        $harness['now'] = 1060;
        for ($index = 50; $index < 100; $index++) {
            $harness['policy']->recordFailure('');
        }
        self::assertSame(1360, $this->ipBucket($harness)['blocked_until']);

        $harness['now'] = 1360;
        for ($index = 100; $index < 200; $index++) {
            $harness['policy']->recordFailure('');
        }
        $bucket = $this->ipBucket($harness);
        self::assertSame(2260, $bucket['blocked_until']);
        self::assertCount(200, $bucket['timestamps']);
    }

    public function testActiveBlockTakesPrecedenceOverValidUserAndEqualityExpires(): void
    {
        $harness = $this->harness(address: null);
        for ($index = 0; $index < 5; $index++) {
            $harness['policy']->recordFailure('admin');
        }

        $validUser = (object) ['is_user' => true];
        $blocked = $harness['policy']->filterAuthentication($validUser, 'ADMIN', 'correct');
        self::assertSame('bastion_login_throttled', $blocked->code);
        self::assertSame('Authentication is temporarily unavailable. Please wait and try again.', $blocked->message);
        self::assertSame(1, $harness['metrics']['throttled_attempts']);

        $harness['now'] = 1060;
        self::assertSame($validUser, $harness['policy']->filterAuthentication($validUser, 'admin', 'correct'));
        self::assertArrayNotHasKey($this->identityKey('admin'), $harness['transients']);
    }

    public function testBlockedFailureIsNotRecountedOrExtendedAndOnlyThrottledMetricChanges(): void
    {
        $harness = $this->harness(address: null);
        for ($index = 0; $index < 5; $index++) {
            $harness['policy']->recordFailure('admin');
        }
        $before = $this->bucketFor($harness, $this->identityKey('admin'));
        $error = $harness['policy']->filterAuthentication((object) ['error' => true], 'admin', 'bad');
        $harness['now'] = 1030;
        $harness['policy']->recordFailure('admin', $error);

        self::assertSame($before, $this->bucketFor($harness, $this->identityKey('admin')));
        self::assertSame(5, $harness['metrics']['failed_attempts']);
        self::assertSame(1, $harness['metrics']['throttled_attempts']);
        self::assertSame(1000, $harness['metrics']['last_throttled_at']);
    }

    public function testSuccessfulAuthenticationClearsIdentityButNeverSharedIp(): void
    {
        $harness = $this->harness(address: '192.0.2.10');
        $harness['policy']->recordFailure('admin');
        $validUser = (object) ['is_user' => true];

        self::assertSame($validUser, $harness['policy']->filterAuthentication($validUser, 'ADMIN', 'correct'));
        self::assertArrayNotHasKey($this->identityKey('admin'), $harness['transients']);
        self::assertArrayHasKey($this->ipKey('192.0.2.10'), $harness['transients']);

        $harness['policy']->recordSuccess('admin', $validUser);
        self::assertArrayHasKey($this->ipKey('192.0.2.10'), $harness['transients']);
    }

    public function testGenerationInvalidationIdempotenceRolloverAndResetPreserveMetrics(): void
    {
        $harness = $this->harness(config: ['enabled' => false, 'generation' => 2147483647]);
        self::assertSame('enabled', $harness['policy']->setEnabled(true));
        self::assertSame(['enabled' => true, 'generation' => 2147483647], $harness['config']);
        self::assertSame('unchanged', $harness['policy']->setEnabled(true));

        $harness['metrics'] = ['failed_attempts' => 9, 'throttled_attempts' => 2, 'last_failed_at' => 800, 'last_throttled_at' => 900];
        self::assertSame('disabled', $harness['policy']->setEnabled(false));
        self::assertSame(['enabled' => false, 'generation' => 1], $harness['config']);
        self::assertSame('unchanged', $harness['policy']->setEnabled(false));
        self::assertSame('reset', $harness['policy']->resetBlocks());
        self::assertSame(['enabled' => false, 'generation' => 2], $harness['config']);
        self::assertSame(9, $harness['policy']->metrics()['failed_attempts']);
    }

    public function testMalformedStateFailsOpenAndCanonicalizesConfigurationAndMetrics(): void
    {
        $harness = $this->harness(config: ['enabled' => 'yes', 'generation' => -4], metrics: [
            'failed_attempts' => -1,
            'throttled_attempts' => PHP_INT_MAX,
            'last_failed_at' => 'secret',
            'last_throttled_at' => -2,
        ]);
        self::assertSame(['enabled' => false, 'generation' => 1], $harness['policy']->state());
        self::assertSame([
            'failed_attempts' => 0,
            'throttled_attempts' => 2147483647,
            'last_failed_at' => 0,
            'last_throttled_at' => 0,
        ], $harness['policy']->metrics());

        $harness = $this->harness(address: null);
        $key = $this->identityKey('admin');
        foreach ([
            'garbage',
            ['timestamps' => [999, 'bad'], 'blocked_until' => 1060],
            ['timestamps' => [1001], 'blocked_until' => 1060],
            ['timestamps' => [999], 'blocked_until' => 999],
            ['timestamps' => [999], 'blocked_until' => 1901],
        ] as $malformed) {
            $harness['transients'][$key] = $malformed;
            self::assertNotSame('bastion_login_throttled', $harness['policy']->filterAuthentication((object) ['error' => true], 'admin', 'bad')->code ?? '');
        }
    }

    public function testFailedConfigurationWritesReportFailureWithoutClaimingState(): void
    {
        $harness = $this->harness(config: ['enabled' => false, 'generation' => 1], writeConfig: false);
        self::assertSame('write_failed', $harness['policy']->setEnabled(true));
        self::assertFalse($harness['policy']->state()['enabled']);
        self::assertSame('write_failed', $harness['policy']->resetBlocks());
    }

    public function testTransientExpirationIsBoundedAndMetricsSaturate(): void
    {
        $harness = $this->harness(address: null, metrics: [
            'failed_attempts' => 2147483647,
            'throttled_attempts' => 2147483647,
            'last_failed_at' => 0,
            'last_throttled_at' => 0,
        ]);
        $harness['policy']->recordFailure('admin');
        self::assertSame(1800, array_values($harness['expirations'])[0]);
        self::assertSame(2147483647, $harness['metrics']['failed_attempts']);
    }

    public function testTouchedPhpAndTestsAvoidPhp82StandaloneLiteralTypes(): void
    {
        foreach ([
            'src/Security/LoginProtectionPolicy.php',
            'src/Admin/LoginProtectionAdmin.php',
            'tests/Unit/LoginProtectionPolicyTest.php',
            'tests/Unit/LoginProtectionAdminTest.php',
        ] as $path) {
            $source = (string) file_get_contents(dirname(__DIR__, 2) . '/' . $path);
            self::assertDoesNotMatchRegularExpression('/(?:function|fn)\s*\([^)]*\)\s*:\s*(?:null|true|false)\b/', $source, $path);
        }
    }

    /** @return array<string, mixed> */
    private function &harness(mixed $address = '192.0.2.10', mixed $config = null, mixed $metrics = null, bool $writeConfig = true): array
    {
        $state = [
            'now' => 1000,
            'config' => $config ?? ['enabled' => true, 'generation' => 1],
            'metrics' => $metrics ?? [],
            'transients' => [],
            'expirations' => [],
        ];
        $policy = new LoginProtectionPolicy(
            static function () use (&$state): int { return $state['now']; },
            static function () use (&$state): mixed { return $state['config']; },
            static function (array $value) use (&$state, $writeConfig): bool {
                if (! $writeConfig) {
                    return false;
                }
                $state['config'] = $value;
                return true;
            },
            static function () use (&$state): mixed { return $state['metrics']; },
            static function (array $value) use (&$state): bool {
                $state['metrics'] = $value;
                return true;
            },
            static function (string $key) use (&$state): mixed { return $state['transients'][$key] ?? false; },
            static function (string $key, array $value, int $expiration) use (&$state): bool {
                $state['transients'][$key] = $value;
                $state['expirations'][$key] = $expiration;
                return true;
            },
            static function (string $key) use (&$state): bool {
                unset($state['transients'][$key]);
                return true;
            },
            static fn (): mixed => $address,
            static fn (): string => 'test-auth-secret',
            static fn (string $code, string $message): object => (object) ['code' => $code, 'message' => $message],
            static fn (string $identity): string => trim($identity),
            static fn (mixed $value): bool => is_object($value) && ($value->is_user ?? false) === true,
        );
        $state['policy'] = $policy;
        $result = [];
        foreach ($state as $key => &$value) {
            $result[$key] =& $value;
        }
        unset($value);

        return $result;
    }

    /** @param array<string, mixed> $harness */
    private function identityBucket(array $harness): array
    {
        return $this->bucketFor($harness, $this->identityKey('user'));
    }

    /** @param array<string, mixed> $harness */
    private function ipBucket(array $harness): array
    {
        return $this->bucketFor($harness, $this->ipKey('192.0.2.10'));
    }

    /** @param array<string, mixed> $harness */
    private function bucketFor(array $harness, string $key): array
    {
        return $harness['transients'][$key];
    }

    private function identityKey(string $identity): string
    {
        return 'bastion_lpu_1_' . hash_hmac('sha256', strtolower(trim($identity)), 'test-auth-secret');
    }

    private function ipKey(string $address): string
    {
        return 'bastion_lpi_1_' . hash_hmac('sha256', $address, 'test-auth-secret');
    }
}
