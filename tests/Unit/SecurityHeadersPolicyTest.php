<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Security\SecurityHeadersPolicy;
use PHPUnit\Framework\TestCase;

final class SecurityHeadersPolicyTest extends TestCase
{
    public function testDisabledPolicyIsAnExactNoOp(): void
    {
        $headers = ['Content-Type' => 'text/html', 'X-Existing' => 'keep'];
        $policy = $this->policy(false);

        self::assertSame($headers, $policy->apply($headers));
    }

    public function testEnabledPolicyAppendsExactlyThePresetInDeterministicOrder(): void
    {
        $headers = $this->policy(true)->apply(['Content-Type' => 'text/html']);

        self::assertSame([
            'Content-Type' => 'text/html',
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
        ], $headers);
    }

    public function testExistingHeaderNamesArePreservedCaseInsensitivelyWithoutReorderingOrOverride(): void
    {
        $headers = [
            'referrer-policy' => 'same-origin',
            'X-Existing' => 'keep',
            'x-content-type-options' => 'custom-value',
        ];

        self::assertSame($headers, $this->policy(true)->apply($headers));
    }

    public function testApplyingEnabledPolicyIsIdempotent(): void
    {
        $policy = $this->policy(true);
        $once = $policy->apply([]);

        self::assertSame($once, $policy->apply($once));
    }

    public function testPreferenceWritesAreIdempotentAndReportFailure(): void
    {
        $stored = false;
        $writes = [];
        $writeSucceeds = true;
        $policy = new SecurityHeadersPolicy(
            static function () use (&$stored): bool {
                return $stored;
            },
            static function (bool $enabled) use (&$stored, &$writes, &$writeSucceeds): bool {
                $writes[] = $enabled;

                if ($writeSucceeds) {
                    $stored = $enabled;
                }

                return $writeSucceeds;
            },
        );

        self::assertSame('updated', $policy->setEnabled(true));
        self::assertSame('unchanged', $policy->setEnabled(true));
        self::assertSame('updated', $policy->setEnabled(false));
        $writeSucceeds = false;
        self::assertSame('write_failed', $policy->setEnabled(true));
        self::assertSame([true, false, true], $writes);
        self::assertFalse($policy->isEnabled());
    }

    public function testPresetExplicitlyExcludesBroaderSecurityHeaders(): void
    {
        $headers = $this->policy(true)->apply([]);
        $normalized = array_map('strtolower', array_keys($headers));

        self::assertSame(['x-content-type-options', 'referrer-policy'], $normalized);
        self::assertNotContains('content-security-policy', $normalized);
        self::assertNotContains('strict-transport-security', $normalized);
        self::assertNotContains('x-frame-options', $normalized);
        self::assertNotContains('permissions-policy', $normalized);
    }

    private function policy(bool $enabled): SecurityHeadersPolicy
    {
        return new SecurityHeadersPolicy(
            static fn (): bool => $enabled,
            static fn (): bool => true,
        );
    }
}
