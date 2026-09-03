<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Security\SecurityHeadersPolicy;
use PHPUnit\Framework\TestCase;

final class SecurityHeadersPolicyTest extends TestCase
{
    private const GROUP_HEADERS = [
        'framing' => ['X-Frame-Options', 'SAMEORIGIN'],
        'browser_capabilities' => ['Permissions-Policy', 'camera=(), microphone=(), geolocation=()'],
        'legacy_cross_domain' => ['X-Permitted-Cross-Domain-Policies', 'none'],
        'mixed_content_upgrade' => ['Content-Security-Policy', 'upgrade-insecure-requests;'],
        'hsts_trial' => ['Strict-Transport-Security', 'max-age=86400'],
        'opener_isolation' => ['Cross-Origin-Opener-Policy', 'same-origin-allow-popups'],
        'resource_isolation' => ['Cross-Origin-Resource-Policy', 'same-site'],
    ];

    public function testBackwardCompatibleBaselineRemainsAnExactNoOpWhenDisabled(): void
    {
        $headers = ['Content-Type' => 'text/html', 'X-Existing' => 'keep'];

        self::assertSame($headers, $this->policy(false)->apply($headers));
    }

    public function testBackwardCompatibleBaselineAppendsOnlyItsExactPreset(): void
    {
        self::assertSame([
            'Content-Type' => 'text/html',
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
        ], $this->policy(true)->apply(['Content-Type' => 'text/html']));
    }

    public function testOptionalGroupsAreOffByDefaultAndCorruptOptionsNormalizeToNone(): void
    {
        foreach ([false, null, 'framing', ['framing', 'unknown'], [1], ['framing' => true]] as $stored) {
            $policy = $this->policy(false, $stored);
            self::assertSame([], $policy->enabledGroupIds());
            self::assertSame([], $policy->apply([]));
        }
    }

    public function testAllowlistedGroupStateIsExposedInDeterministicOrder(): void
    {
        $policy = $this->policy(false, ['resource_isolation', 'framing', 'framing']);

        self::assertSame(array_keys(self::GROUP_HEADERS), array_keys($policy->groupStates()));
        self::assertSame(['framing', 'resource_isolation'], $policy->enabledGroupIds());
        self::assertTrue($policy->isGroupEnabled('framing'));
        self::assertFalse($policy->isGroupEnabled('unknown'));
    }

    public function testEachGroupEmitsItsExactHeaderAndValueIndependentlyOfBaseline(): void
    {
        foreach (self::GROUP_HEADERS as $group => [$name, $value]) {
            $headers = $this->policy(false, [$group], true)->apply([]);
            self::assertSame([$name => $value], $headers, $group);
        }
    }

    public function testCombinedGroupsFollowFixedOrderRegardlessOfStoredOrder(): void
    {
        $policy = $this->policy(false, array_reverse(array_keys(self::GROUP_HEADERS)), true);

        self::assertSame(array_combine(
            array_column(self::GROUP_HEADERS, 0),
            array_column(self::GROUP_HEADERS, 1),
        ), $policy->apply([]));
    }

    public function testBaselineThenOptionalGroupsHaveDeterministicOrder(): void
    {
        $headers = $this->policy(true, ['resource_isolation', 'framing'], true)->apply(['First' => 'keep']);

        self::assertSame([
            'First' => 'keep',
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'X-Frame-Options' => 'SAMEORIGIN',
            'Cross-Origin-Resource-Policy' => 'same-site',
        ], $headers);
    }

    public function testExternalHeadersArePreservedCaseInsensitivelyWithoutOverrideOrReordering(): void
    {
        $headers = [
            'permissions-policy' => 'external-policy',
            'X-Existing' => 'keep',
            'x-frame-options' => 'DENY',
        ];
        $policy = $this->policy(false, ['framing', 'browser_capabilities', 'legacy_cross_domain']);

        self::assertSame([
            'permissions-policy' => 'external-policy',
            'X-Existing' => 'keep',
            'x-frame-options' => 'DENY',
            'X-Permitted-Cross-Domain-Policies' => 'none',
        ], $policy->apply($headers));
    }

    public function testHstsPreferenceIsSkippedOnHttpWithoutAffectingOtherGroups(): void
    {
        $policy = $this->policy(false, ['hsts_trial', 'opener_isolation'], false);

        self::assertSame([
            'Cross-Origin-Opener-Policy' => 'same-origin-allow-popups',
        ], $policy->apply([]));
        self::assertTrue($policy->isGroupEnabled('hsts_trial'));
    }

    public function testGroupWritesAreAllowlistedIdempotentAndReportFailure(): void
    {
        $stored = ['framing'];
        $writes = [];
        $writeSucceeds = true;
        $policy = new SecurityHeadersPolicy(
            static fn (): bool => false,
            static fn (): bool => true,
            static function () use (&$stored): mixed {
                return $stored;
            },
            static function (array $groups) use (&$stored, &$writes, &$writeSucceeds): bool {
                $writes[] = $groups;
                if ($writeSucceeds) {
                    $stored = $groups;
                }

                return $writeSucceeds;
            },
            static fn (): bool => true,
        );

        self::assertSame('invalid_group', $policy->setGroupEnabled('unknown', true));
        self::assertSame('unchanged', $policy->setGroupEnabled('framing', true));
        self::assertSame('updated', $policy->setGroupEnabled('browser_capabilities', true));
        self::assertSame(['framing', 'browser_capabilities'], $stored);
        self::assertSame('updated', $policy->setGroupEnabled('framing', false));
        self::assertSame(['browser_capabilities'], $stored);
        $writeSucceeds = false;
        self::assertSame('write_failed', $policy->setGroupEnabled('resource_isolation', true));
        self::assertSame([
            ['framing', 'browser_capabilities'],
            ['browser_capabilities'],
            ['browser_capabilities', 'resource_isolation'],
        ], $writes);
    }

    public function testBatchGroupWritesAreCanonicalSingleWriteAndIdempotent(): void
    {
        $stored = ['framing'];
        $writes = [];
        $policy = new SecurityHeadersPolicy(
            static fn (): bool => false,
            static fn (): bool => true,
            static function () use (&$stored): array {
                return $stored;
            },
            static function (array $groups) use (&$stored, &$writes): bool {
                $writes[] = $groups;
                $stored = $groups;

                return true;
            },
        );

        self::assertSame('updated', $policy->setGroupsEnabled(['resource_isolation', 'browser_capabilities'], true));
        self::assertSame(['framing', 'browser_capabilities', 'resource_isolation'], $stored);
        self::assertSame('unchanged', $policy->setGroupsEnabled(['browser_capabilities', 'resource_isolation'], true));
        self::assertSame('updated', $policy->setGroupsEnabled(['resource_isolation', 'framing'], false));
        self::assertSame(['browser_capabilities'], $stored);
        self::assertSame([
            ['framing', 'browser_capabilities', 'resource_isolation'],
            ['browser_capabilities'],
        ], $writes);
    }

    public function testBatchGroupWritesRejectInvalidSelectionsBeforeWriting(): void
    {
        $writes = 0;
        $policy = new SecurityHeadersPolicy(
            static fn (): bool => false,
            static fn (): bool => true,
            static fn (): array => [],
            static function () use (&$writes): bool {
                ++$writes;

                return true;
            },
        );

        self::assertSame('invalid_group', $policy->setGroupsEnabled([], true));
        self::assertSame('invalid_group', $policy->setGroupsEnabled(['unknown'], true));
        self::assertSame('invalid_group', $policy->setGroupsEnabled(['framing', 'framing'], true));
        self::assertSame(0, $writes);
    }

    public function testDisableAllGroupsUsesOneWriteAndReportsUnchangedOrFailure(): void
    {
        $stored = ['framing', 'hsts_trial'];
        $writeSucceeds = true;
        $writes = [];
        $policy = new SecurityHeadersPolicy(
            static fn (): bool => true,
            static fn (): bool => true,
            static function () use (&$stored): array {
                return $stored;
            },
            static function (array $groups) use (&$stored, &$writeSucceeds, &$writes): bool {
                $writes[] = $groups;
                if ($writeSucceeds) {
                    $stored = $groups;
                }

                return $writeSucceeds;
            },
        );

        self::assertSame('updated', $policy->disableAllGroups());
        self::assertSame([], $stored);
        self::assertSame('unchanged', $policy->disableAllGroups());
        $stored = ['framing'];
        $writeSucceeds = false;
        self::assertSame('write_failed', $policy->disableAllGroups());
        self::assertSame(['framing'], $stored);
        self::assertSame([[], []], $writes);
    }

    public function testApplyingPolicyIsIdempotent(): void
    {
        $policy = $this->policy(true, array_keys(self::GROUP_HEADERS));
        $once = $policy->apply([]);

        self::assertSame($once, $policy->apply($once));
    }

    public function testBaselinePreferenceWritesRemainBackwardCompatible(): void
    {
        $stored = false;
        $writes = [];
        $policy = new SecurityHeadersPolicy(
            static function () use (&$stored): bool {
                return $stored;
            },
            static function (bool $enabled) use (&$stored, &$writes): bool {
                $writes[] = $enabled;
                $stored = $enabled;

                return true;
            },
        );

        self::assertSame('updated', $policy->setEnabled(true));
        self::assertSame('unchanged', $policy->setEnabled(true));
        self::assertSame([true], $writes);
    }

    public function testSourceUsesNoDirectOrBroaderHeaderHooksAndOmitsUnsafePolicies(): void
    {
        $root = dirname(__DIR__, 2);
        $policySource = (string) file_get_contents($root . '/src/Security/SecurityHeadersPolicy.php');
        $bootstrap = (string) file_get_contents($root . '/src/Bootstrap.php');
        $emissionSources = $policySource . $bootstrap;

        self::assertStringContainsString("add_filter('wp_headers'", $bootstrap);
        self::assertStringNotContainsString('header(', $emissionSources);
        foreach (['rest_pre_serve_request', 'admin_init'] as $hook) {
            self::assertStringNotContainsString($hook, $emissionSources);
        }
        foreach ([
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Access-Control-Allow-Origin',
            'unsafe-none',
            'includeSubDomains',
            'preload',
            'Content-Security-Policy-Report-Only',
            'X-XSS-Protection',
        ] as $omitted) {
            self::assertStringNotContainsString($omitted, $emissionSources);
        }
    }

    public function testReadmeDocumentsSafeActivationExactPoliciesRisksAndBoundaries(): void
    {
        $readme = (string) file_get_contents(dirname(__DIR__, 2) . '/README.md');

        foreach ([
            'X-Content-Type-Options: nosniff',
            'Referrer-Policy: strict-origin-when-cross-origin',
            'X-Frame-Options: SAMEORIGIN',
            'Permissions-Policy: camera=(), microphone=(), geolocation=()',
            'X-Permitted-Cross-Domain-Policies: none',
            'Content-Security-Policy: upgrade-insecure-requests;',
            'Strict-Transport-Security: max-age=86400',
            'Cross-Origin-Opener-Policy: same-origin-allow-popups',
            'Cross-Origin-Resource-Policy: same-site',
        ] as $policy) {
            self::assertStringContainsString($policy, $readme);
        }
        self::assertStringContainsString('off by default', strtolower($readme));
        self::assertStringContainsString('24-hour', $readme);
        self::assertStringContainsString('add-only', $readme);
        self::assertStringContainsString('v5.3.4', $readme);
        self::assertStringContainsString('does not copy', $readme);
        self::assertStringContainsString('does not claim parity', $readme);
        self::assertStringContainsString('wp_headers', $readme);
        self::assertStringContainsString('CDN edge', $readme);
        self::assertStringContainsString('Access-Control-Allow-Origin', $readme);
        self::assertStringContainsString('reporting endpoint', $readme);
        self::assertStringContainsString('Quick navigation', $readme);
        self::assertStringContainsString('Enable selected', $readme);
        self::assertStringContainsString('Disable selected', $readme);
        self::assertStringContainsString('aggregate acknowledgement', $readme);
        self::assertStringContainsString('all-or-nothing preflight', $readme);
        self::assertStringContainsString('Disable all Bastion headers', $readme);
        self::assertStringContainsString('partial failure', $readme);
        self::assertStringContainsString('no enable-all action', $readme);
        self::assertStringContainsString('Individual baseline and group controls', $readme);
    }

    private function policy(bool $baseline, mixed $groups = [], bool $https = true): SecurityHeadersPolicy
    {
        return new SecurityHeadersPolicy(
            static fn (): bool => $baseline,
            static fn (): bool => true,
            static fn (): mixed => $groups,
            static fn (): bool => true,
            static fn (): bool => $https,
        );
    }
}
