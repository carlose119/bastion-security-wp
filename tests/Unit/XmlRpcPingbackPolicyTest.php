<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Security\XmlRpcPingbackPolicy;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class XmlRpcPingbackPolicyTest extends TestCase
{
    public function testDefaultDisabledStateIsReadableAndFiltersFailOpen(): void
    {
        $policy = new XmlRpcPingbackPolicy(static fn (): bool => false);
        $methods = ['pingback.ping' => 'ping', 'demo.method' => 'demo'];
        $headers = ['X-Pingback' => 'https://example.test/xmlrpc.php', 'Content-Type' => 'text/html'];

        self::assertSame(['assessed' => true, 'enabled' => false], $policy->state());
        self::assertSame($methods, $policy->filterMethods($methods));
        self::assertSame($headers, $policy->filterHeaders($headers));
    }

    public function testEnabledPolicyRemovesExactlyBothPingbackMethodsAndPreservesOrderAndValues(): void
    {
        $callback = static fn (): string => 'kept';
        $policy = new XmlRpcPingbackPolicy(static fn (): bool => true);
        $methods = [
            'demo.first' => $callback,
            'pingback.ping' => 'remove-one',
            'demo.middle' => ['Handler', 'method'],
            'pingback.extensions.getPingbacks' => 'remove-two',
            'demo.last' => false,
        ];

        self::assertSame([
            'demo.first' => $callback,
            'demo.middle' => ['Handler', 'method'],
            'demo.last' => false,
        ], $policy->filterMethods($methods));
    }

    public function testEnabledPolicyRemovesEveryCaseInsensitiveXPingbackHeaderOnly(): void
    {
        $policy = new XmlRpcPingbackPolicy(static fn (): bool => true);
        $headers = [
            'Content-Type' => 'text/html',
            'X-Pingback' => 'first',
            'Cache-Control' => ['private', 'no-store'],
            'x-pingback' => 'second',
            'X-PINGBACK' => 'third',
            'X-Pingback-Other' => 'kept',
        ];

        self::assertSame([
            'Content-Type' => 'text/html',
            'Cache-Control' => ['private', 'no-store'],
            'X-Pingback-Other' => 'kept',
        ], $policy->filterHeaders($headers));
    }

    public function testMalformedFilterInputsAndUnreadableStateFailOpenWithoutLeakingExceptions(): void
    {
        $throwing = new XmlRpcPingbackPolicy(static function (): never {
            throw new RuntimeException('private-reader-detail');
        });
        $malformed = new XmlRpcPingbackPolicy(static fn (): string => 'enabled');

        foreach ([$throwing, $malformed] as $policy) {
            self::assertSame(['assessed' => false, 'enabled' => false], $policy->state());
            self::assertSame('not-an-array', $policy->filterMethods('not-an-array'));
            $malformedHeaders = (object) ['header' => 'value'];
            self::assertSame($malformedHeaders, $policy->filterHeaders($malformedHeaders));
            self::assertSame(['pingback.ping' => 'kept'], $policy->filterMethods(['pingback.ping' => 'kept']));
            self::assertSame(['X-Pingback' => 'kept'], $policy->filterHeaders(['X-Pingback' => 'kept']));
            self::assertStringNotContainsString('private-reader-detail', serialize($policy->state()));
        }
    }

    public function testWordPressRoundTripBooleanStringsAreAssessedAndSkipUnchangedWrites(): void
    {
        $writes = 0;
        $enabled = new XmlRpcPingbackPolicy(
            static fn (): string => '1',
            static function (bool $value) use (&$writes): bool {
                ++$writes;
                return true;
            },
        );

        self::assertSame(['assessed' => true, 'enabled' => true], $enabled->state());
        self::assertSame('unchanged', $enabled->setEnabled(true));
        self::assertSame(0, $writes);

        $disabled = new XmlRpcPingbackPolicy(
            static fn (): string => '',
            static function (bool $value) use (&$writes): bool {
                ++$writes;
                return true;
            },
        );

        self::assertSame(['assessed' => true, 'enabled' => false], $disabled->state());
        self::assertSame('unchanged', $disabled->setEnabled(false));
        self::assertSame(0, $writes);
    }

    public function testUnrelatedStringAndNumericFormsRemainUnassessed(): void
    {
        foreach (['enabled', 'true', '0', '2', '01', 'arbitrary', 0, 1, 2, -1] as $value) {
            $policy = new XmlRpcPingbackPolicy(static fn (): mixed => $value);

            self::assertSame(['assessed' => false, 'enabled' => false], $policy->state());
            self::assertFalse($policy->isEnabled());
        }
    }

    public function testPersistenceIsIdempotentBoundedAndKeepsExceptionsPrivate(): void
    {
        $enabled = false;
        $writes = 0;
        $policy = new XmlRpcPingbackPolicy(
            static function () use (&$enabled): bool { return $enabled; },
            static function (bool $value) use (&$enabled, &$writes): bool {
                ++$writes;
                $enabled = $value;
                return true;
            },
        );

        self::assertSame('unchanged', $policy->setEnabled(false));
        self::assertSame(0, $writes);
        self::assertSame('updated', $policy->setEnabled(true));
        self::assertTrue($enabled);
        self::assertSame(1, $writes);
        self::assertSame('unchanged', $policy->setEnabled(true));
        self::assertSame(1, $writes);

        $failed = new XmlRpcPingbackPolicy(
            static fn (): bool => false,
            static fn (bool $value): bool => false,
        );
        self::assertSame('write_failed', $failed->setEnabled(true));

        $throwing = new XmlRpcPingbackPolicy(
            static fn (): bool => false,
            static function (bool $value): never { throw new RuntimeException('private-write-detail'); },
        );
        self::assertSame('write_failed', $throwing->setEnabled(true));
    }
}
