<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Security\CriticalSettingsAlertPolicy;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class CriticalSettingsAlertPolicyTest extends TestCase
{
    public function testConfigurationDefaultsDisabledAndNeverFallsBackToAdministrativeEmail(): void
    {
        $harness = $this->policy(null);

        self::assertSame(['enabled' => false, 'recipients' => []], $harness['policy']->state());
        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        self::assertSame([], $harness['mail']);
    }

    public function testConfigurationRejectsInvalidTokensDeduplicatesAndPreservesRecipientsOnDisable(): void
    {
        $harness = $this->policy(['schema_version' => 1, 'enabled' => false, 'recipients' => ['kept@example.test']]);

        self::assertSame('invalid_recipients', $harness['policy']->setConfiguration(true, 'valid@example.test, invalid-address'));
        self::assertSame('recipient_required', $harness['policy']->setConfiguration(true, " \n, "));
        self::assertSame('updated', $harness['policy']->setConfiguration(true, " First@Example.test,second@example.test\nfirst@example.test "));
        self::assertSame(['schema_version' => 1, 'enabled' => true, 'recipients' => ['First@Example.test', 'second@example.test']], $harness['option']);
        self::assertSame('updated', $harness['policy']->setConfiguration(false, 'ignored@example.test'));
        self::assertSame(['schema_version' => 1, 'enabled' => false, 'recipients' => ['First@Example.test', 'second@example.test']], $harness['option']);
    }

    public function testRecipientBoundsRejectOverlongAddressesAndMoreThanFiftyRecipientsWithoutWriting(): void
    {
        $harness = $this->policy();
        $tooMany = implode(',', array_map(static fn (int $number): string => 'person' . $number . '@example.test', range(1, 51)));

        self::assertSame('invalid_recipients', $harness['policy']->setConfiguration(true, str_repeat('a', 244) . '@example.test'));
        self::assertSame('invalid_recipients', $harness['policy']->setConfiguration(true, $tooMany));
        self::assertSame(0, $harness['writes']);
    }

    public function testHomeAndSiteurlChangesSendOnePrivatePlainTextMailPerRecipient(): void
    {
        $harness = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']]);

        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'siteurl');

        self::assertCount(4, $harness['mail']);
        self::assertSame('one@example.test', $harness['mail'][0][0]);
        self::assertSame('two@example.test', $harness['mail'][1][0]);
        self::assertSame('[Example Site] Home URL changed', $harness['mail'][0][1]);
        self::assertSame('[Example Site] Site URL changed', $harness['mail'][2][1]);
        self::assertSame([], $harness['mail'][0][3]);
        foreach ([
            'Event: Home URL changed',
            'Setting: home',
            'Previous value: https://old.example.test',
            'New value: https://new.example.test',
            'Site: Example Site',
            'Site URL: https://example.test',
            'Timestamp: 2025-02-03 04:05:06 UTC',
        ] as $line) {
            self::assertStringContainsString($line, $harness['mail'][0][2]);
        }
        self::assertStringNotContainsString('two@example.test', $harness['mail'][0][2]);
    }

    public function testOnlyAllowlistedChangedSafeStringValuesCanNotifyAndSensitiveUrlPartsAreRedacted(): void
    {
        $harness = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']]);

        $harness['policy']->onOptionUpdated('https://same.example.test', 'https://same.example.test', 'home');
        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'blogname');
        $harness['policy']->onOptionUpdated(new class {}, 'https://new.example.test', 'home');
        $harness['policy']->onOptionUpdated('https://user:password@old.example.test/path?token=old#fragment', 'https://new.example.test/path?token=new#fragment', 'home');

        self::assertCount(1, $harness['mail']);
        self::assertStringContainsString('Previous value: https://old.example.test/path', $harness['mail'][0][2]);
        self::assertStringContainsString('New value: https://new.example.test/path', $harness['mail'][0][2]);
        foreach (['user:', 'password', 'token=', 'fragment'] as $secret) {
            self::assertStringNotContainsString($secret, $harness['mail'][0][1] . $harness['mail'][0][2]);
        }
    }

    public function testChangedUrlStringsNotifyWhenOnlyRedactedOrTruncatedPartsDiffer(): void
    {
        $harness = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']]);
        $longPrefix = 'https://example.test/' . str_repeat('a', 200);

        $harness['policy']->onOptionUpdated('https://example.test/path?token=old', 'https://example.test/path?token=new', 'home');
        $harness['policy']->onOptionUpdated('https://example.test/path#old', 'https://example.test/path#new', 'home');
        $harness['policy']->onOptionUpdated('https://old-user:old-password@example.test/path', 'https://new-user:new-password@example.test/path', 'home');
        $harness['policy']->onOptionUpdated($longPrefix . 'old', $longPrefix . 'new', 'home');

        self::assertCount(4, $harness['mail']);
        foreach ($harness['mail'] as $mail) {
            self::assertStringNotContainsString('token=', $mail[1] . $mail[2]);
            self::assertStringNotContainsString('old-password', $mail[1] . $mail[2]);
        }
    }

    public function testUnchangedAndNonStringValuesStaySilentButChangedInvalidStringsNotifyUnavailable(): void
    {
        $harness = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']]);

        $harness['policy']->onOptionUpdated('https://example.test/path?token=same', 'https://example.test/path?token=same', 'home');
        $harness['policy']->onOptionUpdated(new class {}, 'https://example.test', 'home');
        $harness['policy']->onOptionUpdated('not a valid old URL', 'not a valid new URL', 'home');

        self::assertCount(1, $harness['mail']);
        self::assertStringContainsString('Previous value: Unavailable', $harness['mail'][0][2]);
        self::assertStringContainsString('New value: Unavailable', $harness['mail'][0][2]);
        self::assertStringNotContainsString('not a valid', $harness['mail'][0][1] . $harness['mail'][0][2]);
    }

    public function testConfigurationWriteAndValidatorFailuresReturnSafeOutcomes(): void
    {
        $falseWrite = $this->policy(writeSucceeds: false);
        self::assertSame('write_failed', $falseWrite['policy']->setConfiguration(true, 'alerts@example.test'));
        self::assertSame(1, $falseWrite['writes']);

        $throwingWrite = $this->policy(writeOption: static function (array $value): never { throw new RuntimeException('private write details'); });
        self::assertSame('write_failed', $throwingWrite['policy']->setConfiguration(true, 'alerts@example.test'));
        self::assertSame(1, $throwingWrite['writes']);

        $throwingValidator = $this->policy(
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']],
            validateEmail: static function (string $email): never { throw new RuntimeException('private validator details'); },
        );
        self::assertSame(['enabled' => false, 'recipients' => []], $throwingValidator['policy']->state());
        self::assertSame('invalid_recipients', $throwingValidator['policy']->setConfiguration(true, 'alerts@example.test'));
        self::assertSame(0, $throwingValidator['writes']);
    }

    public function testMalformedStoredVersionsDuplicateRecipientsAndUnreadableStateFailOpen(): void
    {
        foreach ([
            ['schema_version' => 2, 'enabled' => true, 'recipients' => ['alerts@example.test']],
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test', 'ALERTS@example.test']],
        ] as $option) {
            $harness = $this->policy($option);
            self::assertSame(['enabled' => false, 'recipients' => []], $harness['policy']->state());
            $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
            self::assertSame([], $harness['mail']);
            self::assertSame(0, $harness['writes']);
        }

        $reads = 0;
        $unreadable = new CriticalSettingsAlertPolicy(static function () use (&$reads): never {
            $reads++;
            throw new RuntimeException('private option details');
        });
        self::assertSame(['enabled' => false, 'recipients' => []], $unreadable->state());
        $unreadable->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        self::assertSame(2, $reads);
    }

    public function testThrowingObservationContextFailsOpenWithoutWrites(): void
    {
        foreach ([
            [static function (): never { throw new RuntimeException('private site URL details'); }, static fn (): string => '2025-02-03 04:05:06 UTC'],
            [static fn (): string => 'https://example.test', static function (): never { throw new RuntimeException('private timestamp details'); }],
        ] as [$siteUrl, $timestamp]) {
            $harness = $this->policy(
                ['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']],
                siteUrl: $siteUrl,
                timestamp: $timestamp,
            );
            $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
            self::assertSame([], $harness['mail']);
            self::assertSame(0, $harness['writes']);
        }
    }

    public function testMalformedStateAndMailFailuresFailOpenWithoutObservationWrites(): void
    {
        $malformed = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => 'alerts@example.test']);
        $malformed['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        self::assertSame([], $malformed['mail']);
        self::assertSame(0, $malformed['writes']);

        $harness = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']], throwOnFirstMail: true, siteName: "Example\r\nInjected");
        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        self::assertCount(2, $harness['mail']);
        self::assertStringNotContainsString("\r", $harness['mail'][0][1] . $harness['mail'][0][2]);
    }

    /** @return array<string, mixed> */
    private function &policy(
        mixed $option = ['schema_version' => 1, 'enabled' => false, 'recipients' => []],
        bool $writeSucceeds = true,
        bool $throwOnFirstMail = false,
        string $siteName = 'Example Site',
            ?callable $writeOption = null,
            ?callable $validateEmail = null,
            ?callable $siteUrl = null,
            ?callable $timestamp = null,
    ): array {
        $state = ['option' => $option, 'writes' => 0, 'mail' => []];
        $policy = new CriticalSettingsAlertPolicy(
            static function () use (&$state): mixed { return $state['option']; },
            static function (array $value) use (&$state, $writeSucceeds, $writeOption): bool {
                $state['writes']++;
                if ($writeOption !== null) {
                    return $writeOption($value);
                    }
                if (! $writeSucceeds) {
                    return false;
                }
                $state['option'] = $value;
                return true;
            },
            $validateEmail ?? static fn (string $email): bool => filter_var($email, FILTER_VALIDATE_EMAIL) !== false,
            static function (string $to, string $subject, string $message, array $headers = []) use (&$state, $throwOnFirstMail): bool {
                $state['mail'][] = [$to, $subject, $message, $headers];
                if ($throwOnFirstMail && count($state['mail']) === 1) {
                    throw new RuntimeException('private transport details');
                }
                return true;
            },
            static fn (): string => $siteName,
                $siteUrl ?? static fn (): string => 'https://example.test',
                $timestamp ?? static fn (): string => '2025-02-03 04:05:06 UTC',


        );
        $state['policy'] = $policy;
        $result = [];
        foreach ($state as $key => &$value) {
            $result[$key] =& $value;
        }
        unset($value);

        return $result;
    }
}
