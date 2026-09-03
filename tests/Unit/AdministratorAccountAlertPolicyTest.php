<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Security\AdministratorAccountAlertPolicy;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class AdministratorAccountAlertPolicyTest extends TestCase
{
    public function testConfigurationDefaultsDisabledWithoutAnAdministrativeEmailFallback(): void
    {
        $harness = $this->policy(null);

        self::assertSame(['enabled' => false, 'recipients' => []], $harness['policy']->state());
        self::assertFalse($harness['policy']->diagnosticState()['assessed']);
        $harness['policy']->handleAddUserRole(42, 'administrator');
        self::assertSame([], $harness['mail']);
    }

    public function testEnableNormalizesAndDeduplicatesRecipientsWithBoundedOutcomes(): void
    {
        $harness = $this->policy();

        self::assertSame('updated', $harness['policy']->setConfiguration(
            true,
            " First.Person@Example.com,second@example.test\nfirst.person@example.com ",
        ));
        self::assertSame([
            'enabled' => true,
            'recipients' => ['First.Person@Example.com', 'second@example.test'],
        ], $harness['option']);
        self::assertSame('unchanged', $harness['policy']->setConfiguration(
            true,
            "First.Person@Example.com\nsecond@example.test",
        ));
        self::assertSame(1, $harness['writes']);
    }

    public function testInvalidRecipientInputRejectsTheEntireWriteAndEnablingRequiresARecipient(): void
    {
        $harness = $this->policy(['enabled' => false, 'recipients' => ['kept@example.test']]);

        self::assertSame('invalid_recipients', $harness['policy']->setConfiguration(true, 'valid@example.test, invalid-address'));
        self::assertSame('recipient_required', $harness['policy']->setConfiguration(true, " \n , "));
        self::assertSame('invalid_recipients', $harness['policy']->setConfiguration(true, str_repeat('a', 244) . '@example.test'));
        self::assertSame('invalid_recipients', $harness['policy']->setConfiguration(true, implode(',', array_map(
            static fn (int $number): string => 'person' . $number . '@example.test',
            range(1, 51),
        ))));
        self::assertSame(['enabled' => false, 'recipients' => ['kept@example.test']], $harness['option']);
        self::assertSame(0, $harness['writes']);
    }

    public function testDisablePreservesRecipientsAndWriteFailuresArePrivate(): void
    {
        $harness = $this->policy(['enabled' => true, 'recipients' => ['alerts@example.test']]);

        self::assertSame('updated', $harness['policy']->setConfiguration(false, 'ignored@example.test'));
        self::assertSame(['enabled' => false, 'recipients' => ['alerts@example.test']], $harness['option']);
        self::assertSame('unchanged', $harness['policy']->setConfiguration(false, 'replacement@example.test'));

        $failed = $this->policy(writeSucceeds: false);
        self::assertSame('write_failed', $failed['policy']->setConfiguration(true, 'alerts@example.test'));
        self::assertSame(['enabled' => false, 'recipients' => []], $failed['option']);
    }

    public function testExactAdministratorRoleGrantSendsOnePrivatePlainTextMailPerRecipient(): void
    {
        $harness = $this->policy(['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']]);

        $harness['policy']->handleAddUserRole(42, 'administrator');

        self::assertCount(2, $harness['mail']);
        self::assertSame('one@example.test', $harness['mail'][0][0]);
        self::assertSame('two@example.test', $harness['mail'][1][0]);
        self::assertSame('[Example Site] Administrator role granted', $harness['mail'][0][1]);
        self::assertSame([], $harness['mail'][0][3]);
        foreach ([
            'Event: Administrator role granted',
            'Target user ID: 42',
            'Target login: target-admin',
            'Role: administrator',
            'Contextual current user ID: 7',
            'Contextual current user login: current-operator',
            'Site: Example Site',
            'Site URL: https://example.test',
            'Timestamp: 2025-02-03 04:05:06 UTC',
        ] as $line) {
            self::assertStringContainsString($line, $harness['mail'][0][2]);
        }
        foreach (['@example.test', 'email', 'display', 'password', 'capabilities', 'reassign', 'IP', 'user agent'] as $excluded) {
            self::assertStringNotContainsString($excluded, $harness['mail'][0][2]);
        }
    }

    public function testRoleHandlersIgnoreEveryRoleOtherThanExactAdministrator(): void
    {
        $harness = $this->policy(['enabled' => true, 'recipients' => ['alerts@example.test']]);

        foreach (['editor', 'Administrator', '', ['administrator']] as $role) {
            $harness['policy']->handleAddUserRole(42, $role);
            $harness['policy']->handleRemoveUserRole(42, $role);
        }

        self::assertSame([], $harness['mail']);
    }

    public function testRoleRemovalUsesTrustedHookIdentityAndSafeLoginFallback(): void
    {
        $harness = $this->policy(
            ['enabled' => true, 'recipients' => ['alerts@example.test']],
            targetUser: null,
        );

        $harness['policy']->handleRemoveUserRole(42, 'administrator');

        self::assertCount(1, $harness['mail']);
        self::assertStringContainsString('Event: Administrator role removed', $harness['mail'][0][2]);
        self::assertStringContainsString('Target user ID: 42', $harness['mail'][0][2]);
        self::assertStringContainsString('Target login: Unavailable', $harness['mail'][0][2]);
        self::assertStringContainsString('Role: administrator', $harness['mail'][0][2]);
    }

    public function testDeletionRequiresSuppliedSnapshotWithExactAdministratorRole(): void
    {
        $harness = $this->policy(['enabled' => true, 'recipients' => ['alerts@example.test']]);

        $harness['policy']->handleDeletedUser(42, 99, (object) ['user_login' => 'deleted-admin', 'roles' => ['administrator']]);
        $harness['policy']->handleDeletedUser(43, null, (object) ['user_login' => 'editor', 'roles' => ['editor']]);
        $harness['policy']->handleDeletedUser(44, null, (object) ['user_login' => 'case-mismatch', 'roles' => ['Administrator']]);
        $harness['policy']->handleDeletedUser(45, null, null);

        self::assertCount(1, $harness['mail']);
        self::assertStringContainsString('Event: Administrator account deleted', $harness['mail'][0][2]);
        self::assertStringContainsString('Target login: deleted-admin', $harness['mail'][0][2]);
        self::assertStringNotContainsString('Role:', $harness['mail'][0][2]);
        self::assertStringNotContainsString('99', $harness['mail'][0][2]);
    }

    public function testControlCharactersAreStrippedAndUnavailableActorDoesNotBlockAlerts(): void
    {
        $harness = $this->policy(
            ['enabled' => true, 'recipients' => ['alerts@example.test']],
            targetUser: (object) ['user_login' => "target\r\nBcc: hidden"],
            currentUser: null,
            siteName: "Example\nInjected",
        );

        $harness['policy']->handleAddUserRole(42, 'administrator');

        self::assertCount(1, $harness['mail']);
        self::assertStringContainsString('Target login: target Bcc: hidden', $harness['mail'][0][2]);
        self::assertStringContainsString('Contextual current user ID: Unavailable', $harness['mail'][0][2]);
        self::assertStringContainsString('Contextual current user login: Unavailable', $harness['mail'][0][2]);
        self::assertStringNotContainsString("\r", $harness['mail'][0][1] . $harness['mail'][0][2]);
    }

    public function testMailAndIntegrationFailuresFailOpenAndLaterRecipientsContinue(): void
    {
        $harness = $this->policy(
            ['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            throwOnFirstMail: true,
        );
        $harness['policy']->handleAddUserRole(42, 'administrator');
        self::assertCount(2, $harness['mail']);

        $throwing = new AdministratorAccountAlertPolicy(
            static function (): never { throw new RuntimeException('private option details'); },
        );
        self::assertSame(['enabled' => false, 'recipients' => []], $throwing->state());
        self::assertFalse($throwing->diagnosticState()['assessed']);
        $throwing->handleAddUserRole(42, 'administrator');
        self::assertTrue(true);
    }

    /** @return array<string, mixed> */
    private function &policy(
        mixed $option = ['enabled' => false, 'recipients' => []],
        bool $writeSucceeds = true,
        ?object $targetUser = null,
        ?object $currentUser = null,
        bool $throwOnFirstMail = false,
        string $siteName = 'Example Site',
    ): array {
        $state = ['option' => $option, 'writes' => 0, 'mail' => []];
        $targetWasSpecified = func_num_args() >= 3;
        $target = $targetWasSpecified ? $targetUser : (object) ['user_login' => 'target-admin'];
        $actorWasSpecified = func_num_args() >= 4;
        $actor = $actorWasSpecified ? $currentUser : (object) ['ID' => 7, 'user_login' => 'current-operator'];
        $policy = new AdministratorAccountAlertPolicy(
            static function () use (&$state): mixed { return $state['option']; },
            static function (array $value) use (&$state, $writeSucceeds): bool {
                $state['writes']++;
                if (! $writeSucceeds) {
                    return false;
                }
                $state['option'] = $value;
                return true;
            },
            static fn (string $email): bool => filter_var($email, FILTER_VALIDATE_EMAIL) !== false,
            static fn (int $userId): ?object => $target,
            static fn (): ?object => $actor,
            static function (string $to, string $subject, string $message, array $headers = []) use (&$state, $throwOnFirstMail): bool {
                $state['mail'][] = [$to, $subject, $message, $headers];
                if ($throwOnFirstMail && count($state['mail']) === 1) {
                    throw new RuntimeException('private transport details');
                }
                return true;
            },
            static fn (): string => $siteName,
            static fn (): string => 'https://example.test',
            static fn (): string => '2025-02-03 04:05:06 UTC',
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
