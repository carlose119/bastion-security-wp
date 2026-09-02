<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Admin\FileEditorAdmin;
use BastionSecurityWP\Security\FileEditorPolicy;
use PHPUnit\Framework\TestCase;

final class FileEditorAdminTest extends TestCase
{
    public function testAuthorizedValidEnableAndDisableCommandsAreApplied(): void
    {
        $stored = false;
        $redirects = [];
        $admin = $this->admin($stored, false, true, true, $redirects);

        $admin->handle(['command' => 'enable', '_wpnonce' => 'valid']);
        self::assertTrue($stored);
        self::assertStringContainsString('bastion_notice=updated', $redirects[0]);

        $admin->handle(['command' => 'disable', '_wpnonce' => 'valid']);
        self::assertFalse($stored);
        self::assertStringContainsString('bastion_notice=updated', $redirects[1]);
    }

    public function testUnauthorizedRequestPerformsNoMutation(): void
    {
        $stored = false;
        $redirects = [];
        $admin = $this->admin($stored, false, false, true, $redirects);

        $admin->handle(['command' => 'enable', '_wpnonce' => 'valid']);

        self::assertFalse($stored);
        self::assertStringContainsString('bastion_notice=forbidden', $redirects[0]);
    }

    public function testInvalidNonceOrCommandPerformsNoMutation(): void
    {
        $stored = false;
        $redirects = [];
        $admin = $this->admin($stored, false, true, false, $redirects);
        $admin->handle(['command' => 'enable', '_wpnonce' => 'invalid']);

        $admin = $this->admin($stored, false, true, true, $redirects);
        $admin->handle(['command' => 'toggle', '_wpnonce' => 'valid']);
        $admin->handle(['command' => ['enable'], '_wpnonce' => 'valid']);

        self::assertFalse($stored);
        self::assertStringContainsString('bastion_notice=invalid_nonce', $redirects[0]);
        self::assertStringContainsString('bastion_notice=invalid_command', $redirects[1]);
        self::assertStringContainsString('bastion_notice=invalid_command', $redirects[2]);
    }

    public function testMultisiteRequestPerformsNoMutation(): void
    {
        $stored = false;
        $redirects = [];
        $admin = $this->admin($stored, true, true, true, $redirects);

        $admin->handle(['command' => 'enable', '_wpnonce' => 'valid']);

        self::assertFalse($stored);
        self::assertStringContainsString('bastion_notice=unavailable', $redirects[0]);
    }

    public function testExternalConstantPreventsEnablingBastionPreference(): void
    {
        $stored = false;
        $redirects = [];
        $admin = $this->admin($stored, false, true, true, $redirects, true, false);

        $admin->handle(['command' => 'enable', '_wpnonce' => 'valid']);

        self::assertFalse($stored);
        self::assertStringContainsString('bastion_notice=external_conflict', $redirects[0]);
    }

    /** @param list<string> $redirects */
    private function admin(
        bool &$stored,
        bool $multisite,
        bool $authorized,
        bool $nonceValid,
        array &$redirects,
        bool $externalDefined = false,
        ?bool $externalValue = null,
    ): FileEditorAdmin
    {
        $policy = new FileEditorPolicy(
            static function () use (&$stored): bool {
                return $stored;
            },
            static function (bool $enabled) use (&$stored): bool {
                $stored = $enabled;

                return true;
            },
            static fn (): bool => $multisite,
            static fn (): array => ['defined' => $externalDefined, 'value' => $externalValue],
            static fn (): bool => true,
        );

        return new FileEditorAdmin(
            $policy,
            static fn (string $capability): bool => $authorized && $capability === 'manage_options',
            static fn (string $nonce, string $action): bool => $nonceValid && $nonce === 'valid' && $action === FileEditorAdmin::NONCE_ACTION,
            static function (string $url) use (&$redirects): bool {
                $redirects[] = $url;

                return true;
            },
            static fn (string $path): string => 'https://example.test/wp-admin/' . $path,
            static function (): void {},
        );
    }
}
