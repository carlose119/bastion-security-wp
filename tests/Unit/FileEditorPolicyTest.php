<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Security\FileEditorPolicy;
use PHPUnit\Framework\TestCase;

final class FileEditorPolicyTest extends TestCase
{
    public function testEnabledPluginOptionDefinesAndOwnsEffectiveLock(): void
    {
        $defined = false;
        $value = null;
        $policy = $this->policy(
            true,
            false,
            static function () use (&$defined, &$value): array {
                return ['defined' => $defined, 'value' => $value];
            },
            static function (bool $newValue) use (&$defined, &$value): bool {
                $defined = true;
                $value = $newValue;

                return true;
            },
        );

        $policy->enforce();
        $state = $policy->state();

        self::assertTrue($state['effective_disabled']);
        self::assertTrue($state['plugin_managed']);
        self::assertFalse($state['external_defined']);
    }

    public function testExternalTrueConstantIsPreservedAndNeverClaimedAsPluginManaged(): void
    {
        $defineCalls = 0;
        $policy = $this->policy(
            true,
            false,
            static fn (): array => ['defined' => true, 'value' => true],
            static function () use (&$defineCalls): bool {
                $defineCalls++;

                return true;
            },
        );

        $policy->enforce();
        $state = $policy->state();

        self::assertSame(0, $defineCalls);
        self::assertTrue($state['effective_disabled']);
        self::assertFalse($state['plugin_managed']);
        self::assertTrue($state['external_defined']);
        self::assertTrue($state['external_value']);
    }

    public function testExternalFalseConstantBlocksEnforcementTruthfully(): void
    {
        $policy = $this->policy(
            true,
            false,
            static fn (): array => ['defined' => true, 'value' => false],
            static fn (): bool => self::fail('The external constant must not be redefined.'),
        );

        $policy->enforce();
        $state = $policy->state();

        self::assertFalse($state['effective_disabled']);
        self::assertFalse($state['plugin_managed']);
        self::assertTrue($state['external_defined']);
        self::assertFalse($state['external_value']);
    }

    public function testEnableDisablePersistenceIsAllowlistedAndIdempotent(): void
    {
        $stored = false;
        $writes = [];
        $policy = new FileEditorPolicy(
            static function () use (&$stored): bool {
                return $stored;
            },
            static function (bool $enabled) use (&$stored, &$writes): bool {
                $stored = $enabled;
                $writes[] = $enabled;

                return true;
            },
            static fn (): bool => false,
            static fn (): array => ['defined' => false, 'value' => null],
            static fn (): bool => true,
        );

        self::assertSame('updated', $policy->setEnabled(true));
        self::assertSame('unchanged', $policy->setEnabled(true));
        self::assertSame('updated', $policy->setEnabled(false));
        self::assertSame('unchanged', $policy->setEnabled(false));
        self::assertSame([true, false], $writes);
    }

    public function testExternalDefinitionAllowsClearingStalePluginOptionButNotEnablingIt(): void
    {
        $stored = true;
        $writes = [];
        $policy = new FileEditorPolicy(
            static function () use (&$stored): bool {
                return $stored;
            },
            static function (bool $enabled) use (&$stored, &$writes): bool {
                $stored = $enabled;
                $writes[] = $enabled;

                return true;
            },
            static fn (): bool => false,
            static fn (): array => ['defined' => true, 'value' => true],
            static fn (): bool => true,
        );

        self::assertSame('updated', $policy->setEnabled(false));
        self::assertSame('external_conflict', $policy->setEnabled(true));
        self::assertSame([false], $writes);
    }

    public function testMultisiteNeverDefinesOrPersistsPolicy(): void
    {
        $writes = 0;
        $defines = 0;
        $policy = new FileEditorPolicy(
            static fn (): bool => true,
            static function () use (&$writes): bool {
                $writes++;

                return true;
            },
            static fn (): bool => true,
            static fn (): array => ['defined' => false, 'value' => null],
            static function () use (&$defines): bool {
                $defines++;

                return true;
            },
        );

        $policy->enforce();

        self::assertSame('unavailable', $policy->setEnabled(false));
        self::assertFalse($policy->state()['available']);
        self::assertSame(0, $writes);
        self::assertSame(0, $defines);
    }

    /**
     * @param callable(): array{defined: bool, value: ?bool} $constantState
     * @param callable(bool): bool $defineConstant
     */
    private function policy(bool $option, bool $multisite, callable $constantState, callable $defineConstant): FileEditorPolicy
    {
        return new FileEditorPolicy(
            static fn (): bool => $option,
            static fn (): bool => true,
            static fn (): bool => $multisite,
            $constantState,
            $defineConstant,
        );
    }
}
