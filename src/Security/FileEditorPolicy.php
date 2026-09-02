<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use Closure;

final class FileEditorPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_file_editor_lock';

    private Closure $readOption;
    private Closure $writeOption;
    private Closure $isMultisite;
    private Closure $constantState;
    private Closure $defineConstant;
    private bool $ownsRuntimeConstant = false;

    public function __construct(
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $isMultisite = null,
        ?callable $constantState = null,
        ?callable $defineConstant = null,
    ) {
        $this->readOption = Closure::fromCallable($readOption ?? static fn (): bool => (bool) \get_option(self::OPTION_NAME, false));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (bool $enabled): bool => \update_option(self::OPTION_NAME, $enabled));
        $this->isMultisite = Closure::fromCallable($isMultisite ?? static fn (): bool => \is_multisite());
        $this->constantState = Closure::fromCallable($constantState ?? static fn (): array => [
            'defined' => defined('DISALLOW_FILE_EDIT'),
            'value' => defined('DISALLOW_FILE_EDIT') ? (bool) constant('DISALLOW_FILE_EDIT') : null,
        ]);
        $this->defineConstant = Closure::fromCallable($defineConstant ?? static fn (bool $value): bool => define('DISALLOW_FILE_EDIT', $value));
    }

    public function enforce(): void
    {
        if (($this->isMultisite)() || ! $this->optionEnabled()) {
            return;
        }

        $constant = ($this->constantState)();

        if ($constant['defined']) {
            return;
        }

        $this->ownsRuntimeConstant = (bool) ($this->defineConstant)(true);
    }

    /** @return array{available: bool, option_enabled: bool, effective_disabled: bool, plugin_managed: bool, external_defined: bool, external_value: ?bool} */
    public function state(): array
    {
        $multisite = (bool) ($this->isMultisite)();
        $optionEnabled = $this->optionEnabled();
        $constant = ($this->constantState)();
        $externalDefined = (bool) $constant['defined'] && ! $this->ownsRuntimeConstant;

        return [
            'available' => ! $multisite,
            'option_enabled' => $optionEnabled,
            'effective_disabled' => (bool) ($constant['defined'] && $constant['value']),
            'plugin_managed' => $optionEnabled && $this->ownsRuntimeConstant,
            'external_defined' => $externalDefined,
            'external_value' => $externalDefined ? (bool) $constant['value'] : null,
        ];
    }

    public function setEnabled(bool $enabled): string
    {
        if (($this->isMultisite)()) {
            return 'unavailable';
        }

        $current = $this->optionEnabled();

        if ($current === $enabled) {
            return 'unchanged';
        }

        $constant = ($this->constantState)();

        if ($enabled && $constant['defined'] && ! $this->ownsRuntimeConstant) {
            return 'external_conflict';
        }

        return ($this->writeOption)($enabled) ? 'updated' : 'write_failed';
    }

    private function optionEnabled(): bool
    {
        return (bool) ($this->readOption)();
    }
}
