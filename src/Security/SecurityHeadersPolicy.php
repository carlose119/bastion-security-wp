<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use Closure;

final class SecurityHeadersPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_security_headers';
    public const GROUPS_OPTION_NAME = 'bastion_security_wp_security_header_groups';

    /** @var array<string, string> */
    private const PRESET = [
        'X-Content-Type-Options' => 'nosniff',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
    ];

    /** @var array<string, array{header: string, value: string}> */
    private const GROUPS = [
        'framing' => [
            'header' => 'X-Frame-Options',
            'value' => 'SAMEORIGIN',
        ],
        'browser_capabilities' => [
            'header' => 'Permissions-Policy',
            'value' => 'camera=(), microphone=(), geolocation=()',
        ],
        'legacy_cross_domain' => [
            'header' => 'X-Permitted-Cross-Domain-Policies',
            'value' => 'none',
        ],
        'mixed_content_upgrade' => [
            'header' => 'Content-Security-Policy',
            'value' => 'upgrade-insecure-requests;',
        ],
        'hsts_trial' => [
            'header' => 'Strict-Transport-Security',
            'value' => 'max-age=86400',
        ],
        'opener_isolation' => [
            'header' => 'Cross-Origin-Opener-Policy',
            'value' => 'same-origin-allow-popups',
        ],
        'resource_isolation' => [
            'header' => 'Cross-Origin-Resource-Policy',
            'value' => 'same-site',
        ],
    ];

    private Closure $readOption;
    private Closure $writeOption;
    private Closure $readGroupsOption;
    private Closure $writeGroupsOption;
    private Closure $isHttps;

    public function __construct(
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $readGroupsOption = null,
        ?callable $writeGroupsOption = null,
        ?callable $isHttps = null,
    ) {
        $this->readOption = Closure::fromCallable($readOption ?? static fn (): bool => (bool) \get_option(self::OPTION_NAME, false));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (bool $enabled): bool => \update_option(self::OPTION_NAME, $enabled));
        $defaultGroupsReader = $readOption === null
            ? static fn (): mixed => \get_option(self::GROUPS_OPTION_NAME, [])
            : static fn (): array => [];
        $this->readGroupsOption = Closure::fromCallable($readGroupsOption ?? $defaultGroupsReader);
        $this->writeGroupsOption = Closure::fromCallable($writeGroupsOption ?? static fn (array $groups): bool => \update_option(self::GROUPS_OPTION_NAME, $groups));
        $this->isHttps = Closure::fromCallable($isHttps ?? static fn (): bool => \is_ssl());
    }

    public function isEnabled(): bool
    {
        return (bool) ($this->readOption)();
    }

    /** @return array<string, array{header: string, value: string}> */
    public static function groupDefinitions(): array
    {
        return self::GROUPS;
    }

    /** @return list<string> */
    public function enabledGroupIds(): array
    {
        return $this->normalizeGroups(($this->readGroupsOption)());
    }

    /** @return array<string, bool> */
    public function groupStates(): array
    {
        $enabled = array_fill_keys($this->enabledGroupIds(), true);
        $states = [];

        foreach (array_keys(self::GROUPS) as $group) {
            $states[$group] = isset($enabled[$group]);
        }

        return $states;
    }

    public function isGroupEnabled(string $group): bool
    {
        $states = $this->groupStates();

        return isset($states[$group]) && $states[$group];
    }

    /** @param array<string, string> $headers
     *  @return array<string, string>
     */
    public function apply(array $headers): array
    {
        $existingNames = [];

        foreach (array_keys($headers) as $name) {
            if (is_string($name)) {
                $existingNames[strtolower($name)] = true;
            }
        }

        if ($this->isEnabled()) {
            $this->appendMissing($headers, $existingNames, self::PRESET);
        }

        $enabled = array_fill_keys($this->enabledGroupIds(), true);

        foreach (self::GROUPS as $group => $definition) {
            if (! isset($enabled[$group])) {
                continue;
            }

            if ($group === 'hsts_trial' && ! ($this->isHttps)()) {
                continue;
            }

            $this->appendMissing(
                $headers,
                $existingNames,
                [$definition['header'] => $definition['value']],
            );
        }

        return $headers;
    }

    public function setEnabled(bool $enabled): string
    {
        if ($this->isEnabled() === $enabled) {
            return 'unchanged';
        }

        return ($this->writeOption)($enabled) ? 'updated' : 'write_failed';
    }

    public function setGroupEnabled(string $group, bool $enabled): string
    {
        if (! array_key_exists($group, self::GROUPS)) {
            return 'invalid_group';
        }

        $current = $this->enabledGroupIds();
        $currentSet = array_fill_keys($current, true);

        if (isset($currentSet[$group]) === $enabled) {
            return 'unchanged';
        }

        if ($enabled) {
            $currentSet[$group] = true;
        } else {
            unset($currentSet[$group]);
        }

        $next = array_values(array_filter(
            array_keys(self::GROUPS),
            static fn (string $id): bool => isset($currentSet[$id]),
        ));

        return ($this->writeGroupsOption)($next) ? 'updated' : 'write_failed';
    }

    /** @param array<string, string> $headers
     *  @param array<string, true> $existingNames
     *  @param array<string, string> $toAdd
     */
    private function appendMissing(array &$headers, array &$existingNames, array $toAdd): void
    {
        foreach ($toAdd as $name => $value) {
            $normalizedName = strtolower($name);

            if (isset($existingNames[$normalizedName])) {
                continue;
            }

            $headers[$name] = $value;
            $existingNames[$normalizedName] = true;
        }
    }

    /** @return list<string> */
    private function normalizeGroups(mixed $stored): array
    {
        if (! is_array($stored) || ! array_is_list($stored)) {
            return [];
        }

        $selected = [];

        foreach ($stored as $group) {
            if (! is_string($group) || ! array_key_exists($group, self::GROUPS)) {
                return [];
            }

            $selected[$group] = true;
        }

        return array_values(array_filter(
            array_keys(self::GROUPS),
            static fn (string $group): bool => isset($selected[$group]),
        ));
    }
}
