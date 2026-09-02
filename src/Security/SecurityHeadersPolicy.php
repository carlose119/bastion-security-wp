<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use Closure;

final class SecurityHeadersPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_security_headers';

    /** @var array<string, string> */
    private const PRESET = [
        'X-Content-Type-Options' => 'nosniff',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
    ];

    private Closure $readOption;
    private Closure $writeOption;

    public function __construct(?callable $readOption = null, ?callable $writeOption = null)
    {
        $this->readOption = Closure::fromCallable($readOption ?? static fn (): bool => (bool) \get_option(self::OPTION_NAME, false));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (bool $enabled): bool => \update_option(self::OPTION_NAME, $enabled));
    }

    public function isEnabled(): bool
    {
        return (bool) ($this->readOption)();
    }

    /** @param array<string, string> $headers
     *  @return array<string, string>
     */
    public function apply(array $headers): array
    {
        if (! $this->isEnabled()) {
            return $headers;
        }

        $existingNames = [];

        foreach (array_keys($headers) as $name) {
            if (is_string($name)) {
                $existingNames[strtolower($name)] = true;
            }
        }

        foreach (self::PRESET as $name => $value) {
            if (isset($existingNames[strtolower($name)])) {
                continue;
            }

            $headers[$name] = $value;
            $existingNames[strtolower($name)] = true;
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
}
