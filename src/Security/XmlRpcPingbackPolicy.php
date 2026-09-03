<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use Closure;
use Throwable;

final class XmlRpcPingbackPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_xmlrpc_pingback_protection';

    /** @var list<string> */
    public const REMOVED_METHODS = ['pingback.ping', 'pingback.extensions.getPingbacks'];

    private Closure $readOption;
    private Closure $writeOption;

    public function __construct(
        ?callable $readOption = null,
        ?callable $writeOption = null,
    ) {
        $this->readOption = Closure::fromCallable($readOption ?? static fn (): mixed => \get_option(self::OPTION_NAME, false));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (bool $enabled): bool => \update_option(self::OPTION_NAME, $enabled));
    }

    /** @return array{assessed: bool, enabled: bool} */
    public function state(): array
    {
        try {
            $value = ($this->readOption)();
        } catch (Throwable) {
            return ['assessed' => false, 'enabled' => false];
        }

        if (! is_bool($value)) {
            return ['assessed' => false, 'enabled' => false];
        }

        return ['assessed' => true, 'enabled' => $value];
    }

    public function isEnabled(): bool
    {
        $state = $this->state();

        return $state['assessed'] && $state['enabled'];
    }

    public function setEnabled(bool $enabled): string
    {
        $state = $this->state();
        if ($state['assessed'] && $state['enabled'] === $enabled) {
            return 'unchanged';
        }

        try {
            return ($this->writeOption)($enabled) ? 'updated' : 'write_failed';
        } catch (Throwable) {
            return 'write_failed';
        }
    }

    public function filterMethods(mixed $methods): mixed
    {
        if (! is_array($methods) || ! $this->isEnabled()) {
            return $methods;
        }

        foreach (self::REMOVED_METHODS as $method) {
            unset($methods[$method]);
        }

        return $methods;
    }

    public function filterHeaders(mixed $headers): mixed
    {
        if (! is_array($headers) || ! $this->isEnabled()) {
            return $headers;
        }

        foreach (array_keys($headers) as $name) {
            if (is_string($name) && strcasecmp($name, 'X-Pingback') === 0) {
                unset($headers[$name]);
            }
        }

        return $headers;
    }
}
