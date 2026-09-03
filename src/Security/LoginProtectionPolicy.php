<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use Closure;

final class LoginProtectionPolicy
{
    public const CONFIG_OPTION = 'bastion_security_wp_login_protection';
    public const METRICS_OPTION = 'bastion_security_wp_login_protection_metrics';
    public const ERROR_CODE = 'bastion_login_throttled';
    public const ERROR_MESSAGE = 'Authentication is temporarily unavailable. Please wait and try again.';

    private const WINDOW = 900;
    private const MAX_COOLDOWN = 900;
    private const TRANSIENT_EXPIRATION = self::WINDOW + self::MAX_COOLDOWN;
    private const MAX_INT = 2147483647;
    private const IDENTITY_THRESHOLDS = [5 => 60, 8 => 300, 12 => 900];
    private const IP_THRESHOLDS = [50 => 60, 100 => 300, 200 => 900];

    private Closure $clock;
    private Closure $readConfig;
    private Closure $writeConfig;
    private Closure $readMetrics;
    private Closure $writeMetrics;
    private Closure $readTransient;
    private Closure $writeTransient;
    private Closure $deleteTransient;
    private Closure $directAddress;
    private Closure $secret;
    private Closure $errorFactory;
    private Closure $sanitizeIdentity;
    private Closure $isUser;

    public function __construct(
        ?callable $clock = null,
        ?callable $readConfig = null,
        ?callable $writeConfig = null,
        ?callable $readMetrics = null,
        ?callable $writeMetrics = null,
        ?callable $readTransient = null,
        ?callable $writeTransient = null,
        ?callable $deleteTransient = null,
        ?callable $directAddress = null,
        ?callable $secret = null,
        ?callable $errorFactory = null,
        ?callable $sanitizeIdentity = null,
        ?callable $isUser = null,
    ) {
        $this->clock = Closure::fromCallable($clock ?? static fn (): int => time());
        $this->readConfig = Closure::fromCallable($readConfig ?? static fn (): mixed => \get_option(self::CONFIG_OPTION, []));
        $this->writeConfig = Closure::fromCallable($writeConfig ?? static fn (array $value): bool => \update_option(self::CONFIG_OPTION, $value));
        $this->readMetrics = Closure::fromCallable($readMetrics ?? static fn (): mixed => \get_option(self::METRICS_OPTION, []));
        $this->writeMetrics = Closure::fromCallable($writeMetrics ?? static fn (array $value): bool => \update_option(self::METRICS_OPTION, $value));
        $this->readTransient = Closure::fromCallable($readTransient ?? static fn (string $key): mixed => \get_transient($key));
        $this->writeTransient = Closure::fromCallable($writeTransient ?? static fn (string $key, array $value, int $expiration): bool => \set_transient($key, $value, $expiration));
        $this->deleteTransient = Closure::fromCallable($deleteTransient ?? static fn (string $key): bool => \delete_transient($key));
        $this->directAddress = Closure::fromCallable($directAddress ?? static fn (): mixed => $_SERVER['REMOTE_ADDR'] ?? null);
        $this->secret = Closure::fromCallable($secret ?? static fn (): string => \wp_salt('auth'));
        $this->errorFactory = Closure::fromCallable($errorFactory ?? static fn (string $code, string $message): object => new \WP_Error($code, $message));
        $this->sanitizeIdentity = Closure::fromCallable($sanitizeIdentity ?? static fn (string $identity): string => \sanitize_user($identity));
        $this->isUser = Closure::fromCallable($isUser ?? static fn (mixed $value): bool => $value instanceof \WP_User);
    }

    /** @return array{enabled: bool, generation: int} */
    public function state(): array
    {
        $value = ($this->readConfig)();

        if (! is_array($value)) {
            return ['enabled' => false, 'generation' => 1];
        }

        $enabled = $value['enabled'] ?? null;
        $generation = $value['generation'] ?? null;
        if (! is_bool($enabled) || ! is_int($generation) || $generation < 1 || $generation > self::MAX_INT) {
            return ['enabled' => false, 'generation' => 1];
        }

        return ['enabled' => $enabled, 'generation' => $generation];
    }

    public function isEnabled(): bool
    {
        return $this->state()['enabled'];
    }

    /** @return array{failed_attempts: int, throttled_attempts: int, last_failed_at: int, last_throttled_at: int} */
    public function metrics(): array
    {
        $value = ($this->readMetrics)();
        $value = is_array($value) ? $value : [];

        return [
            'failed_attempts' => $this->boundedInt($value['failed_attempts'] ?? null),
            'throttled_attempts' => $this->boundedInt($value['throttled_attempts'] ?? null),
            'last_failed_at' => $this->boundedInt($value['last_failed_at'] ?? null),
            'last_throttled_at' => $this->boundedInt($value['last_throttled_at'] ?? null),
        ];
    }

    public function peerAvailable(): bool
    {
        return $this->canonicalAddress() !== null;
    }

    public function setEnabled(bool $enabled): string
    {
        $state = $this->state();

        if ($state['enabled'] === $enabled) {
            return 'unchanged';
        }

        $next = [
            'enabled' => $enabled,
            'generation' => $enabled ? $state['generation'] : $this->nextGeneration($state['generation']),
        ];

        if (! ($this->writeConfig)($next)) {
            return 'write_failed';
        }

        return $enabled ? 'enabled' : 'disabled';
    }

    public function resetBlocks(): string
    {
        $state = $this->state();
        $state['generation'] = $this->nextGeneration($state['generation']);

        return ($this->writeConfig)($state) ? 'reset' : 'write_failed';
    }

    public function filterAuthentication(mixed $user, string $username, string $password): mixed
    {
        if (! $this->isEnabled()) {
            return $user;
        }

        $now = ($this->clock)();
        $identityKey = $this->identityKey($username);
        $ipKey = $this->ipKey();

        if (($identityKey !== null && $this->isBlocked($identityKey, $now))
            || ($ipKey !== null && $this->isBlocked($ipKey, $now))) {
            $this->incrementMetric('throttled_attempts', 'last_throttled_at', $now);

            return ($this->errorFactory)(self::ERROR_CODE, self::ERROR_MESSAGE);
        }

        if (($this->isUser)($user) && $identityKey !== null) {
            ($this->deleteTransient)($identityKey);
        }

        return $user;
    }

    public function recordFailure(string $username, mixed $error = null): void
    {
        if (! $this->isEnabled() || $this->errorCode($error) === self::ERROR_CODE) {
            return;
        }

        $now = ($this->clock)();
        $identityKey = $this->identityKey($username);
        $ipKey = $this->ipKey();

        if ($identityKey !== null) {
            $this->appendFailure($identityKey, self::IDENTITY_THRESHOLDS, 12, $now);
        }
        if ($ipKey !== null) {
            $this->appendFailure($ipKey, self::IP_THRESHOLDS, 200, $now);
        }

        $this->incrementMetric('failed_attempts', 'last_failed_at', $now);
    }

    public function recordSuccess(string $username, mixed $user = null): void
    {
        if (! $this->isEnabled()) {
            return;
        }

        $key = $this->identityKey($username);
        if ($key !== null) {
            ($this->deleteTransient)($key);
        }
    }

    private function appendFailure(string $key, array $thresholds, int $cap, int $now): void
    {
        $bucket = $this->bucket($key, $now);
        $timestamps = $bucket['timestamps'];
        $timestamps[] = $now;
        if (count($timestamps) > $cap) {
            $timestamps = array_slice($timestamps, -$cap);
        }

        $count = count($timestamps);
        $cooldown = 0;
        foreach ($thresholds as $threshold => $seconds) {
            if ($count >= $threshold) {
                $cooldown = $seconds;
            }
        }

        ($this->writeTransient)($key, [
            'timestamps' => $timestamps,
            'blocked_until' => $cooldown > 0 ? $now + $cooldown : 0,
        ], self::TRANSIENT_EXPIRATION);
    }

    private function isBlocked(string $key, int $now): bool
    {
        return $this->bucket($key, $now)['blocked_until'] > $now;
    }

    /** @return array{timestamps: list<int>, blocked_until: int} */
    private function bucket(string $key, int $now): array
    {
        $value = ($this->readTransient)($key);
        $cap = str_starts_with($key, 'bastion_lpu_') ? 12 : 200;
        if (! is_array($value) || array_keys($value) !== ['timestamps', 'blocked_until']
            || ! is_array($value['timestamps']) || ! array_is_list($value['timestamps'])
            || count($value['timestamps']) > $cap || ! is_int($value['blocked_until'])) {
            return ['timestamps' => [], 'blocked_until' => 0];
        }

        $timestamps = [];
        $previous = null;
        foreach ($value['timestamps'] as $timestamp) {
            if (! is_int($timestamp) || $timestamp > $now || ($previous !== null && $timestamp < $previous)) {
                return ['timestamps' => [], 'blocked_until' => 0];
            }
            $previous = $timestamp;
            if ($timestamp >= $now - self::WINDOW) {
                $timestamps[] = $timestamp;
            }
        }

        $blockedUntil = $value['blocked_until'];
        if ($blockedUntil < 0 || $blockedUntil > $now + self::MAX_COOLDOWN) {
            return ['timestamps' => [], 'blocked_until' => 0];
        }

        return [
            'timestamps' => $timestamps,
            'blocked_until' => $blockedUntil > $now ? $blockedUntil : 0,
        ];
    }

    private function identityKey(string $username): ?string
    {
        $identity = strtolower(trim((string) ($this->sanitizeIdentity)($username)));

        return $identity === '' ? null : $this->key('bastion_lpu_', $identity);
    }

    private function ipKey(): ?string
    {
        $address = $this->canonicalAddress();

        return $address === null ? null : $this->key('bastion_lpi_', $address);
    }

    private function key(string $prefix, string $value): string
    {
        return $prefix . $this->state()['generation'] . '_' . hash_hmac('sha256', $value, (string) ($this->secret)());
    }

    private function canonicalAddress(): ?string
    {
        $candidate = ($this->directAddress)();
        if (! is_string($candidate) || filter_var($candidate, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $packed = @inet_pton($candidate);
        if ($packed === false) {
            return null;
        }

        if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            $packed = substr($packed, 12);
        }

        $canonical = @inet_ntop($packed);

        return is_string($canonical) ? $canonical : null;
    }

    private function errorCode(mixed $error): ?string
    {
        if (is_object($error) && method_exists($error, 'get_error_code')) {
            $code = $error->get_error_code();
            return is_string($code) ? $code : null;
        }
        if (is_object($error) && isset($error->code) && is_string($error->code)) {
            return $error->code;
        }

        return null;
    }

    private function incrementMetric(string $counter, string $timestamp, int $now): void
    {
        $metrics = $this->metrics();
        $metrics[$counter] = min(self::MAX_INT, $metrics[$counter] + 1);
        $metrics[$timestamp] = max(0, min(self::MAX_INT, $now));
        ($this->writeMetrics)($metrics);
    }

    private function boundedInt(mixed $value): int
    {
        return is_int($value) ? max(0, min(self::MAX_INT, $value)) : 0;
    }

    private function nextGeneration(int $generation): int
    {
        return $generation >= self::MAX_INT ? 1 : $generation + 1;
    }
}
