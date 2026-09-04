<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use Closure;
use Throwable;

final class PluginUpdateCompatibility
{
    private const LABEL = 'Cerrojo: Plugin update compatibility';
    private const MAX_CACHE_AGE = 43_200;
    private const FUTURE_TOLERANCE = 300;
    private const MAX_ITEMS = 50;
    private const MAX_VALUE_LENGTH = 120;

    private Closure $currentUserCan;
    private Closure $isMultisite;
    private Closure $getSiteTransient;
    private Closure $getPlugins;
    private Closure $clock;
    private Closure $wordpressVersion;
    private Closure $phpVersion;
    private Closure $escape;

    public function __construct(
        ?callable $currentUserCan = null,
        ?callable $isMultisite = null,
        ?callable $getSiteTransient = null,
        ?callable $getPlugins = null,
        ?callable $clock = null,
        ?callable $wordpressVersion = null,
        ?callable $phpVersion = null,
        ?callable $escape = null,
    ) {
        $this->currentUserCan = Closure::fromCallable($currentUserCan ?? static fn (string $capability): bool => \current_user_can($capability));
        $this->isMultisite = Closure::fromCallable($isMultisite ?? static fn (): bool => \is_multisite());
        $this->getSiteTransient = Closure::fromCallable($getSiteTransient ?? static fn (): mixed => \get_site_transient('update_plugins'));
        $this->getPlugins = Closure::fromCallable($getPlugins ?? self::readInstalledPlugins(...));
        $this->clock = Closure::fromCallable($clock ?? static fn (): int => time());
        $this->wordpressVersion = Closure::fromCallable($wordpressVersion ?? static function (): mixed {
            global $wp_version;

            return $wp_version;
        });
        $this->phpVersion = Closure::fromCallable($phpVersion ?? static fn (): string => PHP_VERSION);
        $this->escape = Closure::fromCallable($escape ?? static fn (string $value): string => \esc_html($value));
    }

    /** @return array<string, mixed> */
    public function report(): array
    {
        try {
            if (! ($this->currentUserCan)('update_plugins')) {
                return $this->notAssessed('The current user cannot view plugin update inventory.');
            }

            if (($this->isMultisite)() && ! ($this->currentUserCan)('manage_network_plugins')) {
                return $this->notAssessed('The current user cannot view network plugin update inventory.');
            }

            $plugins = ($this->getPlugins)();
            $cache = ($this->getSiteTransient)();
            $now = ($this->clock)();
            $wp = $this->safeVersion(($this->wordpressVersion)());
            $php = $this->safeVersion(($this->phpVersion)());

            if (! is_array($plugins) || ! is_int($now) || $wp === null || $php === null) {
                return $this->notAssessed('The local update inventory was unavailable or incomplete.');
            }

            $normalized = $this->normalizeCache($cache, $now);
            if ($normalized === null || ! $this->installedVersionsMatch($plugins, $normalized['checked'])) {
                return $this->notAssessed('The cached update inventory was stale, malformed, or incomplete.');
            }

            if (array_intersect(array_keys($normalized['response']), array_keys($normalized['no_update'])) !== []) {
                return $this->notAssessed('The cached update inventory was stale, malformed, or incomplete.');
            }

            $pending = $this->pendingInstalledUpdates($plugins, $normalized['response'], $wp, $php);
            $age = $now - $normalized['last_checked'];
            if ($pending === []) {
                return $this->result(
                    DiagnosticStatus::Good,
                    sprintf('Evidence: Cache age is %d seconds; there are no cached pending plugin updates.', $age),
                    'Meaning: The fresh local cache contains no pending installed-plugin update entries. Cache age does not prove that a remote check succeeded.',
                    'Remediation: Continue the site owner\'s normal update monitoring process.',
                );
            }

            usort($pending, static function (array $left, array $right): int {
                $nameOrder = strcmp($left['sort_name'], $right['sort_name']);

                return $nameOrder !== 0 ? $nameOrder : strcmp($left['key'], $right['key']);
            });

            $total = count($pending);
            $shown = min($total, self::MAX_ITEMS);
            $omitted = $total - $shown;
            $rows = '';
            foreach (array_slice($pending, 0, self::MAX_ITEMS) as $item) {
                $rows .= '<li><strong>' . ($this->escape)($item['name']) . '</strong>'
                    . '<br>Installed version: ' . ($this->escape)($item['installed'])
                    . '; Target version: ' . ($this->escape)($item['target'])
                    . '; Declared minimum WordPress: ' . ($this->escape)($item['requires'])
                    . '; Declared minimum PHP: ' . ($this->escape)($item['requires_php'])
                    . '; Publisher tested through WordPress: ' . ($this->escape)($item['tested'])
                    . '; Classification: <strong>' . $item['classification'] . '</strong>'
                    . '; Reason: ' . ($this->escape)($item['reason']) . '.</li>';
            }

            return $this->result(
                DiagnosticStatus::Recommended,
                sprintf(
                    'Evidence: Cache age is %d seconds. Total pending installed updates: %d. Shown: %d. Omitted: %d.<ul>%s</ul>',
                    $age,
                    $total,
                    $shown,
                    $omitted,
                    $rows,
                ),
                'Meaning: Pending updates need review. These classifications use only publisher-declared target requirements; cache age does not prove that a remote check succeeded.',
                'Remediation: Review updates through the normal authorized WordPress administration workflow.',
            );
        } catch (Throwable) {
            return $this->notAssessed('The local update inventory could not be read.');
        }
    }

    /** @return array<string, mixed>|null */
    private function normalizeCache(mixed $cache, int $now): ?array
    {
        $root = $this->container($cache);
        if ($root === null || ! array_key_exists('last_checked', $root)) {
            return null;
        }

        $timestamp = $root['last_checked'];
        $checked = $this->container($root['checked'] ?? null);
        $response = $this->container($root['response'] ?? null);
        $noUpdate = $this->container($root['no_update'] ?? null);
        if ((! is_int($timestamp) && ! is_float($timestamp)) || ! is_finite((float) $timestamp)
            || $checked === null || $response === null || $noUpdate === null) {
            return null;
        }

        $timestamp = (int) $timestamp;
        if ($timestamp <= 0 || $now - $timestamp > self::MAX_CACHE_AGE || $timestamp - $now > self::FUTURE_TOLERANCE) {
            return null;
        }

        return [
            'last_checked' => $timestamp,
            'checked' => $checked,
            'response' => $response,
            'no_update' => $noUpdate,
        ];
    }

    /** @return array<string, mixed>|null */
    private function container(mixed $value): ?array
    {
        if (is_array($value)) {
            return $value;
        }

        return is_object($value) ? get_object_vars($value) : null;
    }

    /** @param array<string, mixed> $plugins
     *  @param array<string, mixed> $checked
     */
    private function installedVersionsMatch(array $plugins, array $checked): bool
    {
        foreach ($plugins as $key => $metadata) {
            if (! is_string($key) || ! is_array($metadata)) {
                return false;
            }

            $installed = $metadata['Version'] ?? null;
            if (! is_string($installed) || ! array_key_exists($key, $checked) || ! is_string($checked[$key]) || $checked[$key] !== $installed) {
                return false;
            }
        }

        return true;
    }

    /** @param array<string, mixed> $plugins
     *  @param array<string, mixed> $response
     *  @return list<array{key: string, sort_name: string, name: string, installed: string, target: string, requires: string, requires_php: string, tested: string, classification: string, reason: string}>
     */
    private function pendingInstalledUpdates(array $plugins, array $response, string $wp, string $php): array
    {
        $pending = [];
        foreach ($response as $key => $targetMetadata) {
            if (! is_string($key) || ! array_key_exists($key, $plugins) || ! is_array($plugins[$key])) {
                continue;
            }

            $target = $this->container($targetMetadata);
            if ($target === null) {
                $target = [];
            }
            $plugin = $plugins[$key];
            $name = $this->bounded($plugin['Name'] ?? null, 'Unnamed plugin');
            $installed = $this->bounded($plugin['Version'] ?? null);
            $targetVersion = $this->bounded($target['new_version'] ?? null);
            $requires = $this->safeVersion($target['requires'] ?? null);
            $requiresPhp = $this->safeVersion($target['requires_php'] ?? null);
            $tested = $this->safeVersion($target['tested'] ?? null);
            [$classification, $reason] = $this->classify($wp, $php, $requires, $requiresPhp, $tested);

            $pending[] = [
                'key' => $key,
                'sort_name' => $name,
                'name' => $name,
                'installed' => $installed,
                'target' => $targetVersion,
                'requires' => $requires ?? 'unavailable',
                'requires_php' => $requiresPhp ?? 'unavailable',
                'tested' => $tested ?? 'unavailable',
                'classification' => $classification,
                'reason' => $reason,
            ];
        }

        return $pending;
    }

    /** @return array{string, string} */
    private function classify(string $wp, string $php, ?string $requires, ?string $requiresPhp, ?string $tested): array
    {
        $failures = [];
        if ($requires !== null && version_compare($wp, $requires, '<')) {
            $failures[] = sprintf('WordPress %s minimum is not met', $requires);
        }
        if ($requiresPhp !== null && version_compare($php, $requiresPhp, '<')) {
            $failures[] = sprintf('PHP %s minimum is not met', $requiresPhp);
        }
        if ($failures !== []) {
            return ['Blocked by declared requirements', implode('; ', $failures)];
        }

        if ($requires === null || $requiresPhp === null || $tested === null) {
            return ['Compatibility unknown', 'Target minimum or tested-through metadata is missing or malformed'];
        }
        if (version_compare($wp, $tested, '>')) {
            return ['Compatibility unknown', 'Current WordPress is newer than the publisher-tested-through WordPress version'];
        }

        return ['Declared requirements met', 'Declared minimums are met and tested-through covers current WordPress; this does not guarantee compatibility or absence of conflicts'];
    }

    private function safeVersion(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        $value = trim($value);

        return strlen($value) <= 32 && preg_match('/^\d+(?:\.\d+){1,3}$/', $value) === 1 ? $value : null;
    }

    private function bounded(mixed $value, string $fallback = 'unavailable'): string
    {
        if (! is_string($value)) {
            return $fallback;
        }

        $value = trim($value);
        if ($value === '') {
            return $fallback;
        }

        return substr($value, 0, self::MAX_VALUE_LENGTH);
    }

    /** @return array<string, mixed> */
    private function notAssessed(string $reason): array
    {
        return $this->result(
            DiagnosticStatus::Recommended,
            'Evidence: The plugin update compatibility inventory was not read.',
            'Meaning: Not assessed. No plugin update compatibility conclusion was made.',
            'Remediation: ' . $reason,
        );
    }

    /** @return array<string, mixed> */
    private function result(DiagnosticStatus $status, string $evidence, string $meaning, string $remediation): array
    {
        return [
            'label' => self::LABEL,
            'status' => $status->value,
            'badge' => ['label' => 'Cerrojo Security Toolkit', 'color' => 'blue'],
            'description' => '<p>' . $evidence . '</p><p>' . $meaning . '</p><p>Ownership: Site owner or hosting administrator.</p>',
            'actions' => '<p>' . $remediation . '</p>',
            'test' => 'bastion_security_wp_plugin_update_compatibility',
        ];
    }

    /** @return array<string, mixed>|null */
    private static function readInstalledPlugins(): ?array
    {
        if (! function_exists('get_plugins')) {
            if (! defined('ABSPATH')) {
                return null;
            }

            $coreFile = ABSPATH . 'wp-admin/includes/plugin.php';
            if (! is_readable($coreFile)) {
                return null;
            }

            require_once $coreFile;
        }

        return function_exists('get_plugins') ? \get_plugins() : null;
    }
}
