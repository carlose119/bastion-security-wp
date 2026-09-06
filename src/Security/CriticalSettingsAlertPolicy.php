<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use Closure;
use Throwable;

/**
 * Observes successful home and siteurl updates without changing their outcome.
 *
 * Notification values are conservative display references, not URL validation:
 * userinfo, query, and fragment are removed, while path context is retained.
 * Change detection uses the original string values so redaction never suppresses an alert.
 */
final class CriticalSettingsAlertPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_critical_settings_alerts';
    private const MAX_RECIPIENTS = 50;
    private const MAX_EMAIL_LENGTH = 254;
    private const MAX_FIELD_LENGTH = 200;

    private Closure $readOption;
    private Closure $writeOption;
    private Closure $validateEmail;
    private Closure $mail;
    private Closure $siteName;
    private Closure $siteUrl;
    private Closure $timestamp;

    public function __construct(
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $validateEmail = null,
        ?callable $mail = null,
        ?callable $siteName = null,
        ?callable $siteUrl = null,
        ?callable $timestamp = null,
    ) {
        $this->readOption = Closure::fromCallable($readOption ?? static fn (): mixed => \get_option(self::OPTION_NAME, null));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (array $value): bool => \update_option(self::OPTION_NAME, $value));
        $this->validateEmail = Closure::fromCallable($validateEmail ?? static fn (string $email): bool => \is_email($email) !== false);
        $this->mail = Closure::fromCallable($mail ?? static fn (string $to, string $subject, string $message, array $headers = []): bool => \wp_mail($to, $subject, $message, $headers));
        $this->siteName = Closure::fromCallable($siteName ?? static fn (): string => (string) \get_bloginfo('name'));
        $this->siteUrl = Closure::fromCallable($siteUrl ?? static fn (): string => (string) \home_url('/'));
        $this->timestamp = Closure::fromCallable($timestamp ?? static fn (): string => (string) \date_i18n('Y-m-d H:i:s T'));
    }

    /** @return array{enabled: bool, recipients: list<string>} */
    public function state(): array
    {
        try {
            return $this->normalizeStoredConfiguration(($this->readOption)()) ?? $this->defaultState();
        } catch (Throwable) {
            return $this->defaultState();
        }
    }

    public function setConfiguration(bool $enabled, string $recipientInput): string
    {
        $current = $this->state();
        if ($enabled) {
            $recipients = $this->normalizeRecipientInput($recipientInput);
            if ($recipients === null) {
                return 'invalid_recipients';
            }
            if ($recipients === []) {
                return 'recipient_required';
            }
            $next = ['enabled' => true, 'recipients' => $recipients];
        } else {
            $next = ['enabled' => false, 'recipients' => $current['recipients']];
        }

        if ($next === $current) {
            return 'unchanged';
        }

        $stored = ['schema_version' => 1, 'enabled' => $next['enabled'], 'recipients' => $next['recipients']];
        try {
            return ($this->writeOption)($stored) ? 'updated' : 'write_failed';
        } catch (Throwable) {
            return 'write_failed';
        }
    }

    /**
     * Callback for update_option_{$option}, whose arguments are old value, new value, option name.
     * It is deliberately strict so direct invocations cannot observe other options.
     */
    public function onOptionUpdated(mixed $oldValue, mixed $newValue, mixed $option): void
    {
        try {
            if (! is_string($option) || ! in_array($option, ['home', 'siteurl'], true)) {
                return;
            }
            if (! is_string($oldValue) || ! is_string($newValue) || $oldValue === $newValue) {
                return;
            }
            $oldDisplay = $this->safeUrlDisplay($oldValue) ?? 'Unavailable';
            $newDisplay = $this->safeUrlDisplay($newValue) ?? 'Unavailable';

            $configuration = $this->state();
            if (! $configuration['enabled'] || $configuration['recipients'] === []) {
                return;
            }
            $this->send($configuration['recipients'], $option, $oldDisplay, $newDisplay);
        } catch (Throwable) {
            return;
        }
    }

    /** @param list<string> $recipients */
    private function send(array $recipients, string $option, string $oldValue, string $newValue): void
    {
        $event = $option === 'home' ? 'Home URL changed' : 'Site URL changed';
        $siteName = $this->safeField(($this->siteName)(), 'Unavailable');
        $siteUrl = $this->safeUrlDisplay(($this->siteUrl)()) ?? 'Unavailable';
        $timestamp = $this->safeField(($this->timestamp)(), 'Unavailable');
        $subject = '[' . $siteName . '] ' . $event;
        $message = implode("\n", [
            'Event: ' . $event,
            'Setting: ' . $option,
            'Previous value: ' . $oldValue,
            'New value: ' . $newValue,
            'Site: ' . $siteName,
            'Site URL: ' . $siteUrl,
            'Timestamp: ' . $timestamp,
        ]) . "\n";

        foreach ($recipients as $recipient) {
            try {
                ($this->mail)($recipient, $subject, $message, []);
            } catch (Throwable) {
                continue;
            }
        }
    }

    /** @return list<string>|null */
    private function normalizeRecipientInput(string $input): ?array
    {
        $tokens = preg_split('/[\r\n,]+/', $input);
        if (! is_array($tokens)) {
            return null;
        }

        $recipients = [];
        $seen = [];
        foreach ($tokens as $token) {
            $email = trim($token);
            if ($email === '') {
                continue;
            }
            try {
                $valid = strlen($email) <= self::MAX_EMAIL_LENGTH && ($this->validateEmail)($email);
            } catch (Throwable) {
                return null;
            }
            if (! $valid) {
                return null;
            }
            $key = strtolower($email);
            if (! isset($seen[$key])) {
                $seen[$key] = true;
                $recipients[] = $email;
            }
            if (count($recipients) > self::MAX_RECIPIENTS) {
                return null;
            }
        }

        return $recipients;
    }

    /** @return array{enabled: bool, recipients: list<string>}|null */
    private function normalizeStoredConfiguration(mixed $value): ?array
    {
        if (! is_array($value) || array_keys($value) !== ['schema_version', 'enabled', 'recipients']
            || $value['schema_version'] !== 1 || ! is_bool($value['enabled']) || ! is_array($value['recipients'])
            || count($value['recipients']) > self::MAX_RECIPIENTS) {
            return null;
        }

        $recipients = [];
        $seen = [];
        foreach ($value['recipients'] as $recipient) {
            try {
                $valid = is_string($recipient) && trim($recipient) === $recipient
                    && strlen($recipient) <= self::MAX_EMAIL_LENGTH && ($this->validateEmail)($recipient);
            } catch (Throwable) {
                return null;
            }
            if (! $valid || isset($seen[strtolower($recipient)])) {
                return null;
            }
            $seen[strtolower($recipient)] = true;
            $recipients[] = $recipient;
        }
        if ($value['enabled'] && $recipients === []) {
            return null;
        }

        return ['enabled' => $value['enabled'], 'recipients' => $recipients];
    }

    private function safeUrlDisplay(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }
        $value = $this->safeField($value, '');
        if ($value === '') {
            return null;
        }
        $parts = parse_url($value);
        if (! is_array($parts) || ! is_string($parts['scheme'] ?? null) || ! is_string($parts['host'] ?? null)
            || ! in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            return null;
        }

        $display = strtolower($parts['scheme']) . '://' . $parts['host'];
        if (is_int($parts['port'] ?? null)) {
            $display .= ':' . $parts['port'];
        }
        if (is_string($parts['path'] ?? null)) {
            $display .= $parts['path'];
        }

        return $this->safeField($display, '');
    }

    private function safeField(mixed $value, string $fallback): string
    {
        if (! is_string($value)) {
            return $fallback;
        }
        $value = trim(preg_replace('/[\r\n\x00-\x1F\x7F]+/', ' ', $value) ?? '');

        return $value === '' ? $fallback : substr($value, 0, self::MAX_FIELD_LENGTH);
    }

    /** @return array{enabled: false, recipients: list<string>} */
    private function defaultState(): array
    {
        return ['enabled' => false, 'recipients' => []];
    }
}
