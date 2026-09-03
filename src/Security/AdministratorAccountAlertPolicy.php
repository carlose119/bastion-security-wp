<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use Closure;
use Throwable;

final class AdministratorAccountAlertPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_administrator_account_alerts';
    private const MAX_RECIPIENTS = 50;
    private const MAX_FIELD_LENGTH = 200;

    private Closure $readOption;
    private Closure $writeOption;
    private Closure $validateEmail;
    private Closure $getUser;
    private Closure $getCurrentUser;
    private Closure $mail;
    private Closure $siteName;
    private Closure $siteUrl;
    private Closure $timestamp;

    public function __construct(
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $validateEmail = null,
        ?callable $getUser = null,
        ?callable $getCurrentUser = null,
        ?callable $mail = null,
        ?callable $siteName = null,
        ?callable $siteUrl = null,
        ?callable $timestamp = null,
    ) {
        $this->readOption = Closure::fromCallable($readOption ?? static fn (): mixed => \get_option(self::OPTION_NAME, null));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (array $value): bool => \update_option(self::OPTION_NAME, $value));
        $this->validateEmail = Closure::fromCallable($validateEmail ?? static fn (string $email): bool => \is_email($email) !== false);
        $this->getUser = Closure::fromCallable($getUser ?? static fn (int $userId): mixed => \get_userdata($userId));
        $this->getCurrentUser = Closure::fromCallable($getCurrentUser ?? static fn (): mixed => \wp_get_current_user());
        $this->mail = Closure::fromCallable($mail ?? static fn (string $to, string $subject, string $message, array $headers = []): bool => \wp_mail($to, $subject, $message, $headers));
        $this->siteName = Closure::fromCallable($siteName ?? static fn (): string => (string) \get_bloginfo('name'));
        $this->siteUrl = Closure::fromCallable($siteUrl ?? static fn (): string => (string) \home_url('/'));
        $this->timestamp = Closure::fromCallable($timestamp ?? static fn (): string => (string) \date_i18n('Y-m-d H:i:s T'));
    }

    /** @return array{enabled: bool, recipients: list<string>} */
    public function state(): array
    {
        $diagnostic = $this->diagnosticState();

        return ['enabled' => $diagnostic['enabled'], 'recipients' => $diagnostic['recipients']];
    }

    /** @return array{assessed: bool, enabled: bool, recipients: list<string>} */
    public function diagnosticState(): array
    {
        try {
            $configuration = $this->normalizeStoredConfiguration(($this->readOption)());
            if ($configuration === null) {
                return ['assessed' => false, 'enabled' => false, 'recipients' => []];
            }

            return ['assessed' => true, 'enabled' => $configuration['enabled'], 'recipients' => $configuration['recipients']];
        } catch (Throwable) {
            return ['assessed' => false, 'enabled' => false, 'recipients' => []];
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

        try {
            return ($this->writeOption)($next) ? 'updated' : 'write_failed';
        } catch (Throwable) {
            return 'write_failed';
        }
    }

    public function handleAddUserRole(mixed $userId, mixed $role): void
    {
        $this->handleRoleChange($userId, $role, 'Administrator role granted');
    }

    public function handleRemoveUserRole(mixed $userId, mixed $role): void
    {
        $this->handleRoleChange($userId, $role, 'Administrator role removed');
    }

    public function handleDeletedUser(mixed $userId, mixed $reassign, mixed $user): void
    {
        try {
            if (! is_int($userId) || $userId <= 0 || ! is_object($user)) {
                return;
            }
            $roles = $user->roles ?? null;
            if (! is_array($roles) || ! in_array('administrator', $roles, true)) {
                return;
            }

            $this->send('Administrator account deleted', $userId, $this->userLogin($user), false);
        } catch (Throwable) {
            return;
        }
    }

    private function handleRoleChange(mixed $userId, mixed $role, string $event): void
    {
        try {
            if (! is_int($userId) || $userId <= 0 || $role !== 'administrator') {
                return;
            }

            $login = 'Unavailable';
            try {
                $login = $this->userLogin(($this->getUser)($userId));
            } catch (Throwable) {
                // The hook identity is sufficient; the login is optional context.
            }
            $this->send($event, $userId, $login, true);
        } catch (Throwable) {
            return;
        }
    }

    private function send(string $event, int $targetUserId, string $targetLogin, bool $includeRole): void
    {
        $configuration = $this->diagnosticState();
        if (! $configuration['assessed'] || ! $configuration['enabled'] || $configuration['recipients'] === []) {
            return;
        }

        $actorId = 'Unavailable';
        $actorLogin = 'Unavailable';
        try {
            $actor = ($this->getCurrentUser)();
            if (is_object($actor)) {
                $candidateId = $actor->ID ?? null;
                if (is_int($candidateId) && $candidateId > 0) {
                    $actorId = (string) $candidateId;
                }
                $actorLogin = $this->userLogin($actor);
            }
        } catch (Throwable) {
            // Actor context is optional and is never treated as forensic attribution.
        }

        $siteName = $this->safeField(($this->siteName)(), 'Unavailable');
        $siteUrl = $this->safeField(($this->siteUrl)(), 'Unavailable');
        $localTimestamp = $this->safeField(($this->timestamp)(), 'Unavailable');
        $lines = [
            'Event: ' . $event,
            'Target user ID: ' . $targetUserId,
            'Target login: ' . $targetLogin,
        ];
        if ($includeRole) {
            $lines[] = 'Role: administrator';
        }
        $lines[] = 'Contextual current user ID: ' . $actorId;
        $lines[] = 'Contextual current user login: ' . $actorLogin;
        $lines[] = 'Site: ' . $siteName;
        $lines[] = 'Site URL: ' . $siteUrl;
        $lines[] = 'Timestamp: ' . $localTimestamp;

        $subject = '[' . $siteName . '] ' . $event;
        $message = implode("\n", $lines) . "\n";
        foreach ($configuration['recipients'] as $recipient) {
            try {
                ($this->mail)($recipient, $subject, $message, []);
            } catch (Throwable) {
                continue;
            }
        }
    }

    private function userLogin(mixed $user): string
    {
        return is_object($user) ? $this->safeField($user->user_login ?? null, 'Unavailable') : 'Unavailable';
    }

    private function safeField(mixed $value, string $fallback): string
    {
        if (! is_string($value)) {
            return $fallback;
        }
        $value = trim(preg_replace('/[\r\n\x00-\x1F\x7F]+/', ' ', $value) ?? '');

        return $value === '' ? $fallback : substr($value, 0, self::MAX_FIELD_LENGTH);
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
                $valid = strlen($email) <= 254 && ($this->validateEmail)($email);
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
        if (! is_array($value) || ! is_bool($value['enabled'] ?? null) || ! is_array($value['recipients'] ?? null)
            || count($value['recipients']) > self::MAX_RECIPIENTS) {
            return null;
        }

        $recipients = [];
        $seen = [];
        foreach ($value['recipients'] as $recipient) {
            if (! is_string($recipient) || trim($recipient) !== $recipient || strlen($recipient) > 254
                || ! ($this->validateEmail)($recipient)) {
                return null;
            }
            $key = strtolower($recipient);
            if (isset($seen[$key])) {
                return null;
            }
            $seen[$key] = true;
            $recipients[] = $recipient;
        }
        if ($value['enabled'] && $recipients === []) {
            return null;
        }

        return ['enabled' => $value['enabled'], 'recipients' => $recipients];
    }
}
