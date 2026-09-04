<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\Security\LoginProtectionPolicy;
use Closure;

final class LoginProtectionAdmin
{
    public const POST_ACTION = 'bastion_security_wp_login_protection';
    public const TARGET = 'login_protection';
    private const CAPABILITY = 'manage_options';
    private const NONCE_PREFIX = 'bastion_security_wp_login_protection_';

    private Closure $currentUserCan;
    private Closure $verifyNonce;
    private Closure $safeRedirect;
    private Closure $adminUrl;
    private Closure $terminate;
    private Closure $requestMethod;
    private Closure $formatTimestamp;

    public function __construct(
        private readonly LoginProtectionPolicy $policy,
        ?callable $currentUserCan = null,
        ?callable $verifyNonce = null,
        ?callable $safeRedirect = null,
        ?callable $adminUrl = null,
        ?callable $terminate = null,
        ?callable $requestMethod = null,
        ?callable $formatTimestamp = null,
    ) {
        $this->currentUserCan = Closure::fromCallable($currentUserCan ?? static fn (string $capability): bool => \current_user_can($capability));
        $this->verifyNonce = Closure::fromCallable($verifyNonce ?? static fn (string $nonce, string $action): bool => (bool) \wp_verify_nonce($nonce, $action));
        $this->safeRedirect = Closure::fromCallable($safeRedirect ?? static fn (string $url): bool => \wp_safe_redirect($url));
        $this->adminUrl = Closure::fromCallable($adminUrl ?? static fn (string $path): string => \admin_url($path));
        $this->terminate = Closure::fromCallable($terminate ?? static function (): never { exit; });
        $this->requestMethod = Closure::fromCallable($requestMethod ?? static fn (): string => is_string($_SERVER['REQUEST_METHOD'] ?? null)
            ? \sanitize_text_field(\wp_unslash($_SERVER['REQUEST_METHOD']))
            : '');
        $this->formatTimestamp = Closure::fromCallable($formatTimestamp ?? static fn (int $timestamp): string => \date_i18n('Y-m-d H:i:s T', $timestamp));
    }

    /** @param array<string, mixed> $post */
    public function handle(array $post): void
    {
        if (strtoupper((string) ($this->requestMethod)()) !== 'POST') {
            $this->redirect('invalid_request');
            return;
        }
        if (! ($this->currentUserCan)(self::CAPABILITY)) {
            $this->redirect('forbidden');
            return;
        }

        $target = $post['target'] ?? null;
        $command = $post['command'] ?? null;
        if ($target !== self::TARGET || ! is_string($command) || ! in_array($command, ['enable', 'disable', 'reset'], true)) {
            $this->redirect('invalid_command');
            return;
        }

        $nonce = $post['_wpnonce'] ?? null;
        if (! is_string($nonce) || ! ($this->verifyNonce)($nonce, self::NONCE_PREFIX . $command)) {
            $this->redirect('invalid_nonce');
            return;
        }

        if ($command === 'enable' && ($post['acknowledge'] ?? null) !== '1') {
            $this->redirect('acknowledgement_required');
            return;
        }

        $result = $command === 'reset'
            ? $this->policy->resetBlocks()
            : $this->policy->setEnabled($command === 'enable');
        $this->redirect($result);
    }

    public function handleRequest(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Raw POST is handed to handle(), which verifies capability, target, command, and the operation-bound nonce before mutation.
        $this->handle($_POST);
    }

    public function renderToolSection(string $notice = ''): void
    {
        $state = $this->policy->state();
        $metrics = $this->policy->metrics();

        echo '<section id="bastion-login-protection" class="bastion-tools bastion-login-protection"><h2>' . \esc_html__('Login Protection', 'cerrojo-security-toolkit') . '</h2>';
        $this->renderNotice($notice);
        echo '<p><strong>' . \esc_html__('Status:', 'cerrojo-security-toolkit') . '</strong> ' . ($state['enabled'] ? \esc_html__('Enabled', 'cerrojo-security-toolkit') : \esc_html__('Disabled', 'cerrojo-security-toolkit')) . '</p>';
        echo '<p>' . \esc_html__('This opt-in, per-site tool progressively delays repeated failed authentication within a 15-minute rolling window. The maximum cooldown is 15 minutes; there are no permanent locks.', 'cerrojo-security-toolkit') . '</p>';
        echo '<table class="widefat striped"><caption class="screen-reader-text">' . \esc_html__('Login Protection thresholds', 'cerrojo-security-toolkit') . '</caption><thead><tr><th scope="col">' . \esc_html__('Bucket', 'cerrojo-security-toolkit') . '</th><th scope="col">' . \esc_html__('Failure thresholds', 'cerrojo-security-toolkit') . '</th><th scope="col">' . \esc_html__('Cooldowns', 'cerrojo-security-toolkit') . '</th></tr></thead><tbody>';
        echo '<tr><th scope="row">' . \esc_html__('Normalized username or email', 'cerrojo-security-toolkit') . '</th><td><code>5 / 8 / 12</code></td><td><code>60 seconds / 5 minutes / 15 minutes</code></td></tr>';
        echo '<tr><th scope="row">' . \esc_html__('Direct peer address', 'cerrojo-security-toolkit') . '</th><td><code>50 / 100 / 200</code></td><td><code>60 seconds / 5 minutes / 15 minutes</code></td></tr></tbody></table>';

        echo '<h3>' . \esc_html__('Aggregate metrics', 'cerrojo-security-toolkit') . '</h3><dl>';
        $this->metric('Failed attempts', $metrics['failed_attempts'], $metrics['last_failed_at']);
        $this->metric('Throttled attempts', $metrics['throttled_attempts'], $metrics['last_throttled_at']);
        echo '</dl><p>' . \esc_html__('Resetting temporary blocks preserves aggregate metrics.', 'cerrojo-security-toolkit') . '</p>';

        echo '<h3>' . \esc_html__('Coverage and limitations', 'cerrojo-security-toolkit') . '</h3>';
        echo '<p>' . ($this->policy->peerAvailable()
            ? \esc_html__('Direct-peer detection is available. The address itself is never displayed.', 'cerrojo-security-toolkit')
            : \esc_html__('Direct-peer detection is unavailable, so only the identity dimension can be applied.', 'cerrojo-security-toolkit')) . '</p>';
        echo '<div class="notice notice-warning inline"><p><strong>' . \esc_html__('Proxy and shared-address warning:', 'cerrojo-security-toolkit') . '</strong> ' . \esc_html__('Only REMOTE_ADDR is used; forwarded headers are not trusted. A shared proxy address can cause temporary lockout for legitimate users.', 'cerrojo-security-toolkit') . '</p></div>';
        echo '<p>' . \esc_html__('Standard wp-login and flows through wp_authenticate(), including ordinary XML-RPC authentication, are covered. REST Application Password authentication is not covered.', 'cerrojo-security-toolkit') . '</p>';
        echo '<p>' . \esc_html__('Enforcement is best-effort: transient eviction and concurrent read-modify-write races can weaken throttling, and aggregate metrics can undercount. Final authentication enforcement still allows WordPress password hashing and user lookup, so this does not provide WAF or DDoS protection or a security guarantee.', 'cerrojo-security-toolkit') . '</p>';
        echo '<p>' . \esc_html__('Bucket keys use HMAC SHA-256 with the WordPress authentication secret. Raw usernames, email addresses, and IP addresses are not stored in these buckets or displayed.', 'cerrojo-security-toolkit') . '</p>';

        if ($state['enabled']) {
            $this->renderForm('disable');
        } else {
            $this->renderEnableForm();
        }
        $this->renderResetForm();
        echo '</section>';
    }

    private function renderEnableForm(): void
    {
        $this->openForm('enable');
        echo '<fieldset><legend class="screen-reader-text">' . \esc_html__('Enable Login Protection', 'cerrojo-security-toolkit') . '</legend>';
        echo '<label><input type="checkbox" name="acknowledge" value="1"> ' . \esc_html__('I understand that legitimate users, especially behind shared proxies, can be temporarily locked out. I can disable Login Protection from this page to stop future enforcement.', 'cerrojo-security-toolkit') . '</label>';
        \submit_button(\esc_html__('Enable Login Protection', 'cerrojo-security-toolkit'));
        echo '</fieldset></form>';
    }

    private function renderForm(string $command): void
    {
        $this->openForm($command);
        $label = $command === 'disable'
            ? \esc_html__('Disable Login Protection', 'cerrojo-security-toolkit')
            : \esc_html__('Enable Login Protection', 'cerrojo-security-toolkit');
        \submit_button($label);
        echo '</form>';
    }

    private function renderResetForm(): void
    {
        echo '<div class="bastion-login-reset">';
        $this->openForm('reset');
        echo '<fieldset><legend><strong>' . \esc_html__('Reset temporary blocks', 'cerrojo-security-toolkit') . '</strong></legend>';
        echo '<p>' . \esc_html__('Invalidate all current Login Protection buckets while preserving the enabled state and aggregate metrics.', 'cerrojo-security-toolkit') . '</p>';
        \submit_button(\esc_html__('Reset temporary blocks', 'cerrojo-security-toolkit'), 'secondary');
        echo '</fieldset></form></div>';
    }

    private function openForm(string $command): void
    {
        echo '<form method="post" action="' . \esc_url(($this->adminUrl)('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . \esc_attr(self::POST_ACTION) . '">';
        echo '<input type="hidden" name="target" value="' . \esc_attr(self::TARGET) . '">';
        echo '<input type="hidden" name="command" value="' . \esc_attr($command) . '">';
        \wp_nonce_field(self::NONCE_PREFIX . $command);
    }

    private function metric(string $label, int $count, int $lastAt): void
    {
        $translatedLabel = $label === 'Failed attempts'
            ? \__('Failed attempts', 'cerrojo-security-toolkit')
            : \__('Throttled attempts', 'cerrojo-security-toolkit');
        $last = $lastAt > 0 ? ($this->formatTimestamp)($lastAt) : \__('Never', 'cerrojo-security-toolkit');
        echo '<div><dt>' . \esc_html($translatedLabel) . '</dt><dd><strong>' . \esc_html((string) $count) . '</strong>; ' . \esc_html__('last:', 'cerrojo-security-toolkit') . ' ' . \esc_html($last) . '</dd></div>';
    }

    private function renderNotice(string $notice): void
    {
        $message = match ($notice) {
            'enabled' => \__('Login Protection was enabled.', 'cerrojo-security-toolkit'),
            'disabled' => \__('Login Protection was disabled and prior temporary blocks were invalidated.', 'cerrojo-security-toolkit'),
            'reset' => \__('Temporary Login Protection blocks were reset. Aggregate metrics were preserved.', 'cerrojo-security-toolkit'),
            'unchanged' => \__('Login Protection was already in the requested state.', 'cerrojo-security-toolkit'),
            'acknowledgement_required' => \__('Acknowledge the temporary legitimate-user and shared-proxy lockout risk before enabling Login Protection.', 'cerrojo-security-toolkit'),
            'invalid_request' => \__('The request must use POST. No change was made.', 'cerrojo-security-toolkit'),
            'invalid_nonce' => \__('The request could not be verified. No change was made.', 'cerrojo-security-toolkit'),
            'invalid_command' => \__('The requested Login Protection target or command is not supported. No change was made.', 'cerrojo-security-toolkit'),
            'forbidden' => \__('You are not allowed to perform this action. No change was made.', 'cerrojo-security-toolkit'),
            'write_failed' => \__('WordPress could not save the Login Protection configuration. The prior state may remain.', 'cerrojo-security-toolkit'),
            default => null,
        };
        if ($message === null) {
            return;
        }

        $severity = match ($notice) {
            'enabled', 'disabled', 'reset' => 'success',
            'unchanged' => 'info',
            'acknowledgement_required' => 'warning',
            default => 'error',
        };
        echo '<div class="notice notice-' . \esc_attr($severity) . '"><p>' . \esc_html($message) . '</p></div>';
    }

    private function redirect(string $notice): void
    {
        $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&tab=hardening&bastion_login_notice=' . rawurlencode($notice) . '#bastion-login-protection');
        ($this->safeRedirect)($url);
        ($this->terminate)();
    }
}
