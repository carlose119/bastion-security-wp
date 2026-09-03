<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\Security\AdministratorAccountAlertPolicy;
use Closure;

final class AdministratorAccountAlertAdmin
{
    public const POST_ACTION = 'bastion_security_wp_administrator_account_alerts';
    public const TARGET = 'administrator_account_alerts';
    public const NONCE_ACTION = 'bastion_security_wp_administrator_account_alerts_save';
    private const CAPABILITY = 'manage_options';

    private Closure $currentUserCan;
    private Closure $verifyNonce;
    private Closure $safeRedirect;
    private Closure $adminUrl;
    private Closure $terminate;
    private Closure $requestMethod;

    public function __construct(
        private readonly AdministratorAccountAlertPolicy $policy,
        ?callable $currentUserCan = null,
        ?callable $verifyNonce = null,
        ?callable $safeRedirect = null,
        ?callable $adminUrl = null,
        ?callable $terminate = null,
        ?callable $requestMethod = null,
    ) {
        $this->currentUserCan = Closure::fromCallable($currentUserCan ?? static fn (string $capability): bool => \current_user_can($capability));
        $this->verifyNonce = Closure::fromCallable($verifyNonce ?? static fn (string $nonce, string $action): bool => (bool) \wp_verify_nonce($nonce, $action));
        $this->safeRedirect = Closure::fromCallable($safeRedirect ?? static fn (string $url): bool => \wp_safe_redirect($url));
        $this->adminUrl = Closure::fromCallable($adminUrl ?? static fn (string $path): string => \admin_url($path));
        $this->terminate = Closure::fromCallable($terminate ?? static function (): never { exit; });
        $this->requestMethod = Closure::fromCallable($requestMethod ?? static fn (): string => is_string($_SERVER['REQUEST_METHOD'] ?? null)
            ? \sanitize_text_field(\wp_unslash($_SERVER['REQUEST_METHOD']))
            : '');
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
        if (($post['target'] ?? null) !== self::TARGET || ($post['command'] ?? null) !== 'save') {
            $this->redirect('invalid_command');
            return;
        }

        $nonce = $post['_wpnonce'] ?? null;
        if (! is_string($nonce) || ! ($this->verifyNonce)($nonce, self::NONCE_ACTION)) {
            $this->redirect('invalid_nonce');
            return;
        }

        $enabledValue = $post['enabled'] ?? null;
        $recipients = $post['recipients'] ?? null;
        if (($enabledValue !== null && $enabledValue !== '1') || ! is_string($recipients)) {
            $this->redirect('invalid_request');
            return;
        }

        $this->redirect($this->policy->setConfiguration($enabledValue === '1', $recipients));
    }

    public function handleRequest(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Raw POST is handed to handle(), which verifies capability, target, command, and the operation-bound nonce before mutation.
        $this->handle($_POST);
    }

    public function renderToolSection(string $notice = ''): void
    {
        $state = $this->policy->state();
        $recipientText = implode("\n", $state['recipients']);

        echo '<section id="bastion-administrator-account-alerts" class="bastion-tools bastion-administrator-account-alerts"><h2>' . \esc_html__('Administrator account alerts', 'bastion-security') . '</h2>';
        $this->renderNotice($notice);
        echo '<p><strong>' . \esc_html__('Status:', 'bastion-security') . '</strong> ' . ($state['enabled'] ? \esc_html__('Enabled', 'bastion-security') : \esc_html__('Disabled', 'bastion-security')) . '</p>';
        echo '<p>' . \esc_html__('This opt-in, per-site tool observes successful WordPress lifecycle hooks for these exact events: Administrator role granted, Administrator role removed, and Administrator account deleted.', 'bastion-security') . '</p>';
        echo '<p>' . \esc_html__('Messages contain the target user ID and bounded login, the administrator role where applicable, contextual current user ID and login, site name and URL, and WordPress-local timestamp. They exclude email addresses, display names, IP addresses, user agents, passwords, capability lists, deletion reassignment, and arbitrary metadata.', 'bastion-security') . '</p>';
        echo '<p>' . \esc_html__('The contextual current user may be unavailable and does not prove causality. Bastion sends one plain-text email per recipient so addresses are not disclosed to each other.', 'bastion-security') . '</p>';
        echo '<p>' . \esc_html__('Only the current site context is observed. On multisite, remove_user_from_blog may bypass the role-removal hook through remove_all_caps. Cross-site fan-out, network deletion, and super-admin grants and revocations are outside this tool.', 'bastion-security') . '</p>';
        echo '<p>' . \esc_html__('Bastion attempts wp_mail delivery independently for each recipient, continues after a failed send, does not retry, and does not prove delivery. The tool does not block or roll back account changes.', 'bastion-security') . '</p>';
        echo '<form method="post" action="' . \esc_url(($this->adminUrl)('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . \esc_attr(self::POST_ACTION) . '">';
        echo '<input type="hidden" name="target" value="' . \esc_attr(self::TARGET) . '">';
        echo '<input type="hidden" name="command" value="save">';
        \wp_nonce_field(self::NONCE_ACTION);
        echo '<fieldset><legend class="screen-reader-text">' . \esc_html__('Administrator account alert settings', 'bastion-security') . '</legend>';
        echo '<label><input type="checkbox" name="enabled" value="1"' . ($state['enabled'] ? ' checked' : '') . '> ' . \esc_html__('Enable administrator account alerts', 'bastion-security') . '</label>';
        echo '<p><label for="bastion-administrator-alert-recipients"><strong>' . \esc_html__('Recipients', 'bastion-security') . '</strong></label></p>';
        echo '<textarea id="bastion-administrator-alert-recipients" name="recipients" rows="5" class="large-text" aria-describedby="bastion-administrator-alert-recipients-help">' . \esc_textarea($recipientText) . '</textarea>';
        echo '<p id="bastion-administrator-alert-recipients-help" class="description">' . \esc_html__('Enter email addresses separated by commas or new lines. Every address must be valid. Enabling requires at least one recipient.', 'bastion-security') . '</p>';
        echo '<p>' . \esc_html__('Disabling preserves the configured recipient list for a later re-enable. Delete the saved option to remove the configuration completely.', 'bastion-security') . '</p>';
        \submit_button(\esc_html__('Save administrator account alert settings', 'bastion-security'));
        echo '</fieldset></form></section>';
    }

    private function renderNotice(string $notice): void
    {
        $message = match ($notice) {
            'updated' => \__('Administrator account alert settings were updated.', 'bastion-security'),
            'unchanged' => \__('Administrator account alert settings were already in the requested state.', 'bastion-security'),
            'invalid_recipients' => \__('Every recipient must be a valid email address. No change was made.', 'bastion-security'),
            'recipient_required' => \__('Add at least one valid recipient before enabling alerts.', 'bastion-security'),
            'invalid_request' => \__('The request was malformed or did not use POST. No change was made.', 'bastion-security'),
            'invalid_nonce' => \__('The request could not be verified. No change was made.', 'bastion-security'),
            'invalid_command' => \__('The requested administrator account alert target or command is not supported. No change was made.', 'bastion-security'),
            'forbidden' => \__('You are not allowed to perform this action. No change was made.', 'bastion-security'),
            'write_failed' => \__('WordPress could not save the administrator account alert settings. The prior state may remain.', 'bastion-security'),
            default => null,
        };
        if ($message === null) {
            return;
        }

        $severity = match ($notice) {
            'updated' => 'success',
            'unchanged' => 'info',
            'invalid_recipients', 'recipient_required' => 'warning',
            default => 'error',
        };
        echo '<div class="notice notice-' . \esc_attr($severity) . '"><p>' . \esc_html($message) . '</p></div>';
    }

    private function redirect(string $notice): void
    {
        $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&tab=hardening&bastion_administrator_alert_notice=' . rawurlencode($notice) . '#bastion-administrator-account-alerts');
        ($this->safeRedirect)($url);
        ($this->terminate)();
    }
}
