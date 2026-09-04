<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\Security\PluginActivityAlertPolicy;
use Closure;

final class PluginActivityAlertAdmin
{
    public const POST_ACTION = 'bastion_security_wp_plugin_activity_alerts';
    public const TARGET = 'plugin_activity_alerts';
    public const NONCE_ACTION = 'bastion_security_wp_plugin_activity_alerts_save';
    private const CAPABILITY = 'manage_options';

    private Closure $currentUserCan;
    private Closure $verifyNonce;
    private Closure $safeRedirect;
    private Closure $adminUrl;
    private Closure $terminate;
    private Closure $requestMethod;

    public function __construct(
        private readonly PluginActivityAlertPolicy $policy,
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

        echo '<section id="bastion-plugin-activity-alerts" class="bastion-tools bastion-plugin-activity-alerts"><h2>' . \esc_html__('Plugin activity email alerts', 'cerrojo-security-toolkit') . '</h2>';
        $this->renderNotice($notice);
        echo '<p><strong>' . \esc_html__('Status:', 'cerrojo-security-toolkit') . '</strong> ' . ($state['enabled'] ? \esc_html__('Enabled', 'cerrojo-security-toolkit') : \esc_html__('Disabled', 'cerrojo-security-toolkit')) . '</p>';
        echo '<p>' . \esc_html__('This opt-in, per-site tool will attempt to send plain-text notices for plugin installations and successful activations. Plugin updates are excluded.', 'cerrojo-security-toolkit') . '</p>';
        echo '<p>' . \esc_html__('Cerrojo sends one email per recipient so addresses are not disclosed to each other. An enabled setting means Cerrojo will attempt to send; it does not prove delivery.', 'cerrojo-security-toolkit') . '</p>';
        echo '<form method="post" action="' . \esc_url(($this->adminUrl)('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . \esc_attr(self::POST_ACTION) . '">';
        echo '<input type="hidden" name="target" value="' . \esc_attr(self::TARGET) . '">';
        echo '<input type="hidden" name="command" value="save">';
        \wp_nonce_field(self::NONCE_ACTION);
        echo '<fieldset><legend class="screen-reader-text">' . \esc_html__('Plugin activity email alert settings', 'cerrojo-security-toolkit') . '</legend>';
        echo '<label><input type="checkbox" name="enabled" value="1"' . ($state['enabled'] ? ' checked' : '') . '> ' . \esc_html__('Enable plugin activity email alerts', 'cerrojo-security-toolkit') . '</label>';
        echo '<p><label for="bastion-plugin-alert-recipients"><strong>' . \esc_html__('Recipients', 'cerrojo-security-toolkit') . '</strong></label></p>';
        echo '<textarea id="bastion-plugin-alert-recipients" name="recipients" rows="5" class="large-text" aria-describedby="bastion-plugin-alert-recipients-help">' . \esc_textarea($recipientText) . '</textarea>';
        echo '<p id="bastion-plugin-alert-recipients-help" class="description">' . \esc_html__('Enter email addresses separated by commas or new lines. Every address must be valid. Enabling requires at least one recipient.', 'cerrojo-security-toolkit') . '</p>';
        echo '<p>' . \esc_html__('Disabling preserves the configured recipient list for a later re-enable.', 'cerrojo-security-toolkit') . '</p>';
        \submit_button(\esc_html__('Save plugin activity alert settings', 'cerrojo-security-toolkit'));
        echo '</fieldset></form></section>';
    }

    private function renderNotice(string $notice): void
    {
        $message = match ($notice) {
            'enabled' => \__('Plugin activity email alerts were enabled.', 'cerrojo-security-toolkit'),
            'disabled' => \__('Plugin activity email alerts were disabled. Configured recipients were preserved.', 'cerrojo-security-toolkit'),
            'unchanged' => \__('Plugin activity email alert settings were already in the requested state.', 'cerrojo-security-toolkit'),
            'invalid_recipients' => \__('Every recipient must be a valid email address. No change was made.', 'cerrojo-security-toolkit'),
            'recipients_required' => \__('Add at least one valid recipient before enabling alerts.', 'cerrojo-security-toolkit'),
            'invalid_request' => \__('The request was malformed or did not use POST. No change was made.', 'cerrojo-security-toolkit'),
            'invalid_nonce' => \__('The request could not be verified. No change was made.', 'cerrojo-security-toolkit'),
            'invalid_command' => \__('The requested plugin activity alert target or command is not supported. No change was made.', 'cerrojo-security-toolkit'),
            'forbidden' => \__('You are not allowed to perform this action. No change was made.', 'cerrojo-security-toolkit'),
            'write_failed' => \__('WordPress could not save the plugin activity email alert settings. The prior state may remain.', 'cerrojo-security-toolkit'),
            default => null,
        };
        if ($message === null) {
            return;
        }

        $severity = match ($notice) {
            'enabled', 'disabled' => 'success',
            'unchanged' => 'info',
            'invalid_recipients', 'recipients_required' => 'warning',
            default => 'error',
        };
        echo '<div class="notice notice-' . \esc_attr($severity) . '"><p>' . \esc_html($message) . '</p></div>';
    }

    private function redirect(string $notice): void
    {
        $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&tab=hardening&bastion_plugin_alert_notice=' . rawurlencode($notice) . '#bastion-plugin-activity-alerts');
        ($this->safeRedirect)($url);
        ($this->terminate)();
    }
}
