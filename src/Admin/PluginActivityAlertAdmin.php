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
        $this->requestMethod = Closure::fromCallable($requestMethod ?? static fn (): string => is_string($_SERVER['REQUEST_METHOD'] ?? null) ? $_SERVER['REQUEST_METHOD'] : '');
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
        $this->handle($_POST);
    }

    public function renderToolSection(string $notice = ''): void
    {
        $state = $this->policy->state();
        $recipientText = implode("\n", $state['recipients']);

        echo '<section id="bastion-plugin-activity-alerts" class="bastion-tools bastion-plugin-activity-alerts"><h2>' . \esc_html__('Plugin activity email alerts', 'bastion-security-wp') . '</h2>';
        $this->renderNotice($notice);
        echo '<p><strong>' . \esc_html__('Status:', 'bastion-security-wp') . '</strong> ' . ($state['enabled'] ? \esc_html__('Enabled', 'bastion-security-wp') : \esc_html__('Disabled', 'bastion-security-wp')) . '</p>';
        echo '<p>' . \esc_html__('This opt-in, per-site tool will attempt to send plain-text notices for plugin installations and successful activations. Plugin updates are excluded.', 'bastion-security-wp') . '</p>';
        echo '<p>' . \esc_html__('Bastion sends one email per recipient so addresses are not disclosed to each other. An enabled setting means Bastion will attempt to send; it does not prove delivery.', 'bastion-security-wp') . '</p>';
        echo '<form method="post" action="' . \esc_url(($this->adminUrl)('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . \esc_attr(self::POST_ACTION) . '">';
        echo '<input type="hidden" name="target" value="' . \esc_attr(self::TARGET) . '">';
        echo '<input type="hidden" name="command" value="save">';
        \wp_nonce_field(self::NONCE_ACTION);
        echo '<fieldset><legend class="screen-reader-text">' . \esc_html__('Plugin activity email alert settings', 'bastion-security-wp') . '</legend>';
        echo '<label><input type="checkbox" name="enabled" value="1"' . ($state['enabled'] ? ' checked' : '') . '> ' . \esc_html__('Enable plugin activity email alerts', 'bastion-security-wp') . '</label>';
        echo '<p><label for="bastion-plugin-alert-recipients"><strong>' . \esc_html__('Recipients', 'bastion-security-wp') . '</strong></label></p>';
        echo '<textarea id="bastion-plugin-alert-recipients" name="recipients" rows="5" class="large-text" aria-describedby="bastion-plugin-alert-recipients-help">' . \esc_textarea($recipientText) . '</textarea>';
        echo '<p id="bastion-plugin-alert-recipients-help" class="description">' . \esc_html__('Enter email addresses separated by commas or new lines. Every address must be valid. Enabling requires at least one recipient.', 'bastion-security-wp') . '</p>';
        echo '<p>' . \esc_html__('Disabling preserves the configured recipient list for a later re-enable.', 'bastion-security-wp') . '</p>';
        \submit_button(\esc_html__('Save plugin activity alert settings', 'bastion-security-wp'));
        echo '</fieldset></form></section>';
    }

    private function renderNotice(string $notice): void
    {
        $messages = [
            'enabled' => 'Plugin activity email alerts were enabled.',
            'disabled' => 'Plugin activity email alerts were disabled. Configured recipients were preserved.',
            'unchanged' => 'Plugin activity email alert settings were already in the requested state.',
            'invalid_recipients' => 'Every recipient must be a valid email address. No change was made.',
            'recipients_required' => 'Add at least one valid recipient before enabling alerts.',
            'invalid_request' => 'The request was malformed or did not use POST. No change was made.',
            'invalid_nonce' => 'The request could not be verified. No change was made.',
            'invalid_command' => 'The requested plugin activity alert target or command is not supported. No change was made.',
            'forbidden' => 'You are not allowed to perform this action. No change was made.',
            'write_failed' => 'WordPress could not save the plugin activity email alert settings. The prior state may remain.',
        ];
        if (! isset($messages[$notice])) {
            return;
        }

        $severity = match ($notice) {
            'enabled', 'disabled' => 'success',
            'unchanged' => 'info',
            'invalid_recipients', 'recipients_required' => 'warning',
            default => 'error',
        };
        echo '<div class="notice notice-' . $severity . '"><p>' . \esc_html__($messages[$notice], 'bastion-security-wp') . '</p></div>';
    }

    private function redirect(string $notice): void
    {
        $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&tab=hardening&bastion_plugin_alert_notice=' . rawurlencode($notice) . '#bastion-plugin-activity-alerts');
        ($this->safeRedirect)($url);
        ($this->terminate)();
    }
}
