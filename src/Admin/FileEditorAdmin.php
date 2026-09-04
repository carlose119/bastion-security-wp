<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\Security\FileEditorPolicy;
use Closure;

final class FileEditorAdmin
{
    public const NONCE_ACTION = 'bastion_security_wp_file_editor_lock';
    public const POST_ACTION = 'bastion_security_wp_file_editor_lock';
    private const CAPABILITY = 'manage_options';
    public const PAGE_SLUG = 'bastion-security-wp';

    private Closure $currentUserCan;
    private Closure $verifyNonce;
    private Closure $safeRedirect;
    private Closure $adminUrl;
    private Closure $terminate;

    public function __construct(
        private readonly FileEditorPolicy $policy,
        ?callable $currentUserCan = null,
        ?callable $verifyNonce = null,
        ?callable $safeRedirect = null,
        ?callable $adminUrl = null,
        ?callable $terminate = null,
    ) {
        $this->currentUserCan = Closure::fromCallable($currentUserCan ?? static fn (string $capability): bool => \current_user_can($capability));
        $this->verifyNonce = Closure::fromCallable($verifyNonce ?? static fn (string $nonce, string $action): bool => (bool) \wp_verify_nonce($nonce, $action));
        $this->safeRedirect = Closure::fromCallable($safeRedirect ?? static fn (string $url): bool => \wp_safe_redirect($url));
        $this->adminUrl = Closure::fromCallable($adminUrl ?? static fn (string $path): string => \admin_url($path));
        $this->terminate = Closure::fromCallable($terminate ?? static function (): never {
            exit;
        });
    }

    /** @param array<string, mixed> $post */
    public function handle(array $post): void
    {
        if (! ($this->currentUserCan)(self::CAPABILITY)) {
            $this->redirect('forbidden');

            return;
        }

        $nonce = $post['_wpnonce'] ?? null;

        if (! is_string($nonce) || ! ($this->verifyNonce)($nonce, self::NONCE_ACTION)) {
            $this->redirect('invalid_nonce');

            return;
        }

        $command = $post['command'] ?? null;

        if (! is_string($command) || ! in_array($command, ['enable', 'disable'], true)) {
            $this->redirect('invalid_command');

            return;
        }

        $result = $this->policy->setEnabled($command === 'enable');
        $this->redirect($result);
    }

    public function handleRequest(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Raw POST is handed to handle(), which verifies capability and the operation-bound nonce before mutation.
        $this->handle($_POST);
    }

    public function renderToolSection(string $notice = ''): void
    {
        $state = $this->policy->state();

        echo '<section id="bastion-file-editor" class="bastion-tools"><h2>' . \esc_html__('WordPress file editor lock', 'cerrojo-security-toolkit') . '</h2>';
        $this->renderNotice($notice);

        if (! $state['available']) {
            echo '<p>' . \esc_html__('This tool is unavailable on multisite. Cerrojo does not change the network file-editor policy.', 'cerrojo-security-toolkit') . '</p></section>';

            return;
        }

        if ($state['external_defined']) {
            $effective = $state['external_value'] ? 'disabled' : 'available';
            echo '<p>' . sprintf(
                /* translators: %s: effective WordPress file editor state. */
                \esc_html__('The file editor is currently %s because DISALLOW_FILE_EDIT is defined outside Cerrojo. Cerrojo will not override or remove that value.', 'cerrojo-security-toolkit'),
                \esc_html($effective),
            ) . '</p>';

            if ($state['option_enabled']) {
                echo '<p>' . \esc_html__('A stale Cerrojo preference is enabled, but it does not own the effective constant. You may clear only that preference.', 'cerrojo-security-toolkit') . '</p>';
                $this->renderForm('disable', 'Clear Cerrojo preference');
            }

            echo '</section>';

            return;
        }

        echo '<p>' . ($state['plugin_managed']
            ? \esc_html__('The file editor is disabled by Cerrojo for this request.', 'cerrojo-security-toolkit')
            : \esc_html__('The file editor is available. Cerrojo does not currently manage the lock.', 'cerrojo-security-toolkit')) . '</p>';
        echo '<p>' . \esc_html__('Cerrojo stores one WordPress option. Disabling it stops Cerrojo from defining the constant on the next request. No configuration file is edited.', 'cerrojo-security-toolkit') . '</p>';
        $this->renderForm($state['option_enabled'] ? 'disable' : 'enable', $state['option_enabled'] ? 'Disable Cerrojo lock' : 'Enable Cerrojo lock');
        echo '</section>';
    }

    private function renderForm(string $command, string $label): void
    {
        echo '<form method="post" action="' . \esc_url(($this->adminUrl)('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . \esc_attr(self::POST_ACTION) . '">';
        echo '<input type="hidden" name="command" value="' . \esc_attr($command) . '">';
        \wp_nonce_field(self::NONCE_ACTION);
        \submit_button($label);
        echo '</form>';
    }

    private function renderNotice(string $notice): void
    {
        $message = match ($notice) {
            'updated' => \__('The Cerrojo file-editor preference was updated.', 'cerrojo-security-toolkit'),
            'unchanged' => \__('The Cerrojo file-editor preference was already in the requested state.', 'cerrojo-security-toolkit'),
            'unavailable' => \__('This tool is unavailable on multisite.', 'cerrojo-security-toolkit'),
            'external_conflict' => \__('DISALLOW_FILE_EDIT is defined outside Cerrojo, so Cerrojo did not change its preference.', 'cerrojo-security-toolkit'),
            'write_failed' => \__('WordPress could not save the Cerrojo file-editor preference.', 'cerrojo-security-toolkit'),
            'invalid_nonce' => \__('The request could not be verified. No change was made.', 'cerrojo-security-toolkit'),
            'invalid_command' => \__('The requested command is not supported. No change was made.', 'cerrojo-security-toolkit'),
            'forbidden' => \__('You are not allowed to perform this action. No change was made.', 'cerrojo-security-toolkit'),
            default => null,
        };

        if ($message === null) {
            return;
        }

        $severity = match ($notice) {
            'updated' => 'success',
            'unchanged' => 'info',
            'unavailable', 'external_conflict' => 'warning',
            default => 'error',
        };

        echo '<div class="notice notice-' . \esc_attr($severity) . '"><p>' . \esc_html($message) . '</p></div>';
    }

    private function redirect(string $notice): void
    {
        $url = ($this->adminUrl)('tools.php?page=' . self::PAGE_SLUG . '&tab=hardening&bastion_notice=' . rawurlencode($notice) . '#bastion-file-editor');
        ($this->safeRedirect)($url);
        ($this->terminate)();
    }
}
