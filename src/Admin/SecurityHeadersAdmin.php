<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\Security\SecurityHeadersPolicy;
use Closure;

final class SecurityHeadersAdmin
{
    public const NONCE_ACTION = 'bastion_security_wp_security_headers';
    public const POST_ACTION = 'bastion_security_wp_security_headers';
    public const NOTICE_QUERY = 'bastion_security_headers_notice';
    private const CAPABILITY = 'manage_options';

    private Closure $currentUserCan;
    private Closure $verifyNonce;
    private Closure $safeRedirect;
    private Closure $adminUrl;
    private Closure $terminate;

    public function __construct(
        private readonly SecurityHeadersPolicy $policy,
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

        $this->redirect($this->policy->setEnabled($command === 'enable'));
    }

    public function handleRequest(): void
    {
        $this->handle($_POST);
    }

    public function renderToolSection(string $notice = ''): void
    {
        $enabled = $this->policy->isEnabled();

        echo '<section class="bastion-tools"><h2>' . \esc_html__('HTTP security header preset', 'bastion-security-wp') . '</h2>';
        $this->renderNotice($notice);
        echo '<p>' . \esc_html__('This per-site preference uses WordPress to add this exact conservative preset:', 'bastion-security-wp') . '</p>';
        echo '<ul><li><code>X-Content-Type-Options: nosniff</code></li><li><code>Referrer-Policy: strict-origin-when-cross-origin</code></li></ul>';
        echo '<p>' . \esc_html__('Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, and Permissions-Policy are intentionally outside this conservative preset because they require site-specific validation and can break site behavior or be difficult to reverse.', 'bastion-security-wp') . '</p>';
        echo '<p>' . \esc_html__('Bastion only adds missing headers. Existing header names are matched case-insensitively and their spelling, values, and order are preserved.', 'bastion-security-wp') . '</p>';
        echo '<p>' . \esc_html__('Coverage is narrow: the wp_headers filter covers standard front-end responses handled by WP::send_headers(). It is not guaranteed for wp-admin, wp-login, REST, redirects, static files, CDN or cache responses, or headers emitted by the web server.', 'bastion-security-wp') . '</p>';
        echo '<p>' . ($enabled
            ? \esc_html__('The preset preference is enabled. Disable it for immediate Bastion rollback; headers supplied elsewhere remain unchanged.', 'bastion-security-wp')
            : \esc_html__('The preset preference is disabled. Bastion does not change the response header array.', 'bastion-security-wp')) . '</p>';
        $this->renderForm($enabled ? 'disable' : 'enable', $enabled ? 'Disable security header preset' : 'Enable security header preset');
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
        $messages = [
            'updated' => 'The Bastion security-header preference was updated.',
            'unchanged' => 'The Bastion security-header preference was already in the requested state.',
            'write_failed' => 'WordPress could not save the Bastion security-header preference.',
            'invalid_nonce' => 'The request could not be verified. No change was made.',
            'invalid_command' => 'The requested command is not supported. No change was made.',
            'forbidden' => 'You are not allowed to perform this action. No change was made.',
        ];

        if (! isset($messages[$notice])) {
            return;
        }

        echo '<div class="notice notice-info"><p>' . \esc_html__($messages[$notice], 'bastion-security-wp') . '</p></div>';
    }

    private function redirect(string $notice): void
    {
        $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&' . self::NOTICE_QUERY . '=' . rawurlencode($notice));
        ($this->safeRedirect)($url);
        ($this->terminate)();
    }
}
