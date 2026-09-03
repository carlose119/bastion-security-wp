<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\Security\XmlRpcPingbackPolicy;
use Closure;

final class XmlRpcPingbackAdmin
{
    public const POST_ACTION = 'bastion_security_wp_xmlrpc_pingback_protection';
    public const TARGET = 'xmlrpc_pingback_protection';
    private const CAPABILITY = 'manage_options';
    private const NONCE_PREFIX = 'bastion_security_wp_xmlrpc_pingback_protection_';

    private Closure $currentUserCan;
    private Closure $verifyNonce;
    private Closure $safeRedirect;
    private Closure $adminUrl;
    private Closure $terminate;
    private Closure $requestMethod;

    public function __construct(
        private readonly XmlRpcPingbackPolicy $policy,
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

        $target = $post['target'] ?? null;
        $command = $post['command'] ?? null;
        if ($target !== self::TARGET || ! is_string($command) || ! in_array($command, ['enable', 'disable'], true)) {
            $this->redirect('invalid_command');
            return;
        }

        $nonce = $post['_wpnonce'] ?? null;
        if (! is_string($nonce) || ! ($this->verifyNonce)($nonce, self::NONCE_PREFIX . $command)) {
            $this->redirect('invalid_nonce');
            return;
        }

        $this->redirect($this->policy->setEnabled($command === 'enable'));
    }

    public function handleRequest(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Raw POST is handed to handle(), which verifies capability, target, command, and the operation-bound nonce before mutation.
        $this->handle($_POST);
    }

    public function renderToolSection(string $notice = ''): void
    {
        $state = $this->policy->state();
        $status = ! $state['assessed']
            ? \__('Not assessed', 'bastion-security')
            : ($state['enabled'] ? \__('Enabled', 'bastion-security') : \__('Disabled', 'bastion-security'));

        echo '<section id="bastion-xmlrpc-pingback-protection" class="bastion-tools bastion-xmlrpc-pingback-protection"><h2>' . \esc_html__('XML-RPC Pingback Protection', 'bastion-security') . '</h2>';
        $this->renderNotice($notice);
        echo '<p><strong>' . \esc_html__('Status:', 'bastion-security') . '</strong> ' . \esc_html($status) . '</p>';
        echo '<p>' . \esc_html__('This opt-in, per-site tool removes the pingback.ping and pingback.extensions.getPingbacks methods while other authenticated XML-RPC methods remain available. It does not disable xmlrpc.php.', 'bastion-security') . '</p>';
        echo '<div class="notice notice-warning inline"><p><strong>' . \esc_html__('Compatibility warning:', 'bastion-security') . '</strong> ' . \esc_html__('When enabled, native pingback consumers stop working. Trackbacks, outbound pings, REST, and Application Passwords are not changed.', 'bastion-security') . '</p></div>';
        echo '<h3>' . \esc_html__('Coverage and limitations', 'bastion-security') . '</h3>';
        echo '<p>' . \esc_html__('Bastion also removes every case-insensitive X-Pingback entry from the WordPress wp_headers filter. A later filter at the same priority can re-add methods or headers, and direct, server, proxy, or CDN headers are outside this coverage.', 'bastion-security') . '</p>';
        echo '<p>' . \esc_html__('Disabling Bastion filtering cannot restore removals made by other components. It only stops Bastion from removing these methods and WordPress-filtered headers on later requests.', 'bastion-security') . '</p>';

        $this->openForm($state['enabled'] ? 'disable' : 'enable');
        $buttonLabel = $state['enabled']
            ? \esc_html__('Disable XML-RPC Pingback Protection', 'bastion-security')
            : \esc_html__('Enable XML-RPC Pingback Protection', 'bastion-security');
        \submit_button($buttonLabel);
        echo '</form></section>';
    }

    private function openForm(string $command): void
    {
        echo '<form method="post" action="' . \esc_url(($this->adminUrl)('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . \esc_attr(self::POST_ACTION) . '">';
        echo '<input type="hidden" name="target" value="' . \esc_attr(self::TARGET) . '">';
        echo '<input type="hidden" name="command" value="' . \esc_attr($command) . '">';
        \wp_nonce_field(self::NONCE_PREFIX . $command);
    }

    private function renderNotice(string $notice): void
    {
        $message = match ($notice) {
            'updated' => \__('XML-RPC Pingback Protection was updated.', 'bastion-security'),
            'unchanged' => \__('XML-RPC Pingback Protection was already in the requested state.', 'bastion-security'),
            'invalid_request' => \__('The request must use POST. No change was made.', 'bastion-security'),
            'invalid_nonce' => \__('The request could not be verified. No change was made.', 'bastion-security'),
            'invalid_command' => \__('The requested XML-RPC pingback target or command is not supported. No change was made.', 'bastion-security'),
            'forbidden' => \__('You are not allowed to perform this action. No change was made.', 'bastion-security'),
            'write_failed' => \__('WordPress could not save the XML-RPC pingback preference. The prior state may remain.', 'bastion-security'),
            default => null,
        };
        if ($message === null) {
            return;
        }

        $severity = match ($notice) {
            'updated' => 'success',
            'unchanged' => 'info',
            default => 'error',
        };
        echo '<div class="notice notice-' . \esc_attr($severity) . '"><p>' . \esc_html($message) . '</p></div>';
    }

    private function redirect(string $notice): void
    {
        $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&tab=hardening&bastion_xmlrpc_pingback_notice=' . rawurlencode($notice) . '#bastion-xmlrpc-pingback-protection');
        ($this->safeRedirect)($url);
        ($this->terminate)();
    }
}
