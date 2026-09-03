<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\Security\SecurityHeadersPolicy;
use Closure;
use Throwable;

final class SecurityHeadersAdmin
{
    public const NONCE_ACTION = 'bastion_security_wp_security_headers';
    public const POST_ACTION = 'bastion_security_wp_security_headers';
    public const NOTICE_QUERY = 'bastion_security_headers_notice';
    private const CAPABILITY = 'manage_options';

    /** @var list<string> */
    private const HIGH_IMPACT_GROUPS = [
        'framing',
        'browser_capabilities',
        'mixed_content_upgrade',
        'hsts_trial',
        'opener_isolation',
        'resource_isolation',
    ];

    private Closure $currentUserCan;
    private Closure $verifyNonce;
    private Closure $safeRedirect;
    private Closure $adminUrl;
    private Closure $terminate;
    private Closure $hstsReady;

    public function __construct(
        private readonly SecurityHeadersPolicy $policy,
        ?callable $currentUserCan = null,
        ?callable $verifyNonce = null,
        ?callable $safeRedirect = null,
        ?callable $adminUrl = null,
        ?callable $terminate = null,
        ?callable $hstsReady = null,
    ) {
        $this->currentUserCan = Closure::fromCallable($currentUserCan ?? static fn (string $capability): bool => \current_user_can($capability));
        $this->verifyNonce = Closure::fromCallable($verifyNonce ?? static fn (string $nonce, string $action): bool => (bool) \wp_verify_nonce($nonce, $action));
        $this->safeRedirect = Closure::fromCallable($safeRedirect ?? static fn (string $url): bool => \wp_safe_redirect($url));
        $this->adminUrl = Closure::fromCallable($adminUrl ?? static fn (string $path): string => \admin_url($path));
        $this->terminate = Closure::fromCallable($terminate ?? static function (): never {
            exit;
        });
        $this->hstsReady = Closure::fromCallable($hstsReady ?? self::observeHstsReadiness(...));
    }

    /** @param array<string, mixed> $post */
    public function handle(array $post): void
    {
        if (! ($this->currentUserCan)(self::CAPABILITY)) {
            $this->redirect('forbidden');

            return;
        }

        $command = $post['command'] ?? null;

        if (! is_string($command) || ! in_array($command, ['enable', 'disable'], true)) {
            $this->redirect('invalid_command');

            return;
        }

        $target = $post['target'] ?? 'baseline';

        if (! is_string($target) || ! in_array($target, ['baseline', 'group'], true)) {
            $this->redirect('invalid_target');

            return;
        }

        $group = null;
        $nonceAction = self::NONCE_ACTION;

        if ($target === 'group') {
            $candidate = $post['group'] ?? null;
            if (! is_string($candidate) || ! array_key_exists($candidate, SecurityHeadersPolicy::groupDefinitions())) {
                $this->redirect('invalid_group');

                return;
            }

            $group = $candidate;
            $nonceAction = self::NONCE_ACTION . ':group:' . $group;
        }

        $nonce = $post['_wpnonce'] ?? null;

        if (! is_string($nonce) || ! ($this->verifyNonce)($nonce, $nonceAction)) {
            $this->redirect('invalid_nonce');

            return;
        }

        $enable = $command === 'enable';

        if ($target === 'baseline') {
            $this->redirect($this->policy->setEnabled($enable));

            return;
        }

        if ($enable && in_array($group, self::HIGH_IMPACT_GROUPS, true) && ($post['acknowledgement'] ?? null) !== '1') {
            $this->redirect('acknowledgement_required');

            return;
        }

        if ($enable && $group === 'hsts_trial' && ! $this->isHstsReady()) {
            $this->redirect('hsts_not_ready');

            return;
        }

        $this->redirect($this->policy->setGroupEnabled((string) $group, $enable));
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
        echo '<p>' . \esc_html__('Start safely: enable the conservative baseline, verify final headers at the browser or CDN edge, then enable and validate optional groups one at a time.', 'bastion-security-wp') . '</p>';
        echo '<h3>' . \esc_html__('Conservative baseline', 'bastion-security-wp') . '</h3>';
        echo '<p>' . \esc_html__('This independent per-site baseline uses WordPress to add exactly:', 'bastion-security-wp') . '</p>';
        echo '<ul><li><code>' . \esc_html('X-Content-Type-Options') . ': ' . \esc_html('nosniff') . '</code></li>';
        echo '<li><code>' . \esc_html('Referrer-Policy') . ': ' . \esc_html('strict-origin-when-cross-origin') . '</code></li></ul>';
        echo '<p><strong>' . \esc_html__('Status:', 'bastion-security-wp') . '</strong> ' . ($enabled ? \esc_html__('Enabled', 'bastion-security-wp') : \esc_html__('Disabled', 'bastion-security-wp')) . '</p>';
        $this->renderForm(
            'baseline',
            null,
            $enabled ? 'disable' : 'enable',
            $enabled
                ? \esc_html__('Disable security header preset', 'bastion-security-wp')
                : \esc_html__('Enable security header preset', 'bastion-security-wp'),
            false,
        );

        echo '<h3>' . \esc_html__('Optional policy groups', 'bastion-security-wp') . '</h3>';
        echo '<p>' . \esc_html__('All optional groups start disabled as per-site preferences and work independently of the baseline. This is a safe-intent policy set inspired by a public reference, not byte-for-byte parity with it.', 'bastion-security-wp') . '</p>';
        echo '<div class="bastion-header-omissions">';
        echo '<h4>' . \esc_html__('Intentional policy omissions', 'bastion-security-wp') . '</h4>';
        echo '<p>' . \esc_html__('Bastion follows safe intent rather than byte parity with the reference plugin.', 'bastion-security-wp') . '</p>';
        echo '<ul>';
        echo '<li>' . \esc_html__('No global', 'bastion-security-wp') . ' <code>' . \esc_html('Access-Control-Allow-*') . '</code> ' . \esc_html__('headers without an explicit allowed-origin contract.', 'bastion-security-wp') . '</li>';
        echo '<li>' . \esc_html__('No COOP', 'bastion-security-wp') . ' <code>' . \esc_html('unsafe-none') . '</code> ' . \esc_html__('or CORP', 'bastion-security-wp') . ' <code>' . \esc_html('cross-origin') . '</code> ' . \esc_html__('values because they add no meaningful isolation.', 'bastion-security-wp') . '</li>';
        echo '<li>' . \esc_html__('No HSTS', 'bastion-security-wp') . ' <code>' . \esc_html('includeSubDomains') . '</code> ' . \esc_html__('or', 'bastion-security-wp') . ' <code>' . \esc_html('preload') . '</code> ' . \esc_html__('directives in trial mode.', 'bastion-security-wp') . '</li>';
        echo '<li>' . \esc_html__('No CSP', 'bastion-security-wp') . ' <code>' . \esc_html('Report-Only') . '</code> ' . \esc_html__('policy without a configured reporting endpoint.', 'bastion-security-wp') . '</li>';
        echo '<li>' . \esc_html__('No deprecated headers.', 'bastion-security-wp') . '</li>';
        echo '</ul></div>';
        $states = $this->policy->groupStates();

        foreach (SecurityHeadersPolicy::groupDefinitions() as $group => $definition) {
            $groupEnabled = $states[$group];
            echo '<div class="bastion-header-group">';
            echo '<h4>' . $this->translatedGroupLabel($group) . '</h4>';
            echo '<p><strong>' . \esc_html__('Status:', 'bastion-security-wp') . '</strong> ' . ($groupEnabled ? \esc_html__('Enabled', 'bastion-security-wp') : \esc_html__('Disabled', 'bastion-security-wp')) . '</p>';
            echo '<p><code>' . \esc_html($definition['header']) . ': ' . \esc_html($definition['value']) . '</code></p>';
            echo '<p>' . $this->translatedGroupRisk($group) . '</p>';
            echo '<p>' . \esc_html__('Coverage: this group is emitted only on eligible wp_headers front-end responses; verify the final response at every serving edge.', 'bastion-security-wp') . '</p>';
            if ($group === 'hsts_trial') {
                echo '<p>' . \esc_html__('Before enabling, the current request, home URL, and site URL must all use HTTPS. Disabling stops future emission, but browsers may retain the 24-hour policy until it expires.', 'bastion-security-wp') . '</p>';
            }
            $this->renderForm(
                'group',
                $group,
                $groupEnabled ? 'disable' : 'enable',
                $this->translatedGroupSubmitLabel($group, $groupEnabled ? 'disable' : 'enable'),
                ! $groupEnabled && in_array($group, self::HIGH_IMPACT_GROUPS, true),
            );
            echo '</div>';
        }

        echo '<p>' . \esc_html__('Bastion only adds missing headers. Existing names are matched case-insensitively; external spelling, values, and order remain unchanged.', 'bastion-security-wp') . '</p>';
        echo '<p>' . \esc_html__('Coverage is narrow: the wp_headers filter covers standard front-end responses handled by WP::send_headers(). It is not guaranteed for wp-admin, wp-login, REST, redirects, static files, CDN or cache responses, or headers emitted by the web server.', 'bastion-security-wp') . '</p>';
        echo '</section>';
    }

    private function translatedGroupLabel(string $group): string
    {
        return match ($group) {
            'framing' => \esc_html__('Same-origin framing', 'bastion-security-wp'),
            'browser_capabilities' => \esc_html__('Browser capability restrictions', 'bastion-security-wp'),
            'legacy_cross_domain' => \esc_html__('Legacy cross-domain policy denial', 'bastion-security-wp'),
            'mixed_content_upgrade' => \esc_html__('Mixed-content upgrade', 'bastion-security-wp'),
            'hsts_trial' => \esc_html__('HSTS 24-hour trial', 'bastion-security-wp'),
            'opener_isolation' => \esc_html__('Opener isolation', 'bastion-security-wp'),
            'resource_isolation' => \esc_html__('Same-site resource isolation', 'bastion-security-wp'),
        };
    }

    private function translatedGroupRisk(string $group): string
    {
        return match ($group) {
            'framing' => \esc_html__('Can break legitimate', 'bastion-security-wp') . ' <code>' . \esc_html('cross-origin') . '</code> ' . \esc_html__('iframe embedding. Validate every intended embedding flow.', 'bastion-security-wp'),
            'browser_capabilities' => \esc_html__('Disables camera, microphone, and geolocation for this response, including embedded features that rely on them.', 'bastion-security-wp'),
            'legacy_cross_domain' => \esc_html__('Blocks legacy Adobe cross-domain policy discovery; validate any remaining legacy client dependency.', 'bastion-security-wp'),
            'mixed_content_upgrade' => \esc_html__('Requests insecure subresources over HTTPS instead and can expose broken resources without an HTTPS endpoint.', 'bastion-security-wp'),
            'hsts_trial' => \esc_html__('Forces future browser requests to HTTPS for 24 hours. A broken HTTPS deployment can make the site unreachable to returning browsers.', 'bastion-security-wp'),
            'opener_isolation' => \esc_html__('Can change popup and opener relationships. Validate authentication, payment, and integration popup flows.', 'bastion-security-wp'),
            'resource_isolation' => \esc_html__('Can block other sites from loading this site\'s resources. Validate every intentional cross-site consumer.', 'bastion-security-wp'),
        };
    }

    private function translatedGroupSubmitLabel(string $group, string $command): string
    {
        return match ($command . ':' . $group) {
            'enable:framing' => \esc_html__('Enable Same-origin framing', 'bastion-security-wp'),
            'disable:framing' => \esc_html__('Disable Same-origin framing', 'bastion-security-wp'),
            'enable:browser_capabilities' => \esc_html__('Enable Browser capability restrictions', 'bastion-security-wp'),
            'disable:browser_capabilities' => \esc_html__('Disable Browser capability restrictions', 'bastion-security-wp'),
            'enable:legacy_cross_domain' => \esc_html__('Enable Legacy cross-domain policy denial', 'bastion-security-wp'),
            'disable:legacy_cross_domain' => \esc_html__('Disable Legacy cross-domain policy denial', 'bastion-security-wp'),
            'enable:mixed_content_upgrade' => \esc_html__('Enable Mixed-content upgrade', 'bastion-security-wp'),
            'disable:mixed_content_upgrade' => \esc_html__('Disable Mixed-content upgrade', 'bastion-security-wp'),
            'enable:hsts_trial' => \esc_html__('Enable HSTS 24-hour trial', 'bastion-security-wp'),
            'disable:hsts_trial' => \esc_html__('Disable HSTS 24-hour trial', 'bastion-security-wp'),
            'enable:opener_isolation' => \esc_html__('Enable Opener isolation', 'bastion-security-wp'),
            'disable:opener_isolation' => \esc_html__('Disable Opener isolation', 'bastion-security-wp'),
            'enable:resource_isolation' => \esc_html__('Enable Same-site resource isolation', 'bastion-security-wp'),
            'disable:resource_isolation' => \esc_html__('Disable Same-site resource isolation', 'bastion-security-wp'),
        };
    }

    private function renderForm(string $target, ?string $group, string $command, string $label, bool $acknowledgement): void
    {
        echo '<form method="post" action="' . \esc_url(($this->adminUrl)('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . \esc_attr(self::POST_ACTION) . '">';
        echo '<input type="hidden" name="target" value="' . \esc_attr($target) . '">';
        echo '<input type="hidden" name="command" value="' . \esc_attr($command) . '">';
        if ($group !== null) {
            echo '<input type="hidden" name="group" value="' . \esc_attr($group) . '">';
        }
        if ($acknowledgement) {
            echo '<label><input type="checkbox" name="acknowledgement" value="1" required> ' . \esc_html__('I acknowledge this policy can break site behavior and have validated a rollback path.', 'bastion-security-wp') . '</label>';
        }
        \wp_nonce_field($group === null ? self::NONCE_ACTION : self::NONCE_ACTION . ':group:' . $group);
        \submit_button($label);
        echo '</form>';
    }

    private function renderNotice(string $notice): void
    {
        $message = match ($notice) {
            'updated' => \esc_html__('The Bastion security-header preference was updated.', 'bastion-security-wp'),
            'unchanged' => \esc_html__('The Bastion security-header preference was already in the requested state.', 'bastion-security-wp'),
            'write_failed' => \esc_html__('WordPress could not save the Bastion security-header preference.', 'bastion-security-wp'),
            'invalid_nonce' => \esc_html__('The request could not be verified. No change was made.', 'bastion-security-wp'),
            'invalid_command' => \esc_html__('The requested command is not supported. No change was made.', 'bastion-security-wp'),
            'invalid_target' => \esc_html__('The requested security-header target is not supported. No change was made.', 'bastion-security-wp'),
            'invalid_group' => \esc_html__('The requested security-header group is not supported. No change was made.', 'bastion-security-wp'),
            'acknowledgement_required' => \esc_html__('A risk acknowledgement is required before enabling this policy group. No change was made.', 'bastion-security-wp'),
            'hsts_not_ready' => \esc_html__('Bastion could not confirm HSTS readiness. Use an HTTPS admin request and configure both the WordPress Address and Site Address with HTTPS, then retry.', 'bastion-security-wp'),
            'forbidden' => \esc_html__('You are not allowed to perform this action. No change was made.', 'bastion-security-wp'),
            default => null,
        };

        if ($message === null) {
            return;
        }

        echo '<div class="notice notice-info"><p>' . $message . '</p></div>';
    }

    private function isHstsReady(): bool
    {
        try {
            return (bool) ($this->hstsReady)();
        } catch (Throwable) {
            return false;
        }
    }

    private static function observeHstsReadiness(): bool
    {
        if (! \is_ssl()) {
            return false;
        }

        $home = \get_option('home', '');
        $site = \get_option('siteurl', '');

        return is_string($home) && is_string($site)
            && str_starts_with(strtolower($home), 'https://')
            && str_starts_with(strtolower($site), 'https://');
    }

    private function redirect(string $notice): void
    {
        $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&' . self::NOTICE_QUERY . '=' . rawurlencode($notice));
        ($this->safeRedirect)($url);
        ($this->terminate)();
    }
}
