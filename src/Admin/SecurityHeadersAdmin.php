<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\Security\SecurityHeadersPolicy;
use Closure;
use Throwable;

final class SecurityHeadersAdmin
{
    public const NONCE_ACTION = 'bastion_security_wp_security_headers';
    public const SELECTED_NONCE_ACTION = 'bastion_security_wp_security_headers_selected';
    public const DISABLE_ALL_NONCE_ACTION = 'bastion_security_wp_security_headers_disable_all';
    public const POST_ACTION = 'bastion_security_wp_security_headers';
    public const NOTICE_QUERY = 'bastion_notice';
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

    /** @var array<string, list<string>> */
    private const POLICY_SECTIONS = [
        'Conservative baseline' => ['baseline'],
        'Compatibility restrictions' => ['framing', 'browser_capabilities', 'legacy_cross_domain'],
        'Transport/content upgrade' => ['mixed_content_upgrade', 'hsts_trial'],
        'Cross-origin isolation' => ['opener_isolation', 'resource_isolation'],
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

        if (! is_string($command) || ! in_array($command, ['enable', 'disable', 'enable_selected', 'disable_selected', 'disable_all'], true)) {
            $this->redirect('invalid_command');

            return;
        }

        if (in_array($command, ['enable_selected', 'disable_selected'], true)) {
            $this->handleSelected($post, $command === 'enable_selected');

            return;
        }

        if ($command === 'disable_all') {
            if (! $this->hasValidNonce($post, self::DISABLE_ALL_NONCE_ACTION)) {
                $this->redirect('invalid_nonce');

                return;
            }

            $groupsResult = $this->policy->disableAllGroups();
            $baselineResult = $this->policy->setEnabled(false);
            $this->redirect($this->combineResults([$groupsResult, $baselineResult]));

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

        if (! $this->hasValidNonce($post, $nonceAction)) {
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
        $baselineEnabled = $this->policy->isEnabled();
        $states = $this->policy->groupStates();

        echo '<section id="bastion-header-actions" class="bastion-tools bastion-header-tool"><h2>' . \esc_html__('HTTP security header policies', 'bastion-security-wp') . '</h2>';
        $this->renderNotice($notice);
        echo '<p>' . \esc_html__('Choose only the policies you intend to change, review their exact values and risks, then apply one selected action.', 'bastion-security-wp') . '</p>';
        echo '<div class="notice notice-warning inline"><p><strong>' . \esc_html__('High-impact policies can break embedding, browser features, resources, transport, or', 'bastion-security-wp') . ' ' . \esc_html('cross-origin') . ' ' . \esc_html__('workflows.', 'bastion-security-wp') . '</strong> ' . \esc_html__('Enabling any high-impact selection requires the aggregate acknowledgement below.', 'bastion-security-wp') . '</p></div>';
        $this->renderBatchForm($baselineEnabled, $states);

        echo '<h3>' . \esc_html__('Individual controls', 'bastion-security-wp') . '</h3>';
        echo '<p>' . \esc_html__('Use these controls when you want to change and verify one policy at a time.', 'bastion-security-wp') . '</p>';
        $this->renderIndividualBaseline($baselineEnabled);

        foreach (SecurityHeadersPolicy::groupDefinitions() as $group => $definition) {
            $this->renderIndividualGroup($group, $definition, $states[$group]);
        }

        echo '<div class="bastion-header-omissions"><h3>' . \esc_html__('Coverage and intentional omissions', 'bastion-security-wp') . '</h3>';
        echo '<p>' . \esc_html__('This is a safe-intent policy set, not byte-for-byte parity with the reference plugin. Bastion follows safe intent rather than byte parity.', 'bastion-security-wp') . '</p>';
        echo '<p>' . \esc_html__('Bastion only adds missing header names on eligible front-end responses. Existing names are matched case-insensitively; external spelling, values, and order remain unchanged.', 'bastion-security-wp') . '</p>';
        echo '<p>' . \esc_html__('Coverage is limited to the', 'bastion-security-wp') . ' <code>' . \esc_html('wp_headers') . '</code> ' . \esc_html__('path used by standard front-end responses. Verify wp-admin, wp-login, REST, redirects, static files, cache responses, and every CDN or proxy edge separately.', 'bastion-security-wp') . '</p>';
        echo '<ul>';
        echo '<li>' . \esc_html__('No global', 'bastion-security-wp') . ' <code>' . \esc_html('Access-Control-Allow-*') . '</code> ' . \esc_html__('headers without an explicit allowed-origin contract.', 'bastion-security-wp') . '</li>';
        echo '<li>' . \esc_html__('No COOP', 'bastion-security-wp') . ' <code>' . \esc_html('unsafe-none') . '</code> ' . \esc_html__('or CORP', 'bastion-security-wp') . ' <code>' . \esc_html('cross-origin') . '</code> ' . \esc_html__('values because they add no meaningful isolation.', 'bastion-security-wp') . '</li>';
        echo '<li>' . \esc_html__('No HSTS', 'bastion-security-wp') . ' <code>' . \esc_html('includeSubDomains') . '</code> ' . \esc_html__('or', 'bastion-security-wp') . ' <code>' . \esc_html('preload') . '</code> ' . \esc_html__('directives in trial mode.', 'bastion-security-wp') . '</li>';
        echo '<li>' . \esc_html__('No CSP', 'bastion-security-wp') . ' <code>' . \esc_html('Report-Only') . '</code> ' . \esc_html__('policy without a configured reporting endpoint.', 'bastion-security-wp') . '</li>';
        echo '<li>' . \esc_html__('No deprecated headers.', 'bastion-security-wp') . '</li>';
        echo '</ul></div>';
        $this->renderDisableAllForm();
        $this->renderStyles();
        echo '</section>';
    }

    /** @param array<string, bool> $states */
    private function renderBatchForm(bool $baselineEnabled, array $states): void
    {
        echo '<form class="bastion-header-batch" method="post" action="' . \esc_url(($this->adminUrl)('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . \esc_attr(self::POST_ACTION) . '">';

        foreach (self::POLICY_SECTIONS as $legend => $policyIds) {
            echo '<fieldset><legend>' . $this->translatedSectionLegend($legend) . '</legend>';
            foreach ($policyIds as $policyId) {
                if ($policyId === 'baseline') {
                    $this->renderPolicyCheckbox(
                        'baseline',
                        \esc_html__('Baseline', 'bastion-security-wp'),
                        $baselineEnabled,
                        \esc_html('X-Content-Type-Options') . ': ' . \esc_html('nosniff') . '; ' . \esc_html('Referrer-Policy') . ': ' . \esc_html('strict-origin-when-cross-origin'),
                        \esc_html__('Low-risk defaults, but final delivery still depends on the serving path.', 'bastion-security-wp'),
                    );
                    continue;
                }

                $definition = SecurityHeadersPolicy::groupDefinitions()[$policyId];
                $this->renderPolicyCheckbox(
                    $policyId,
                    $this->translatedGroupLabel($policyId),
                    $states[$policyId],
                    \esc_html($definition['header']) . ': ' . \esc_html($definition['value']),
                    $this->translatedGroupRisk($policyId),
                );
            }
            echo '</fieldset>';
        }

        echo '<label class="bastion-header-acknowledgement"><input type="checkbox" name="acknowledgement" value="1"> ' . \esc_html__('I acknowledge that selected high-impact policies can break site behavior and I have validated a rollback path.', 'bastion-security-wp') . '</label>';
        \wp_nonce_field(self::SELECTED_NONCE_ACTION);
        echo '<div class="bastion-header-batch-bar">';
        echo '<button type="submit" class="button button-primary" name="command" value="enable_selected">' . \esc_html__('Enable selected', 'bastion-security-wp') . '</button> ';
        echo '<button type="submit" class="button" name="command" value="disable_selected">' . \esc_html__('Disable selected', 'bastion-security-wp') . '</button>';
        echo '</div></form>';
    }

    private function renderPolicyCheckbox(string $id, string $label, bool $enabled, string $policy, string $risk): void
    {
        echo '<label class="bastion-header-choice"><input type="checkbox" name="groups[]" value="' . \esc_attr($id) . '"> ';
        echo '<span><strong>' . $label . '</strong> <span class="bastion-header-state">' . ($enabled ? \esc_html__('Enabled', 'bastion-security-wp') : \esc_html__('Disabled', 'bastion-security-wp')) . '</span>';
        echo '<code>' . $policy . '</code><span>' . $risk . '</span></span></label>';
    }

    private function renderIndividualBaseline(bool $enabled): void
    {
        echo '<div class="bastion-header-group"><h4>' . \esc_html__('Conservative baseline', 'bastion-security-wp') . '</h4>';
        echo '<p><code>' . \esc_html('X-Content-Type-Options') . ': ' . \esc_html('nosniff') . '</code><br><code>' . \esc_html('Referrer-Policy') . ': ' . \esc_html('strict-origin-when-cross-origin') . '</code></p>';
        echo '<p><strong>' . \esc_html__('Status:', 'bastion-security-wp') . '</strong> ' . ($enabled ? \esc_html__('Enabled', 'bastion-security-wp') : \esc_html__('Disabled', 'bastion-security-wp')) . '</p>';
        $this->renderForm('baseline', null, $enabled ? 'disable' : 'enable', $enabled ? \esc_html__('Disable security header baseline', 'bastion-security-wp') : \esc_html__('Enable security header baseline', 'bastion-security-wp'), false);
        echo '</div>';
    }

    /** @param array{header: string, value: string} $definition */
    private function renderIndividualGroup(string $group, array $definition, bool $enabled): void
    {
        echo '<div class="bastion-header-group"><h4>' . $this->translatedGroupLabel($group) . '</h4>';
        echo '<p><strong>' . \esc_html__('Status:', 'bastion-security-wp') . '</strong> ' . ($enabled ? \esc_html__('Enabled', 'bastion-security-wp') : \esc_html__('Disabled', 'bastion-security-wp')) . '</p>';
        echo '<p><code>' . \esc_html($definition['header']) . ': ' . \esc_html($definition['value']) . '</code></p>';
        echo '<p>' . $this->translatedGroupRisk($group) . '</p>';
        echo '<p>' . \esc_html__('Coverage: this group is emitted only on eligible wp_headers front-end responses; verify the final response at every serving edge.', 'bastion-security-wp') . '</p>';
        if ($group === 'hsts_trial') {
            echo '<p>' . \esc_html__('Before enabling, the current request, home URL, and site URL must all use HTTPS. Disabling stops future emission, but browsers may retain the 24-hour policy until it expires.', 'bastion-security-wp') . '</p>';
        }
        $this->renderForm('group', $group, $enabled ? 'disable' : 'enable', $this->translatedGroupSubmitLabel($group, $enabled ? 'disable' : 'enable'), ! $enabled && in_array($group, self::HIGH_IMPACT_GROUPS, true));
        echo '</div>';
    }

    private function renderDisableAllForm(): void
    {
        echo '<div class="bastion-header-danger"><h3>' . \esc_html__('Emergency rollback', 'bastion-security-wp') . '</h3>';
        echo '<p>' . \esc_html__('Disable every Bastion-managed header preference. Optional groups are disabled before the baseline; a two-option write can partially fail, and the resulting state will be shown after redirect.', 'bastion-security-wp') . '</p>';
        echo '<form method="post" action="' . \esc_url(($this->adminUrl)('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . \esc_attr(self::POST_ACTION) . '">';
        echo '<input type="hidden" name="command" value="disable_all">';
        \wp_nonce_field(self::DISABLE_ALL_NONCE_ACTION);
        \submit_button(\esc_html__('Disable all Bastion headers', 'bastion-security-wp'));
        echo '</form></div>';
    }

    /** @param array<string, mixed> $post */
    private function handleSelected(array $post, bool $enable): void
    {
        $selection = $post['groups'] ?? null;
        $allowed = array_merge(['baseline'], array_keys(SecurityHeadersPolicy::groupDefinitions()));

        if (! is_array($selection) || ! array_is_list($selection) || $selection === []) {
            $this->redirect('invalid_selection');

            return;
        }

        foreach ($selection as $id) {
            if (! is_string($id) || ! in_array($id, $allowed, true)) {
                $this->redirect('invalid_selection');

                return;
            }
        }

        if (count($selection) !== count(array_unique($selection))) {
            $this->redirect('invalid_selection');

            return;
        }

        if (! $this->hasValidNonce($post, self::SELECTED_NONCE_ACTION)) {
            $this->redirect('invalid_nonce');

            return;
        }

        $selected = array_values(array_filter($allowed, static fn (string $id): bool => in_array($id, $selection, true)));
        $selectedGroups = array_values(array_filter($selected, static fn (string $id): bool => $id !== 'baseline'));

        if ($enable && array_intersect($selectedGroups, self::HIGH_IMPACT_GROUPS) !== [] && ($post['acknowledgement'] ?? null) !== '1') {
            $this->redirect('acknowledgement_required');

            return;
        }

        if ($enable && in_array('hsts_trial', $selectedGroups, true) && ! $this->isHstsReady()) {
            $this->redirect('hsts_not_ready');

            return;
        }

        $results = [];
        if ($selectedGroups !== []) {
            $results[] = $this->policy->setGroupsEnabled($selectedGroups, $enable);
        }
        if (in_array('baseline', $selected, true)) {
            $results[] = $this->policy->setEnabled($enable);
        }

        $this->redirect($this->combineResults($results));
    }

    /** @param array<string, mixed> $post */
    private function hasValidNonce(array $post, string $action): bool
    {
        $nonce = $post['_wpnonce'] ?? null;

        return is_string($nonce) && ($this->verifyNonce)($nonce, $action);
    }

    /** @param list<string> $results */
    private function combineResults(array $results): string
    {
        $updated = in_array('updated', $results, true);
        $failed = in_array('write_failed', $results, true);

        if ($updated && $failed) {
            return 'partial_failure';
        }
        if ($failed) {
            return 'write_failed';
        }

        return $updated ? 'updated' : 'unchanged';
    }

    private function translatedSectionLegend(string $section): string
    {
        return match ($section) {
            'Conservative baseline' => \esc_html__('Conservative baseline', 'bastion-security-wp'),
            'Compatibility restrictions' => \esc_html__('Compatibility restrictions', 'bastion-security-wp'),
            'Transport/content upgrade' => \esc_html__('Transport/content upgrade', 'bastion-security-wp'),
            'Cross-origin isolation' => \esc_html('Cross-origin') . ' ' . \esc_html__('isolation', 'bastion-security-wp'),
        };
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
            'updated' => \esc_html__('The selected Bastion security-header preferences were updated. The current states are shown below.', 'bastion-security-wp'),
            'unchanged' => \esc_html__('The selected Bastion security-header preferences were already in the requested states.', 'bastion-security-wp'),
            'partial_failure' => \esc_html__('Only part of the requested header change was saved. Review the resulting states below before retrying.', 'bastion-security-wp'),
            'write_failed' => \esc_html__('WordPress could not save the Bastion security-header preference.', 'bastion-security-wp'),
            'invalid_nonce' => \esc_html__('The request could not be verified. No change was made.', 'bastion-security-wp'),
            'invalid_command' => \esc_html__('The requested command is not supported. No change was made.', 'bastion-security-wp'),
            'invalid_target' => \esc_html__('The requested security-header target is not supported. No change was made.', 'bastion-security-wp'),
            'invalid_group' => \esc_html__('The requested security-header group is not supported. No change was made.', 'bastion-security-wp'),
            'invalid_selection' => \esc_html__('Select one or more unique supported policies. No change was made.', 'bastion-security-wp'),
            'acknowledgement_required' => \esc_html__('A risk acknowledgement is required before enabling the selected high-impact policies. No change was made.', 'bastion-security-wp'),
            'hsts_not_ready' => \esc_html__('Bastion could not confirm HSTS readiness, so no selected policy was changed. Use an HTTPS admin request and configure both the WordPress Address and Site Address with HTTPS, then retry.', 'bastion-security-wp'),
            'forbidden' => \esc_html__('You are not allowed to perform this action. No change was made.', 'bastion-security-wp'),
            default => null,
        };

        if ($message === null) {
            return;
        }

        $severity = match ($notice) {
            'updated' => 'success',
            'unchanged' => 'info',
            'partial_failure', 'acknowledgement_required', 'hsts_not_ready' => 'warning',
            default => 'error',
        };
        echo '<div class="notice notice-' . $severity . '"><p>' . $message . '</p></div>';
    }

    private function renderStyles(): void
    {
        echo <<<'HTML'
<style>
.bastion-header-tool .bastion-header-batch fieldset {
    margin: 16px 0;
    padding: 12px 16px;
    border: 1px solid #c3c4c7;
    background: #fff;
}
.bastion-header-tool .bastion-header-batch legend { padding: 0 6px; font-weight: 600; }
.bastion-header-tool .bastion-header-choice { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 8px; margin: 10px 0; }
.bastion-header-tool .bastion-header-choice > span,
.bastion-header-tool .bastion-header-choice code { display: block; }
.bastion-header-tool .bastion-header-state { margin-left: 6px; color: #50575e; font-weight: 400; }
.bastion-header-tool .bastion-header-batch-bar { position: sticky; bottom: 0; z-index: 2; padding: 12px; border: 1px solid #c3c4c7; background: #f6f7f7; }
.bastion-header-tool .bastion-header-acknowledgement { display: block; margin: 16px 0; font-weight: 600; }
.bastion-header-tool .bastion-header-group { margin: 16px 0; padding: 16px; border-left: 4px solid #72aee6; background: #fff; }
.bastion-header-tool .bastion-header-danger { margin-top: 24px; padding: 16px; border: 1px solid #d63638; background: #fff; }
@media (max-width: 782px) {
    .bastion-header-tool .bastion-header-batch-bar { position: static; }
    .bastion-header-tool .bastion-header-batch-bar .button { display: block; width: 100%; margin: 8px 0; }
}
</style>
HTML;
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
        $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&tab=headers&' . self::NOTICE_QUERY . '=' . rawurlencode($notice) . '#bastion-header-actions');
        ($this->safeRedirect)($url);
        ($this->terminate)();
    }
}
