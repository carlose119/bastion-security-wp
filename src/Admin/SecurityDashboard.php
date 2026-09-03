<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\SiteHealthDiagnostics;
use Closure;

final class SecurityDashboard
{
    private const CAPABILITY = 'manage_options';

    /** @var list<string> */
    private const TABS = ['overview', 'hardening', 'headers'];

    private Closure $currentUserCan;
    private Closure $adminUrl;
    private Closure $sanitizeHtml;

    public function __construct(
        private readonly SiteHealthDiagnostics $diagnostics,
        private readonly FileEditorAdmin $fileEditorAdmin,
        private readonly SecurityHeadersAdmin $securityHeadersAdmin,
        private readonly LoginProtectionAdmin $loginProtectionAdmin,
        private readonly PluginActivityAlertAdmin $pluginActivityAlertAdmin,
        ?callable $currentUserCan = null,
        ?callable $adminUrl = null,
        ?callable $sanitizeHtml = null,
    ) {
        $this->currentUserCan = Closure::fromCallable($currentUserCan ?? static fn (string $capability): bool => \current_user_can($capability));
        $this->adminUrl = Closure::fromCallable($adminUrl ?? static fn (string $path): string => \admin_url($path));
        $this->sanitizeHtml = Closure::fromCallable($sanitizeHtml ?? static fn (string $html): string => \wp_kses_post($html));
    }

    public function registerPage(): void
    {
        \add_management_page(
            'Bastion Security',
            'Bastion Security',
            self::CAPABILITY,
            FileEditorAdmin::PAGE_SLUG,
            $this->render(...),
        );
    }

    public function render(): void
    {
        if (! ($this->currentUserCan)(self::CAPABILITY)) {
            \wp_die(\esc_html__('You are not allowed to manage Bastion Security.', 'bastion-security-wp'));

            return;
        }

        $tab = $this->activeTab();
        $notice = isset($_GET['bastion_notice']) && is_string($_GET['bastion_notice'])
            ? $_GET['bastion_notice']
            : '';
        $loginNotice = isset($_GET['bastion_login_notice']) && is_string($_GET['bastion_login_notice'])
            ? $_GET['bastion_login_notice']
            : '';
        $pluginAlertNotice = isset($_GET['bastion_plugin_alert_notice']) && is_string($_GET['bastion_plugin_alert_notice'])
            ? $_GET['bastion_plugin_alert_notice']
            : '';

        echo '<div class="wrap bastion-security-dashboard"><h1>' . \esc_html__('Bastion Security', 'bastion-security-wp') . '</h1>';
        $this->renderTabs($tab);
        $this->renderStyles();

        if ($tab === 'hardening') {
            echo '<p class="bastion-tab-introduction">' . \esc_html__('Manage reversible WordPress hardening controls.', 'bastion-security-wp') . '</p>';
            $this->fileEditorAdmin->renderToolSection($notice);
            $this->loginProtectionAdmin->renderToolSection($loginNotice);
            $this->pluginActivityAlertAdmin->renderToolSection($pluginAlertNotice);
        } elseif ($tab === 'headers') {
            echo '<p class="bastion-tab-introduction">' . \esc_html__('Review exact header policies, select bounded changes, and verify the final response at every serving edge.', 'bastion-security-wp') . '</p>';
            $this->securityHeadersAdmin->renderToolSection($notice);
        } else {
            $this->renderOverview();
        }

        echo '</div>';
    }

    private function activeTab(): string
    {
        $candidate = $_GET['tab'] ?? 'overview';

        return is_string($candidate) && in_array($candidate, self::TABS, true)
            ? $candidate
            : 'overview';
    }

    private function renderTabs(string $activeTab): void
    {
        echo '<nav class="nav-tab-wrapper" aria-label="' . \esc_attr(\esc_html__('Bastion Security sections', 'bastion-security-wp')) . '">';
        foreach (self::TABS as $tab) {
            $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&tab=' . $tab);
            $class = 'nav-tab' . ($tab === $activeTab ? ' nav-tab-active' : '');
            echo '<a class="' . \esc_attr($class) . '" href="' . \esc_url($url) . '"';
            if ($tab === $activeTab) {
                echo ' aria-current="page"';
            }
            echo '>' . $this->translatedTabLabel($tab) . '</a>';
        }
        echo '</nav>';
    }

    private function renderOverview(): void
    {
        $reports = $this->diagnostics->reports();
        $good = count(array_filter($reports, static fn (array $report): bool => ($report['status'] ?? null) === 'good'));
        $needsAttention = count($reports) - $good;
        $siteHealthUrl = ($this->adminUrl)('site-health.php');

        echo '<p class="bastion-tab-introduction">' . \esc_html__('Review Bastion’s focused posture checks, then use native WordPress Site Health for the full test suite.', 'bastion-security-wp') . '</p>';
        echo '<div class="bastion-summary-cards">';
        $this->renderSummaryCard(\esc_html__('Total diagnostics', 'bastion-security-wp'), count($reports));
        $this->renderSummaryCard(\esc_html__('Good', 'bastion-security-wp'), $good);
        $this->renderSummaryCard(\esc_html__('Needs attention', 'bastion-security-wp'), $needsAttention);
        echo '</div>';
        echo '<p><a class="button" href="' . \esc_url($siteHealthUrl) . '">' . \esc_html__('Open WordPress Site Health', 'bastion-security-wp') . '</a></p>';
        echo '<h2>' . \esc_html__('Bastion diagnostics', 'bastion-security-wp') . '</h2><div class="bastion-diagnostics">';
        foreach ($reports as $result) {
            $this->renderDiagnostic($result);
        }
        echo '</div>';
    }

    private function renderSummaryCard(string $label, int $count): void
    {
        echo '<div class="bastion-summary-card"><span>' . $label . '</span><strong>' . $count . '</strong></div>';
    }

    private function translatedTabLabel(string $tab): string
    {
        return match ($tab) {
            'overview' => \esc_html__('Overview', 'bastion-security-wp'),
            'hardening' => \esc_html__('Hardening', 'bastion-security-wp'),
            'headers' => \esc_html__('Security headers', 'bastion-security-wp'),
        };
    }

    private function renderStyles(): void
    {
        echo <<<'HTML'
<style>
.bastion-security-dashboard .bastion-tab-introduction { max-width: 72ch; font-size: 14px; }
.bastion-security-dashboard .bastion-summary-cards { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; max-width: 900px; margin: 20px 0; }
.bastion-security-dashboard .bastion-summary-card { padding: 18px 20px; border: 1px solid #c3c4c7; background: #fff; box-shadow: 0 1px 1px rgba(0, 0, 0, 0.04); }
.bastion-security-dashboard .bastion-summary-card span,
.bastion-security-dashboard .bastion-summary-card strong { display: block; }
.bastion-security-dashboard .bastion-summary-card strong { margin-top: 8px; font-size: 28px; line-height: 1; }
.bastion-security-dashboard .bastion-diagnostics { overflow: hidden; margin: 0 0 24px; border: 1px solid #c3c4c7; border-radius: 2px; background: #fff; box-shadow: 0 1px 1px rgba(0, 0, 0, 0.04); }
.bastion-security-dashboard .bastion-diagnostic + .bastion-diagnostic { border-top: 1px solid #dcdcde; }
.bastion-security-dashboard .bastion-diagnostic-summary { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 12px; align-items: center; padding: 16px 20px; cursor: pointer; list-style: none; }
.bastion-security-dashboard .bastion-diagnostic-summary::-webkit-details-marker { display: none; }
.bastion-security-dashboard .bastion-diagnostic-summary:focus-visible { outline: 2px solid #2271b1; outline-offset: -2px; }
.bastion-security-dashboard .bastion-diagnostic-title { color: #1d2327; font-size: 14px; font-weight: 600; line-height: 1.4; }
.bastion-security-dashboard .bastion-diagnostic-badge { display: inline-block; padding: 2px 9px; border: 1px solid currentColor; border-radius: 12px; font-size: 12px; font-weight: 600; line-height: 1.5; white-space: nowrap; }
.bastion-security-dashboard .bastion-diagnostic-badge--good { color: #008a20; }
.bastion-security-dashboard .bastion-diagnostic-badge--recommended { color: #996800; }
.bastion-security-dashboard .bastion-diagnostic-summary::after { width: 7px; height: 7px; border-right: 2px solid #50575e; border-bottom: 2px solid #50575e; content: ""; transform: rotate(45deg) translateY(-2px); }
.bastion-security-dashboard .bastion-diagnostic[open] > .bastion-diagnostic-summary::after { transform: rotate(225deg) translate(-2px, -2px); }
.bastion-security-dashboard .bastion-diagnostic-panel { padding: 4px 20px 20px; border-top: 1px solid #f0f0f1; color: #3c434a; }
.bastion-security-dashboard .bastion-diagnostic-status { margin: 16px 0; }
.bastion-security-dashboard .bastion-diagnostic-status-label { font-weight: 600; }
.bastion-security-dashboard .bastion-diagnostic-description p,
.bastion-security-dashboard .bastion-diagnostic-action p { max-width: 72ch; }
.bastion-security-dashboard .bastion-diagnostic-action { margin-top: 16px; }
.bastion-security-dashboard .bastion-login-protection,
.bastion-security-dashboard .bastion-plugin-activity-alerts { margin-top: 28px; padding-top: 8px; border-top: 2px solid #c3c4c7; }
.bastion-security-dashboard .bastion-login-reset { max-width: 72ch; margin-top: 20px; padding: 14px 16px; border-left: 4px solid #dba617; background: #fff; }
@media (max-width: 782px) {
    .bastion-security-dashboard .bastion-summary-cards { grid-template-columns: 1fr; gap: 10px; }
    .bastion-security-dashboard .bastion-diagnostic-summary { grid-template-columns: minmax(0, 1fr) auto; padding: 14px 16px; }
    .bastion-security-dashboard .bastion-diagnostic-badge { grid-column: 1; justify-self: start; }
    .bastion-security-dashboard .bastion-diagnostic-summary::after { grid-column: 2; grid-row: 1 / span 2; }
    .bastion-security-dashboard .bastion-diagnostic-panel { padding: 4px 16px 16px; }
}
</style>
HTML;
    }

    /** @param array<string, mixed> $result */
    private function renderDiagnostic(array $result): void
    {
        $label = is_string($result['label'] ?? null) ? $result['label'] : 'Bastion diagnostic';
        $status = is_string($result['status'] ?? null) ? $result['status'] : 'recommended';
        $description = is_string($result['description'] ?? null) ? $result['description'] : '';
        $actions = is_string($result['actions'] ?? null) ? $result['actions'] : '';
        $statusPresentation = $this->statusPresentation($status);

        echo '<details class="bastion-diagnostic"><summary class="bastion-diagnostic-summary">';
        echo '<span class="bastion-diagnostic-title">' . \esc_html($label) . '</span>';
        echo '<span class="bastion-diagnostic-badge ' . $statusPresentation['class'] . '">' . \esc_html($statusPresentation['label']) . '</span>';
        echo '</summary><div class="bastion-diagnostic-panel">';
        echo '<p class="bastion-diagnostic-status"><span class="bastion-diagnostic-status-label">' . \esc_html__('Status:', 'bastion-security-wp') . '</span> <strong>' . \esc_html($statusPresentation['label']) . '</strong></p>';
        echo '<div class="bastion-diagnostic-description">' . ($this->sanitizeHtml)($description) . '</div>';
        echo '<div class="bastion-diagnostic-action"><strong>' . \esc_html__('Recommended action', 'bastion-security-wp') . '</strong>' . ($this->sanitizeHtml)($actions) . '</div>';
        echo '</div></details>';
    }

    /** @return array{label: string, class: string} */
    private function statusPresentation(string $status): array
    {
        if ($status === 'good') {
            return ['label' => 'Good', 'class' => 'bastion-diagnostic-badge--good'];
        }

        return ['label' => 'Recommended', 'class' => 'bastion-diagnostic-badge--recommended'];
    }
}
