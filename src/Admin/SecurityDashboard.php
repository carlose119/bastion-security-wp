<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\SiteHealthDiagnostics;
use Closure;

final class SecurityDashboard
{
    private const CAPABILITY = 'manage_options';

    /** @var list<string> */
    private const TABS = ['overview', 'hardening', 'headers', 'rest-api'];

    private Closure $currentUserCan;
    private Closure $adminUrl;
    private Closure $sanitizeHtml;

    public function __construct(
        private readonly SiteHealthDiagnostics $diagnostics,
        private readonly FileEditorAdmin $fileEditorAdmin,
        private readonly SecurityHeadersAdmin $securityHeadersAdmin,
        private readonly LoginProtectionAdmin $loginProtectionAdmin,
        private readonly XmlRpcPingbackAdmin $xmlRpcPingbackAdmin,
        private readonly RestRouteControlsAdmin $restRouteControlsAdmin,
        private readonly PluginActivityAlertAdmin $pluginActivityAlertAdmin,
        private readonly AdministratorAccountAlertAdmin $administratorAccountAlertAdmin,
        ?callable $currentUserCan = null,
        ?callable $adminUrl = null,
        ?callable $sanitizeHtml = null,
        private readonly ?CriticalSettingsAlertAdmin $criticalSettingsAlertAdmin = null,
    ) {
        $this->currentUserCan = Closure::fromCallable($currentUserCan ?? static fn (string $capability): bool => \current_user_can($capability));
        $this->adminUrl = Closure::fromCallable($adminUrl ?? static fn (string $path): string => \admin_url($path));
        $this->sanitizeHtml = Closure::fromCallable($sanitizeHtml ?? static fn (string $html): string => \wp_kses_post($html));
    }

    public function registerPage(): void
    {
        $pageHook = \add_management_page(
            'Cerrojo Security Toolkit',
            'Cerrojo Security Toolkit',
            self::CAPABILITY,
            FileEditorAdmin::PAGE_SLUG,
            $this->render(...),
        );
        \add_action('admin_enqueue_scripts', static function (string $hook) use ($pageHook): void {
            if ($hook !== $pageHook) {
                return;
            }

            \wp_enqueue_style(
                'bastion-security-wp-admin',
                \plugins_url('assets/css/admin.css', dirname(__DIR__, 2) . '/cerrojo-security-toolkit.php'),
                [],
                '1.0.0',
            );
        });
    }

    public function render(): void
    {
        if (! ($this->currentUserCan)(self::CAPABILITY)) {
            \wp_die(\esc_html__('You are not allowed to manage Cerrojo Security Toolkit.', 'cerrojo-security-toolkit'));

            return;
        }

        $tab = $this->activeTab();
        $notice = $this->queryToken('bastion_notice');
        $loginNotice = $this->queryToken('bastion_login_notice');
        $xmlRpcPingbackNotice = $this->queryToken('bastion_xmlrpc_pingback_notice');
        $restRouteControlsNotice = $this->queryToken('bastion_rest_route_controls_notice');
        $pluginAlertNotice = $this->queryToken('bastion_plugin_alert_notice');
        $administratorAlertNotice = $this->queryToken('bastion_administrator_alert_notice');
        $criticalSettingsAlertNotice = $this->queryToken(CriticalSettingsAlertAdmin::NOTICE_QUERY);

        echo '<div class="wrap bastion-security-dashboard"><h1>' . \esc_html__('Cerrojo Security Toolkit', 'cerrojo-security-toolkit') . '</h1>';
        $this->renderTabs($tab);

        if ($tab === 'hardening') {
            echo '<p class="bastion-tab-introduction">' . \esc_html__('Manage reversible WordPress hardening controls.', 'cerrojo-security-toolkit') . '</p>';
            $this->fileEditorAdmin->renderToolSection($notice);
            $this->loginProtectionAdmin->renderToolSection($loginNotice);
            $this->xmlRpcPingbackAdmin->renderToolSection($xmlRpcPingbackNotice);
            $this->pluginActivityAlertAdmin->renderToolSection($pluginAlertNotice);
            $this->administratorAccountAlertAdmin->renderToolSection($administratorAlertNotice);
            if ($this->criticalSettingsAlertAdmin !== null) {
                $this->criticalSettingsAlertAdmin->renderToolSection($criticalSettingsAlertNotice);
            }
        } elseif ($tab === 'headers') {
            echo '<p class="bastion-tab-introduction">' . \esc_html__('Review exact header policies, select bounded changes, and verify the final response at every serving edge.', 'cerrojo-security-toolkit') . '</p>';
            $this->securityHeadersAdmin->renderToolSection($notice);
        } elseif ($tab === 'rest-api') {
            echo '<p class="bastion-tab-introduction">' . \esc_html__('Review the active REST route-template catalog and choose method-level blocks.', 'cerrojo-security-toolkit') . '</p>';
            $this->restRouteControlsAdmin->renderCatalog($restRouteControlsNotice);
        } else {
            $this->renderOverview();
        }

        echo '</div>';
    }

    private function activeTab(): string
    {
        $candidate = $this->queryToken('tab');

        return in_array($candidate, self::TABS, true) ? $candidate : 'overview';
    }

    private function queryToken(string $key): string
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only PRG notice and tab selectors cannot mutate state; mutation handlers verify operation-bound nonces separately.
        return isset($_GET[$key]) && is_string($_GET[$key]) ? \sanitize_key(\wp_unslash($_GET[$key])) : '';
    }

    private function renderTabs(string $activeTab): void
    {
        echo '<nav class="nav-tab-wrapper" aria-label="' . \esc_attr(\esc_html__('Cerrojo Security Toolkit sections', 'cerrojo-security-toolkit')) . '">';
        foreach (self::TABS as $tab) {
            $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&tab=' . $tab);
            $class = 'nav-tab' . ($tab === $activeTab ? ' nav-tab-active' : '');
            echo '<a class="' . \esc_attr($class) . '" href="' . \esc_url($url) . '"';
            if ($tab === $activeTab) {
                echo ' aria-current="page"';
            }
            echo '>' . \esc_html($this->translatedTabLabel($tab)) . '</a>';
        }
        echo '</nav>';
    }

    private function renderOverview(): void
    {
        $reports = $this->diagnostics->reports();
        $good = count(array_filter($reports, static fn (array $report): bool => ($report['status'] ?? null) === 'good'));
        $needsAttention = count($reports) - $good;
        $siteHealthUrl = ($this->adminUrl)('site-health.php');

        echo '<p class="bastion-tab-introduction">' . \esc_html__('Review Cerrojo’s focused posture checks, then use native WordPress Site Health for the full test suite.', 'cerrojo-security-toolkit') . '</p>';
        echo '<div class="bastion-summary-cards">';
        $this->renderSummaryCard(\esc_html__('Total diagnostics', 'cerrojo-security-toolkit'), count($reports));
        $this->renderSummaryCard(\esc_html__('Good', 'cerrojo-security-toolkit'), $good);
        $this->renderSummaryCard(\esc_html__('Needs attention', 'cerrojo-security-toolkit'), $needsAttention);
        echo '</div>';
        echo '<p><a class="button" href="' . \esc_url($siteHealthUrl) . '">' . \esc_html__('Open WordPress Site Health', 'cerrojo-security-toolkit') . '</a></p>';
        echo '<h2>' . \esc_html__('Cerrojo diagnostics', 'cerrojo-security-toolkit') . '</h2><div class="bastion-diagnostics">';
        foreach ($reports as $result) {
            $this->renderDiagnostic($result);
        }
        echo '</div>';
    }

    private function renderSummaryCard(string $label, int $count): void
    {
        echo '<div class="bastion-summary-card"><span>' . \esc_html($label) . '</span><strong>' . \esc_html((string) $count) . '</strong></div>';
    }

    private function translatedTabLabel(string $tab): string
    {
        return match ($tab) {
            'overview' => \esc_html__('Overview', 'cerrojo-security-toolkit'),
            'hardening' => \esc_html__('Hardening', 'cerrojo-security-toolkit'),
            'headers' => \esc_html__('Security headers', 'cerrojo-security-toolkit'),
            'rest-api' => \esc_html__('REST API', 'cerrojo-security-toolkit'),
        };
    }

    /** @param array<string, mixed> $result */
    private function renderDiagnostic(array $result): void
    {
        $label = is_string($result['label'] ?? null) ? $result['label'] : 'Cerrojo diagnostic';
        $status = is_string($result['status'] ?? null) ? $result['status'] : 'recommended';
        $description = is_string($result['description'] ?? null) ? $result['description'] : '';
        $actions = is_string($result['actions'] ?? null) ? $result['actions'] : '';
        $statusPresentation = $this->statusPresentation($status);

        echo '<details class="bastion-diagnostic"><summary class="bastion-diagnostic-summary">';
        echo '<span class="bastion-diagnostic-title">' . \esc_html($label) . '</span>';
        echo '<span class="bastion-diagnostic-badge ' . \esc_attr($statusPresentation['class']) . '">' . \esc_html($statusPresentation['label']) . '</span>';
        echo '</summary><div class="bastion-diagnostic-panel">';
        echo '<p class="bastion-diagnostic-status"><span class="bastion-diagnostic-status-label">' . \esc_html__('Status:', 'cerrojo-security-toolkit') . '</span> <strong>' . \esc_html($statusPresentation['label']) . '</strong></p>';
        echo '<div class="bastion-diagnostic-description">' . \wp_kses_post(($this->sanitizeHtml)($description)) . '</div>';
        echo '<div class="bastion-diagnostic-action"><strong>' . \esc_html__('Recommended action', 'cerrojo-security-toolkit') . '</strong>' . \wp_kses_post(($this->sanitizeHtml)($actions)) . '</div>';
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
