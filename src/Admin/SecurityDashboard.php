<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\SiteHealthDiagnostics;
use Closure;

final class SecurityDashboard
{
    private const CAPABILITY = 'manage_options';

    private Closure $currentUserCan;
    private Closure $adminUrl;
    private Closure $sanitizeHtml;

    public function __construct(
        private readonly SiteHealthDiagnostics $diagnostics,
        private readonly FileEditorAdmin $fileEditorAdmin,
        private readonly SecurityHeadersAdmin $securityHeadersAdmin,
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

        $siteHealthUrl = ($this->adminUrl)('site-health.php');
        $notice = isset($_GET['bastion_notice']) && is_string($_GET['bastion_notice'])
            ? $_GET['bastion_notice']
            : '';
        $securityHeadersNotice = isset($_GET[SecurityHeadersAdmin::NOTICE_QUERY]) && is_string($_GET[SecurityHeadersAdmin::NOTICE_QUERY])
            ? $_GET[SecurityHeadersAdmin::NOTICE_QUERY]
            : '';

        echo '<div class="wrap bastion-security-dashboard"><h1>' . \esc_html__('Bastion Security', 'bastion-security-wp') . '</h1>';
        echo '<p>' . \esc_html__('Bastion reports its own focused security posture checks here.', 'bastion-security-wp') . ' ';
        echo '<a href="' . \esc_url($siteHealthUrl) . '">' . \esc_html__('Open WordPress Site Health for the full native test suite.', 'bastion-security-wp') . '</a></p>';
        $this->renderStyles();
        echo '<h2>' . \esc_html__('Bastion diagnostics', 'bastion-security-wp') . '</h2>';
        echo '<div class="bastion-diagnostics">';

        foreach ($this->diagnostics->reports() as $result) {
            $this->renderDiagnostic($result);
        }

        echo '</div>';
        $this->fileEditorAdmin->renderToolSection($notice);
        $this->securityHeadersAdmin->renderToolSection($securityHeadersNotice);
        echo '</div>';
    }

    private function renderStyles(): void
    {
        echo <<<'HTML'
<style>
.bastion-security-dashboard .bastion-diagnostics {
    overflow: hidden;
    margin: 0 0 24px;
    border: 1px solid #c3c4c7;
    border-radius: 2px;
    background: #fff;
    box-shadow: 0 1px 1px rgba(0, 0, 0, 0.04);
}
.bastion-security-dashboard .bastion-diagnostic + .bastion-diagnostic {
    border-top: 1px solid #dcdcde;
}
.bastion-security-dashboard .bastion-diagnostic-summary {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto auto;
    gap: 12px;
    align-items: center;
    padding: 16px 20px;
    cursor: pointer;
    list-style: none;
}
.bastion-security-dashboard .bastion-diagnostic-summary::-webkit-details-marker {
    display: none;
}
.bastion-security-dashboard .bastion-diagnostic-summary:focus-visible {
    outline: 2px solid #2271b1;
    outline-offset: -2px;
}
.bastion-security-dashboard .bastion-diagnostic-title {
    color: #1d2327;
    font-size: 14px;
    font-weight: 600;
    line-height: 1.4;
}
.bastion-security-dashboard .bastion-diagnostic-badge {
    display: inline-block;
    padding: 2px 9px;
    border: 1px solid currentColor;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
    line-height: 1.5;
    white-space: nowrap;
}
.bastion-security-dashboard .bastion-diagnostic-badge--good {
    color: #008a20;
}
.bastion-security-dashboard .bastion-diagnostic-badge--recommended {
    color: #996800;
}
.bastion-security-dashboard .bastion-diagnostic-summary::after {
    width: 7px;
    height: 7px;
    border-right: 2px solid #50575e;
    border-bottom: 2px solid #50575e;
    content: "";
    transform: rotate(45deg) translateY(-2px);
}
.bastion-security-dashboard .bastion-diagnostic[open] > .bastion-diagnostic-summary::after {
    transform: rotate(225deg) translate(-2px, -2px);
}
.bastion-security-dashboard .bastion-diagnostic-panel {
    padding: 4px 20px 20px;
    border-top: 1px solid #f0f0f1;
    color: #3c434a;
}
.bastion-security-dashboard .bastion-diagnostic-status {
    margin: 16px 0;
}
.bastion-security-dashboard .bastion-diagnostic-status-label {
    font-weight: 600;
}
.bastion-security-dashboard .bastion-diagnostic-description p,
.bastion-security-dashboard .bastion-diagnostic-action p {
    max-width: 72ch;
}
.bastion-security-dashboard .bastion-diagnostic-action {
    margin-top: 16px;
}
@media (max-width: 782px) {
    .bastion-security-dashboard .bastion-diagnostic-summary {
        grid-template-columns: minmax(0, 1fr) auto;
        padding: 14px 16px;
    }
    .bastion-security-dashboard .bastion-diagnostic-badge {
        grid-column: 1;
        justify-self: start;
    }
    .bastion-security-dashboard .bastion-diagnostic-summary::after {
        grid-column: 2;
        grid-row: 1 / span 2;
    }
    .bastion-security-dashboard .bastion-diagnostic-panel {
        padding: 4px 16px 16px;
    }
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

        echo '<details class="bastion-diagnostic">';
        echo '<summary class="bastion-diagnostic-summary">';
        echo '<span class="bastion-diagnostic-title">' . \esc_html($label) . '</span>';
        echo '<span class="bastion-diagnostic-badge ' . $statusPresentation['class'] . '">' . \esc_html($statusPresentation['label']) . '</span>';
        echo '</summary>';
        echo '<div class="bastion-diagnostic-panel">';
        echo '<p class="bastion-diagnostic-status"><span class="bastion-diagnostic-status-label">' . \esc_html__('Status:', 'bastion-security-wp') . '</span> <strong>' . \esc_html($statusPresentation['label']) . '</strong></p>';
        echo '<div class="bastion-diagnostic-description">' . ($this->sanitizeHtml)($description) . '</div>';
        echo '<div class="bastion-diagnostic-action"><strong>' . \esc_html__('Recommended action', 'bastion-security-wp') . '</strong>' . ($this->sanitizeHtml)($actions) . '</div>';
        echo '</div>';
        echo '</details>';
    }

    /** @return array{label: string, class: string} */
    private function statusPresentation(string $status): array
    {
        if ($status === 'good') {
            return [
                'label' => 'Good',
                'class' => 'bastion-diagnostic-badge--good',
            ];
        }

        return [
            'label' => 'Recommended',
            'class' => 'bastion-diagnostic-badge--recommended',
        ];
    }
}
