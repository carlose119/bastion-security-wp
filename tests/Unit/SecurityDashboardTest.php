<?php

declare(strict_types=1);

namespace {
    if (! function_exists('esc_html')) {
        function esc_html(string $value): string
        {
            return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
    }

    if (! function_exists('esc_html__')) {
        function esc_html__(string $value, string $domain): string
        {
            return esc_html($value);
        }
    }

    if (! function_exists('esc_attr')) {
        function esc_attr(string $value): string
        {
            return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
    }

    if (! function_exists('esc_url')) {
        function esc_url(string $value): string
        {
            return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
    }

    if (! function_exists('wp_nonce_field')) {
        function wp_nonce_field(string $action): void
        {
            echo '<input type="hidden" name="_wpnonce" value="nonce-for-' . esc_attr($action) . '">';
        }
    }

    if (! function_exists('submit_button')) {
        function submit_button(string $label): void
        {
            echo '<button type="submit">' . esc_html($label) . '</button>';
        }
    }

    if (! function_exists('wp_die')) {
        function wp_die(string $message): never
        {
            throw new \RuntimeException($message);
        }
    }
}

namespace BastionSecurityWP\Tests\Unit {
    use BastionSecurityWP\Admin\FileEditorAdmin;
    use BastionSecurityWP\Admin\SecurityDashboard;
    use BastionSecurityWP\Admin\SecurityHeadersAdmin;
    use BastionSecurityWP\Security\FileEditorPolicy;
    use BastionSecurityWP\Security\SecurityHeadersPolicy;
    use BastionSecurityWP\SiteHealthDiagnostics;
    use PHPUnit\Framework\TestCase;

    final class SecurityDashboardTest extends TestCase
    {
        public function testDashboardRendersSevenBastionResultsNativeSiteHealthLinkAndTwoManagedTools(): void
        {
            $dashboard = $this->dashboard();

            ob_start();
            $dashboard->render();
            $html = (string) ob_get_clean();

            self::assertSame(7, substr_count($html, '<details class="bastion-diagnostic">'));
            self::assertSame(7, substr_count($html, '<summary class="bastion-diagnostic-summary">'));
            self::assertSame(2, substr_count($html, '<section class="bastion-tools">'));
            self::assertStringContainsString('HTTPS and admin transport posture', $html);
            self::assertStringContainsString('File editor posture', $html);
            self::assertStringContainsString('Security header preset', $html);
            self::assertStringContainsString('File modification posture', $html);
            self::assertStringContainsString('Runtime compatibility notice', $html);
            self::assertStringContainsString('Plugin update compatibility', $html);
            self::assertStringContainsString('REST surface inventory', $html);
            self::assertTrue(
                strpos($html, 'HTTPS and admin transport posture')
                < strpos($html, 'File editor posture')
                && strpos($html, 'File editor posture') < strpos($html, 'Security header preset')
                && strpos($html, 'Security header preset') < strpos($html, 'File modification posture')
                && strpos($html, 'File modification posture') < strpos($html, 'Runtime compatibility notice')
                && strpos($html, 'Runtime compatibility notice') < strpos($html, 'Plugin update compatibility')
                && strpos($html, 'Plugin update compatibility') < strpos($html, 'REST surface inventory'),
            );
            self::assertStringContainsString('site-health.php', $html);
            self::assertStringContainsString('WordPress Site Health', $html);
            self::assertStringContainsString('WordPress file editor lock', $html);
            self::assertStringContainsString('HTTP security header preset', $html);
            self::assertTrue(strpos($html, 'WordPress file editor lock') < strpos($html, 'HTTP security header preset'));
            self::assertSame(2, substr_count($html, 'name="command" value="enable"'));
            self::assertStringNotContainsString('wordpress_core', $html);
        }

        public function testDiagnosticsRenderAsCollapsedAccessibleStatusRowsWithoutJavaScript(): void
        {
            ob_start();
            $this->dashboard()->render();
            $html = (string) ob_get_clean();

            self::assertSame(7, substr_count($html, '<details class="bastion-diagnostic">'));
            self::assertSame(7, substr_count($html, '<summary class="bastion-diagnostic-summary">'));
            self::assertStringNotContainsString('<details class="bastion-diagnostic" open', $html);
            self::assertDoesNotMatchRegularExpression('/<details\b[^>]*\bopen\b/i', $html);
            self::assertStringContainsString('class="bastion-diagnostic-badge bastion-diagnostic-badge--good">Good</span>', $html);
            self::assertStringContainsString('class="bastion-diagnostic-badge bastion-diagnostic-badge--recommended">Recommended</span>', $html);
            self::assertStringContainsString('<span class="bastion-diagnostic-status-label">Status:</span>', $html);
            self::assertStringContainsString('<strong>Recommended action</strong>', $html);
            self::assertStringContainsString('class="wrap bastion-security-dashboard"', $html);
            self::assertStringContainsString('.bastion-security-dashboard .bastion-diagnostics', $html);
            self::assertStringContainsString('@media (max-width: 782px)', $html);
            self::assertStringNotContainsString('<script', $html);
        }

        public function testDiagnosticStatusClassUsesAnAllowlist(): void
        {
            $method = new \ReflectionMethod(SecurityDashboard::class, 'renderDiagnostic');
            $method->setAccessible(true);

            ob_start();
            $method->invoke($this->dashboard(), [
                'label' => 'Unexpected status',
                'status' => 'good\" onmouseover=\"alert(1)',
                'description' => '<p>Description</p>',
                'actions' => '<p>Action</p>',
            ]);
            $html = (string) ob_get_clean();

            self::assertStringContainsString('bastion-diagnostic-badge--recommended', $html);
            self::assertStringNotContainsString('onmouseover', $html);
            self::assertStringNotContainsString('alert(1)', $html);
        }

        public function testManagedToolRendersDisableCommandWhenPreferenceIsEnabled(): void
        {
            ob_start();
            $this->dashboard(optionEnabled: true)->render();
            $html = (string) ob_get_clean();

            self::assertStringContainsString('name="command" value="disable"', $html);
            self::assertStringContainsString('Disable Bastion lock', $html);
        }

        public function testExternalOwnershipAndMultisiteRemainConservative(): void
        {
            ob_start();
            $this->dashboard(externalDefined: true)->render();
            $externalHtml = (string) ob_get_clean();

            self::assertStringContainsString('defined outside Bastion', $externalHtml);
            self::assertStringNotContainsString('Clear Bastion preference', $externalHtml);
            self::assertStringContainsString('Enable security header preset', $externalHtml);

            ob_start();
            $this->dashboard(optionEnabled: true, externalDefined: true)->render();
            $stalePreferenceHtml = (string) ob_get_clean();

            self::assertStringContainsString('Clear Bastion preference', $stalePreferenceHtml);
            self::assertStringContainsString('name="command" value="disable"', $stalePreferenceHtml);
            self::assertStringContainsString('Enable security header preset', $stalePreferenceHtml);

            ob_start();
            $this->dashboard(multisite: true)->render();
            $multisiteHtml = (string) ob_get_clean();

            self::assertStringContainsString('unavailable on multisite', $multisiteHtml);
            self::assertStringContainsString('per-site preference', $multisiteHtml);
            self::assertStringContainsString('Enable security header preset', $multisiteHtml);
            self::assertStringNotContainsString('Enable Bastion lock', $multisiteHtml);
        }

        public function testDashboardRequiresManageOptionsCapability(): void
        {
            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessage('not allowed');

            $this->dashboard(authorized: false)->render();
        }

        public function testDashboardSanitizesDiagnosticHtmlAndShowsUnassessedRestInventory(): void
        {
            $sanitizedFragments = [];
            $dashboard = $this->dashboard(
                static fn (string $value): string => '<script>' . $value . '</script>',
                static function (string $html) use (&$sanitizedFragments): string {
                    $sanitizedFragments[] = $html;

                    return strip_tags($html, '<p>');
                },
            );

            ob_start();
            $dashboard->render();
            $html = (string) ob_get_clean();

            self::assertCount(14, $sanitizedFragments);
            self::assertStringNotContainsString('<script>', $html);
            self::assertStringContainsString('Not assessed', $html);
            self::assertStringContainsString('site-health.php', $html);
        }

        private function dashboard(
            ?callable $escape = null,
            ?callable $sanitize = null,
            bool $optionEnabled = false,
            bool $externalDefined = false,
            bool $multisite = false,
            bool $authorized = true,
        ): SecurityDashboard {
            $values = [
                'is_ssl' => true,
                'force_ssl_admin' => true,
                'disallow_file_edit' => false,
                'disallow_file_mods' => false,
                'wordpress_version' => '6.8.2',
                'php_version' => '8.4.1',
            ];
            $policy = new FileEditorPolicy(
                static fn (): bool => $optionEnabled,
                static fn (bool $enabled): bool => true,
                static fn (): bool => $multisite,
                static fn (): array => ['defined' => $externalDefined, 'value' => $externalDefined ? true : null],
                static fn (): bool => true,
            );
            $fileEditor = new FileEditorAdmin(
                $policy,
                static fn (string $capability): bool => $capability === 'manage_options',
                static fn (): bool => true,
                static fn (): bool => true,
                static fn (string $path): string => 'https://example.test/wp-admin/' . $path,
                static function (): void {},
            );
            $securityHeadersPolicy = new SecurityHeadersPolicy(
                static fn (): bool => false,
                static fn (): bool => true,
            );
            $securityHeaders = new SecurityHeadersAdmin(
                $securityHeadersPolicy,
                static fn (string $capability): bool => $capability === 'manage_options',
                static fn (): bool => true,
                static fn (): bool => true,
                static fn (string $path): string => 'https://example.test/wp-admin/' . $path,
                static function (): void {},
            );

            $diagnostics = new SiteHealthDiagnostics(
                static fn (string $key): mixed => $values[$key],
                $escape ?? static fn (string $value): string => esc_html($value),
                fileEditorPolicy: $policy,
                securityHeadersPolicy: $securityHeadersPolicy,
            );

            return new SecurityDashboard(
                $diagnostics,
                $fileEditor,
                $securityHeaders,
                static fn (string $capability): bool => $authorized && $capability === 'manage_options',
                static fn (string $path): string => 'https://example.test/wp-admin/' . $path,
                $sanitize ?? static fn (string $html): string => strip_tags($html, '<p><strong><a>'),
            );
        }
    }
}
