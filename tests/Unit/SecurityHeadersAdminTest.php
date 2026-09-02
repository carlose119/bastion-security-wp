<?php

declare(strict_types=1);

namespace {
    if (! function_exists('esc_html__')) {
        function esc_html__(string $value, string $domain): string
        {
            return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
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
            echo '<button type="submit">' . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . '</button>';
        }
    }
}

namespace BastionSecurityWP\Tests\Unit {
    use BastionSecurityWP\Admin\SecurityHeadersAdmin;
    use BastionSecurityWP\Security\SecurityHeadersPolicy;
    use PHPUnit\Framework\TestCase;

    final class SecurityHeadersAdminTest extends TestCase
    {
        public function testAuthorizedValidCommandsAreAppliedAndRedirected(): void
        {
            $stored = false;
            $redirects = [];
            $admin = $this->admin($stored, true, true, $redirects);

            $admin->handle(['command' => 'enable', '_wpnonce' => 'valid']);
            self::assertTrue($stored);
            self::assertStringContainsString('bastion_security_headers_notice=updated', $redirects[0]);

            $admin->handle(['command' => 'enable', '_wpnonce' => 'valid']);
            self::assertStringContainsString('bastion_security_headers_notice=unchanged', $redirects[1]);

            $admin->handle(['command' => 'disable', '_wpnonce' => 'valid']);
            self::assertFalse($stored);
        }

        public function testUnauthorizedNonceAndCommandRejectionsNeverMutate(): void
        {
            $stored = false;
            $redirects = [];

            $this->admin($stored, false, true, $redirects)->handle(['command' => 'enable', '_wpnonce' => 'valid']);
            $this->admin($stored, true, false, $redirects)->handle(['command' => 'enable', '_wpnonce' => 'invalid']);
            $this->admin($stored, true, true, $redirects)->handle(['command' => 'toggle', '_wpnonce' => 'valid']);
            $this->admin($stored, true, true, $redirects)->handle(['command' => ['enable'], '_wpnonce' => 'valid']);

            self::assertFalse($stored);
            self::assertStringContainsString('forbidden', $redirects[0]);
            self::assertStringContainsString('invalid_nonce', $redirects[1]);
            self::assertStringContainsString('invalid_command', $redirects[2]);
            self::assertStringContainsString('invalid_command', $redirects[3]);
        }

        public function testWriteFailureIsReportedWithoutClaimingSuccess(): void
        {
            $stored = false;
            $redirects = [];
            $admin = $this->admin($stored, true, true, $redirects, false);

            $admin->handle(['command' => 'enable', '_wpnonce' => 'valid']);

            self::assertFalse($stored);
            self::assertStringContainsString('write_failed', $redirects[0]);
        }

        public function testSectionRendersExactPresetCoverageRollbackFormAndNotices(): void
        {
            $stored = false;
            $redirects = [];
            $admin = $this->admin($stored, true, true, $redirects);

            ob_start();
            $admin->renderToolSection('write_failed');
            $html = (string) ob_get_clean();

            self::assertStringContainsString('HTTP security header preset', $html);
            self::assertStringContainsString('X-Content-Type-Options: nosniff', $html);
            self::assertStringContainsString('Referrer-Policy: strict-origin-when-cross-origin', $html);
            self::assertStringContainsString('Content-Security-Policy (CSP)', $html);
            self::assertStringContainsString('Strict-Transport-Security (HSTS)', $html);
            self::assertStringContainsString('X-Frame-Options', $html);
            self::assertStringContainsString('Permissions-Policy', $html);
            self::assertStringContainsString('site-specific validation', $html);
            self::assertStringContainsString('only adds missing headers', $html);
            self::assertStringContainsString('standard front-end responses', $html);
            self::assertStringContainsString('wp-admin', $html);
            self::assertStringContainsString('wp-login', $html);
            self::assertStringContainsString('REST', $html);
            self::assertStringContainsString('redirects', $html);
            self::assertStringContainsString('static', $html);
            self::assertStringContainsString('CDN', $html);
            self::assertStringContainsString('web server', $html);
            self::assertStringContainsString('per-site', $html);
            self::assertStringContainsString('name="action" value="' . SecurityHeadersAdmin::POST_ACTION . '"', $html);
            self::assertStringContainsString('name="command" value="enable"', $html);
            self::assertStringContainsString('could not save', $html);

            $stored = true;
            ob_start();
            $admin->renderToolSection('unchanged');
            $enabledHtml = (string) ob_get_clean();

            self::assertStringContainsString('name="command" value="disable"', $enabledHtml);
            self::assertStringContainsString('rollback', strtolower($enabledHtml));
            self::assertStringContainsString('already in the requested state', $enabledHtml);
        }

        /** @param list<string> $redirects */
        private function admin(
            bool &$stored,
            bool $authorized,
            bool $nonceValid,
            array &$redirects,
            bool $writeSucceeds = true,
        ): SecurityHeadersAdmin {
            $policy = new SecurityHeadersPolicy(
                static function () use (&$stored): bool {
                    return $stored;
                },
                static function (bool $enabled) use (&$stored, $writeSucceeds): bool {
                    if ($writeSucceeds) {
                        $stored = $enabled;
                    }

                    return $writeSucceeds;
                },
            );

            return new SecurityHeadersAdmin(
                $policy,
                static fn (string $capability): bool => $authorized && $capability === 'manage_options',
                static fn (string $nonce, string $action): bool => $nonceValid && $nonce === 'valid' && $action === SecurityHeadersAdmin::NONCE_ACTION,
                static function (string $url) use (&$redirects): bool {
                    $redirects[] = $url;

                    return true;
                },
                static fn (string $path): string => 'https://example.test/wp-admin/' . $path,
                static function (): void {},
            );
        }
    }
}
