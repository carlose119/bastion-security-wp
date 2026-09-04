<?php

declare(strict_types=1);

namespace {
    if (! function_exists('__')) {
        function __(string $text, string $domain = 'default'): string { return $text; }
    }
    if (! function_exists('esc_html')) {
        function esc_html(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
    }
    if (! function_exists('esc_html__')) {
        function esc_html__(string $value, string $domain): string { return esc_html($value); }
    }
    if (! function_exists('esc_attr')) {
        function esc_attr(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
    }
    if (! function_exists('esc_url')) {
        function esc_url(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
    }
    if (! function_exists('wp_nonce_field')) {
        function wp_nonce_field(string $action): void { echo '<input type="hidden" name="_wpnonce" value="nonce-for-' . esc_attr($action) . '">'; }
    }
    if (! function_exists('submit_button')) {
        function submit_button(string $label, string $type = 'primary'): void { echo '<button type="submit" class="button button-' . esc_attr($type) . '">' . esc_html($label) . '</button>'; }
    }
    if (! function_exists('date_i18n')) {
        function date_i18n(string $format, int $timestamp): string { return gmdate('Y-m-d H:i:s', $timestamp); }
    }
}

namespace BastionSecurityWP\Tests\Unit {
    use BastionSecurityWP\Admin\LoginProtectionAdmin;
    use BastionSecurityWP\Security\LoginProtectionPolicy;
    use PHPUnit\Framework\TestCase;

    final class LoginProtectionAdminTest extends TestCase
    {
        public function testCommandsRequirePostCapabilityExactTargetAndOperationBoundNonce(): void
        {
            foreach ([
                ['GET', true, 'login_protection', 'enable', true, 'invalid_request'],
                ['POST', false, 'login_protection', 'enable', true, 'forbidden'],
                ['POST', true, 'wrong', 'enable', true, 'invalid_command'],
                ['POST', true, 'login_protection', 'toggle', true, 'invalid_command'],
                ['POST', true, 'login_protection', 'enable', false, 'invalid_nonce'],
            ] as [$method, $authorized, $target, $command, $nonceValid, $notice]) {
                $harness = $this->admin(method: $method, authorized: $authorized, nonceValid: $nonceValid);
                $harness['admin']->handle([
                    'target' => $target,
                    'command' => $command,
                    '_wpnonce' => 'valid',
                    'acknowledge' => '1',
                ]);
                self::assertFalse($harness['config']['enabled']);
                self::assertStringContainsString('bastion_login_notice=' . $notice, $harness['redirects'][0]);
            }
        }

        public function testEnableRequiresAcknowledgementButDisableAndResetDoNot(): void
        {
            $harness = $this->admin();
            $harness['admin']->handle(['target' => 'login_protection', 'command' => 'enable', '_wpnonce' => 'valid']);
            self::assertFalse($harness['config']['enabled']);
            self::assertStringContainsString('acknowledgement_required', $harness['redirects'][0]);

            $harness['admin']->handle(['target' => 'login_protection', 'command' => 'enable', '_wpnonce' => 'valid', 'acknowledge' => '1']);
            self::assertTrue($harness['config']['enabled']);
            self::assertStringContainsString('bastion_login_notice=enabled', $harness['redirects'][1]);

            $harness['admin']->handle(['target' => 'login_protection', 'command' => 'disable', '_wpnonce' => 'valid']);
            self::assertFalse($harness['config']['enabled']);
            self::assertStringContainsString('bastion_login_notice=disabled', $harness['redirects'][2]);

            $generation = $harness['config']['generation'];
            $harness['admin']->handle(['target' => 'login_protection', 'command' => 'reset', '_wpnonce' => 'valid']);
            self::assertSame($generation + 1, $harness['config']['generation']);
            self::assertStringContainsString('bastion_login_notice=reset', $harness['redirects'][3]);
        }

        public function testRedirectIsDedicatedPrgRouteWithHardeningTabAndFragment(): void
        {
            $harness = $this->admin();
            $harness['admin']->handle([
                'target' => 'login_protection',
                'command' => 'enable',
                '_wpnonce' => 'valid',
                'acknowledge' => '1',
            ]);

            self::assertSame(
                'https://example.test/wp-admin/tools.php?page=bastion-security-wp&tab=hardening&bastion_login_notice=enabled#bastion-login-protection',
                $harness['redirects'][0],
            );
            self::assertSame(['bastion_security_wp_login_protection_enable'], $harness['nonceActions']);
            self::assertSame(1, $harness['terminations']);
        }

        public function testWriteFailuresAndIdempotentOperationsHaveTruthfulNotices(): void
        {
            $failed = $this->admin(writeConfig: false);
            $failed['admin']->handle(['target' => 'login_protection', 'command' => 'enable', '_wpnonce' => 'valid', 'acknowledge' => '1']);
            self::assertStringContainsString('write_failed', $failed['redirects'][0]);

            $unchanged = $this->admin(config: ['enabled' => false, 'generation' => 3]);
            $unchanged['admin']->handle(['target' => 'login_protection', 'command' => 'disable', '_wpnonce' => 'valid']);
            self::assertStringContainsString('unchanged', $unchanged['redirects'][0]);
        }

        public function testUiRendersCompletePolicyPrivacyCoverageMetricsAndAccessibleFormsWithoutJavascript(): void
        {
            $harness = $this->admin(metrics: [
                'failed_attempts' => 12,
                'throttled_attempts' => 3,
                'last_failed_at' => 1000,
                'last_throttled_at' => 1010,
            ]);
            ob_start();
            $harness['admin']->renderToolSection('acknowledgement_required');
            $html = (string) ob_get_clean();

            self::assertStringContainsString('id="bastion-login-protection"', $html);
            self::assertStringContainsString('Login Protection', $html);
            self::assertStringContainsString('Disabled', $html);
            self::assertStringContainsString('5 / 8 / 12', $html);
            self::assertStringContainsString('50 / 100 / 200', $html);
            self::assertStringContainsString('60 seconds / 5 minutes / 15 minutes', $html);
            self::assertStringContainsString('15-minute rolling window', $html);
            self::assertStringContainsString('Failed attempts', $html);
            self::assertStringContainsString('12', $html);
            self::assertStringContainsString('Throttled attempts', $html);
            self::assertStringContainsString('3', $html);
            self::assertStringContainsString('Direct-peer detection is available', $html);
            self::assertStringContainsString('REMOTE_ADDR', $html);
            self::assertStringContainsString('forwarded headers are not trusted', $html);
            self::assertStringContainsString('shared proxy', strtolower($html));
            self::assertStringContainsString('best-effort', strtolower($html));
            self::assertStringContainsString('transient eviction', strtolower($html));
            self::assertStringContainsString('race', strtolower($html));
            self::assertStringContainsString('does not provide WAF or DDoS protection', $html);
            self::assertStringContainsString('wp-login', $html);
            self::assertStringContainsString('wp_authenticate()', $html);
            self::assertStringContainsString('XML-RPC', $html);
            self::assertStringContainsString('REST Application Password', $html);
            self::assertStringContainsString('name="acknowledge" value="1"', $html);
            self::assertStringContainsString('<fieldset>', $html);
            self::assertStringContainsString('<legend', $html);
            self::assertStringContainsString('Reset temporary blocks', $html);
            self::assertStringContainsString('preserves aggregate metrics', $html);
            self::assertStringNotContainsString('192.0.2.10', $html);
            self::assertStringNotContainsString('<script', $html);
            self::assertStringContainsString('notice notice-warning', $html);
        }

        public function testEnabledUiOffersDisableAndResetAndUnavailablePeerNeverLeaksAddress(): void
        {
            $harness = $this->admin(config: ['enabled' => true, 'generation' => 2], address: 'not-an-ip');
            ob_start();
            $harness['admin']->renderToolSection();
            $html = (string) ob_get_clean();

            self::assertStringContainsString('Enabled', $html);
            self::assertStringContainsString('name="command" value="disable"', $html);
            self::assertStringContainsString('name="command" value="reset"', $html);
            self::assertStringContainsString('Direct-peer detection is unavailable', $html);
            self::assertStringNotContainsString('not-an-ip', $html);
        }

        public function testReadmeDocumentsSetupRollbackPrivacyCoverageAndBestEffortBoundaries(): void
        {
            $readme = (string) file_get_contents(dirname(__DIR__, 2) . '/README.md');

            foreach ([
                'twelve Cerrojo diagnostics', 'Login Protection', '5 / 8 / 12', '50 / 100 / 200',
                'HMAC SHA-256', 'Raw usernames', 'wp_authenticate()', 'XML-RPC',
                'REST Application Password', 'REMOTE_ADDR', 'X-Forwarded-For', 'shared proxy',
                'Transient eviction', 'read-modify-write', 'not a WAF', 'DDoS',
                'Reset temporary blocks', 'aggregate metrics', 'only administrator session',
                'remain in the database', 'no uninstall cleanup routine',
            ] as $expected) {
                self::assertStringContainsString($expected, $readme, $expected);
            }
        }

        public function testNoticesUseDedicatedAllowlistAndAccurateSeverities(): void
        {
            $harness = $this->admin();
            foreach ([
                'enabled' => 'success', 'disabled' => 'success', 'reset' => 'success',
                'unchanged' => 'info', 'acknowledgement_required' => 'warning',
                'invalid_request' => 'error', 'invalid_nonce' => 'error',
                'invalid_command' => 'error', 'forbidden' => 'error', 'write_failed' => 'error',
            ] as $notice => $severity) {
                ob_start();
                $harness['admin']->renderToolSection($notice);
                $html = (string) ob_get_clean();
                self::assertStringContainsString('notice notice-' . $severity, $html, $notice);
            }

            ob_start();
            $harness['admin']->renderToolSection('updated');
            self::assertStringNotContainsString('Login Protection was updated', (string) ob_get_clean());
        }

        /** @return array<string, mixed> */
        private function &admin(
            string $method = 'POST',
            bool $authorized = true,
            bool $nonceValid = true,
            bool $writeConfig = true,
            ?array $config = null,
            ?array $metrics = null,
            mixed $address = '192.0.2.10',
        ): array {
            $state = [
                'config' => $config ?? ['enabled' => false, 'generation' => 1],
                'metrics' => $metrics ?? [],
                'redirects' => [],
                'nonceActions' => [],
                'terminations' => 0,
                'transients' => [],
            ];
            $policy = new LoginProtectionPolicy(
                static fn (): int => 1100,
                static function () use (&$state): mixed { return $state['config']; },
                static function (array $value) use (&$state, $writeConfig): bool {
                    if (! $writeConfig) { return false; }
                    $state['config'] = $value;
                    return true;
                },
                static function () use (&$state): mixed { return $state['metrics']; },
                static function (array $value) use (&$state): bool { $state['metrics'] = $value; return true; },
                static function (string $key) use (&$state): mixed { return $state['transients'][$key] ?? false; },
                static function (string $key, array $value, int $expiration) use (&$state): bool { $state['transients'][$key] = $value; return true; },
                static function (string $key) use (&$state): bool { unset($state['transients'][$key]); return true; },
                static fn (): mixed => $address,
                static fn (): string => 'test-secret',
                static fn (string $code, string $message): object => (object) ['code' => $code, 'message' => $message],
                static fn (string $identity): string => trim($identity),
                static fn (mixed $value): bool => false,
            );
            $admin = new LoginProtectionAdmin(
                $policy,
                static fn (string $capability): bool => $authorized && $capability === 'manage_options',
                static function (string $nonce, string $action) use (&$state, $nonceValid): bool {
                    $state['nonceActions'][] = $action;
                    return $nonceValid && $nonce === 'valid';
                },
                static function (string $url) use (&$state): bool { $state['redirects'][] = $url; return true; },
                static fn (string $path): string => 'https://example.test/wp-admin/' . $path,
                static function () use (&$state): void { $state['terminations']++; },
                static fn (): string => $method,
                static fn (int $timestamp): string => gmdate('Y-m-d H:i:s', $timestamp) . ' UTC',
            );
            $state['policy'] = $policy;
            $state['admin'] = $admin;
            $result = [];
            foreach ($state as $key => &$value) {
                $result[$key] =& $value;
            }
            unset($value);

            return $result;
        }
    }
}
