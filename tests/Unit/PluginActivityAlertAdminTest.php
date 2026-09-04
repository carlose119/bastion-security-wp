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
    if (! function_exists('esc_textarea')) {
        function esc_textarea(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
    }
    if (! function_exists('esc_url')) {
        function esc_url(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
    }
    if (! function_exists('wp_nonce_field')) {
        function wp_nonce_field(string $action): void { echo '<input type="hidden" name="_wpnonce" value="nonce-for-' . esc_attr($action) . '">'; }
    }
    if (! function_exists('submit_button')) {
        function submit_button(string $label): void { echo '<button type="submit">' . esc_html($label) . '</button>'; }
    }
}

namespace BastionSecurityWP\Tests\Unit {
    use BastionSecurityWP\Admin\PluginActivityAlertAdmin;
    use BastionSecurityWP\Security\PluginActivityAlertPolicy;
    use PHPUnit\Framework\TestCase;

    final class PluginActivityAlertAdminTest extends TestCase
    {
        public function testMutationRequiresPostCapabilityExactTargetCommandAndOperationBoundNonce(): void
        {
            foreach ([
                ['GET', true, 'plugin_activity_alerts', 'save', true, 'invalid_request'],
                ['POST', false, 'plugin_activity_alerts', 'save', true, 'forbidden'],
                ['POST', true, 'wrong', 'save', true, 'invalid_command'],
                ['POST', true, 'plugin_activity_alerts', 'toggle', true, 'invalid_command'],
                ['POST', true, 'plugin_activity_alerts', 'save', false, 'invalid_nonce'],
            ] as [$method, $authorized, $target, $command, $nonceValid, $notice]) {
                $harness = $this->admin(method: $method, authorized: $authorized, nonceValid: $nonceValid);
                $harness['admin']->handle([
                    'target' => $target,
                    'command' => $command,
                    '_wpnonce' => 'valid',
                    'enabled' => '1',
                    'recipients' => 'alerts@example.test',
                ]);

                self::assertSame(['enabled' => false, 'recipients' => []], $harness['option']);
                self::assertStringContainsString('bastion_plugin_alert_notice=' . $notice, $harness['redirects'][0]);
            }
        }

        public function testSaveEnablesWithValidatedRecipientsAndUncheckedCheckboxDisablesWithoutReplacingRecipients(): void
        {
            $harness = $this->admin();
            $harness['admin']->handle([
                'target' => 'plugin_activity_alerts',
                'command' => 'save',
                '_wpnonce' => 'valid',
                'enabled' => '1',
                'recipients' => "First@Example.test\nsecond@example.test",
            ]);
            self::assertSame([
                'enabled' => true,
                'recipients' => ['First@Example.test', 'second@example.test'],
            ], $harness['option']);
            self::assertStringContainsString('bastion_plugin_alert_notice=enabled', $harness['redirects'][0]);

            $harness['admin']->handle([
                'target' => 'plugin_activity_alerts',
                'command' => 'save',
                '_wpnonce' => 'valid',
                'recipients' => 'replacement@example.test',
            ]);
            self::assertSame([
                'enabled' => false,
                'recipients' => ['First@Example.test', 'second@example.test'],
            ], $harness['option']);
            self::assertStringContainsString('bastion_plugin_alert_notice=disabled', $harness['redirects'][1]);
        }

        public function testInvalidPayloadsAreRejectedAsBoundedNoticesWithoutPartialWrites(): void
        {
            $harness = $this->admin();
            foreach ([
                ['enabled' => ['1'], 'recipients' => 'alerts@example.test', 'notice' => 'invalid_request'],
                ['enabled' => '1', 'recipients' => ['alerts@example.test'], 'notice' => 'invalid_request'],
                ['enabled' => 'unexpected', 'recipients' => 'alerts@example.test', 'notice' => 'invalid_request'],
                ['enabled' => '1', 'recipients' => 'invalid-address', 'notice' => 'invalid_recipients'],
                ['enabled' => '1', 'recipients' => '', 'notice' => 'recipients_required'],
            ] as $case) {
                $harness['admin']->handle([
                    'target' => 'plugin_activity_alerts',
                    'command' => 'save',
                    '_wpnonce' => 'valid',
                    'enabled' => $case['enabled'],
                    'recipients' => $case['recipients'],
                ]);
                self::assertStringContainsString('bastion_plugin_alert_notice=' . $case['notice'], end($harness['redirects']));
            }
            self::assertSame(['enabled' => false, 'recipients' => []], $harness['option']);
        }

        public function testRedirectUsesDedicatedPrgRouteAndTerminates(): void
        {
            $harness = $this->admin();
            $harness['admin']->handle([
                'target' => 'plugin_activity_alerts',
                'command' => 'save',
                '_wpnonce' => 'valid',
                'recipients' => '',
            ]);

            self::assertSame(
                'https://example.test/wp-admin/tools.php?page=bastion-security-wp&tab=hardening&bastion_plugin_alert_notice=unchanged#bastion-plugin-activity-alerts',
                $harness['redirects'][0],
            );
            self::assertSame(['bastion_security_wp_plugin_activity_alerts_save'], $harness['nonceActions']);
            self::assertSame(1, $harness['terminations']);
        }

        public function testUiRendersOptInRecipientsPrivacySemanticsAndRollbackWithoutJavascript(): void
        {
            $harness = $this->admin([
                'enabled' => true,
                'recipients' => ['one@example.test', 'two@example.test'],
            ]);
            ob_start();
            $harness['admin']->renderToolSection('enabled');
            $html = (string) ob_get_clean();

            self::assertStringContainsString('id="bastion-plugin-activity-alerts"', $html);
            self::assertStringContainsString('Plugin activity email alerts', $html);
            self::assertStringContainsString('name="enabled" value="1" checked', $html);
            self::assertStringContainsString('name="recipients"', $html);
            self::assertStringContainsString("one@example.test\ntwo@example.test", html_entity_decode($html));
            self::assertStringContainsString('one email per recipient', $html);
            self::assertStringContainsString('installations and successful activations', $html);
            self::assertStringContainsString('updates are excluded', strtolower($html));
            self::assertStringContainsString('attempt to send', $html);
            self::assertStringContainsString('does not prove delivery', $html);
            self::assertStringContainsString('Disabling preserves', $html);
            self::assertStringNotContainsString('<script', $html);
            self::assertStringContainsString('notice notice-success', $html);
        }

        public function testReadmeDocumentsSetupPrivacyEventsMultisiteRollbackAndLimitations(): void
        {
            $readme = (string) file_get_contents(dirname(__DIR__, 2) . '/README.md');

            foreach ([
                'Plugin activity email alerts', 'comma or newline', 'one plain-text email per recipient',
                'Plugin installations', 'successful plugin activation', 'two separate notifications',
                'Plugin updates are excluded', 'per-site', 'network-wide', 'current site context',
                'no historical events', 'no queue', 'retry', 'delivery receipt', 'audit log',
                'exactly-once', 'wp_mail', 'metadata may be unavailable', 'Cerrojo must be active',
                'Disabling preserves',
            ] as $expected) {
                self::assertStringContainsString($expected, $readme, $expected);
            }
        }

        public function testNoticesAreAllowlistedWithAccurateSeverities(): void
        {
            $harness = $this->admin();
            foreach ([
                'enabled' => 'success', 'disabled' => 'success', 'unchanged' => 'info',
                'invalid_recipients' => 'warning', 'recipients_required' => 'warning',
                'invalid_request' => 'error', 'invalid_nonce' => 'error',
                'invalid_command' => 'error', 'forbidden' => 'error', 'write_failed' => 'error',
            ] as $notice => $severity) {
                ob_start();
                $harness['admin']->renderToolSection($notice);
                self::assertStringContainsString('notice notice-' . $severity, (string) ob_get_clean(), $notice);
            }

            ob_start();
            $harness['admin']->renderToolSection('private-error-details');
            self::assertStringNotContainsString('private-error-details', (string) ob_get_clean());
        }

        /** @return array<string, mixed> */
        private function &admin(
            ?array $option = null,
            string $method = 'POST',
            bool $authorized = true,
            bool $nonceValid = true,
        ): array {
            $state = [
                'option' => $option ?? ['enabled' => false, 'recipients' => []],
                'redirects' => [],
                'nonceActions' => [],
                'terminations' => 0,
            ];
            $policy = new PluginActivityAlertPolicy(
                static function () use (&$state): mixed { return $state['option']; },
                static function (array $value) use (&$state): bool { $state['option'] = $value; return true; },
                static fn (string $email): bool => filter_var($email, FILTER_VALIDATE_EMAIL) !== false,
            );
            $admin = new PluginActivityAlertAdmin(
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
            );
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
