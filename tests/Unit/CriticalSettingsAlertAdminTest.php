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
    use BastionSecurityWP\Admin\CriticalSettingsAlertAdmin;
    use BastionSecurityWP\Security\CriticalSettingsAlertPolicy;
    use PHPUnit\Framework\TestCase;

    final class CriticalSettingsAlertAdminTest extends TestCase
    {
        public function testMutationRequiresPostCapabilityExactTargetCommandAndOperationBoundNonce(): void
        {
            foreach ([
                ['GET', true, 'critical_settings_alerts', 'save', true, 'invalid_request'],
                ['POST', false, 'critical_settings_alerts', 'save', true, 'forbidden'],
                ['POST', true, 'wrong', 'save', true, 'invalid_command'],
                ['POST', true, 'critical_settings_alerts', 'toggle', true, 'invalid_command'],
                ['POST', true, 'critical_settings_alerts', 'save', false, 'invalid_nonce'],
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
                self::assertStringContainsString('bastion_critical_settings_alert_notice=' . $notice, $harness['redirects'][0]);
            }
        }

        public function testSaveUsesPolicyOutcomesAndDisablingPreservesRecipients(): void
        {
            $harness = $this->admin();
            $harness['admin']->handle([
                'target' => 'critical_settings_alerts',
                'command' => 'save',
                '_wpnonce' => 'valid',
                'enabled' => '1',
                'recipients' => "First@Example.test\nsecond@example.test",
            ]);
            self::assertSame(['schema_version' => 1, 'enabled' => true, 'recipients' => ['First@Example.test', 'second@example.test']], $harness['option']);
            self::assertStringContainsString('bastion_critical_settings_alert_notice=updated', $harness['redirects'][0]);

            $harness['admin']->handle([
                'target' => 'critical_settings_alerts',
                'command' => 'save',
                '_wpnonce' => 'valid',
                'recipients' => 'replacement@example.test',
            ]);
            self::assertSame(['schema_version' => 1, 'enabled' => false, 'recipients' => ['First@Example.test', 'second@example.test']], $harness['option']);
            self::assertStringContainsString('bastion_critical_settings_alert_notice=updated', $harness['redirects'][1]);
        }

        public function testMalformedPayloadsAndInvalidRecipientsAreRejectedWithoutWrites(): void
        {
            $harness = $this->admin();
            foreach ([
                ['enabled' => ['1'], 'recipients' => 'alerts@example.test', 'notice' => 'invalid_request'],
                ['enabled' => '1', 'recipients' => ['alerts@example.test'], 'notice' => 'invalid_request'],
                ['enabled' => 'unexpected', 'recipients' => 'alerts@example.test', 'notice' => 'invalid_request'],
                ['enabled' => '1', 'recipients' => 'invalid-address', 'notice' => 'invalid_recipients'],
                ['enabled' => '1', 'recipients' => '', 'notice' => 'recipient_required'],
            ] as $case) {
                $harness['admin']->handle([
                    'target' => 'critical_settings_alerts',
                    'command' => 'save',
                    '_wpnonce' => 'valid',
                    'enabled' => $case['enabled'],
                    'recipients' => $case['recipients'],
                ]);
                self::assertStringContainsString('bastion_critical_settings_alert_notice=' . $case['notice'], end($harness['redirects']));
            }
            self::assertSame(['enabled' => false, 'recipients' => []], $harness['option']);
        }

        public function testUiUsesUrlChangeAlertsTitleAndExplainsScopePrivacyAndDeliveryLimits(): void
        {
            $harness = $this->admin(['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']]);
            ob_start();
            $harness['admin']->renderToolSection('updated');
            $html = (string) ob_get_clean();

            foreach ([
                'URL Change Alerts', 'home', 'siteurl', 'successful local updates', 'Old and new URL values',
                'redacted and bounded', 'two settings', 'two notices', 'one plain-text email per recipient',
                'does not prove delivery', 'current site context', 'no cross-site or network fan-out',
                'Disabled by default', 'does not fall back', '50 recipients', 'Disabling preserves',
            ] as $expected) {
                self::assertStringContainsString($expected, $html, $expected);
            }
            self::assertStringContainsString('name="enabled" value="1" checked', $html);
            self::assertStringContainsString("one@example.test\ntwo@example.test", html_entity_decode($html));
            self::assertStringContainsString('name="action" value="bastion_security_wp_critical_settings_alerts"', $html);
            self::assertStringContainsString('name="target" value="critical_settings_alerts"', $html);
            self::assertStringContainsString('nonce-for-bastion_security_wp_critical_settings_alerts_save', $html);
            self::assertStringContainsString('notice notice-success', $html);
            self::assertStringNotContainsString('<script', $html);
        }

        public function testRedirectAndNoticesAreDedicatedAllowlistedAndAccuratelyClassified(): void
        {
            $harness = $this->admin();
            $harness['admin']->handle([
                'target' => 'critical_settings_alerts',
                'command' => 'save',
                '_wpnonce' => 'valid',
                'recipients' => '',
            ]);
            self::assertSame(
                'https://example.test/wp-admin/tools.php?page=bastion-security-wp&tab=hardening&bastion_critical_settings_alert_notice=unchanged#bastion-critical-settings-alerts',
                $harness['redirects'][0],
            );
            self::assertSame(['bastion_security_wp_critical_settings_alerts_save'], $harness['nonceActions']);
            self::assertSame(1, $harness['terminations']);

            foreach ([
                'updated' => 'success', 'unchanged' => 'info', 'invalid_recipients' => 'warning',
                'recipient_required' => 'warning', 'invalid_request' => 'error', 'invalid_nonce' => 'error',
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
            $policy = new CriticalSettingsAlertPolicy(
                static function () use (&$state): mixed { return $state['option']; },
                static function (array $value) use (&$state): bool { $state['option'] = $value; return true; },
                static fn (string $email): bool => filter_var($email, FILTER_VALIDATE_EMAIL) !== false,
            );
            $admin = new CriticalSettingsAlertAdmin(
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
