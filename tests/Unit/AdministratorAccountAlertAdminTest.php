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
    use BastionSecurityWP\Admin\AdministratorAccountAlertAdmin;
    use BastionSecurityWP\Security\AdministratorAccountAlertPolicy;
    use PHPUnit\Framework\TestCase;

    final class AdministratorAccountAlertAdminTest extends TestCase
    {
        public function testMutationRequiresPostCapabilityExactTargetCommandAndCommandBoundNonce(): void
        {
            foreach ([
                ['GET', true, 'administrator_account_alerts', 'save', true, 'invalid_request'],
                ['POST', false, 'administrator_account_alerts', 'save', true, 'forbidden'],
                ['POST', true, 'wrong', 'save', true, 'invalid_command'],
                ['POST', true, 'administrator_account_alerts', 'toggle', true, 'invalid_command'],
                ['POST', true, 'administrator_account_alerts', 'save', false, 'invalid_nonce'],
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
                self::assertStringContainsString('bastion_administrator_alert_notice=' . $notice, $harness['redirects'][0]);
            }
        }

        public function testSaveUsesBoundedPolicyOutcomesAndDisablingPreservesRecipients(): void
        {
            $harness = $this->admin();
            $harness['admin']->handle([
                'target' => 'administrator_account_alerts',
                'command' => 'save',
                '_wpnonce' => 'valid',
                'enabled' => '1',
                'recipients' => "First@Example.test\nsecond@example.test",
            ]);
            self::assertSame(['enabled' => true, 'recipients' => ['First@Example.test', 'second@example.test']], $harness['option']);
            self::assertStringContainsString('bastion_administrator_alert_notice=updated', $harness['redirects'][0]);

            $harness['admin']->handle([
                'target' => 'administrator_account_alerts',
                'command' => 'save',
                '_wpnonce' => 'valid',
                'recipients' => 'replacement@example.test',
            ]);
            self::assertSame(['enabled' => false, 'recipients' => ['First@Example.test', 'second@example.test']], $harness['option']);
            self::assertStringContainsString('bastion_administrator_alert_notice=updated', $harness['redirects'][1]);
        }

        public function testMalformedPayloadsAreRejectedWithoutPartialWrites(): void
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
                    'target' => 'administrator_account_alerts',
                    'command' => 'save',
                    '_wpnonce' => 'valid',
                    'enabled' => $case['enabled'],
                    'recipients' => $case['recipients'],
                ]);
                self::assertStringContainsString('bastion_administrator_alert_notice=' . $case['notice'], end($harness['redirects']));
            }
            self::assertSame(['enabled' => false, 'recipients' => []], $harness['option']);
        }

        public function testUiExplainsEventsPrivacyActorMultisiteDeliveryRollbackAndLimitations(): void
        {
            $harness = $this->admin(['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']]);
            ob_start();
            $harness['admin']->renderToolSection('updated');
            $html = (string) ob_get_clean();

            foreach ([
                'Administrator account alerts', 'Administrator role granted', 'Administrator role removed',
                'Administrator account deleted', 'one plain-text email per recipient', 'not disclosed',
                'contextual current user', 'does not prove causality', 'current site', 'remove_user_from_blog',
                'super-admin', 'network deletion', 'does not prove delivery', 'Disabling preserves',
                'does not block or roll back',
            ] as $expected) {
                self::assertStringContainsString($expected, $html, $expected);
            }
            self::assertStringContainsString('name="enabled" value="1" checked', $html);
            self::assertStringContainsString("one@example.test\ntwo@example.test", html_entity_decode($html));
            self::assertStringNotContainsString('<script', $html);
            self::assertStringContainsString('notice notice-success', $html);
        }

        public function testReadmeDocumentsSetupEventsPrivacyMultisiteDeliveryRollbackAndDatabaseScope(): void
        {
            $readme = (string) file_get_contents(dirname(__DIR__, 2) . '/README.md');

            foreach ([
                'seven reversible security tools', 'twelve Bastion diagnostics', 'Administrator Account Alerts',
                'comma or newline', '50 recipients', '254 bytes', 'never falls back to `admin_email`',
                'Administrator role granted', 'Administrator role removed', 'Administrator account deleted',
                '`add_user_role`', '`remove_user_role`', '`deleted_user`', '`set_user_role`', '`user_register`',
                '`delete_user`', 'target user ID', 'contextual current WordPress user ID',
                'does not prove who caused', 'IP addresses', 'user agents', 'one plain-text `wp_mail` call per recipient',
                '`remove_user_from_blog`', '`remove_all_caps`', 'super-admin', 'network deletion',
                'does not call `switch_to_blog`', 'does not reverse account changes',
                '`bastion_security_wp_administrator_account_alerts`', 'no enforcement', 'no AJAX or REST mutation path',
            ] as $expected) {
                self::assertStringContainsString($expected, $readme, $expected);
            }
        }

        public function testRedirectAndNoticesAreDedicatedAllowlistedAndAccuratelyClassified(): void
        {
            $harness = $this->admin();
            $harness['admin']->handle([
                'target' => 'administrator_account_alerts',
                'command' => 'save',
                '_wpnonce' => 'valid',
                'recipients' => '',
            ]);
            self::assertSame(
                'https://example.test/wp-admin/tools.php?page=bastion-security-wp&tab=hardening&bastion_administrator_alert_notice=unchanged#bastion-administrator-account-alerts',
                $harness['redirects'][0],
            );
            self::assertSame(['bastion_security_wp_administrator_account_alerts_save'], $harness['nonceActions']);
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
            $policy = new AdministratorAccountAlertPolicy(
                static function () use (&$state): mixed { return $state['option']; },
                static function (array $value) use (&$state): bool { $state['option'] = $value; return true; },
                static fn (string $email): bool => filter_var($email, FILTER_VALIDATE_EMAIL) !== false,
            );
            $admin = new AdministratorAccountAlertAdmin(
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
