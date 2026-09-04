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
}

namespace BastionSecurityWP\Tests\Unit {
    use BastionSecurityWP\Admin\XmlRpcPingbackAdmin;
    use BastionSecurityWP\Security\XmlRpcPingbackPolicy;
    use PHPUnit\Framework\TestCase;
    use RuntimeException;

    final class XmlRpcPingbackAdminTest extends TestCase
    {
        public function testCommandsRequirePostCapabilityExactTargetExactCommandAndCommandBoundNonce(): void
        {
            foreach ([
                ['GET', true, 'xmlrpc_pingback_protection', 'enable', true, 'invalid_request'],
                ['POST', false, 'xmlrpc_pingback_protection', 'enable', true, 'forbidden'],
                ['POST', true, 'wrong', 'enable', true, 'invalid_command'],
                ['POST', true, 'xmlrpc_pingback_protection', 'toggle', true, 'invalid_command'],
                ['POST', true, 'xmlrpc_pingback_protection', 'enable', false, 'invalid_nonce'],
            ] as [$method, $authorized, $target, $command, $nonceValid, $notice]) {
                $harness = $this->admin(method: $method, authorized: $authorized, nonceValid: $nonceValid);
                $harness['admin']->handle(['target' => $target, 'command' => $command, '_wpnonce' => 'valid']);

                self::assertFalse($harness['enabled']);
                self::assertStringContainsString('bastion_xmlrpc_pingback_notice=' . $notice, $harness['redirects'][0]);
            }
        }

        public function testEnableAndDisableUseDedicatedSafePrgRouteWithoutAcknowledgement(): void
        {
            $harness = $this->admin();
            $harness['admin']->handle([
                'target' => 'xmlrpc_pingback_protection',
                'command' => 'enable',
                '_wpnonce' => 'valid',
            ]);

            self::assertTrue($harness['enabled']);
            self::assertSame(['bastion_security_wp_xmlrpc_pingback_protection_enable'], $harness['nonceActions']);
            self::assertSame(
                'https://example.test/wp-admin/tools.php?page=bastion-security-wp&tab=hardening&bastion_xmlrpc_pingback_notice=updated#bastion-xmlrpc-pingback-protection',
                $harness['redirects'][0],
            );
            self::assertSame(1, $harness['terminations']);

            $harness['admin']->handle([
                'target' => 'xmlrpc_pingback_protection',
                'command' => 'disable',
                '_wpnonce' => 'valid',
            ]);
            self::assertFalse($harness['enabled']);
            self::assertSame('bastion_security_wp_xmlrpc_pingback_protection_disable', $harness['nonceActions'][1]);
        }

        public function testWriteFailuresAndIdempotentOperationsHaveBoundedTruthfulNotices(): void
        {
            $unchanged = $this->admin();
            $unchanged['admin']->handle(['target' => 'xmlrpc_pingback_protection', 'command' => 'disable', '_wpnonce' => 'valid']);
            self::assertStringContainsString('bastion_xmlrpc_pingback_notice=unchanged', $unchanged['redirects'][0]);

            $failed = $this->admin(writeSucceeds: false);
            $failed['admin']->handle(['target' => 'xmlrpc_pingback_protection', 'command' => 'enable', '_wpnonce' => 'valid']);
            self::assertStringContainsString('bastion_xmlrpc_pingback_notice=write_failed', $failed['redirects'][0]);
        }

        public function testUiExplainsExactScopeStatusReversibilityAndLimitations(): void
        {
            $harness = $this->admin();
            ob_start();
            $harness['admin']->renderToolSection('write_failed');
            $html = (string) ob_get_clean();

            foreach ([
                'id="bastion-xmlrpc-pingback-protection"',
                'XML-RPC Pingback Protection',
                'Disabled',
                'pingback.ping',
                'pingback.extensions.getPingbacks',
                'authenticated XML-RPC methods remain available',
                'native pingback consumers stop working',
                'per-site',
                'later filter at the same priority can re-add',
                'direct, server, proxy, or CDN headers',
                'does not disable xmlrpc.php',
                'Disabling Cerrojo filtering cannot restore removals made by other components',
                'name="command" value="enable"',
                'notice notice-error',
            ] as $expected) {
                self::assertStringContainsString($expected, $html, $expected);
            }
            self::assertStringNotContainsString('name="acknowledge"', $html);
            self::assertStringNotContainsString('<script', $html);
        }

        public function testEnabledAndUnassessedStatesRenderTruthfullyWithAllowlistedNotices(): void
        {
            $enabled = $this->admin(enabled: '1');
            ob_start();
            $enabled['admin']->renderToolSection('updated');
            $enabledHtml = (string) ob_get_clean();
            self::assertStringContainsString('Enabled', $enabledHtml);
            self::assertStringContainsString('name="command" value="disable"', $enabledHtml);
            self::assertStringContainsString('notice notice-success', $enabledHtml);

            $unassessed = $this->admin(readThrows: true);
            ob_start();
            $unassessed['admin']->renderToolSection('private-message');
            $unassessedHtml = (string) ob_get_clean();
            self::assertStringContainsString('Not assessed', $unassessedHtml);
            self::assertStringNotContainsString('private-reader-detail', $unassessedHtml);
            self::assertStringNotContainsString('private-message', $unassessedHtml);
        }

        /** @return array<string, mixed> */
        private function &admin(
            string $method = 'POST',
            bool $authorized = true,
            bool $nonceValid = true,
            bool $writeSucceeds = true,
            bool|string $enabled = false,
            bool $readThrows = false,
        ): array {
            $state = [
                'enabled' => $enabled,
                'redirects' => [],
                'nonceActions' => [],
                'terminations' => 0,
            ];
            $policy = new XmlRpcPingbackPolicy(
                static function () use (&$state, $readThrows): mixed {
                    if ($readThrows) { throw new RuntimeException('private-reader-detail'); }
                    return $state['enabled'];
                },
                static function (bool $value) use (&$state, $writeSucceeds): bool {
                    if (! $writeSucceeds) { return false; }
                    $state['enabled'] = $value;
                    return true;
                },
            );
            $admin = new XmlRpcPingbackAdmin(
                $policy,
                static fn (string $capability): bool => $authorized && $capability === 'manage_options',
                static function (string $nonce, string $action) use (&$state, $nonceValid): bool {
                    $state['nonceActions'][] = $action;
                    return $nonceValid && $nonce === 'valid';
                },
                static function (string $url) use (&$state): bool { $state['redirects'][] = $url; return true; },
                static fn (string $path): string => 'https://example.test/wp-admin/' . $path,
                static function () use (&$state): void { ++$state['terminations']; },
                static fn (): string => $method,
            );
            $state['policy'] = $policy;
            $state['admin'] = $admin;
            $result = [];
            foreach ($state as $key => &$value) { $result[$key] =& $value; }
            unset($value);

            return $result;
        }
    }
}
