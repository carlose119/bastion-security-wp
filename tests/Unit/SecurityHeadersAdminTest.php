<?php

declare(strict_types=1);

namespace {
    if (! function_exists('esc_html__')) {
        function esc_html__(string $value, string $domain): string
        {
            return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
    }

    if (! function_exists('esc_html')) {
        function esc_html(string $value): string
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
        public function testLegacyBaselineFormRemainsBackwardCompatible(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $admin = $this->admin($baseline, $groups, $redirects);

            $admin->handle(['command' => 'enable', '_wpnonce' => 'valid']);
            self::assertTrue($baseline);
            self::assertStringContainsString('bastion_security_headers_notice=updated', $redirects[0]);

            $admin->handle(['command' => 'disable', '_wpnonce' => 'valid']);
            self::assertFalse($baseline);
        }

        public function testGroupTargetUsesStrictAllowlistsAndTargetBoundNonce(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $verifiedActions = [];
            $admin = $this->admin($baseline, $groups, $redirects, verifiedActions: $verifiedActions);

            $admin->handle($this->groupPost('legacy_cross_domain', 'enable'));
            self::assertSame(['legacy_cross_domain'], $groups);
            self::assertSame(SecurityHeadersAdmin::NONCE_ACTION . ':group:legacy_cross_domain', $verifiedActions[0]);

            $admin->handle(['target' => 'other', 'group' => 'framing', 'command' => 'enable', '_wpnonce' => 'valid']);
            $admin->handle($this->groupPost('unknown', 'enable'));
            $admin->handle(['target' => 'group', 'group' => 'framing', 'command' => 'toggle', '_wpnonce' => 'valid']);

            self::assertSame(['legacy_cross_domain'], $groups);
            self::assertStringContainsString('invalid_target', $redirects[1]);
            self::assertStringContainsString('invalid_group', $redirects[2]);
            self::assertStringContainsString('invalid_command', $redirects[3]);
        }

        public function testCapabilityAndNonceFailuresNeverMutate(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];

            $this->admin($baseline, $groups, $redirects, authorized: false)->handle($this->groupPost('legacy_cross_domain', 'enable'));
            $this->admin($baseline, $groups, $redirects, nonceValid: false)->handle($this->groupPost('legacy_cross_domain', 'enable'));

            self::assertSame([], $groups);
            self::assertStringContainsString('forbidden', $redirects[0]);
            self::assertStringContainsString('invalid_nonce', $redirects[1]);
        }

        public function testAcknowledgementIsRequiredOnlyWhenEnablingHighImpactGroups(): void
        {
            $baseline = false;
            $groups = ['framing'];
            $redirects = [];
            $admin = $this->admin($baseline, $groups, $redirects);

            $admin->handle($this->groupPost('framing', 'disable'));
            self::assertSame([], $groups);

            $admin->handle($this->groupPost('legacy_cross_domain', 'enable'));
            self::assertSame(['legacy_cross_domain'], $groups);

            $admin->handle($this->groupPost('browser_capabilities', 'enable'));
            self::assertSame(['legacy_cross_domain'], $groups);
            self::assertStringContainsString('acknowledgement_required', $redirects[2]);

            $admin->handle($this->groupPost('browser_capabilities', 'enable', true));
            self::assertSame(['browser_capabilities', 'legacy_cross_domain'], $groups);
        }

        public function testEveryHighImpactGroupRequiresAcknowledgementWhileLegacyGroupDoesNot(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $admin = $this->admin($baseline, $groups, $redirects);

            foreach (['framing', 'browser_capabilities', 'mixed_content_upgrade', 'hsts_trial', 'opener_isolation', 'resource_isolation'] as $group) {
                $admin->handle($this->groupPost($group, 'enable'));
            }

            self::assertSame([], $groups);
            foreach (array_slice($redirects, 0, 6) as $redirect) {
                self::assertStringContainsString('acknowledgement_required', $redirect);
            }

            $admin->handle($this->groupPost('legacy_cross_domain', 'enable'));
            self::assertSame(['legacy_cross_domain'], $groups);
        }

        public function testHstsReadinessBlocksEnableButNeverBlocksDisable(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $admin = $this->admin($baseline, $groups, $redirects, hstsReady: false);

            $admin->handle($this->groupPost('hsts_trial', 'enable', true));
            self::assertSame([], $groups);
            self::assertStringContainsString('hsts_not_ready', $redirects[0]);

            $groups = ['hsts_trial'];
            $admin->handle($this->groupPost('hsts_trial', 'disable'));
            self::assertSame([], $groups);
        }

        public function testHstsReadinessAllowsAcknowledgedEnableWhenTheInjectedCheckPasses(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $admin = $this->admin($baseline, $groups, $redirects, hstsReady: true);

            $admin->handle($this->groupPost('hsts_trial', 'enable', true));

            self::assertSame(['hsts_trial'], $groups);
            self::assertStringContainsString('updated', $redirects[0]);
        }

        public function testGroupWritesAreIdempotentAndFailuresAreReported(): void
        {
            $baseline = false;
            $groups = ['legacy_cross_domain'];
            $redirects = [];
            $admin = $this->admin($baseline, $groups, $redirects);

            $admin->handle($this->groupPost('legacy_cross_domain', 'enable'));
            self::assertStringContainsString('unchanged', $redirects[0]);

            $failing = $this->admin($baseline, $groups, $redirects, writeSucceeds: false);
            $failing->handle($this->groupPost('resource_isolation', 'enable', true));
            self::assertSame(['legacy_cross_domain'], $groups);
            self::assertStringContainsString('write_failed', $redirects[1]);
        }

        public function testSectionRendersExactValuesStatesRisksCoverageFormsAndNotices(): void
        {
            $baseline = false;
            $groups = ['legacy_cross_domain', 'hsts_trial'];
            $redirects = [];
            $admin = $this->admin($baseline, $groups, $redirects);

            ob_start();
            $admin->renderToolSection('hsts_not_ready');
            $html = (string) ob_get_clean();

            foreach ([
                'X-Content-Type-Options: nosniff',
                'Referrer-Policy: strict-origin-when-cross-origin',
                'X-Frame-Options: SAMEORIGIN',
                'Permissions-Policy: camera=(), microphone=(), geolocation=()',
                'X-Permitted-Cross-Domain-Policies: none',
                'Content-Security-Policy: upgrade-insecure-requests;',
                'Strict-Transport-Security: max-age=86400',
                'Cross-Origin-Opener-Policy: same-origin-allow-popups',
                'Cross-Origin-Resource-Policy: same-site',
            ] as $policy) {
                self::assertStringContainsString($policy, $html);
            }
            self::assertSame(8, substr_count($html, 'name="target"'));
            self::assertSame(7, substr_count($html, 'name="group"'));
            self::assertStringContainsString('nonce-for-' . SecurityHeadersAdmin::NONCE_ACTION . ':group:framing', $html);
            self::assertStringContainsString('Enabled', $html);
            self::assertStringContainsString('Disabled', $html);
            self::assertSame(5, substr_count($html, 'name="acknowledgement"'));
            self::assertStringContainsString('current request, home URL, and site URL must all use HTTPS', $html);
            self::assertStringContainsString('browsers may retain the 24-hour policy until it expires', $html);
            self::assertStringContainsString('safe-intent policy set', $html);
            self::assertStringContainsString('not byte-for-byte parity', $html);
            self::assertSame(7, substr_count($html, 'Coverage: this group is emitted only on eligible wp_headers front-end responses'));
            self::assertStringContainsString('standard front-end responses', $html);
            self::assertStringContainsString('wp-admin', $html);
            self::assertStringContainsString('CDN', $html);
            self::assertStringContainsString('could not confirm HSTS readiness', $html);

            $visibleText = strip_tags($html);
            foreach ([
                'Access-Control-Allow-*',
                'explicit allowed-origin contract',
                'unsafe-none',
                'cross-origin',
                'no meaningful isolation',
                'includeSubDomains',
                'preload',
                'trial mode',
                'Report-Only',
                'configured reporting endpoint',
                'deprecated headers',
                'safe intent rather than byte parity',
            ] as $omissionDisclosure) {
                self::assertStringContainsString($omissionDisclosure, $visibleText);
            }
        }

        public function testTechnicalTokensAreEscapedSeparatelyFromLiteralTranslationSourceStrings(): void
        {
            $source = file_get_contents(__DIR__ . '/../../src/Admin/SecurityHeadersAdmin.php');
            self::assertIsString($source);

            $translationCallWithDynamicSource = '/\\\\(?:__|_e|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\\s*\\(\\s*+([^\'\"])/';
            self::assertSame(
                0,
                preg_match_all($translationCallWithDynamicSource, $source, $matches),
                'Translation function source strings must be static literals; found: ' . implode(', ', $matches[0] ?? []),
            );
        }

        public function testTechnicalTokensAreNotEmbeddedInTranslationStringsAndAreEscapedSeparately(): void
        {
            $source = (string) file_get_contents(__DIR__ . '/../../src/Admin/SecurityHeadersAdmin.php');

            foreach ([
                'X-Content-Type-Options',
                'nosniff',
                'Referrer-Policy',
                'strict-origin-when-cross-origin',
                'Access-Control-Allow-*',
                'unsafe-none',
                'cross-origin',
                'includeSubDomains',
                'preload',
                'Report-Only',
            ] as $technicalToken) {
                self::assertStringContainsString(
                    "\\esc_html('" . $technicalToken . "')",
                    $source,
                    $technicalToken . ' must be escaped independently.',
                );
                self::assertDoesNotMatchRegularExpression(
                    '/\\\\(?:__|esc_html__)\\(\'[^\']*' . preg_quote($technicalToken, '/') . '/',
                    $source,
                    $technicalToken . ' must not be embedded in a translation source string.',
                );
            }

            self::assertStringContainsString("\\esc_html(\$definition['header']) . ': ' . \\esc_html(\$definition['value'])", $source);
            self::assertStringNotContainsString('<code>X-Content-Type-Options: nosniff</code>', $source);
        }

        /** @return array<string, string> */
        private function groupPost(string $group, string $command, bool $acknowledge = false): array
        {
            $post = [
                'target' => 'group',
                'group' => $group,
                'command' => $command,
                '_wpnonce' => 'valid',
            ];
            if ($acknowledge) {
                $post['acknowledgement'] = '1';
            }

            return $post;
        }

        /** @param list<string> $groups
         *  @param list<string> $redirects
         *  @param list<string> $verifiedActions
         */
        private function admin(
            bool &$baseline,
            array &$groups,
            array &$redirects,
            bool $authorized = true,
            bool $nonceValid = true,
            bool $writeSucceeds = true,
            bool $hstsReady = true,
            array &$verifiedActions = [],
        ): SecurityHeadersAdmin {
            $policy = new SecurityHeadersPolicy(
                static function () use (&$baseline): bool {
                    return $baseline;
                },
                static function (bool $enabled) use (&$baseline, $writeSucceeds): bool {
                    if ($writeSucceeds) {
                        $baseline = $enabled;
                    }

                    return $writeSucceeds;
                },
                static function () use (&$groups): array {
                    return $groups;
                },
                static function (array $enabledGroups) use (&$groups, $writeSucceeds): bool {
                    if ($writeSucceeds) {
                        $groups = $enabledGroups;
                    }

                    return $writeSucceeds;
                },
                static fn (): bool => true,
            );

            return new SecurityHeadersAdmin(
                $policy,
                static fn (string $capability): bool => $authorized && $capability === 'manage_options',
                static function (string $nonce, string $action) use ($nonceValid, &$verifiedActions): bool {
                    $verifiedActions[] = $action;

                    return $nonceValid && $nonce === 'valid';
                },
                static function (string $url) use (&$redirects): bool {
                    $redirects[] = $url;

                    return true;
                },
                static fn (string $path): string => 'https://example.test/wp-admin/' . $path,
                static function (): void {},
                static fn (): bool => $hstsReady,
            );
        }
    }
}
