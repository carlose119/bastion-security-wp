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
            self::assertStringContainsString('bastion_notice=updated', $redirects[0]);

            $admin->handle(['command' => 'disable', '_wpnonce' => 'valid']);
            self::assertFalse($baseline);
        }

        public function testRedirectPreservesHeadersTabSharedNoticeAndFragment(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $this->admin($baseline, $groups, $redirects)->handle([
                'command' => 'enable',
                '_wpnonce' => 'valid',
            ]);

            self::assertSame(
                'https://example.test/wp-admin/tools.php?page=bastion-security-wp&tab=headers&bastion_notice=updated#bastion-header-actions',
                $redirects[0],
            );
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
            $this->admin($baseline, $groups, $redirects, authorized: false)->handle($this->selectedPost('enable_selected', ['baseline']));
            $this->admin($baseline, $groups, $redirects, nonceValid: false)->handle($this->groupPost('legacy_cross_domain', 'enable'));

            self::assertFalse($baseline);
            self::assertSame([], $groups);
            self::assertStringContainsString('forbidden', $redirects[0]);
            self::assertStringContainsString('forbidden', $redirects[1]);
            self::assertStringContainsString('invalid_nonce', $redirects[2]);
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

        public function testSelectedBatchRejectsMalformedEmptyUnknownAndDuplicateSelectionsBeforeWrites(): void
        {
            foreach ([null, 'baseline', [], ['unknown'], ['framing', 'framing'], ['framing' => 'framing'], [['framing']]] as $selection) {
                $baseline = false;
                $groups = [];
                $redirects = [];
                $admin = $this->admin($baseline, $groups, $redirects);
                $post = $this->selectedPost('enable_selected', $selection);

                $admin->handle($post);

                self::assertFalse($baseline);
                self::assertSame([], $groups);
                self::assertStringContainsString('invalid_selection', $redirects[0]);
            }
        }

        public function testSelectedBatchUsesFamilyNonceCanonicalizesAndRequiresOneAggregateAcknowledgement(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $verifiedActions = [];
            $admin = $this->admin($baseline, $groups, $redirects, verifiedActions: $verifiedActions);

            $admin->handle($this->selectedPost('enable_selected', ['resource_isolation', 'baseline', 'legacy_cross_domain']));
            self::assertFalse($baseline);
            self::assertSame([], $groups);
            self::assertStringContainsString('acknowledgement_required', $redirects[0]);

            $admin->handle($this->selectedPost('enable_selected', ['resource_isolation', 'baseline', 'legacy_cross_domain'], true));
            self::assertTrue($baseline);
            self::assertSame(['legacy_cross_domain', 'resource_isolation'], $groups);
            self::assertSame([
                SecurityHeadersAdmin::SELECTED_NONCE_ACTION,
                SecurityHeadersAdmin::SELECTED_NONCE_ACTION,
            ], $verifiedActions);
        }

        public function testSelectedBaselineAndLowImpactGroupDoNotRequireAcknowledgement(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $admin = $this->admin($baseline, $groups, $redirects);

            $admin->handle($this->selectedPost('enable_selected', ['legacy_cross_domain', 'baseline']));

            self::assertTrue($baseline);
            self::assertSame(['legacy_cross_domain'], $groups);
            self::assertStringContainsString('updated', $redirects[0]);
        }

        public function testSelectedHstsPreflightBlocksEntireBatchBeforeAnyWrite(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $admin = $this->admin($baseline, $groups, $redirects, hstsReady: false);

            $admin->handle($this->selectedPost('enable_selected', ['baseline', 'legacy_cross_domain', 'hsts_trial'], true));

            self::assertFalse($baseline);
            self::assertSame([], $groups);
            self::assertStringContainsString('hsts_not_ready', $redirects[0]);
        }

        public function testDisableSelectedBypassesAcknowledgementAndHstsReadiness(): void
        {
            $baseline = true;
            $groups = ['framing', 'hsts_trial', 'resource_isolation'];
            $redirects = [];
            $admin = $this->admin($baseline, $groups, $redirects, hstsReady: false);

            $admin->handle($this->selectedPost('disable_selected', ['baseline', 'hsts_trial', 'framing']));

            self::assertFalse($baseline);
            self::assertSame(['resource_isolation'], $groups);
            self::assertStringContainsString('updated', $redirects[0]);
        }

        public function testDisableAllUsesSeparateNonceGroupsFirstAndReportsPartialFailure(): void
        {
            $baseline = true;
            $groups = ['framing'];
            $redirects = [];
            $verifiedActions = [];
            $writeOrder = [];
            $admin = $this->admin(
                $baseline,
                $groups,
                $redirects,
                baselineWriteSucceeds: false,
                groupsWriteSucceeds: true,
                verifiedActions: $verifiedActions,
                writeOrder: $writeOrder,
            );

            $admin->handle([
                'command' => 'disable_all',
                '_wpnonce' => 'valid',
            ]);

            self::assertTrue($baseline);
            self::assertSame([], $groups);
            self::assertSame(['groups', 'baseline'], $writeOrder);
            self::assertSame([SecurityHeadersAdmin::DISABLE_ALL_NONCE_ACTION], $verifiedActions);
            self::assertStringContainsString('partial_failure', $redirects[0]);
        }

        public function testSelectedMixedWriteReportsPartialFailureAndResultingState(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $admin = $this->admin(
                $baseline,
                $groups,
                $redirects,
                baselineWriteSucceeds: false,
                groupsWriteSucceeds: true,
            );

            $admin->handle($this->selectedPost('enable_selected', ['baseline', 'legacy_cross_domain']));

            self::assertFalse($baseline);
            self::assertSame(['legacy_cross_domain'], $groups);
            self::assertStringContainsString('partial_failure', $redirects[0]);
        }

        public function testDisableAllReportsUnchangedAndCompleteWriteFailure(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $this->admin($baseline, $groups, $redirects)->handle(['command' => 'disable_all', '_wpnonce' => 'valid']);
            self::assertStringContainsString('unchanged', $redirects[0]);

            $baseline = true;
            $groups = ['framing'];
            $failing = $this->admin($baseline, $groups, $redirects, writeSucceeds: false);
            $failing->handle(['command' => 'disable_all', '_wpnonce' => 'valid']);
            self::assertTrue($baseline);
            self::assertSame(['framing'], $groups);
            self::assertStringContainsString('write_failed', $redirects[1]);
        }

        public function testSelectedAndDisableAllCommandsRequireTheirOwnOperationNonce(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $verifiedActions = [];
            $admin = $this->admin($baseline, $groups, $redirects, nonceValid: false, verifiedActions: $verifiedActions);

            $admin->handle($this->selectedPost('enable_selected', ['baseline']));
            $admin->handle(['command' => 'disable_all', '_wpnonce' => 'invalid']);

            self::assertSame([
                SecurityHeadersAdmin::SELECTED_NONCE_ACTION,
                SecurityHeadersAdmin::DISABLE_ALL_NONCE_ACTION,
            ], $verifiedActions);
            self::assertFalse($baseline);
            self::assertSame([], $groups);
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
            self::assertSame(6, substr_count($html, 'name="acknowledgement"'));
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

        public function testSectionUsesAccessibleGroupedBatchControlsWithoutEnableAllOrJavaScript(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            ob_start();
            $this->admin($baseline, $groups, $redirects)->renderToolSection();
            $html = (string) ob_get_clean();

            self::assertStringContainsString('<fieldset', $html);
            foreach ([
                'Conservative baseline',
                'Compatibility restrictions',
                'Transport/content upgrade',
                'Cross-origin isolation',
            ] as $legend) {
                self::assertStringContainsString('<legend>' . $legend . '</legend>', $html);
            }
            self::assertStringContainsString('name="groups[]" value="baseline"', $html);
            self::assertSame(8, substr_count($html, 'name="groups[]"'));
            self::assertStringContainsString('name="command" value="enable_selected"', $html);
            self::assertStringContainsString('name="command" value="disable_selected"', $html);
            self::assertStringContainsString('name="command" value="disable_all"', $html);
            self::assertStringContainsString('name="acknowledgement" value="1"', $html);
            self::assertStringNotContainsString('Enable all', $html);
            self::assertStringNotContainsString('<script', $html);
            self::assertStringContainsString('@media (max-width: 782px)', $html);
            self::assertStringContainsString('position: sticky', $html);
        }

        public function testHeaderNoticesUseAccurateNativeSeverities(): void
        {
            $baseline = false;
            $groups = [];
            $redirects = [];
            $admin = $this->admin($baseline, $groups, $redirects);

            foreach ([
                'updated' => 'success',
                'unchanged' => 'info',
                'acknowledgement_required' => 'warning',
                'hsts_not_ready' => 'warning',
                'partial_failure' => 'warning',
                'invalid_selection' => 'error',
                'forbidden' => 'error',
                'write_failed' => 'error',
            ] as $notice => $severity) {
                ob_start();
                $admin->renderToolSection($notice);
                $html = (string) ob_get_clean();
                self::assertStringContainsString('notice notice-' . $severity, $html, $notice);
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

        /** @return array<string, mixed> */
        private function selectedPost(string $command, mixed $selection, bool $acknowledge = false): array
        {
            $post = [
                'command' => $command,
                'groups' => $selection,
                '_wpnonce' => 'valid',
            ];
            if ($acknowledge) {
                $post['acknowledgement'] = '1';
            }

            return $post;
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
            ?bool $baselineWriteSucceeds = null,
            ?bool $groupsWriteSucceeds = null,
            array &$writeOrder = [],
        ): SecurityHeadersAdmin {
            $baselineWriteSucceeds ??= $writeSucceeds;
            $groupsWriteSucceeds ??= $writeSucceeds;
            $policy = new SecurityHeadersPolicy(
                static function () use (&$baseline): bool {
                    return $baseline;
                },
                static function (bool $enabled) use (&$baseline, $baselineWriteSucceeds, &$writeOrder): bool {
                    $writeOrder[] = 'baseline';
                    if ($baselineWriteSucceeds) {
                        $baseline = $enabled;
                    }

                    return $baselineWriteSucceeds;
                },
                static function () use (&$groups): array {
                    return $groups;
                },
                static function (array $enabledGroups) use (&$groups, $groupsWriteSucceeds, &$writeOrder): bool {
                    $writeOrder[] = 'groups';
                    if ($groupsWriteSucceeds) {
                        $groups = $enabledGroups;
                    }

                    return $groupsWriteSucceeds;
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
