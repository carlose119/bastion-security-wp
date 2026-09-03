<?php

declare(strict_types=1);

namespace {
    if (! function_exists('esc_html')) { function esc_html(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); } }
    if (! function_exists('esc_html__')) { function esc_html__(string $v, string $d): string { return esc_html($v); } }
    if (! function_exists('esc_attr')) { function esc_attr(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); } }
    if (! function_exists('esc_url')) { function esc_url(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); } }
    if (! function_exists('wp_nonce_field')) { function wp_nonce_field(string $a): void { echo '<input name="_wpnonce" value="nonce-' . esc_attr($a) . '">'; } }
    if (! function_exists('submit_button')) { function submit_button(string $l, string $t = 'primary'): void { echo '<button type="submit" class="button button-' . esc_attr($t) . '">' . esc_html($l) . '</button>'; } }
}

namespace BastionSecurityWP\Tests\Unit {
    use BastionSecurityWP\Admin\RestRouteControlsAdmin;
    use BastionSecurityWP\RestRouteCatalog;
    use BastionSecurityWP\Security\RestRouteControlsPolicy;
    use PHPUnit\Framework\TestCase;
    use RuntimeException;

    final class RestRouteControlsAdminTest extends TestCase
    {
        public function testReadmeDocumentsCatalogIndependentClearAllRollback(): void
        {
            $readme = (string) file_get_contents(dirname(__DIR__, 2) . '/README.md');

            self::assertStringContainsString('**Tools > Bastion Security > REST API**', $readme);
            self::assertStringContainsString('**Clear all REST Route Controls**', $readme);
            self::assertStringContainsString('non-REST admin-post', $readme);
            self::assertStringContainsString('does not load the catalog', $readme);
            self::assertStringContainsString('stops blocking configured routes on later requests', $readme);
            self::assertStringContainsString('cannot restore behavior blocked by another component', $readme);
            self::assertStringNotContainsString('clear the rules textarea', $readme);
        }

        public function testSaveAndClearUseOperationBoundSecurityAndClearNeverLoadsCatalog(): void
        {
            foreach ([
                ['GET', true, 'save', true, 'invalid_request'],
                ['POST', false, 'save', true, 'forbidden'],
                ['POST', true, 'other', true, 'invalid_command'],
                ['POST', true, 'save', false, 'invalid_nonce'],
            ] as [$method, $allowed, $command, $nonce, $notice]) {
                $h = $this->harness(method: $method, authorized: $allowed, nonceValid: $nonce);
                $h['admin']->handle($this->post($command, []));
                self::assertSame(0, $h['writes']);
                self::assertStringContainsString($notice, $h['redirects'][0]);
            }

            $clear = $this->harness([['method' => 'GET', 'route_pattern' => '/a']]);
            $clear['admin']->handle($this->post('clear', [], nonce: 'clear'));
            self::assertSame([], $clear['stored']['rules']);
            self::assertSame(0, $clear['catalogLoads']);
            self::assertSame([RestRouteControlsAdmin::nonceAction('clear')], $clear['nonceActions']);
        }

        public function testSaveAcceptsOnlyCanonicalUniqueTokensFromCurrentOrPreviouslyStoredStaleRules(): void
        {
            $fresh = RestRouteCatalog::token('GET', '/wp/v2/posts/(?P<id>[\\d]+)');
            $stale = RestRouteCatalog::token('DELETE', '/gone/v1/item');
            $h = $this->harness([['method' => 'DELETE', 'route_pattern' => '/gone/v1/item']]);
            $h['admin']->handle($this->post('save', [$fresh, $stale], true));
            self::assertSame([
                ['method' => 'DELETE', 'route_pattern' => '/gone/v1/item'],
                ['method' => 'GET', 'route_pattern' => '/wp/v2/posts/(?P<id>[\\d]+)'],
            ], $h['stored']['rules']);

            foreach ([
                ['rules' => [$fresh, $fresh], 'notice' => 'invalid_rules'],
                ['rules' => ['v1.bad='], 'notice' => 'invalid_rules'],
                ['rules' => [RestRouteCatalog::token('POST', '/unknown')], 'notice' => 'invalid_rules'],
                ['rules' => array_fill(0, 101, $fresh), 'notice' => 'too_many_rules'],
            ] as $case) {
                $bad = $this->harness();
                $bad['admin']->handle($this->post('save', $case['rules'], true));
                self::assertSame(0, $bad['writes']);
                self::assertStringContainsString($case['notice'], $bad['redirects'][0]);
            }
        }

        public function testAcknowledgementIsOnlyRequiredForAdditionsAndMalformedPriorCountsEmpty(): void
        {
            $token = RestRouteCatalog::token('GET', '/wp/v2/posts/(?P<id>[\\d]+)');
            $addition = $this->harness();
            $addition['admin']->handle($this->post('save', [$token]));
            self::assertSame(0, $addition['writes']);
            self::assertStringContainsString('acknowledgement_required', $addition['redirects'][0]);

            $same = $this->harness([['method' => 'GET', 'route_pattern' => '/wp/v2/posts/(?P<id>[\\d]+)']]);
            $same['admin']->handle($this->post('save', [$token]));
            self::assertStringContainsString('unchanged', $same['redirects'][0]);

            $removal = $this->harness([['method' => 'GET', 'route_pattern' => '/wp/v2/posts/(?P<id>[\\d]+)']]);
            $removal['admin']->handle($this->post('save', []));
            self::assertSame([], $removal['stored']['rules']);

            $malformed = $this->harness(readThrows: true);
            $malformed['admin']->handle($this->post('save', [$token]));
            self::assertStringContainsString('acknowledgement_required', $malformed['redirects'][0]);
        }

        public function testCatalogUnavailableBlocksSaveButNotClear(): void
        {
            $h = $this->harness(catalogAvailable: false);
            $h['admin']->handle($this->post('save', []));
            self::assertStringContainsString('catalog_unavailable', $h['redirects'][0]);
            self::assertSame(0, $h['writes']);
        }

        public function testUiRendersCatalogCheckboxesCountsSelectedOpenGroupsStaleAndRollback(): void
        {
            $h = $this->harness([
                ['method' => 'DELETE', 'route_pattern' => '/gone/v1/item'],
                ['method' => 'GET', 'route_pattern' => '/wp/v2/posts/(?P<id>[\\d]+)'],
            ]);
            ob_start();
            $h['admin']->renderCatalog('updated');
            $html = (string) ob_get_clean();
            foreach ([
                'REST Route Controls', 'Namespaces', 'Route templates', 'Selectable pairs', 'Selected', 'Stale',
                ' open><summary>', 'name="rules[]"', 'type="checkbox"', 'checked', '/wp/v2/posts/',
                'No configurable methods', 'Stale selected rules', 'GET and synthesized HEAD', 'OPTIONS', 'ALL users',
                'remain discoverable', 'browser Find', '100', 'active REST catalog', 'name="command" value="clear"',
                'notice notice-success',
            ] as $expected) {
                self::assertStringContainsStringIgnoringCase($expected, $html, $expected);
            }
            self::assertStringNotContainsString('<textarea', $html);
            self::assertStringContainsString('(?P&lt;id&gt;[\\d]+)', $html);
        }

        /** @return array<string, mixed> */
        private function post(string $command, array $rules, bool $ack = false, string $nonce = 'save'): array
        {
            return ['target' => RestRouteControlsAdmin::TARGET, 'command' => $command, '_wpnonce' => $nonce, 'rules' => $rules, 'acknowledgement' => $ack ? '1' : ''];
        }

        /** @param list<array{method:string,route_pattern:string}> $rules */
        private function &harness(
            array $rules = [], string $method = 'POST', bool $authorized = true, bool $nonceValid = true,
            bool $catalogAvailable = true, bool $readThrows = false,
        ): array {
            $state = ['stored' => ['schema_version' => 1, 'rules' => $rules], 'writes' => 0, 'redirects' => [], 'nonceActions' => [], 'catalogLoads' => 0];
            $policy = new RestRouteControlsPolicy(
                static function () use (&$state, $readThrows): mixed { if ($readThrows) { throw new RuntimeException('private'); } return $state['stored']; },
                static function (array $value) use (&$state): bool { ++$state['writes']; $state['stored'] = $value; return true; },
            );
            $catalog = new RestRouteCatalog(static function () use (&$state, $catalogAvailable): object {
                ++$state['catalogLoads'];
                if (! $catalogAvailable) { throw new RuntimeException('private'); }
                return new class {
                    public function get_routes(): array { return [
                        '/wp/v2/posts/(?P<id>[\\d]+)' => [['methods' => ['GET' => true, 'POST' => true]]],
                        '/wp/v2/options-only' => [['methods' => ['OPTIONS' => true]]],
                    ]; }
                    public function get_route_options(string $route): array { return ['namespace' => 'wp/v2']; }
                };
            });
            $admin = new RestRouteControlsAdmin(
                $policy, $catalog,
                static fn (string $cap): bool => $authorized && $cap === 'manage_options',
                static function (string $nonce, string $action) use (&$state, $nonceValid): bool { $state['nonceActions'][] = $action; return $nonceValid && $nonce === (str_ends_with($action, ':clear') ? 'clear' : 'save'); },
                static function (string $url) use (&$state): bool { $state['redirects'][] = $url; return true; },
                static fn (string $path): string => 'https://example.test/wp-admin/' . $path,
                static function (): void {},
                static fn (): string => $method,
            );
            $state['admin'] = $admin;
            $result = [];
            foreach ($state as $key => &$value) { $result[$key] =& $value; }
            unset($value);
            return $result;
        }
    }
}
