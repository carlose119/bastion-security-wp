<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\RestRouteCatalog;
use BastionSecurityWP\Security\RestRouteControlsPolicy;
use Closure;
use Throwable;

final class RestRouteControlsAdmin
{
    public const POST_ACTION = 'bastion_security_wp_rest_route_controls';
    public const TARGET = 'rest_route_controls';
    private const CAPABILITY = 'manage_options';

    private Closure $currentUserCan;
    private Closure $verifyNonce;
    private Closure $safeRedirect;
    private Closure $adminUrl;
    private Closure $terminate;
    private Closure $requestMethod;

    public function __construct(
        private readonly RestRouteControlsPolicy $policy,
        private readonly RestRouteCatalog $catalog,
        ?callable $currentUserCan = null,
        ?callable $verifyNonce = null,
        ?callable $safeRedirect = null,
        ?callable $adminUrl = null,
        ?callable $terminate = null,
        ?callable $requestMethod = null,
    ) {
        $this->currentUserCan = Closure::fromCallable($currentUserCan ?? static fn (string $capability): bool => \current_user_can($capability));
        $this->verifyNonce = Closure::fromCallable($verifyNonce ?? static fn (string $nonce, string $action): bool => (bool) \wp_verify_nonce($nonce, $action));
        $this->safeRedirect = Closure::fromCallable($safeRedirect ?? static fn (string $url): bool => \wp_safe_redirect($url));
        $this->adminUrl = Closure::fromCallable($adminUrl ?? static fn (string $path): string => \admin_url($path));
        $this->terminate = Closure::fromCallable($terminate ?? static function (): never { exit; });
        $this->requestMethod = Closure::fromCallable($requestMethod ?? static fn (): string => is_string($_SERVER['REQUEST_METHOD'] ?? null)
            ? \sanitize_text_field(\wp_unslash($_SERVER['REQUEST_METHOD']))
            : '');
    }

    public static function nonceAction(string $command): string
    {
        return self::POST_ACTION . ':' . self::TARGET . ':' . $command;
    }

    /** @param array<string,mixed> $post */
    public function handle(array $post): void
    {
        if (strtoupper((string) ($this->requestMethod)()) !== 'POST') {
            $this->redirect('invalid_request');
            return;
        }
        if (! ($this->currentUserCan)(self::CAPABILITY)) {
            $this->redirect('forbidden');
            return;
        }
        if (($post['target'] ?? null) !== self::TARGET || ! is_string($post['command'] ?? null)
            || ! in_array($post['command'], ['save', 'clear'], true)) {
            $this->redirect('invalid_command');
            return;
        }
        $command = $post['command'];
        $nonce = $post['_wpnonce'] ?? null;
        if (! is_string($nonce) || ! ($this->verifyNonce)($nonce, self::nonceAction($command))) {
            $this->redirect('invalid_nonce');
            return;
        }
        if ($command === 'clear') {
            $this->redirect($this->policy->saveRules([]));
            return;
        }

        $state = $this->policy->state();
        $previous = $state['assessed'] ? $state['rules'] : [];
        $catalog = $this->catalog->load($previous);
        if (! $catalog['available']) {
            $this->redirect('catalog_unavailable');
            return;
        }
        $submitted = $post['rules'] ?? [];
        if (! is_array($submitted) || ! array_is_list($submitted)) {
            $this->redirect('invalid_rules');
            return;
        }
        if (count($submitted) > RestRouteControlsPolicy::MAX_RULES) {
            $this->redirect('too_many_rules');
            return;
        }

        $allowed = $this->allowedKeys($catalog, $previous);
        $seenTokens = [];
        $rules = [];
        foreach ($submitted as $token) {
            if (! is_string($token) || isset($seenTokens[$token])) {
                $this->redirect('invalid_rules');
                return;
            }
            $seenTokens[$token] = true;
            $rule = RestRouteCatalog::decodeToken($token);
            if ($rule === null || ! isset($allowed[$rule['method'] . "\0" . $rule['route_pattern']])) {
                $this->redirect('invalid_rules');
                return;
            }
            $rules[] = $rule;
        }
        $canonical = $this->policy->canonicalRules($rules);
        if ($canonical === null) {
            $this->redirect('invalid_rules');
            return;
        }
        if ($this->hasAdditions($canonical, $previous) && ($post['acknowledgement'] ?? null) !== '1') {
            $this->redirect('acknowledgement_required');
            return;
        }
        $this->redirect($this->policy->saveRules($canonical));
    }

    public function handleRequest(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Raw POST is handed to handle(), which verifies capability, target, command, and the operation-bound nonce before mutation.
        $this->handle($_POST);
    }

    public function renderCatalog(string $notice = ''): void
    {
        if (! ($this->currentUserCan)(self::CAPABILITY)) {
            return;
        }
        $state = $this->policy->state();
        $catalog = $this->catalog->load($state['assessed'] ? $state['rules'] : []);
        echo '<section id="bastion-rest-route-controls" class="bastion-tools bastion-rest-route-controls"><h2>' . \esc_html__('REST Route Controls', 'bastion-security') . '</h2>';
        $this->renderNotice($notice);
        if (! $catalog['available']) {
            echo '<div class="notice notice-error inline"><p>' . \esc_html__('The active REST catalog is unavailable. Normal saving is disabled; Clear all remains available for recovery.', 'bastion-security') . '</p></div>';
            $this->renderClearForm();
            echo '</section>';
            return;
        }

        echo '<p>' . \esc_html__('Select registered REST route templates and methods to block for ALL users and integrations. Dynamic templates match every concrete URL accepted by WordPress.', 'bastion-security') . '</p>';
        echo '<div class="bastion-summary-cards">';
        foreach (['namespaces', 'templates', 'pairs', 'selected', 'stale'] as $key) {
            echo '<div class="bastion-summary-card"><span>' . \esc_html($this->summaryLabel($key)) . '</span><strong>' . \esc_html((string) (int) $catalog['counts'][$key]) . '</strong></div>';
        }
        echo '</div>';
        echo '<p>' . \esc_html__('The active REST catalog is loaded only on this tab and while validating a save. Discovery calls rest_get_server()->get_routes(), which initializes the request-local registry, fires rest_api_init/rest_endpoints, and materializes route options. It never invokes endpoint or permission callbacks.', 'bastion-security') . '</p>';
        echo '<p>' . \esc_html__('Namespaces are collapsed for scanning; selected groups open automatically. Use browser Find to locate a route. Routes remain discoverable because this policy does not remove or hide them.', 'bastion-security') . '</p>';

        echo '<form method="post" action="' . \esc_url(($this->adminUrl)('admin-post.php')) . '">';
        $this->hiddenFields('save');
        foreach ($catalog['groups'] as $group) {
            $label = $group['namespace'] === '' ? 'Root / unknown namespace' : $group['namespace'];
            echo '<details class="bastion-rest-namespace"' . ($group['selected'] ? ' open' : '') . '><summary>' . \esc_html($label) . ' (' . count($group['routes']) . ')</summary>';
            foreach ($group['routes'] as $route) {
                echo '<fieldset class="bastion-rest-route"><legend><code>' . \esc_html($route['route_pattern']) . '</code></legend>';
                if ($route['pairs'] === []) {
                    echo '<p>' . \esc_html__('No configurable methods (OPTIONS and unknown methods are omitted).', 'bastion-security') . '</p>';
                }
                foreach ($route['pairs'] as $pair) {
                    $id = 'bastion-rest-' . substr(hash('sha256', $pair['token']), 0, 16);
                    echo '<label for="' . \esc_attr($id) . '"><input id="' . \esc_attr($id) . '" type="checkbox" name="rules[]" value="' . \esc_attr($pair['token']) . '"' . ($pair['selected'] ? ' checked' : '') . '> ' . \esc_html($pair['method']) . ($pair['selected'] ? ' — ' . \esc_html__('Selected', 'bastion-security') : '') . '</label> ';
                }
                echo '</fieldset>';
            }
            echo '</details>';
        }
        if ($catalog['stale'] !== []) {
            echo '<details class="bastion-rest-namespace" open><summary>' . \esc_html__('Stale selected rules', 'bastion-security') . ' (' . count($catalog['stale']) . ')</summary>';
            echo '<p>' . \esc_html__('These saved templates are no longer in the active registry. Keep them checked to retain them or uncheck them to remove them.', 'bastion-security') . '</p>';
            foreach ($catalog['stale'] as $rule) {
                $id = 'bastion-rest-' . substr(hash('sha256', $rule['token']), 0, 16);
                echo '<label for="' . \esc_attr($id) . '"><input id="' . \esc_attr($id) . '" type="checkbox" name="rules[]" value="' . \esc_attr($rule['token']) . '" checked> <code>' . \esc_html($rule['route_pattern']) . '</code> ' . \esc_html($rule['method']) . ' — ' . \esc_html__('Selected (stale)', 'bastion-security') . '</label>';
            }
            echo '</details>';
        }
        echo '<div class="notice notice-warning inline"><p><strong>' . \esc_html__('Compatibility warning:', 'bastion-security') . '</strong> ' . \esc_html__('New selections can break administration, site features, and integrations for every identity. Keep an independent non-REST rollback path.', 'bastion-security') . '</p></div>';
        echo '<p><label><input type="checkbox" name="acknowledgement" value="1"> ' . \esc_html__('I understand the impact of every newly selected method and route template.', 'bastion-security') . '</label></p>';
        echo '<p>' . \esc_html__('A maximum of 100 selected rules is allowed. GET and synthesized HEAD are independent selections. OPTIONS is not configurable. Query strings are outside the matched request route.', 'bastion-security') . '</p>';
        echo '<p>' . \esc_html__('Blocking occurs before permission and endpoint callbacks, after earlier authentication/validation work. Earlier rest_pre_dispatch responses, later filters, direct callback invocation, non-REST paths, and edge caches remain outside this control.', 'bastion-security') . '</p>';
        \submit_button(\esc_html__('Save REST Route Controls', 'bastion-security'));
        echo '</form>';
        $this->renderClearForm();
        echo '</section>';
    }

    private function summaryLabel(string $key): string
    {
        return match ($key) {
            'namespaces' => \__('Namespaces', 'bastion-security'),
            'templates' => \__('Route templates', 'bastion-security'),
            'pairs' => \__('Selectable pairs', 'bastion-security'),
            'selected' => \__('Selected', 'bastion-security'),
            'stale' => \__('Stale', 'bastion-security'),
            default => '',
        };
    }

    /** @param array<string,mixed> $catalog @param list<array{method:string,route_pattern:string}> $previous @return array<string,bool> */
    private function allowedKeys(array $catalog, array $previous): array
    {
        $allowed = [];
        foreach ($catalog['groups'] as $group) {
            foreach ($group['routes'] as $route) {
                foreach ($route['methods'] as $method) {
                    $allowed[$method . "\0" . $route['route_pattern']] = true;
                }
            }
        }
        foreach ($previous as $rule) {
            $allowed[$rule['method'] . "\0" . $rule['route_pattern']] = true;
        }
        return $allowed;
    }

    /** @param list<array{method:string,route_pattern:string}> $rules @param list<array{method:string,route_pattern:string}> $previous */
    private function hasAdditions(array $rules, array $previous): bool
    {
        $old = [];
        foreach ($previous as $rule) {
            $old[$rule['method'] . "\0" . $rule['route_pattern']] = true;
        }
        foreach ($rules as $rule) {
            if (! isset($old[$rule['method'] . "\0" . $rule['route_pattern']])) {
                return true;
            }
        }
        return false;
    }

    private function hiddenFields(string $command): void
    {
        echo '<input type="hidden" name="action" value="' . \esc_attr(self::POST_ACTION) . '">';
        echo '<input type="hidden" name="target" value="' . \esc_attr(self::TARGET) . '">';
        echo '<input type="hidden" name="command" value="' . \esc_attr($command) . '">';
        \wp_nonce_field(self::nonceAction($command));
    }

    private function renderClearForm(): void
    {
        echo '<h3>' . \esc_html__('Emergency rollback', 'bastion-security') . '</h3><p>' . \esc_html__('Clear all saved REST route rules without loading the catalog. Deactivation also stops enforcement but preserves the option.', 'bastion-security') . '</p>';
        echo '<form method="post" action="' . \esc_url(($this->adminUrl)('admin-post.php')) . '">';
        $this->hiddenFields('clear');
        \submit_button(\esc_html__('Clear all REST Route Controls', 'bastion-security'), 'secondary');
        echo '</form>';
    }

    private function renderNotice(string $notice): void
    {
        $message = match ($notice) {
            'updated' => \__('REST Route Controls were updated.', 'bastion-security'),
            'unchanged' => \__('REST Route Controls were already in the requested state.', 'bastion-security'),
            'acknowledgement_required' => \__('A compatibility acknowledgement is required before adding route rules.', 'bastion-security'),
            'invalid_rules' => \__('The selected route rules are invalid. No change was made.', 'bastion-security'),
            'too_many_rules' => \__('More than 100 route rules were submitted. No change was made.', 'bastion-security'),
            'catalog_unavailable' => \__('The active REST catalog is unavailable. No change was made.', 'bastion-security'),
            'invalid_request' => \__('The request must use POST. No change was made.', 'bastion-security'),
            'invalid_nonce' => \__('The request could not be verified. No change was made.', 'bastion-security'),
            'invalid_command' => \__('The requested REST route target or command is not supported. No change was made.', 'bastion-security'),
            'forbidden' => \__('You are not allowed to perform this action. No change was made.', 'bastion-security'),
            'write_failed' => \__('WordPress could not save and verify the REST route rules. The displayed state is authoritative.', 'bastion-security'),
            default => null,
        };
        if ($message === null) {
            return;
        }
        $severity = match ($notice) { 'updated' => 'success', 'unchanged' => 'info', 'acknowledgement_required' => 'warning', default => 'error' };
        echo '<div class="notice notice-' . \esc_attr($severity) . '"><p>' . \esc_html($message) . '</p></div>';
    }

    private function redirect(string $notice): void
    {
        try {
            $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&tab=rest-api&bastion_rest_route_controls_notice=' . rawurlencode($notice) . '#bastion-rest-route-controls');
            ($this->safeRedirect)($url);
            ($this->terminate)();
        } catch (Throwable) {
            // Administrative redirect failures must not expose private errors.
        }
    }
}
