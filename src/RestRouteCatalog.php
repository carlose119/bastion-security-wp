<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use BastionSecurityWP\Security\RestRouteControlsPolicy;
use Closure;
use Throwable;

final class RestRouteCatalog
{
    private Closure $serverReader;

    public function __construct(?callable $serverReader = null)
    {
        $this->serverReader = Closure::fromCallable($serverReader ?? static fn (): object => \rest_get_server());
    }

    /**
     * Active admin-only discovery. Calling WordPress's REST server intentionally initializes the
     * effective registry, firing rest_api_init/rest_endpoints and materializing route options.
     *
     * @param list<array{method:string,route_pattern:string}> $selectedRules
     * @return array<string,mixed>
     */
    public function load(array $selectedRules): array
    {
        try {
            $server = ($this->serverReader)();
            if (! is_object($server) || ! method_exists($server, 'get_routes')) {
                return $this->unavailable();
            }
            $registry = $server->get_routes();
            if (! is_array($registry)) {
                return $this->unavailable();
            }

            $selected = [];
            foreach ($selectedRules as $rule) {
                if (is_string($rule['method'] ?? null) && is_string($rule['route_pattern'] ?? null)) {
                    $selected[$rule['method'] . "\0" . $rule['route_pattern']] = $rule;
                }
            }

            /** @var array<string,array<string,array<string,bool>>> $grouped */
            $grouped = [];
            $registered = [];
            foreach ($registry as $pattern => $handlers) {
                if (! is_string($pattern) || ! $this->validPattern($pattern)) {
                    continue;
                }
                $methods = $this->methods($handlers);
                $namespace = $this->namespace($server, $pattern);
                $grouped[$namespace][$pattern] = array_fill_keys($methods, true);
                foreach ($methods as $method) {
                    $registered[$method . "\0" . $pattern] = true;
                }
            }

            ksort($grouped, SORT_STRING);
            $groups = [];
            $pairCount = 0;
            foreach ($grouped as $namespace => $routes) {
                ksort($routes, SORT_STRING);
                $routeRows = [];
                $groupSelected = false;
                foreach ($routes as $pattern => $methodMap) {
                    $methods = array_keys($methodMap);
                    $methods = $this->sortMethods($methods);
                    $pairs = [];
                    foreach ($methods as $method) {
                        $key = $method . "\0" . $pattern;
                        $isSelected = isset($selected[$key]);
                        $groupSelected = $groupSelected || $isSelected;
                        $pairs[] = ['method' => $method, 'token' => self::token($method, $pattern), 'selected' => $isSelected];
                    }
                    $pairCount += count($methods);
                    $routeRows[] = ['route_pattern' => $pattern, 'methods' => $methods, 'pairs' => $pairs];
                }
                $groups[] = ['namespace' => $namespace, 'routes' => $routeRows, 'selected' => $groupSelected];
            }

            $stale = [];
            foreach ($selected as $key => $rule) {
                if (! isset($registered[$key])) {
                    $stale[] = $rule + ['token' => self::token($rule['method'], $rule['route_pattern'])];
                }
            }
            usort($stale, self::compareRules(...));

            return [
                'available' => true,
                'groups' => $groups,
                'stale' => $stale,
                'counts' => [
                    'namespaces' => count($groups),
                    'templates' => array_sum(array_map(static fn (array $group): int => count($group['routes']), $groups)),
                    'pairs' => $pairCount,
                    'selected' => count($selected),
                    'stale' => count($stale),
                ],
            ];
        } catch (Throwable) {
            return $this->unavailable();
        }
    }

    public static function token(string $method, string $routePattern): string
    {
        return 'v1.' . rtrim(strtr(base64_encode($method . "\0" . $routePattern), '+/', '-_'), '=');
    }

    /** @return array{method:string,route_pattern:string}|null */
    public static function decodeToken(mixed $token): ?array
    {
        if (! is_string($token) || strlen($token) < 6 || strlen($token) > 2743
            || ! str_starts_with($token, 'v1.') || preg_match('/\Av1\.[A-Za-z0-9_-]+\z/D', $token) !== 1) {
            return null;
        }
        $encoded = substr($token, 3);
        $padding = (4 - strlen($encoded) % 4) % 4;
        $decoded = base64_decode(strtr($encoded, '-_', '+/') . str_repeat('=', $padding), true);
        if (! is_string($decoded) || substr_count($decoded, "\0") !== 1) {
            return null;
        }
        [$method, $pattern] = explode("\0", $decoded, 2);
        $rule = ['method' => $method, 'route_pattern' => $pattern];
        $canonical = (new RestRouteControlsPolicy())->canonicalRules([$rule]);
        if ($canonical !== [$rule] || self::token($method, $pattern) !== $token) {
            return null;
        }
        return $rule;
    }

    /** @return list<string> */
    private function methods(mixed $handlers): array
    {
        if (! is_array($handlers)) {
            return [];
        }
        $handlerList = array_is_list($handlers) ? $handlers : [$handlers];
        $found = [];
        foreach ($handlerList as $handler) {
            if (! is_array($handler) || ! array_key_exists('methods', $handler)) {
                continue;
            }
            $methods = $handler['methods'];
            if (is_string($methods)) {
                $methods = preg_split('/\s*,\s*/', $methods) ?: [];
                foreach ($methods as $method) {
                    $method = strtoupper($method);
                    if (in_array($method, RestRouteControlsPolicy::METHODS, true)) {
                        $found[$method] = true;
                    }
                }
            } elseif (is_array($methods)) {
                foreach ($methods as $method => $enabled) {
                    if (! is_string($method) || ! $enabled) {
                        continue;
                    }
                    $method = strtoupper($method);
                    if (in_array($method, RestRouteControlsPolicy::METHODS, true)) {
                        $found[$method] = true;
                    }
                }
            }
        }
        if (isset($found['GET'])) {
            $found['HEAD'] = true;
        }
        return $this->sortMethods(array_keys($found));
    }

    private function namespace(object $server, string $pattern): string
    {
        if (method_exists($server, 'get_route_options')) {
            try {
                $options = $server->get_route_options($pattern);
                if (is_array($options) && is_string($options['namespace'] ?? null)) {
                    return $options['namespace'];
                }
            } catch (Throwable) {
                // Keep the route in the safe unknown/root group.
            }
        }
        return '';
    }

    /** @param list<string> $methods @return list<string> */
    private function sortMethods(array $methods): array
    {
        $order = array_flip(RestRouteControlsPolicy::METHODS);
        usort($methods, static fn (string $a, string $b): int => $order[$a] <=> $order[$b]);
        return $methods;
    }

    private function validPattern(string $pattern): bool
    {
        return (new RestRouteControlsPolicy())->canonicalRules([['method' => 'GET', 'route_pattern' => $pattern]]) !== null;
    }

    /** @param array{method:string,route_pattern:string} $a @param array{method:string,route_pattern:string} $b */
    private static function compareRules(array $a, array $b): int
    {
        $route = strcmp($a['route_pattern'], $b['route_pattern']);
        if ($route !== 0) {
            return $route;
        }
        $order = array_flip(RestRouteControlsPolicy::METHODS);
        return $order[$a['method']] <=> $order[$b['method']];
    }

    /** @return array<string,mixed> */
    private function unavailable(): array
    {
        return ['available' => false, 'groups' => [], 'stale' => [], 'counts' => ['namespaces' => 0, 'templates' => 0, 'pairs' => 0, 'selected' => 0, 'stale' => 0]];
    }
}
