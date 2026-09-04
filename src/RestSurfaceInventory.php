<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use Closure;
use Throwable;

final class RestSurfaceInventory
{
    public const ITEM_LIMIT = 100;

    private Closure $read;
    private Closure $escape;

    public function __construct(?callable $read = null, ?callable $escape = null)
    {
        $this->read = Closure::fromCallable($read ?? self::readRegistry(...));
        $this->escape = Closure::fromCallable($escape ?? static fn (string $value): string => \esc_html($value));
    }

    /** @return array<string, mixed> */
    public function report(): array
    {
        try {
            $registry = ($this->read)();
            if (! is_array($registry) || ! is_array($registry['namespaces'] ?? null) || ! is_array($registry['routes'] ?? null)) {
                return $this->notAssessed();
            }

            $tuples = $this->tuples($registry['namespaces'], $registry['routes']);
            $shown = array_slice($tuples, 0, self::ITEM_LIMIT);
            $items = array_map(function (array $tuple): string {
                return sprintf(
                    '<li><code>%s</code> <code>%s</code> Methods: <code>%s</code></li>',
                    ($this->escape)($tuple[0]),
                    ($this->escape)($tuple[1]),
                    ($this->escape)($tuple[2] === '' ? 'none' : $tuple[2]),
                );
            }, $shown);
            $truncated = count($tuples) - count($shown);

            return $this->result(
                DiagnosticStatus::Good,
                sprintf(
                    '<p>Registered REST namespace, route pattern, and methods only. Showing %d of %d routes; %d truncated.</p><ul>%s</ul>',
                    count($shown),
                    count($tuples),
                    $truncated,
                    implode('', $items),
                ),
                '<p>This read-only inventory makes no security or authorization conclusion.</p>',
            );
        } catch (Throwable) {
            return $this->notAssessed();
        }
    }

    /** @param array<mixed> $namespaces
     *  @param array<mixed> $routes
     *  @return list<array{string, string, string}>
     */
    private function tuples(array $namespaces, array $routes): array
    {
        $tuples = [];
        $namespaces = array_values(array_unique(array_filter($namespaces, 'is_string')));
        sort($namespaces, SORT_STRING);

        foreach ($namespaces as $namespace) {
            if (! is_array($routes[$namespace] ?? null)) {
                continue;
            }

            foreach ($routes[$namespace] as $route => $handlers) {
                if (! is_string($route) || ! is_array($handlers)) {
                    continue;
                }

                $methods = [];
                foreach ($handlers as $handler) {
                    if (! is_array($handler)) {
                        continue;
                    }

                    $registered = $handler['methods'] ?? null;
                    $candidates = is_string($registered) ? explode(',', $registered) : [];
                    if (is_array($registered)) {
                        $candidates = array_merge(
                            array_values(array_filter($registered, 'is_string')),
                            array_keys(array_filter($registered, static fn (mixed $enabled): bool => $enabled === true)),
                        );
                    }
                    foreach ($candidates as $method) {
                        $method = is_string($method) ? strtoupper(trim($method)) : '';
                        if (preg_match('/^[!#$%&\'*+.^_`|~0-9A-Z-]+$/D', $method) === 1) {
                            $methods[$method] = true;
                        }
                    }
                }

                $methods = array_keys($methods);
                sort($methods, SORT_STRING);
                $tuples[] = [$namespace, $route, implode(', ', $methods)];
            }
        }

        sort($tuples, SORT_REGULAR);

        return $tuples;
    }

    /** @return array{namespaces: array<mixed>, routes: array<mixed>}|null */
    private static function readRegistry(): ?array
    {
        global $wp_rest_server;

        if (! class_exists('WP_REST_Server', false) || ! $wp_rest_server instanceof \WP_REST_Server) {
            return null;
        }

        // get_routes() applies rest_endpoints filters and materializes route options; reflect only the raw registry needed here.
        $reflection = new \ReflectionClass($wp_rest_server);
        $read = static function (string $name) use ($reflection, $wp_rest_server): ?array {
            if (! $reflection->hasProperty($name)) {
                return null;
            }

            $property = $reflection->getProperty($name);
            $value = ! $property->isStatic() && $property->isProtected() ? $property->getValue($wp_rest_server) : null;

            return is_array($value) ? $value : null;
        };
        $namespaceMap = $read('namespaces');
        $endpoints = $read('endpoints');
        if ($namespaceMap === null || $endpoints === null) {
            return null;
        }

        $routes = [];
        foreach ($namespaceMap as $namespace => $namespaceRoutes) {
            if (! is_string($namespace) || ! is_array($namespaceRoutes)) {
                return null;
            }

            $routes[$namespace] = [];
            foreach ($namespaceRoutes as $route => $registered) {
                if (! is_string($route) || $registered !== true || ! is_array($endpoints[$route] ?? null)) {
                    return null;
                }

                $routes[$namespace][$route] = [];
                foreach ($endpoints[$route] as $key => $handler) {
                    if (! is_int($key)) {
                        continue;
                    }
                    if (! is_array($handler) || ! array_key_exists('methods', $handler)
                        || (! is_string($handler['methods']) && ! is_array($handler['methods']))) {
                        return null;
                    }
                    foreach (is_array($handler['methods']) ? $handler['methods'] : [] as $method => $enabled) {
                        if (! is_string($enabled) && (! is_string($method) || $enabled !== true)) {
                            return null;
                        }
                    }

                    $routes[$namespace][$route][] = ['methods' => $handler['methods']];
                }
            }
        }

        return ['namespaces' => array_keys($namespaceMap), 'routes' => $routes];
    }

    /** @return array<string, mixed> */
    private function notAssessed(): array
    {
        return $this->result(
            DiagnosticStatus::Recommended,
            '<p>Not assessed. A completed, existing REST registry was unavailable; no security conclusion was made.</p>',
            '<p>Retry Site Health after WordPress has initialized the REST registry.</p>',
        );
    }

    /** @return array<string, mixed> */
    private function result(DiagnosticStatus $status, string $description, string $actions): array
    {
        return [
            'label' => 'Cerrojo: REST surface inventory',
            'status' => $status->value,
            'badge' => ['label' => 'Cerrojo Security Toolkit', 'color' => 'blue'],
            'description' => $description,
            'actions' => $actions,
            'test' => 'bastion_security_wp_rest_surface_inventory',
        ];
    }
}
