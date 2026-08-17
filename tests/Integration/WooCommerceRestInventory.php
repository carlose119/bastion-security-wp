<?php

declare(strict_types=1);

function check(bool $condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException($message);
    }
}

function valueShape(mixed $value): mixed
{
    if (is_array($value)) {
        $shape = [];
        foreach ($value as $key => $item) {
            $shape[$key] = valueShape($item);
        }

        return $shape;
    }

    if (is_object($value)) {
        return $value::class . '#' . spl_object_id($value);
    }

    return $value;
}

/** @return list<string> */
function methodsFor(array $handlers): array
{
    $methods = [];
    foreach ($handlers as $handler) {
        if (! is_array($handler) || ! isset($handler['methods'])) {
            continue;
        }
        $registered = is_array($handler['methods'])
            ? array_merge(array_keys(array_filter($handler['methods'])), array_values($handler['methods']))
            : explode(',', (string) $handler['methods']);
        foreach ($registered as $method) {
            if (is_string($method) && preg_match('/^[A-Z]+$/', trim($method))) {
                $methods[] = trim($method);
            }
        }
    }
    $methods = array_values(array_unique($methods));
    sort($methods);

    return $methods;
}

/** @return array<string, mixed> */
function dispatchSnapshot(WP_REST_Server $server, string $route, array &$calls): array
{
    $before = $calls;
    $response = $server->dispatch(new WP_REST_Request('GET', $route));
    $headers = array_intersect_key($response->get_headers(), array_flip(['Allow', 'X-WP-Total', 'X-WP-TotalPages']));
    ksort($headers);

    return [
        'status' => $response->get_status(),
        'body' => wp_json_encode($response->get_data(), JSON_UNESCAPED_SLASHES),
        'headers' => $headers,
        'permission_callbacks' => $calls['permission'] - $before['permission'],
        'route_callbacks' => $calls['callback'] - $before['callback'],
    ];
}

/** @return array<string, mixed> */
function stateSnapshot(WP_REST_Server $server, ReflectionProperty $endpoints): array
{
    global $wpdb;

    $routes = $server->get_routes();
    $options = [];
    foreach (array_keys($routes) as $route) {
        $options[$route] = valueShape($server->get_route_options($route));
    }

    return [
        'server' => spl_object_id($server),
        'user' => get_current_user_id(),
        'buffer_level' => ob_get_level(),
        'buffer' => ob_get_contents(),
        'queries' => $wpdb->num_queries,
        'namespaces' => $server->get_namespaces(),
        'endpoints' => hash('sha256', serialize(valueShape($endpoints->getValue($server)))),
        'route_options' => hash('sha256', serialize($options)),
        'handlers' => array_sum(array_map(static fn (array $handlers): int => count(array_filter(array_keys($handlers), 'is_int')), $routes)),
        'wc_session' => WC()->session->get_session_data(),
        'cart' => WC()->cart->get_cart_contents(),
        'cart_hash' => WC()->cart->get_cart_hash(),
        'cart_totals' => WC()->cart->get_totals(),
    ];
}

$root = realpath($argv[1] ?? '');
check($root !== false && is_file($root . '/wp-load.php'), 'Invalid WordPress fixture root.');
$_SERVER['HTTP_HOST'] = 'bastion.test';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/';
define('WP_USE_THEMES', false);
require $root . '/wp-load.php';

require_once ABSPATH . 'wp-admin/includes/plugin.php';
foreach (['woocommerce/woocommerce.php', 'bastion-security-wp/bastion-security-wp.php'] as $plugin) {
    check(is_plugin_active($plugin), 'Required plugin is not active: ' . $plugin);
}
wp_set_current_user(0);
wc_load_cart();
check(WC()->cart->is_empty(), 'The compatibility cart was not initialized empty.');
$server = rest_get_server();
do_action('rest_api_init');
$routes = $server->get_routes();

check(in_array('wc/store/v1', $server->get_namespaces(), true), 'Missing wc/store/v1 namespace.');
check(in_array('wc/v3', $server->get_namespaces(), true), 'Missing wc/v3 namespace.');
$expected = [
    '/wc/store/v1/products' => ['GET'],
    '/wc/store/v1/cart' => ['GET'],
    '/wc/store/v1/checkout' => ['GET', 'PATCH', 'POST', 'PUT'],
    '/wc/v3/products' => ['GET', 'POST'],
];
foreach ($expected as $route => $methods) {
    check(isset($routes[$route]), 'Missing route ' . $route);
    check(methodsFor($routes[$route]) === $methods, 'Unexpected methods for ' . $route);
}

// Materialize route options before the inventory boundary, then instrument every registered callable.
foreach (array_keys($routes) as $route) {
    $server->get_route_options($route);
}
$reflection = new ReflectionClass($server);
$endpoints = $reflection->getProperty('endpoints');
$registered = $endpoints->getValue($server);
$calls = ['callback' => 0, 'permission' => 0, 'routes' => []];
foreach ($registered as $route => &$handlers) {
    foreach ($handlers as $index => &$handler) {
        if (! is_int($index) || ! is_array($handler)) {
            continue;
        }
        foreach (['callback', 'permission_callback'] as $key) {
            if (! is_callable($handler[$key] ?? null)) {
                continue;
            }
            $original = $handler[$key];
            $counter = $key === 'callback' ? 'callback' : 'permission';
            $handler[$key] = static function (...$args) use ($original, $counter, $route, &$calls): mixed {
                $calls[$counter]++;
                $calls['routes'][$route] = ($calls['routes'][$route] ?? 0) + 1;
                return $original(...$args);
            };
        }
    }
}
unset($handlers, $handler);
$endpoints->setValue($server, $registered);

$targets = ['/wc/store/v1/products', '/wc/store/v1/cart', '/wc/v3/products'];
foreach ($targets as $target) {
    dispatchSnapshot($server, $target, $calls); // Warm request-local WooCommerce state.
}
$beforeDispatch = [];
foreach ($targets as $target) {
    $beforeDispatch[$target] = dispatchSnapshot($server, $target, $calls);
}
check($beforeDispatch['/wc/store/v1/products']['status'] === 200, 'Public Store products dispatch failed.');
check($beforeDispatch['/wc/store/v1/cart']['status'] === 200, 'Initialized empty cart dispatch failed.');
check($beforeDispatch['/wc/v3/products']['status'] === 401, 'WC REST products was not unauthenticated.');
check($beforeDispatch['/wc/store/v1/products']['route_callbacks'] === 1, 'Store products callback was not observed.');
check($beforeDispatch['/wc/store/v1/cart']['route_callbacks'] === 1, 'Store cart callback was not observed.');
check($beforeDispatch['/wc/v3/products']['route_callbacks'] === 0, 'Unauthorized WC REST products invoked its route callback.');
foreach ($beforeDispatch as $dispatch) {
    check($dispatch['permission_callbacks'] === 1, 'A dispatch did not invoke one permission callback.');
}
$beforeObjects = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type IN ('product', 'shop_order')");
$beforeState = stateSnapshot($server, $endpoints);
$beforeCalls = $calls;
$tests = apply_filters('site_status_tests', []);
$report = $tests['direct']['bastion_security_wp_rest_surface_inventory']['test']();
$afterState = stateSnapshot($server, $endpoints);
$afterObjects = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type IN ('product', 'shop_order')");

check($calls === $beforeCalls, 'Inventory invoked a registered REST callback.');
check(($calls['routes']['/wc/store/v1/checkout'] ?? 0) === 0, 'Checkout was dispatched.');
check($afterObjects === $beforeObjects, 'Inventory created a product or order.');
check($afterState === $beforeState, 'Inventory changed measured registry, user, output, SQL, session, or cart state.');
check(($report['status'] ?? null) === 'good', 'Inventory did not parse the real registry.');
check(preg_match('/Showing 100 of ([1-9][0-9]{2,}) routes; ([1-9][0-9]*) truncated/', (string) ($report['description'] ?? '')) === 1, 'Inventory did not prove bounded real-registry output.');

$afterDispatch = [];
foreach ($targets as $target) {
    $afterDispatch[$target] = dispatchSnapshot($server, $target, $calls);
}
check($afterDispatch === $beforeDispatch, 'Inventory changed lightweight REST dispatch outcomes.');
fwrite(STDOUT, "BASTION_WC_COMPAT_OK: inventory assertions passed\n");
