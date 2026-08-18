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

function responseValueShape(mixed $value): mixed
{
    if (is_array($value)) {
        return array_map(responseValueShape(...), $value);
    }

    if (is_object($value)) {
        return [
            'class' => $value::class,
            'properties' => array_map(responseValueShape(...), get_object_vars($value)),
        ];
    }

    return $value;
}

/**
 * @param array<string, list<string>> $headers
 * @return array<string, list<string>>
 */
function normalizeCartHeaders(array $headers, int $dispatchStartedAt, int $dispatchFinishedAt): array
{
    $timestamps = $headers['nonce-timestamp'] ?? [];
    check(count($timestamps) === 1, 'Cart response did not contain exactly one nonce timestamp.');
    $timestampValue = $timestamps[0];
    check(preg_match('/^(?:0|[1-9][0-9]*)$/D', $timestampValue) === 1, 'Cart response nonce timestamp was not an integer.');
    $timestamp = (int) $timestampValue;
    check(
        $timestamp >= $dispatchStartedAt && $timestamp <= $dispatchFinishedAt,
        'Cart response nonce timestamp was outside its dispatch window.',
    );

    $tokens = $headers['cart-token'] ?? [];
    check(count($tokens) === 1 && $tokens[0] !== '', 'Cart response did not contain exactly one cart token.');
    $token = $tokens[0];
    $tokenUtils = Automattic\WooCommerce\StoreApi\Utilities\CartTokenUtils::class;
    check($tokenUtils::validate_cart_token($token), 'Cart response token signature was invalid.');
    $payload = $tokenUtils::get_cart_token_payload($token);
    $customerId = (string) WC()->session->get_customer_id();
    check(($payload['iss'] ?? null) === 'store-api', 'Cart response token issuer was invalid.');
    check((string) ($payload['user_id'] ?? '') === $customerId, 'Cart response token customer was invalid.');
    $expiration = $payload['exp'] ?? null;
    check(is_int($expiration), 'Cart response token expiration was not an integer.');
    $issuedAt = $expiration - (DAY_IN_SECONDS * 2);
    check(
        $issuedAt >= $dispatchStartedAt && $issuedAt <= $dispatchFinishedAt,
        'Cart response token expiration was outside its expected 48-hour lifetime.',
    );

    $headers['nonce-timestamp'] = ['valid:within-dispatch-window'];
    $headers['cart-token'] = [sprintf('valid:store-api:%s:%d', $customerId, DAY_IN_SECONDS * 2)];

    return $headers;
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
function dispatchSnapshot(
    WP_REST_Server $server,
    string $route,
    array &$calls,
    array &$hookCalls,
    ?array &$responseHeaders = null,
): array
{
    $before = $calls;
    $hooksBefore = $hookCalls;
    $dispatchStartedAt = time();
    $response = $server->dispatch(new WP_REST_Request('GET', $route));
    $dispatchFinishedAt = time();
    $headers = [];
    foreach ($response->get_headers() as $name => $value) {
        $key = strtolower($name);
        $values = is_array($value) ? $value : [$value];
        $headers[$key] = array_merge(
            $headers[$key] ?? [],
            array_map(static fn (mixed $item): string => (string) $item, $values),
        );
    }
    ksort($headers);
    $responseHeaders = $headers;
    if ($route === '/wc/store/v1/cart') {
        $headers = normalizeCartHeaders($headers, $dispatchStartedAt, $dispatchFinishedAt);
    }
    $error = $response instanceof WP_REST_Response && $response->is_error() ? $response->as_error() : null;
    $errors = [];
    foreach ($error?->get_error_codes() ?? [] as $code) {
        $errors[$code] = [
            'messages' => $error->get_error_messages($code),
            'data' => responseValueShape($error->get_all_error_data($code)),
        ];
    }
    $hookDeltas = [];
    foreach ($hookCalls as $hook => $count) {
        $hookDeltas[$hook] = $count - $hooksBefore[$hook];
    }

    return [
        'status' => $response->get_status(),
        'headers' => $headers,
        'data' => responseValueShape($response->get_data()),
        'body' => wp_json_encode($response->get_data(), JSON_UNESCAPED_SLASHES),
        'errors' => $errors,
        'hooks' => $hookDeltas,
        'permission_callbacks' => $calls['permission'] - $before['permission'],
        'route_callbacks' => $calls['callback'] - $before['callback'],
    ];
}

/** @return array<string, mixed> */
function stateSnapshot(
    WP_REST_Server $server,
    ReflectionProperty $endpoints,
    ReflectionProperty $routeOptions,
): array
{
    global $wpdb;

    return [
        'server' => spl_object_id($server),
        'user' => get_current_user_id(),
        'buffer_level' => ob_get_level(),
        'buffer' => ob_get_contents(),
        'queries' => $wpdb->num_queries,
        'namespaces' => $server->get_namespaces(),
        'endpoints' => hash('sha256', serialize(valueShape($endpoints->getValue($server)))),
        'route_options' => hash('sha256', serialize(valueShape($routeOptions->getValue($server)))),
        'wc_session' => WC()->session->get_session_data(),
        'cart' => WC()->cart->get_cart_contents(),
        'cart_hash' => WC()->cart->get_cart_hash(),
        'cart_totals' => WC()->cart->get_totals(),
    ];
}

/** @param array<string, int> $calls
 *  @return array<string, Closure>
 */
function installHookProbes(array &$calls): array
{
    $probes = [];
    foreach ([
        'rest_api_init',
        'rest_endpoints',
        'rest_pre_dispatch',
        'rest_request_before_callbacks',
        'rest_request_after_callbacks',
        'rest_post_dispatch',
        'woocommerce_init',
        'woocommerce_load_cart_from_session',
        'woocommerce_cart_loaded_from_session',
        'woocommerce_rest_check_permissions',
        'bastion_inventory_hook_probe',
    ] as $hook) {
        $calls[$hook] = 0;
        $probes[$hook] = static function (...$args) use ($hook, &$calls): mixed {
            ++$calls[$hook];

            return $args[0] ?? null;
        };
        add_filter($hook, $probes[$hook], PHP_INT_MAX, 99);
    }

    return $probes;
}

/** @param array<string, Closure> $probes
 *  @return array<string, array{probe_priority: int|false, callbacks: array<int, list<string>>}>
 */
function hookRegistrationSnapshot(array $probes): array
{
    global $wp_filter;

    $state = [];
    foreach ($probes as $hook => $probe) {
        $callbacks = [];
        $registered = $wp_filter[$hook] ?? null;
        if ($registered instanceof WP_Hook) {
            foreach ($registered->callbacks as $priority => $entries) {
                $identities = array_map('strval', array_keys($entries));
                sort($identities, SORT_STRING);
                $callbacks[$priority] = $identities;
            }
            ksort($callbacks, SORT_NUMERIC);
        }
        $state[$hook] = [
            'probe_priority' => has_filter($hook, $probe),
            'callbacks' => $callbacks,
        ];
    }

    return $state;
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
WC()->initialize_session();
WC()->initialize_cart();
check(WC()->session instanceof WC_Session, 'The compatibility session was not initialized.');
check(WC()->cart instanceof WC_Cart, 'The compatibility cart was not initialized.');
check(WC()->cart->is_empty(), 'The compatibility cart was not initialized empty.');
$server = new WP_REST_Server();
$GLOBALS['wp_rest_server'] = $server;
$coldRoute = '/bastion-probe/v1/item';
$calls = ['callback' => 0, 'permission' => 0, 'routes' => []];
$coldCallback = static function () use (&$calls, $coldRoute): WP_REST_Response {
    ++$calls['callback'];
    $calls['routes'][$coldRoute] = ($calls['routes'][$coldRoute] ?? 0) + 1;

    return new WP_REST_Response(['probe' => true]);
};
$server->register_route('bastion-probe/v1', $coldRoute, [[
    'methods' => WP_REST_Server::READABLE,
    'callback' => $coldCallback,
    'permission_callback' => '__return_true',
]]);
$reflection = new ReflectionClass($server);
$endpoints = $reflection->getProperty('endpoints');
$routeOptions = $reflection->getProperty('route_options');

$hookCalls = [];
$hookProbes = installHookProbes($hookCalls);
$tests = apply_filters('site_status_tests', []);
$inventory = $tests['direct']['bastion_security_wp_rest_surface_inventory']['test'] ?? null;
check(is_callable($inventory), 'Inventory report callback was not registered.');

// The first report runs against a registered route before get_routes() materializes its options.
stateSnapshot($server, $endpoints, $routeOptions);
$coldOptionBefore = valueShape($server->get_route_options($coldRoute));
$coldStateBefore = stateSnapshot($server, $endpoints, $routeOptions);
$coldCallsBefore = $calls;
$coldHooksBefore = $hookCalls;
$coldHookRegistrationsBefore = hookRegistrationSnapshot($hookProbes);
$report = $inventory();
$coldStateAfter = stateSnapshot($server, $endpoints, $routeOptions);
$coldHookRegistrationsAfter = hookRegistrationSnapshot($hookProbes);

check($calls === $coldCallsBefore, 'Cold inventory invoked a registered REST callback.');
check($hookCalls === $coldHooksBefore, 'Cold inventory invoked a lifecycle or REST hook.');
check($coldHookRegistrationsAfter === $coldHookRegistrationsBefore, 'Cold inventory changed lifecycle or REST hook registrations.');
check($coldStateAfter === $coldStateBefore, 'Cold inventory changed registry, route-option, user, output, SQL, session, or cart state.');
check(valueShape($server->get_route_options($coldRoute)) === $coldOptionBefore, 'Cold inventory exposed new route options.');
check(($report['status'] ?? null) === 'good', 'Cold inventory did not parse the registered route.');
check(str_contains((string) ($report['description'] ?? ''), $coldRoute), 'Cold inventory omitted the registered route.');

$coldCallbackBefore = $calls['callback'];
$coldRouteCallsBefore = $calls['routes'][$coldRoute] ?? 0;
$coldCallback();
check($calls['callback'] === $coldCallbackBefore + 1 && $calls['routes'][$coldRoute] === $coldRouteCallsBefore + 1, 'Cold callback probe did not detect its negative control.');
$registrationControl = hookRegistrationSnapshot($hookProbes);
check(remove_filter('rest_pre_dispatch', $hookProbes['rest_pre_dispatch'], PHP_INT_MAX), 'Hook registration control could not remove its probe.');
check(hookRegistrationSnapshot($hookProbes) !== $registrationControl, 'Hook registration snapshot did not detect probe removal.');
check(add_filter('rest_pre_dispatch', $hookProbes['rest_pre_dispatch'], PHP_INT_MAX, 99), 'Hook registration control could not restore its probe.');
check(hookRegistrationSnapshot($hookProbes) === $registrationControl, 'Hook registration control did not restore its original state.');
do_action('bastion_inventory_hook_probe');
check($hookCalls['bastion_inventory_hook_probe'] === 1, 'Hook invocation probe did not detect its negative control.');
$postDispatchBefore = $hookCalls['rest_post_dispatch'];
apply_filters('rest_post_dispatch', new WP_REST_Response(['probe' => true]), $server, new WP_REST_Request('GET', $coldRoute));
check($hookCalls['rest_post_dispatch'] === $postDispatchBefore + 1, 'Response-serving hook probe did not detect its negative control.');
$restEndpointFiltersBefore = $hookCalls['rest_endpoints'];
$routes = $server->get_routes();
check($hookCalls['rest_endpoints'] === $restEndpointFiltersBefore + 1, 'Route materialization did not reach the rest_endpoints probe.');
check(valueShape($server->get_route_options($coldRoute)) !== $coldOptionBefore, 'Route-option snapshot did not detect materialization.');
$restInitBefore = $hookCalls['rest_api_init'];
do_action('rest_api_init', $server);
check($hookCalls['rest_api_init'] === $restInitBefore + 1, 'REST initialization did not reach its lifecycle probe.');
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

$registered = $endpoints->getValue($server);
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
                ++$calls[$counter];
                $calls['routes'][$route] = ($calls['routes'][$route] ?? 0) + 1;

                return $original(...$args);
            };
        }
    }
}
unset($handlers, $handler);
$endpoints->setValue($server, $registered);

$targets = ['/wc/store/v1/products', '/wc/store/v1/cart', '/wc/v3/products'];
$dispatchHooksBefore = $hookCalls;
foreach ($targets as $target) {
    dispatchSnapshot($server, $target, $calls, $hookCalls); // Warm request-local WooCommerce state.
}
$beforeDispatch = [];
$beforeCartHeaders = null;
foreach ($targets as $target) {
    $responseHeaders = null;
    $beforeDispatch[$target] = dispatchSnapshot($server, $target, $calls, $hookCalls, $responseHeaders);
    if ($target === '/wc/store/v1/cart') {
        $beforeCartHeaders = $responseHeaders;
    }
}
check(is_array($beforeCartHeaders), 'Cart dispatch did not expose its response headers to the volatility control.');
sleep(1);
$volatileCartHeaders = null;
$volatileCartDispatch = dispatchSnapshot($server, '/wc/store/v1/cart', $calls, $hookCalls, $volatileCartHeaders);
check(
    $volatileCartHeaders['cart-token'] !== $beforeCartHeaders['cart-token']
        && $volatileCartHeaders['nonce-timestamp'] !== $beforeCartHeaders['nonce-timestamp'],
    'Cart dispatch control did not produce legitimate volatile headers.',
);
check(
    $volatileCartDispatch === $beforeDispatch['/wc/store/v1/cart'],
    'Semantic cart header normalization rejected an equivalent dispatch.',
);
check($beforeDispatch['/wc/store/v1/products']['status'] === 200, 'Public Store products dispatch failed.');
check($beforeDispatch['/wc/store/v1/cart']['status'] === 200, 'Initialized empty cart dispatch failed.');
check($beforeDispatch['/wc/v3/products']['status'] === 401, 'WC REST products was not unauthenticated.');
check($beforeDispatch['/wc/store/v1/products']['route_callbacks'] === 1, 'Store products callback was not observed.');
check($beforeDispatch['/wc/store/v1/cart']['route_callbacks'] === 1, 'Store cart callback was not observed.');
check($beforeDispatch['/wc/v3/products']['route_callbacks'] === 0, 'Unauthorized WC REST products invoked its route callback.');
foreach ($beforeDispatch as $dispatch) {
    check($dispatch['permission_callbacks'] === 1, 'A dispatch did not invoke one permission callback.');
}
check($beforeDispatch['/wc/store/v1/products']['errors'] === [], 'Public Store products returned an error shape.');
check($beforeDispatch['/wc/v3/products']['errors'] !== [], 'Unauthorized WC REST products omitted its error shape.');
foreach (['rest_pre_dispatch', 'rest_request_before_callbacks', 'rest_request_after_callbacks'] as $hook) {
    check($hookCalls[$hook] > $dispatchHooksBefore[$hook], 'Dispatch did not reach the ' . $hook . ' probe.');
}
check($hookCalls['woocommerce_rest_check_permissions'] > $dispatchHooksBefore['woocommerce_rest_check_permissions'], 'Dispatch did not reach the WooCommerce permission probe.');

$headerProbe = static function (WP_HTTP_Response $response): WP_HTTP_Response {
    $response->header('X-Bastion-Probe', 'detected');

    return $response;
};
add_filter('rest_request_after_callbacks', $headerProbe, PHP_INT_MAX);
$probedProductDispatch = dispatchSnapshot($server, '/wc/store/v1/products', $calls, $hookCalls);
$probedCartDispatch = dispatchSnapshot($server, '/wc/store/v1/cart', $calls, $hookCalls);
check(remove_filter('rest_request_after_callbacks', $headerProbe, PHP_INT_MAX), 'Response header probe could not be removed.');
check($probedProductDispatch !== $beforeDispatch['/wc/store/v1/products'], 'Dispatch snapshot did not detect a response header side effect.');
check($probedCartDispatch !== $beforeDispatch['/wc/store/v1/cart'], 'Cart snapshot normalization hid a response header side effect.');
check(($probedProductDispatch['headers']['x-bastion-probe'] ?? null) === ['detected'], 'Dispatch snapshot omitted the probed response header.');
check(($probedCartDispatch['headers']['x-bastion-probe'] ?? null) === ['detected'], 'Cart snapshot omitted the probed response header.');

stateSnapshot($server, $endpoints, $routeOptions);
$beforeObjects = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type IN ('product', 'shop_order')");
$beforeState = stateSnapshot($server, $endpoints, $routeOptions);
$beforeCalls = $calls;
$beforeHooks = $hookCalls;
$beforeHookRegistrations = hookRegistrationSnapshot($hookProbes);
$warmReport = $inventory();
$afterState = stateSnapshot($server, $endpoints, $routeOptions);
$afterHookRegistrations = hookRegistrationSnapshot($hookProbes);
$afterObjects = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type IN ('product', 'shop_order')");

check($calls === $beforeCalls, 'Inventory invoked a registered REST callback.');
check($hookCalls === $beforeHooks, 'Inventory invoked a lifecycle or REST hook.');
check($afterHookRegistrations === $beforeHookRegistrations, 'Inventory changed lifecycle or REST hook registrations.');
check(($calls['routes']['/wc/store/v1/checkout'] ?? 0) === 0, 'Checkout was dispatched.');
check($afterObjects === $beforeObjects, 'Inventory created a product or order.');
check($afterState === $beforeState, 'Inventory changed measured registry, user, output, SQL, session, or cart state.');
check(($warmReport['status'] ?? null) === 'good', 'Inventory did not parse the real registry.');
check(preg_match('/Showing 100 of ([1-9][0-9]{2,}) routes; ([1-9][0-9]*) truncated/', (string) ($warmReport['description'] ?? '')) === 1, 'Inventory did not prove bounded real-registry output.');

$afterDispatch = [];
foreach ($targets as $target) {
    $afterDispatch[$target] = dispatchSnapshot($server, $target, $calls, $hookCalls);
}
check($afterDispatch === $beforeDispatch, 'Inventory changed full REST dispatch outcomes.');
foreach ($hookProbes as $hook => $probe) {
    check(remove_filter($hook, $probe, PHP_INT_MAX), 'Hook probe could not be removed: ' . $hook);
    check(has_filter($hook, $probe) === false, 'Hook probe remained registered: ' . $hook);
}

fwrite(STDOUT, "BASTION_WC_COMPAT_OK: inventory assertions passed\n");
fwrite(STDOUT, "BASTION_WC_COMPAT_LIMITATION: PHP CLI cannot observe SAPI header() or setcookie() emissions; response-object headers are covered\n");
