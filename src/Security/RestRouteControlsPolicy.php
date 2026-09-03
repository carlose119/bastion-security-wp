<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use Closure;
use Throwable;

final class RestRouteControlsPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_rest_route_controls';
    public const MAX_RULES = 100;
    public const MAX_ROUTE_BYTES = 2048;
    /** @var list<string> */
    public const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];

    private Closure $readOption;
    private Closure $writeOption;
    private Closure $errorFactory;
    private Closure $isError;
    /** @var array{assessed:bool,rules:list<array{method:string,route_pattern:string}>}|null */
    private ?array $cachedState = null;

    public function __construct(
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $errorFactory = null,
        ?callable $isError = null,
    ) {
        $this->readOption = Closure::fromCallable($readOption ?? static fn (): mixed => \get_option(self::OPTION_NAME, false));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (array $value): bool => \update_option(self::OPTION_NAME, $value));
        $this->errorFactory = Closure::fromCallable($errorFactory ?? static fn (string $code, string $message, array $data): object => new \WP_Error($code, $message, $data));
        $this->isError = Closure::fromCallable($isError ?? static fn (mixed $value): bool => \is_wp_error($value));
    }

    /** @return array{assessed:bool,rules:list<array{method:string,route_pattern:string}>} */
    public function state(): array
    {
        if ($this->cachedState !== null) {
            return $this->cachedState;
        }
        try {
            return $this->cachedState = $this->validateStored(($this->readOption)());
        } catch (Throwable) {
            return $this->cachedState = ['assessed' => false, 'rules' => []];
        }
    }

    /** @return list<array{method:string,route_pattern:string}>|null */
    public function canonicalRules(mixed $rules): ?array
    {
        if (! is_array($rules) || ! array_is_list($rules) || count($rules) > self::MAX_RULES) {
            return null;
        }
        $canonical = [];
        $seen = [];
        foreach ($rules as $rule) {
            if (! is_array($rule) || array_keys($rule) !== ['method', 'route_pattern']
                || ! is_string($rule['method']) || ! is_string($rule['route_pattern'])) {
                return null;
            }
            $method = strtoupper($rule['method']);
            $pattern = $rule['route_pattern'];
            if (! in_array($method, self::METHODS, true) || ! $this->validPattern($pattern)) {
                return null;
            }
            $key = $method . "\0" . $pattern;
            if (isset($seen[$key])) {
                return null;
            }
            $seen[$key] = true;
            $canonical[] = ['method' => $method, 'route_pattern' => $pattern];
        }
        $order = array_flip(self::METHODS);
        usort($canonical, static function (array $left, array $right) use ($order): int {
            $route = strcmp($left['route_pattern'], $right['route_pattern']);
            return $route !== 0 ? $route : $order[$left['method']] <=> $order[$right['method']];
        });
        return $canonical;
    }

    /** @param list<array{method:string,route_pattern:string}> $rules */
    public function saveRules(array $rules): string
    {
        $canonical = $this->canonicalRules($rules);
        if ($canonical === null) {
            return 'write_failed';
        }
        $state = $this->state();
        if ($state['assessed'] && $state['rules'] === $canonical) {
            return 'unchanged';
        }
        $expected = ['schema_version' => 1, 'rules' => $canonical];
        try {
            if (! ($this->writeOption)($expected)) {
                return 'write_failed';
            }
            $readBack = ($this->readOption)();
        } catch (Throwable) {
            return 'write_failed';
        }
        if ($readBack !== $expected) {
            return 'write_failed';
        }
        $this->cachedState = ['assessed' => true, 'rules' => $canonical];
        return 'updated';
    }

    public function filterRequest(mixed $response, mixed $handler, mixed $request): mixed
    {
        try {
            if (($this->isError)($response) || ! is_object($request)
                || ! method_exists($request, 'get_method') || ! method_exists($request, 'get_route')) {
                return $response;
            }
            $method = $request->get_method();
            $route = $request->get_route();
            if (! is_string($method) || ! is_string($route) || ! in_array($method, self::METHODS, true)) {
                return $response;
            }
            $state = $this->state();
            if (! $state['assessed']) {
                return $response;
            }
            foreach ($state['rules'] as $rule) {
                if ($rule['method'] === $method && @preg_match('@^' . $rule['route_pattern'] . '$@i', $route) === 1) {
                    return ($this->errorFactory)(
                        'bastion_rest_route_disabled',
                        'This REST route is disabled by site policy.',
                        ['status' => 403],
                    );
                }
            }
        } catch (Throwable) {
            return $response;
        }
        return $response;
    }

    /** @return array{assessed:bool,rules:list<array{method:string,route_pattern:string}>} */
    private function validateStored(mixed $value): array
    {
        if ($value === false) {
            return ['assessed' => true, 'rules' => []];
        }
        if (! is_array($value) || array_keys($value) !== ['schema_version', 'rules'] || $value['schema_version'] !== 1) {
            return ['assessed' => false, 'rules' => []];
        }
        $canonical = $this->canonicalRules($value['rules']);
        if ($canonical === null || $canonical !== $value['rules']) {
            return ['assessed' => false, 'rules' => []];
        }
        return ['assessed' => true, 'rules' => $canonical];
    }

    private function validPattern(string $pattern): bool
    {
        $length = strlen($pattern);
        if ($length === 0 || $length > self::MAX_ROUTE_BYTES || $pattern[0] !== '/') {
            return false;
        }
        for ($i = 0; $i < $length; ++$i) {
            $byte = ord($pattern[$i]);
            if ($byte < 0x20 || $byte === 0x7F) {
                return false;
            }
        }
        return @preg_match('@^' . $pattern . '$@i', '') !== false;
    }
}
