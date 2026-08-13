<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use InvalidArgumentException;

final class DiagnosticSnapshot
{
    /** @param array<string, bool|float|int|string|null> $values */
    public function __construct(private readonly array $values)
    {
        foreach ($values as $key => $_value) {
            if (! is_string($key)) {
                throw new InvalidArgumentException('Snapshot keys must be strings.');
            }
        }
    }

    public function value(string $key): bool|float|int|string|null
    {
        return $this->values[$key] ?? null;
    }
}
