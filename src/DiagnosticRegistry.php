<?php

declare(strict_types=1);

namespace BastionSecurityWP;

final class DiagnosticRegistry
{
    /** @var list<Diagnostic> */
    private readonly array $diagnostics;

    public function __construct(Diagnostic ...$diagnostics)
    {
        $this->diagnostics = $diagnostics;
    }

    /** @return list<Diagnostic> */
    public function all(): array
    {
        return $this->diagnostics;
    }
}
