<?php

declare(strict_types=1);

namespace BastionSecurityWP;

interface Diagnostic
{
    public function id(): string;

    public function assess(DiagnosticSnapshot $snapshot): DiagnosticResult;
}
