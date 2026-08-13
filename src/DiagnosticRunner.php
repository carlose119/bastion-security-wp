<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use Throwable;

final class DiagnosticRunner
{
    public function __construct(private readonly DiagnosticRegistry $registry)
    {
    }

    /** @return list<DiagnosticResult> */
    public function run(DiagnosticSnapshot $snapshot): array
    {
        $results = [];

        foreach ($this->registry->all() as $index => $diagnostic) {
            $id = 'diagnostic-' . ($index + 1);

            try {
                $id = $diagnostic->id();
                $results[] = $diagnostic->assess($snapshot);
            } catch (Throwable) {
                $results[] = new DiagnosticResult(
                    $id,
                    DiagnosticStatus::NotAssessed,
                    'Diagnostic not assessed',
                    'This diagnostic could not be completed during the current request.',
                );
            }
        }

        return $results;
    }
}
