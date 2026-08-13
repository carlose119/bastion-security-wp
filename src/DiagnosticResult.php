<?php

declare(strict_types=1);

namespace BastionSecurityWP;

final class DiagnosticResult
{
    public function __construct(
        public readonly string $id,
        public readonly DiagnosticStatus $status,
        public readonly string $summary,
        public readonly string $description,
    ) {
    }

    /** @return array{id: string, status: string, summary: string, description: string} */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'status' => $this->status->value,
            'summary' => $this->summary,
            'description' => $this->description,
        ];
    }
}
