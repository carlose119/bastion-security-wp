<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Diagnostic;
use BastionSecurityWP\DiagnosticRegistry;
use BastionSecurityWP\DiagnosticResult;
use BastionSecurityWP\DiagnosticRunner;
use BastionSecurityWP\DiagnosticSnapshot;
use BastionSecurityWP\DiagnosticStatus;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class DiagnosticRunnerTest extends TestCase
{
    public function testResultsRetainRegistryOrderAndExposeStableShape(): void
    {
        $registry = new DiagnosticRegistry(
            $this->diagnostic('first'),
            $this->diagnostic('second'),
        );

        $results = (new DiagnosticRunner($registry))->run(new DiagnosticSnapshot(['enabled' => true]));

        self::assertSame(['first', 'second'], array_map(
            static fn (DiagnosticResult $result): string => $result->id,
            $results,
        ));
        self::assertSame([
            'id' => 'first',
            'status' => 'good',
            'summary' => 'Assessment complete',
            'description' => 'The diagnostic completed.',
        ], $results[0]->toArray());
    }

    public function testFailureIsNeutralAndDoesNotLeakExceptionDetails(): void
    {
        $failing = new class implements Diagnostic {
            public function id(): string
            {
                return 'failing';
            }

            public function assess(DiagnosticSnapshot $snapshot): DiagnosticResult
            {
                throw new RuntimeException('secret-token-123');
            }
        };

        $result = (new DiagnosticRunner(new DiagnosticRegistry($failing)))
            ->run(new DiagnosticSnapshot([]))[0];
        $serialized = json_encode($result->toArray(), JSON_THROW_ON_ERROR);

        self::assertSame(DiagnosticStatus::NotAssessed, $result->status);
        self::assertStringNotContainsString('secret-token-123', $serialized);
        self::assertStringNotContainsString(RuntimeException::class, $serialized);
    }

    private function diagnostic(string $id): Diagnostic
    {
        return new class($id) implements Diagnostic {
            public function __construct(private readonly string $id)
            {
            }

            public function id(): string
            {
                return $this->id;
            }

            public function assess(DiagnosticSnapshot $snapshot): DiagnosticResult
            {
                return new DiagnosticResult(
                    $this->id,
                    DiagnosticStatus::Good,
                    'Assessment complete',
                    'The diagnostic completed.',
                );
            }
        };
    }
}
