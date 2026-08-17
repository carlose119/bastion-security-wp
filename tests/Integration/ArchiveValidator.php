<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Integration;

use RuntimeException;
use Throwable;
use ZipArchive;

final class ArchiveValidator
{
    public static function assertSafe(string $archive, string $expectedRoot): void
    {
        if (preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/D', $expectedRoot) !== 1) {
            throw new RuntimeException('Invalid expected archive root.');
        }

        $zip = new ZipArchive();
        if (! is_file($archive) || $zip->open($archive) !== true) {
            throw new RuntimeException('Could not open archive.');
        }

        try {
            if ($zip->numFiles < 1) {
                throw new RuntimeException('Archive is empty.');
            }

            for ($index = 0; $index < $zip->numFiles; ++$index) {
                $entry = $zip->getNameIndex($index);
                if (! is_string($entry) || self::isUnsafeName($entry, $expectedRoot)) {
                    throw new RuntimeException('Unsafe archive entry: ' . ($entry ?: '(empty)'));
                }

                $operatingSystem = 0;
                $attributes = 0;
                if ($zip->getExternalAttributesIndex($index, $operatingSystem, $attributes)
                    && $operatingSystem === ZipArchive::OPSYS_UNIX
                    && (($attributes >> 16) & 0170000) === 0120000) {
                    throw new RuntimeException('Archive contains a symbolic link: ' . $entry);
                }
            }
        } finally {
            $zip->close();
        }
    }

    private static function isUnsafeName(string $entry, string $expectedRoot): bool
    {
        return $entry === ''
            || str_starts_with($entry, '/')
            || str_contains($entry, "\0")
            || str_contains($entry, '\\')
            || str_contains($entry, '//')
            || preg_match('~(?:^|/)[A-Za-z]:~', $entry) === 1
            || preg_match('~(?:^|/)\.\.?($|/)~', $entry) === 1
            || ($entry !== $expectedRoot . '/' && ! str_starts_with($entry, $expectedRoot . '/'));
    }
}

if (realpath((string) ($_SERVER['SCRIPT_FILENAME'] ?? '')) === __FILE__) {
    try {
        ArchiveValidator::assertSafe($argv[1] ?? '', $argv[2] ?? '');
        fwrite(STDOUT, "BASTION_ARCHIVE_OK: expected root and safe entries verified\n");
    } catch (Throwable $error) {
        fwrite(STDERR, $error->getMessage() . "\n");
        exit(1);
    }
}
