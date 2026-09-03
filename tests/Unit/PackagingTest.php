<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use FilesystemIterator;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ZipArchive;

final class PackagingTest extends TestCase
{
    private const ROOT = 'bastion-security/';

    private static string $archive;
    private static string $extracted;

    public static function setUpBeforeClass(): void
    {
        $root = dirname(__DIR__, 2);
        self::runBuild($root);
        self::$archive = $root . '/.build/bastion-security.zip';
        self::assertFileExists(self::$archive);
        self::$extracted = sys_get_temp_dir() . '/bastion-package-' . bin2hex(random_bytes(6));
    }

    public static function tearDownAfterClass(): void
    {
        if (! isset(self::$extracted) || ! is_dir(self::$extracted)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(self::$extracted, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $item) {
            $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
        }

        rmdir(self::$extracted);
    }

    public function testArchiveManifestMatchesTheProductionContract(): void
    {
        $entries = self::archiveEntries();

        self::assertSame($entries, array_values(array_filter(
            $entries,
            static fn (string $entry): bool => str_starts_with($entry, self::ROOT),
        )));
        self::assertSame($entries, array_values(array_unique($entries)));
        $sorted = $entries;
        sort($sorted, SORT_STRING);
        self::assertSame($sorted, $entries);

        foreach (['bastion-security-wp.php', 'readme.txt', 'LICENSE', 'composer.json', 'src/Bootstrap.php', 'vendor/autoload.php'] as $required) {
            self::assertContains(self::ROOT . $required, $entries);
        }

        $allowedTopLevel = ['LICENSE', 'bastion-security-wp.php', 'composer.json', 'readme.txt', 'src', 'vendor'];

        foreach ($entries as $entry) {
            $relative = substr($entry, strlen(self::ROOT));
            $segments = explode('/', $relative);
            self::assertContains($segments[0], $allowedTopLevel, 'Unexpected top-level package entry: ' . $entry);

            foreach ($segments as $segment) {
                self::assertFalse(str_starts_with($segment, '.'), 'Hidden package path segment: ' . $entry);
            }

            self::assertDoesNotMatchRegularExpression(
                '~(?:^|/)(?:README\.md|composer\.lock|tests|tools|\.github|\.atl|\.codegraph|phpunit\.xml\.dist)(?:/|$)~i',
                $relative,
            );
            self::assertStringNotContainsString('\\', $entry);
            self::assertStringNotContainsString('//', $entry);
            self::assertDoesNotMatchRegularExpression('~(?:^|/)\.\.?(/|$)|(?:^|/)[A-Za-z]:~', $entry);
        }

        $lock = json_decode((string) file_get_contents(dirname(__DIR__, 2) . '/composer.lock'), true, flags: JSON_THROW_ON_ERROR);

        foreach ($lock['packages-dev'] ?? [] as $package) {
            self::assertIsString($package['name'] ?? null, 'Every packages-dev entry must have a name.');
            $directory = self::ROOT . 'vendor/' . trim($package['name'], '/') . '/';
            self::assertSame([], array_values(array_filter(
                $entries,
                static fn (string $entry): bool => str_starts_with($entry, $directory),
            )), sprintf('Development package %s appeared at %s.', $package['name'], $directory));
        }
    }

    public function testArchiveContainsOnlySanitizedProductionComposerMetadata(): void
    {
        $root = dirname(__DIR__, 2);
        $source = json_decode((string) file_get_contents($root . '/composer.json'), true, flags: JSON_THROW_ON_ERROR);
        $zip = new ZipArchive();
        self::assertTrue($zip->open(self::$archive));

        try {
            $contents = $zip->getFromName(self::ROOT . 'composer.json');
            self::assertIsString($contents);
            $production = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        } finally {
            $zip->close();
        }

        self::assertSame(
            ['name', 'description', 'type', 'license', 'require', 'autoload'],
            array_keys($production),
        );

        foreach (['name', 'description', 'type', 'license', 'require', 'autoload'] as $field) {
            self::assertSame($source[$field], $production[$field], 'Unexpected production Composer field: ' . $field);
        }

        foreach (['require-dev', 'autoload-dev', 'scripts', 'scripts-descriptions', 'config', 'extra', 'repositories'] as $developmentKey) {
            self::assertArrayNotHasKey($developmentKey, $production);
        }

        foreach (array_keys($source['require-dev'] ?? []) as $developmentPackage) {
            self::assertArrayNotHasKey($developmentPackage, $production['require']);
        }
    }

    public function testArchiveContainsTheCompleteDistributionDocuments(): void
    {
        $root = dirname(__DIR__, 2);
        $zip = new ZipArchive();
        self::assertTrue($zip->open(self::$archive));

        try {
            self::assertSame(
                file_get_contents($root . '/LICENSE'),
                $zip->getFromName(self::ROOT . 'LICENSE'),
            );
            self::assertSame(
                file_get_contents($root . '/readme.txt'),
                $zip->getFromName(self::ROOT . 'readme.txt'),
            );
        } finally {
            $zip->close();
        }

        $license = (string) file_get_contents($root . '/LICENSE');
        self::assertStringStartsWith("                    GNU GENERAL PUBLIC LICENSE\n", $license);
        self::assertStringContainsString("TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION\n", $license);
        self::assertStringContainsString("  12. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING", $license);
        self::assertStringContainsString("END OF TERMS AND CONDITIONS\n", $license);
        self::assertStringContainsString("How to Apply These Terms to Your New Programs\n", $license);
    }

    public function testArchiveContainsNoSymbolicLinks(): void
    {
        $zip = new ZipArchive();
        self::assertTrue($zip->open(self::$archive));

        try {
            for ($index = 0; $index < $zip->numFiles; ++$index) {
                $operatingSystem = 0;
                $attributes = 0;
                self::assertTrue($zip->getExternalAttributesIndex($index, $operatingSystem, $attributes));
                self::assertSame(ZipArchive::OPSYS_UNIX, $operatingSystem);
                self::assertNotSame(0120000, (($attributes >> 16) & 0170000));
            }
        } finally {
            $zip->close();
        }
    }

    public function testExtractedPluginBootstrapsWithoutWordPressHooks(): void
    {
        $zip = new ZipArchive();
        self::assertTrue($zip->open(self::$archive));
        self::assertTrue($zip->extractTo(self::$extracted));
        $zip->close();

        self::assertFalse(function_exists('add_filter'));
        $entry = self::$extracted . '/' . self::ROOT . 'bastion-security-wp.php';
        $smoke = self::$extracted . '/smoke.php';
        $code = '<?php define("ABSPATH", ' . var_export(self::$extracted . '/', true) . ');'
            . 'require ' . var_export($entry, true) . ';'
            . 'exit(class_exists("BastionSecurityWP\\Bootstrap") ? 0 : 1);';
        file_put_contents($smoke, $code);
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($smoke) . ' 2>&1', $output, $status);
        self::assertSame(0, $status, implode(PHP_EOL, $output));
    }

    public function testEveryArchiveEntryUsesTheFixedLocalDate(): void
    {
        $zip = new ZipArchive();
        self::assertTrue($zip->open(self::$archive));

        try {
            for ($index = 0; $index < $zip->numFiles; ++$index) {
                $entry = $zip->statIndex($index);
                self::assertIsArray($entry);
                self::assertSame('1981-01-01', date('Y-m-d', $entry['mtime']), 'Unexpected archive date: ' . $entry['name']);
            }
        } finally {
            $zip->close();
        }
    }

    public function testBuildRemovesStaleOutputBeforeCreatingTheArchive(): void
    {
        $root = dirname(__DIR__, 2);
        file_put_contents($root . '/.build/bastion-security-wp.zip', 'stale archive');

        self::runBuild($root);

        self::assertSame(['bastion-security.zip'], array_values(array_diff(scandir($root . '/.build'), ['.', '..'])));
    }

    public function testBuildIsDeterministic(): void
    {
        $root = dirname(__DIR__, 2);
        $firstHash = hash_file('sha256', self::$archive);
        self::assertIsString($firstHash);

        self::runBuild($root);
        $secondHash = hash_file('sha256', self::$archive);
        self::assertSame($firstHash, $secondHash);
    }

    public function testFailedBuildRemovesArchiveAndStagingDirectory(): void
    {
        $root = dirname(__DIR__, 2);
        $command = self::environmentPrefix('COMPOSER_BINARY', $root . '/missing-composer.phar')
            . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/tools/build.php') . ' 2>&1';
        exec($command, $output, $status);

        self::assertNotSame(0, $status, implode(PHP_EOL, $output));
        self::assertFileDoesNotExist(self::$archive);
        self::assertDirectoryDoesNotExist($root . '/.build/stage');
        self::runBuild($root);
    }

    /** @return list<string> */
    private static function archiveEntries(): array
    {
        $zip = new ZipArchive();
        self::assertTrue($zip->open(self::$archive));
        $entries = [];

        for ($index = 0; $index < $zip->numFiles; ++$index) {
            $entry = $zip->getNameIndex($index);
            self::assertIsString($entry);
            $entries[] = $entry;
        }

        $zip->close();

        return $entries;
    }

    private static function runBuild(string $root): void
    {
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/tools/build.php') . ' 2>&1', $output, $status);
        self::assertSame(0, $status, implode(PHP_EOL, $output));
    }

    private static function environmentPrefix(string $name, string $value): string
    {
        if (PHP_OS_FAMILY === 'Windows') {
            return 'set ' . $name . '=' . escapeshellarg($value) . '&& ';
        }

        return $name . '=' . escapeshellarg($value) . ' ';
    }
}
