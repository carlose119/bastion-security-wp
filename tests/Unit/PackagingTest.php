<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use FilesystemIterator;
use ZipArchive;

final class PackagingTest extends TestCase
{
    private const ROOT = 'bastion-security-wp/';

    private static string $archive;
    private static string $extracted;

    public static function setUpBeforeClass(): void
    {
        $root = dirname(__DIR__, 2);
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/tools/build.php') . ' 2>&1', $output, $status);
        self::assertSame(0, $status, implode(PHP_EOL, $output));
        self::$archive = $root . '/.build/bastion-security-wp.zip';
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

    public function testArchiveManifestHasOnlyTheProductionRoot(): void
    {
        $zip = new ZipArchive();
        self::assertTrue($zip->open(self::$archive));
        $entries = [];

        for ($index = 0; $index < $zip->numFiles; $index++) {
            $entries[] = $zip->getNameIndex($index);
        }

        $zip->close();
        self::assertSame($entries, array_values(array_filter($entries, static fn (string $entry): bool => str_starts_with($entry, self::ROOT))));
        self::assertSame($entries, array_values(array_unique($entries)));
        $sorted = $entries;
        sort($sorted, SORT_STRING);
        self::assertSame($sorted, $entries);

        foreach (['bastion-security-wp.php', 'src/Bootstrap.php', 'README.md', 'composer.json', 'composer.lock', 'vendor/autoload.php'] as $required) {
            self::assertContains(self::ROOT . $required, $entries);
        }

        foreach ($entries as $entry) {
            self::assertDoesNotMatchRegularExpression('~/(tests|\.git|\.github)(/|\.)|/phpunit\.~', $entry);
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

    public function testBuildRejectsSourceSymlinksAndCleansUp(): void
    {
        $root = dirname(__DIR__, 2);
        $target = tempnam(sys_get_temp_dir(), 'bastion-source-');
        $link = $root . '/src/.packaging-symlink-' . bin2hex(random_bytes(6));

        if ($target === false || ! @symlink($target, $link)) {
            $target === false || unlink($target);
            self::markTestSkipped('Creating symlinks is not permitted on this platform.');
        }

        try {
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/tools/build.php') . ' 2>&1', $output, $status);
            self::assertNotSame(0, $status, implode(PHP_EOL, $output));
            self::assertFileDoesNotExist(self::$archive);
            self::assertDirectoryDoesNotExist($root . '/.build/stage');
        } finally {
            is_link($link) && unlink($link);
            is_file($target) && unlink($target);
        }
    }
}
