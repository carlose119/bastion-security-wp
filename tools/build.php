<?php

declare(strict_types=1);

const PLUGIN_DIRECTORY = 'bastion-security-wp';
const ZIP_TIMESTAMP = 315532800;

$root = realpath(dirname(__DIR__)) ?: throw new RuntimeException('Could not resolve repository root.');
$build = $root . '/.build';
$stage = $build . '/stage/' . PLUGIN_DIRECTORY;
$archive = $build . '/' . PLUGIN_DIRECTORY . '.zip';
$exitCode = 0;

function removeTree(string $path): void
{
    if (! is_dir($path)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }

    rmdir($path);
}

function sourcePath(string $path, string $root, string $allowed): string
{
    $canonical = realpath($path);
    $allowed = realpath($allowed);

    if (is_link($path) || $canonical === false || $allowed === false
        || ($canonical !== $root && ! str_starts_with($canonical, $root . DIRECTORY_SEPARATOR))
        || ($canonical !== $allowed && ! str_starts_with($canonical, $allowed . DIRECTORY_SEPARATOR))) {
        throw new RuntimeException('Unsafe runtime source path: ' . $path);
    }

    return $canonical;
}

function copyTree(string $source, string $target, string $root): void
{
    $source = sourcePath($source, $root, $source);
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST,
    );

    foreach ($iterator as $item) {
        $relative = substr($item->getPathname(), strlen($source) + 1);
        $destination = $target . '/' . $relative;
        $path = sourcePath($item->getPathname(), $root, $source);
        $item->isDir() ? mkdir($destination, 0777, true) : copy($path, $destination);
    }
}

try {
    if (! extension_loaded('zip')) {
        throw new RuntimeException('The PHP zip extension is required.');
    }

    removeTree(dirname($stage));
    mkdir($stage, 0777, true);

    foreach (['bastion-security-wp.php', 'composer.json', 'composer.lock', 'README.md', 'LICENSE', 'LICENSE.md'] as $file) {
        $source = $root . '/' . $file;

        if (file_exists($source) || is_link($source)) {
            copy(sourcePath($source, $root, $root), $stage . '/' . $file);
        }
    }

    mkdir($stage . '/src');
    copyTree($root . '/src', $stage . '/src', $root);

    $composer = getenv('COMPOSER_BINARY') ?: '';

    if (PHP_OS_FAMILY === 'Windows') {
        if ($composer === '') {
            exec('where.exe composer.bat', $matches, $composerStatus);
            $composer = $matches[0] ?? '';
        }

        $composer = str_ends_with(strtolower($composer), '.phar') ? $composer : dirname($composer) . '/composer.phar';
        $composerCommand = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($composer);
    } else {
        $composerCommand = escapeshellarg($composer ?: 'composer');
    }

    $command = $composerCommand . ' install --no-dev --classmap-authoritative --no-interaction --no-progress --no-scripts'
        . ' --working-dir=' . escapeshellarg($stage);
    passthru($command, $status);

    if ($status !== 0 || ! is_file($stage . '/vendor/autoload.php')) {
        throw new RuntimeException('Production Composer install failed.');
    }

    $files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($stage, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterator as $file) {
        if ($file->isFile()) {
            $relative = str_replace('\\', '/', substr($file->getPathname(), strlen($stage) + 1));
            $files[$relative] = $file->getPathname();
        }
    }

    ksort($files, SORT_STRING);
    $zip = new ZipArchive();

    if ($zip->open($archive, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Could not create archive.');
    }

    foreach ($files as $relative => $file) {
        $name = PLUGIN_DIRECTORY . '/' . $relative;
        if (! $zip->addFile($file, $name)
            || ! $zip->setMtimeName($name, ZIP_TIMESTAMP)
            || ! $zip->setExternalAttributesName($name, ZipArchive::OPSYS_UNIX, 0100644 << 16)
            || ! $zip->setCompressionName($name, ZipArchive::CM_DEFLATE, 9)) {
            throw new RuntimeException('Could not write archive entry: ' . $name);
        }
    }

    if (! $zip->close()) {
        $zip = null;
        throw new RuntimeException('Could not finalize archive.');
    }

    $zip = null;
    printf("Built %s with %d files.\n", $archive, count($files));
} catch (Throwable $error) {
    if (isset($zip) && $zip instanceof ZipArchive && ! $zip->close()) {
        fwrite(STDERR, "Could not close failed archive.\n");
    }

    if (is_file($archive)) {
        unlink($archive);
    }

    fwrite(STDERR, $error->getMessage() . PHP_EOL);
    $exitCode = 1;
} finally {
    removeTree(dirname($stage));
}

exit($exitCode);
