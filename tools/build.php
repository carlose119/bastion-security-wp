<?php

declare(strict_types=1);

const PLUGIN_DIRECTORY = 'cerrojo-security-toolkit';

$root = realpath(dirname(__DIR__)) ?: throw new RuntimeException('Could not resolve repository root.');
$build = $root . '/.build';
$stage = $build . '/stage/' . PLUGIN_DIRECTORY;
$archive = $build . '/' . PLUGIN_DIRECTORY . '.zip';
$exitCode = 0;

function removeTree(string $path): void
{
    if (is_link($path)) {
        throw new RuntimeException('Refusing to remove symbolic-link directory: ' . $path);
    }

    if (! is_dir($path)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $item) {
        if ($item->isLink() || ! $item->isDir()) {
            unlink($item->getPathname());
        } else {
            rmdir($item->getPathname());
        }
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

function productionComposerManifest(string $source): string
{
    $composer = json_decode(
        (string) file_get_contents($source),
        true,
        flags: JSON_THROW_ON_ERROR,
    );

    $manifest = [
        'name' => $composer['name'] ?? null,
        'description' => $composer['description'] ?? null,
        'type' => $composer['type'] ?? null,
        'license' => $composer['license'] ?? null,
        'require' => ['php' => $composer['require']['php'] ?? null],
        'autoload' => [
            'psr-4' => [
                'BastionSecurityWP\\' => $composer['autoload']['psr-4']['BastionSecurityWP\\'] ?? null,
            ],
        ],
    ];

    foreach (['name', 'description', 'type', 'license'] as $field) {
        if (! is_string($manifest[$field]) || $manifest[$field] === '') {
            throw new RuntimeException('Invalid Composer runtime field: ' . $field);
        }
    }

    if (! is_string($manifest['require']['php']) || $manifest['require']['php'] === ''
        || ! is_string($manifest['autoload']['psr-4']['BastionSecurityWP\\'])
        || $manifest['autoload']['psr-4']['BastionSecurityWP\\'] === '') {
        throw new RuntimeException('Invalid Composer runtime requirements or autoload mapping.');
    }

    return json_encode(
        $manifest,
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
    ) . PHP_EOL;
}

try {
    if (! extension_loaded('zip')) {
        throw new RuntimeException('The PHP zip extension is required.');
    }

    removeTree($build);
    mkdir($stage, 0777, true);
    $zipTimestamp = mktime(0, 0, 0, 1, 1, 1981);

    foreach (['bastion-security-wp.php', 'readme.txt', 'LICENSE', 'composer.json', 'composer.lock'] as $file) {
        $source = $root . '/' . $file;
        copy(sourcePath($source, $root, $root), $stage . '/' . $file);
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

    $productionComposer = productionComposerManifest($stage . '/composer.json');

    if (file_put_contents($stage . '/composer.json', $productionComposer) === false
        || ! unlink($stage . '/composer.lock')) {
        throw new RuntimeException('Could not prepare production Composer metadata.');
    }

    $files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($stage, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterator as $file) {
        if ($file->isFile()) {
            $relative = str_replace('\\', '/', substr($file->getPathname(), strlen($stage) + 1));
            $segments = explode('/', $relative);

            if (array_filter($segments, static fn (string $segment): bool => str_starts_with($segment, '.')) !== []) {
                continue;
            }

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
            || ! $zip->setMtimeName($name, $zipTimestamp)
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
    $verification = new ZipArchive();

    if (! is_file($archive) || $verification->open($archive) !== true) {
        throw new RuntimeException('Could not verify finalized archive.');
    }

    $verifiedFileCount = $verification->numFiles;
    $verificationClosed = $verification->close();

    if ($verifiedFileCount !== count($files) || ! $verificationClosed) {
        throw new RuntimeException('Could not verify finalized archive.');
    }

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
