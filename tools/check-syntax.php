<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$files = [$root . '/bastion-security-wp.php'];

foreach (['src', 'tests', 'tools'] as $directory) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root . '/' . $directory, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $files[] = $file->getPathname();
        }
    }
}

sort($files, SORT_STRING);

foreach ($files as $file) {
    passthru(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($file), $status);

    if ($status !== 0) {
        exit($status);
    }
}
