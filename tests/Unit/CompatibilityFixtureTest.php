<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Tests\Integration\ArchiveValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ZipArchive;

final class CompatibilityFixtureTest extends TestCase
{
    public function testWorkflowInstallsBootstrapsAndRequiresSuccessMarkers(): void
    {
        $root = dirname(__DIR__, 2);
        $workflow = (string) file_get_contents($root . '/.github/workflows/ci.yml');
        $runtime = (string) file_get_contents($root . '/tests/Integration/WooCommerceRestInventory.php');

        self::assertStringContainsString('php tests/Integration/InstallWordPress.php', $workflow);
        self::assertStringContainsString("grep -Fxq 'BASTION_WP_INSTALL_OK: WordPress installed'", $workflow);
        self::assertStringContainsString('validate_archive "$fixture/downloads/wordpress.zip" wordpress', $workflow);
        self::assertStringContainsString('validate_archive "$fixture/downloads/woocommerce.zip" woocommerce', $workflow);
        self::assertStringContainsString('php tests/Integration/FixtureLifecycle.php verify', $workflow);
        self::assertStringContainsString('php tests/Integration/FixtureLifecycle.php activate', $workflow);
        self::assertStringContainsString("grep -Fxq 'BASTION_WC_COMPAT_OK: inventory assertions passed'", $workflow);
        self::assertStringContainsString('WC()->initialize_session();', $runtime);
        self::assertStringContainsString('WC()->initialize_cart();', $runtime);
        self::assertStringContainsString('WC()->session instanceof WC_Session', $runtime);
        self::assertStringContainsString('WC()->cart instanceof WC_Cart', $runtime);
        self::assertTrue(
            strpos($workflow, 'php tests/Integration/InstallWordPress.php')
                < strpos($workflow, 'php tests/Integration/FixtureLifecycle.php verify')
            && strpos($workflow, 'php tests/Integration/FixtureLifecycle.php verify')
                < strpos($workflow, 'php tests/Integration/FixtureLifecycle.php activate')
            && strpos($workflow, 'php tests/Integration/FixtureLifecycle.php activate')
                < strpos($workflow, 'php tests/Integration/WooCommerceRestInventory.php'),
            'The fixture lifecycle must install, verify, activate, then assert in separate processes.',
        );
    }

    #[DataProvider('validArchiveEntries')]
    public function testArchiveValidatorPreservesExpectedPluginRoots(string $root, array $entries): void
    {
        $archive = $this->archiveWith($entries);

        try {
            ArchiveValidator::assertSafe($archive, $root);
            self::addToAssertionCount(1);
        } finally {
            unlink($archive);
        }
    }

    /** @return iterable<string, array{string, list<string>}> */
    public static function validArchiveEntries(): iterable
    {
        yield 'WordPress' => ['wordpress', ['wordpress/', 'wordpress/index.php']];
        yield 'WooCommerce' => ['woocommerce', ['woocommerce/', 'woocommerce/woocommerce.php']];
    }

    #[DataProvider('unsafeArchiveEntries')]
    public function testArchiveValidatorRejectsUnsafeOrUnexpectedRoots(string $entry): void
    {
        $archive = $this->archiveWith([$entry]);

        try {
            $this->expectException(\RuntimeException::class);
            ArchiveValidator::assertSafe($archive, 'wordpress');
        } finally {
            unlink($archive);
        }
    }

    /** @return iterable<string, array{string}> */
    public static function unsafeArchiveEntries(): iterable
    {
        yield 'forward-slash drive path' => ['C:/wordpress/index.php'];
        yield 'backslash drive path' => ['C:\\wordpress\\index.php'];
        yield 'absolute path' => ['/wordpress/index.php'];
        yield 'parent traversal' => ['wordpress/../index.php'];
        yield 'unexpected root' => ['other/index.php'];
    }

    /** @param list<string> $entries */
    private function archiveWith(array $entries): string
    {
        $archive = sys_get_temp_dir() . '/bastion-fixture-' . bin2hex(random_bytes(6)) . '.zip';
        $zip = new ZipArchive();
        self::assertTrue($zip->open($archive, ZipArchive::CREATE | ZipArchive::OVERWRITE));

        foreach ($entries as $entry) {
            self::assertTrue($zip->addFromString($entry, str_ends_with($entry, '/') ? '' : '<?php'));
        }

        self::assertTrue($zip->close());

        return $archive;
    }
}
