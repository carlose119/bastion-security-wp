<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

final class WordPressOrgMetadataTest extends TestCase
{
    private const EXPECTED_PLUGIN_NAME = 'Cerrojo Security Toolkit';
    private const EXPECTED_TEXT_DOMAIN = 'cerrojo-security-toolkit';
    private const EXPECTED_VERSION = '0.2.1';

    public function testPublicPluginHeaderUsesWordPressOrgIdentity(): void
    {
        $headers = $this->pluginHeaders();

        self::assertSame(self::EXPECTED_PLUGIN_NAME, $headers['Plugin Name'] ?? null);
        self::assertSame(self::EXPECTED_TEXT_DOMAIN, $headers['Text Domain'] ?? null);
        self::assertSame(self::EXPECTED_VERSION, $headers['Version'] ?? null);
        self::assertSame('6.8', $headers['Requires at least'] ?? null);
        self::assertSame('8.1', $headers['Requires PHP'] ?? null);
        self::assertSame('GPL-2.0-or-later', $headers['License'] ?? null);
        self::assertSame('https://github.com/carlose119/bastion-security-wp', $headers['Plugin URI'] ?? null);
    }

    public function testReadmePublishesRequiredWordPressOrgMetadata(): void
    {
        $readme = $this->readme();
        $headers = $this->readmeHeaders($readme);

        self::assertStringStartsWith('=== Cerrojo Security Toolkit ===', $readme);
        self::assertSame('carlose119', $headers['Contributors'] ?? null);
        self::assertSame('6.8', $headers['Requires at least'] ?? null);
        self::assertSame('7.1', $headers['Tested up to'] ?? null);
        self::assertSame(self::EXPECTED_VERSION, $headers['Stable tag'] ?? null);
        self::assertSame('8.1', $headers['Requires PHP'] ?? null);
        self::assertSame('GPLv2 or later', $headers['License'] ?? null);
        self::assertSame('https://www.gnu.org/licenses/gpl-2.0.html', $headers['License URI'] ?? null);

        $tags = array_values(array_filter(array_map('trim', explode(',', $headers['Tags'] ?? ''))));
        self::assertNotEmpty($tags);
        self::assertLessThanOrEqual(5, count($tags));
    }

    public function testReadmeVersionsAndRequirementsAgreeWithPluginHeader(): void
    {
        $pluginHeaders = $this->pluginHeaders();
        $readmeHeaders = $this->readmeHeaders($this->readme());

        self::assertSame($pluginHeaders['Version'] ?? null, $readmeHeaders['Stable tag'] ?? null);
        self::assertSame($pluginHeaders['Requires at least'] ?? null, $readmeHeaders['Requires at least'] ?? null);
        self::assertSame($pluginHeaders['Requires PHP'] ?? null, $readmeHeaders['Requires PHP'] ?? null);
    }

    public function testReadmeDescriptionsStayWithinDirectoryLimits(): void
    {
        $readme = $this->readme();
        self::assertMatchesRegularExpression('/\n\n([^\r\n]+)\r?\n\r?\n== Description ==\r?\n/s', $readme);
        preg_match('/\n\n([^\r\n]+)\r?\n\r?\n== Description ==\r?\n/s', $readme, $shortMatch);
        self::assertLessThanOrEqual(150, mb_strlen(trim($shortMatch[1])));

        self::assertMatchesRegularExpression('/== Description ==\r?\n(.*?)\r?\n== [^=]+ ==/s', $readme);
        preg_match('/== Description ==\r?\n(.*?)\r?\n== [^=]+ ==/s', $readme, $descriptionMatch);
        self::assertLessThanOrEqual(2500, mb_strlen(trim($descriptionMatch[1])));
    }

    public function testProductionTranslationsUseLiteralSourcesAndPublicTextDomain(): void
    {
        foreach ($this->productionPhpFiles() as $file) {
            $source = (string) file_get_contents($file);
            self::assertDoesNotMatchRegularExpression(
                '/\\\\(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(\s*[^\'\"]/',
                $source,
                $file . ' must use literal translation source strings.',
            );
            self::assertDoesNotMatchRegularExpression(
                '/\\\\(?:__|_e|_x|esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\([^;]*?[\'\"](?:bastion-security|bastion-security-wp)[\'\"]\s*\)/s',
                $source,
                $file . ' still uses an old public translation domain.',
            );
        }

        $fileEditorSource = (string) file_get_contents($this->root() . '/src/Admin/FileEditorAdmin.php');
        self::assertStringContainsString("PAGE_SLUG = 'bastion-security-wp'", $fileEditorSource);
        self::assertStringContainsString('https://github.com/carlose119/bastion-security-wp', (string) file_get_contents($this->root() . '/bastion-security-wp.php'));
    }

    /** @return array<string, string> */
    private function pluginHeaders(): array
    {
        return $this->parseHeaders((string) file_get_contents($this->root() . '/bastion-security-wp.php'));
    }

    private function readme(): string
    {
        $path = $this->root() . '/readme.txt';
        self::assertFileExists($path, 'The canonical WordPress.org readme.txt is required.');

        return (string) file_get_contents($path);
    }

    /** @return array<string, string> */
    private function readmeHeaders(string $readme): array
    {
        return $this->parseHeaders(strstr($readme, "\n\n", true) ?: $readme);
    }

    /** @return array<string, string> */
    private function parseHeaders(string $source): array
    {
        preg_match_all('/^[ \t*]*([^:\r\n]+):[ \t]*(.+)$/m', $source, $matches, PREG_SET_ORDER);
        $headers = [];

        foreach ($matches as $match) {
            $headers[trim($match[1])] = trim($match[2]);
        }

        return $headers;
    }

    /** @return list<string> */
    private function productionPhpFiles(): array
    {
        $files = [$this->root() . '/bastion-security-wp.php'];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->root() . '/src'));

        foreach ($iterator as $item) {
            if ($item->isFile() && $item->getExtension() === 'php') {
                $files[] = $item->getPathname();
            }
        }

        return $files;
    }

    private function root(): string
    {
        return dirname(__DIR__, 2);
    }
}
