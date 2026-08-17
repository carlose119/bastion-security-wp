<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use Closure;
use Throwable;

final class SiteHealthDiagnostics
{
    private Closure $observe;
    private Closure $escape;
    private RestSurfaceInventory $restInventory;

    public function __construct(?callable $observe = null, ?callable $escape = null, ?RestSurfaceInventory $restInventory = null)
    {
        $this->observe = Closure::fromCallable($observe ?? self::observe(...));
        $this->escape = Closure::fromCallable($escape ?? static fn (string $value): string => \esc_html($value));
        $this->restInventory = $restInventory ?? new RestSurfaceInventory();
    }

    /** @param array<string, mixed> $tests
     *  @return array<string, mixed>
     */
    public function register(array $tests): array
    {
        $tests['direct']['bastion_security_wp_transport'] = [
            'label' => 'Bastion: HTTPS and admin transport posture',
            'test' => $this->transport(...),
        ];
        $tests['direct']['bastion_security_wp_file_editor'] = [
            'label' => 'Bastion: File editor posture',
            'test' => $this->fileEditor(...),
        ];
        $tests['direct']['bastion_security_wp_file_modifications'] = [
            'label' => 'Bastion: File modification posture',
            'test' => $this->fileModifications(...),
        ];
        $tests['direct']['bastion_security_wp_runtime'] = [
            'label' => 'Bastion: Runtime compatibility notice',
            'test' => $this->runtime(...),
        ];
        $tests['direct']['bastion_security_wp_rest_surface_inventory'] = [
            'label' => 'Bastion: REST surface inventory',
            'test' => $this->restInventory->report(...),
        ];

        return $tests;
    }

    /** @return array<string, mixed> */
    public function transport(): array
    {
        try {
            $ssl = (bool) ($this->observe)('is_ssl');
            $admin = (bool) ($this->observe)('force_ssl_admin');

            return $this->result(
                $ssl && $admin ? DiagnosticStatus::Good : DiagnosticStatus::Recommended,
                'Bastion: HTTPS and admin transport posture',
                sprintf('Evidence: The current request is %s; FORCE_SSL_ADMIN is %s.', $ssl ? 'HTTPS' : 'not HTTPS', $admin ? 'enabled' : 'not enabled'),
                'Meaning: Encrypted administration transport reduces exposure of authenticated sessions in transit.',
                'Remediation: The site owner should validate HTTPS end to end, then enable FORCE_SSL_ADMIN in WordPress configuration.',
            );
        } catch (Throwable) {
            return $this->notAssessed('Bastion: HTTPS and admin transport posture');
        }
    }

    /** @return array<string, mixed> */
    public function fileEditor(): array
    {
        try {
            $disabled = (bool) ($this->observe)('disallow_file_edit');

            return $this->result(
                $disabled ? DiagnosticStatus::Good : DiagnosticStatus::Recommended,
                'Bastion: File editor posture',
                'Evidence: The built-in plugin and theme editor is ' . ($disabled ? 'disabled.' : 'available.'),
                'Meaning: Disabling dashboard code editing reduces accidental or compromised-admin source changes.',
                'Remediation: The site owner should set DISALLOW_FILE_EDIT to true in WordPress configuration.',
            );
        } catch (Throwable) {
            return $this->notAssessed('Bastion: File editor posture');
        }
    }

    /** @return array<string, mixed> */
    public function fileModifications(): array
    {
        try {
            $blocked = (bool) ($this->observe)('disallow_file_mods');

            return $this->result(
                $blocked ? DiagnosticStatus::Recommended : DiagnosticStatus::Good,
                'Bastion: File modification posture',
                'Evidence: WordPress file installation and updates are ' . ($blocked ? 'blocked.' : 'permitted.'),
                'Meaning: DISALLOW_FILE_MODS is distinct from editor hardening and can prevent security updates.',
                'Remediation: The site owner should keep updates available or document and verify an external patching process.',
            );
        } catch (Throwable) {
            return $this->notAssessed('Bastion: File modification posture');
        }
    }

    /** @return array<string, mixed> */
    public function runtime(): array
    {
        try {
            $wp = $this->safeVersion(($this->observe)('wordpress_version'));
            $php = $this->safeVersion(($this->observe)('php_version'));
            $target = $wp !== null && $php !== null
                && version_compare($wp, '6.8', '>=') && version_compare($wp, '7.1', '<')
                && version_compare($php, '8.1', '>=') && version_compare($php, '8.5', '<');
            $evidence = sprintf(
                'Evidence: WordPress %s and PHP %s were observed.',
                ($this->escape)($wp ?? 'unavailable'),
                ($this->escape)($php ?? 'unavailable'),
            );

            if (! $target) {
                return $this->result(
                    DiagnosticStatus::Recommended,
                    'Bastion: Runtime compatibility notice',
                    $evidence,
                    'Meaning: Not assessed. This runtime is outside Bastion validation targets; that alone is not an insecurity finding.',
                    'Remediation: The site owner should consult official WordPress and PHP compatibility and support guidance.',
                );
            }

            return $this->result(
                DiagnosticStatus::Good,
                'Bastion: Runtime compatibility notice',
                $evidence,
                'Meaning: This runtime is within Bastion validation targets; this is not a security guarantee.',
                'Remediation: The site owner should continue applying supported WordPress and PHP updates.',
            );
        } catch (Throwable) {
            return $this->notAssessed('Bastion: Runtime compatibility notice');
        }
    }

    private static function observe(string $key): mixed
    {
        global $wp_version;

        return match ($key) {
            'is_ssl' => \is_ssl(),
            'force_ssl_admin' => defined('FORCE_SSL_ADMIN') && (bool) constant('FORCE_SSL_ADMIN'),
            'disallow_file_edit' => defined('DISALLOW_FILE_EDIT') && (bool) constant('DISALLOW_FILE_EDIT'),
            'disallow_file_mods' => defined('DISALLOW_FILE_MODS') && (bool) constant('DISALLOW_FILE_MODS'),
            'wordpress_version' => $wp_version,
            'php_version' => PHP_VERSION,
        };
    }

    private function safeVersion(mixed $version): ?string
    {
        return is_string($version) && preg_match('/^\d+(?:\.\d+){1,2}$/', $version) === 1 ? $version : null;
    }

    /** @return array<string, mixed> */
    private function notAssessed(string $label): array
    {
        return $this->result(
            DiagnosticStatus::Recommended,
            $label,
            'Evidence: The observation was unavailable for this request.',
            'Meaning: Not assessed. No posture conclusion was made.',
            'Remediation: The site owner should retry Site Health and investigate the local observation failure.',
        );
    }

    /** @return array<string, mixed> */
    private function result(DiagnosticStatus $status, string $label, string $evidence, string $meaning, string $remediation): array
    {
        return [
            'label' => $label,
            'status' => $status->value,
            'badge' => ['label' => 'Bastion Security', 'color' => 'blue'],
            'description' => '<p>' . $evidence . '</p><p>' . $meaning . '</p><p>Ownership: Site owner or hosting administrator.</p>',
            'actions' => '<p>' . $remediation . '</p>',
            'test' => 'bastion_security_wp_' . match ($label) {
                'Bastion: HTTPS and admin transport posture' => 'transport',
                'Bastion: File editor posture' => 'file_editor',
                'Bastion: File modification posture' => 'file_modifications',
                default => 'runtime',
            },
        ];
    }
}
