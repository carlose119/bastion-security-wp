<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use BastionSecurityWP\Security\FileEditorPolicy;
use Closure;
use Throwable;

final class SiteHealthDiagnostics
{
    private Closure $observe;
    private Closure $escape;
    private RestSurfaceInventory $restInventory;

    public function __construct(
        ?callable $observe = null,
        ?callable $escape = null,
        ?RestSurfaceInventory $restInventory = null,
        private readonly ?FileEditorPolicy $fileEditorPolicy = null,
    ) {
        $this->observe = Closure::fromCallable($observe ?? self::observe(...));
        $this->escape = Closure::fromCallable($escape ?? static fn (string $value): string => \esc_html($value));
        $this->restInventory = $restInventory ?? new RestSurfaceInventory();
    }

    /** @param array<string, mixed> $tests
     *  @return array<string, mixed>
     */
    public function register(array $tests): array
    {
        foreach ($this->definitions() as $id => $definition) {
            $tests['direct'][$id] = $definition;
        }

        return $tests;
    }

    /** @return list<array<string, mixed>> */
    public function reports(): array
    {
        return array_values(array_map(
            static fn (array $definition): array => ($definition['test'])(),
            $this->definitions(),
        ));
    }

    /** @return array<string, array{label: string, test: callable(): array<string, mixed>}> */
    private function definitions(): array
    {
        return [
            'bastion_security_wp_transport' => [
                'label' => 'Bastion: HTTPS and admin transport posture',
                'test' => $this->transport(...),
            ],
            'bastion_security_wp_file_editor' => [
                'label' => 'Bastion: File editor posture',
                'test' => $this->fileEditor(...),
            ],
            'bastion_security_wp_file_modifications' => [
                'label' => 'Bastion: File modification posture',
                'test' => $this->fileModifications(...),
            ],
            'bastion_security_wp_runtime' => [
                'label' => 'Bastion: Runtime compatibility notice',
                'test' => $this->runtime(...),
            ],
            'bastion_security_wp_rest_surface_inventory' => [
                'label' => 'Bastion: REST surface inventory',
                'test' => $this->restInventory->report(...),
            ],
        ];
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
            if ($this->fileEditorPolicy === null) {
                $disabled = (bool) ($this->observe)('disallow_file_edit');
                $evidence = 'Evidence: The built-in plugin and theme editor is ' . ($disabled ? 'disabled.' : 'available.');
                $remediation = $disabled
                    ? 'Remediation: No change is suggested for the file-editor lock.'
                    : 'Remediation: Open Tools > Bastion Security to enable the plugin-managed lock, or define DISALLOW_FILE_EDIT externally.';
            } else {
                $state = $this->fileEditorPolicy->state();
                $disabled = $state['effective_disabled'];

                if (! $state['available']) {
                    $evidence = 'Evidence: The built-in plugin and theme editor is ' . ($disabled ? 'disabled.' : 'available.') . ' Bastion management is unavailable on multisite.';
                    $remediation = 'Remediation: A network administrator should manage the file-editor policy outside this Bastion tool.';
                } elseif ($state['external_defined']) {
                    $evidence = 'Evidence: The built-in plugin and theme editor is ' . ($disabled ? 'disabled.' : 'available.') . ' DISALLOW_FILE_EDIT is defined outside Bastion.';
                    $remediation = 'Remediation: Review the external WordPress configuration. Bastion will not override or remove that value.';
                } elseif ($state['plugin_managed']) {
                    $evidence = 'Evidence: The built-in plugin and theme editor is disabled by the Bastion-managed lock.';
                    $remediation = 'Remediation: Open Tools > Bastion Security to review or disable the Bastion preference.';
                } else {
                    $evidence = 'Evidence: The built-in plugin and theme editor is available and Bastion does not manage the lock.';
                    $remediation = 'Remediation: Open Tools > Bastion Security to enable the plugin-managed lock.';
                }
            }

            return $this->result(
                $disabled ? DiagnosticStatus::Good : DiagnosticStatus::Recommended,
                'Bastion: File editor posture',
                $evidence,
                'Meaning: Disabling dashboard code editing reduces accidental or compromised-admin source changes.',
                $remediation,
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
