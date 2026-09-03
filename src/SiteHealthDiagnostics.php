<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use BastionSecurityWP\Security\AdministratorAccountAlertPolicy;
use BastionSecurityWP\Security\FileEditorPolicy;
use BastionSecurityWP\Security\LoginProtectionPolicy;
use BastionSecurityWP\Security\PluginActivityAlertPolicy;
use BastionSecurityWP\Security\SecurityHeadersPolicy;
use BastionSecurityWP\Security\XmlRpcPingbackPolicy;
use Closure;
use Throwable;

final class SiteHealthDiagnostics
{
    private Closure $observe;
    private Closure $escape;
    private RestSurfaceInventory $restInventory;
    private PluginUpdateCompatibility $pluginUpdateCompatibility;

    public function __construct(
        ?callable $observe = null,
        ?callable $escape = null,
        ?RestSurfaceInventory $restInventory = null,
        private readonly ?FileEditorPolicy $fileEditorPolicy = null,
        private readonly ?SecurityHeadersPolicy $securityHeadersPolicy = null,
        ?PluginUpdateCompatibility $pluginUpdateCompatibility = null,
        private readonly ?LoginProtectionPolicy $loginProtectionPolicy = null,
        private readonly ?PluginActivityAlertPolicy $pluginActivityAlertPolicy = null,
        private readonly ?AdministratorAccountAlertPolicy $administratorAccountAlertPolicy = null,
        private readonly ?XmlRpcPingbackPolicy $xmlRpcPingbackPolicy = null,
    ) {
        $this->observe = Closure::fromCallable($observe ?? self::observe(...));
        $this->escape = Closure::fromCallable($escape ?? static fn (string $value): string => \esc_html($value));
        $this->restInventory = $restInventory ?? new RestSurfaceInventory();
        $this->pluginUpdateCompatibility = $pluginUpdateCompatibility ?? new PluginUpdateCompatibility();
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
            'bastion_security_wp_login_protection' => [
                'label' => 'Bastion: Login Protection',
                'test' => $this->loginProtection(...),
            ],
            'bastion_security_wp_xmlrpc_pingback_protection' => [
                'label' => 'Bastion: XML-RPC Pingback Protection',
                'test' => $this->xmlRpcPingbackProtection(...),
            ],
            'bastion_security_wp_plugin_activity_alerts' => [
                'label' => 'Bastion: Plugin activity email alerts',
                'test' => $this->pluginActivityAlerts(...),
            ],
            'bastion_security_wp_administrator_account_alerts' => [
                'label' => 'Bastion: Administrator account alerts',
                'test' => $this->administratorAccountAlerts(...),
            ],
            'bastion_security_wp_security_headers' => [
                'label' => 'Bastion: Security header preset',
                'test' => $this->securityHeaders(...),
            ],
            'bastion_security_wp_file_modifications' => [
                'label' => 'Bastion: File modification posture',
                'test' => $this->fileModifications(...),
            ],
            'bastion_security_wp_runtime' => [
                'label' => 'Bastion: Runtime compatibility notice',
                'test' => $this->runtime(...),
            ],
            'bastion_security_wp_plugin_update_compatibility' => [
                'label' => 'Bastion: Plugin update compatibility',
                'test' => $this->pluginUpdateCompatibility->report(...),
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
    public function loginProtection(): array
    {
        try {
            $enabled = $this->loginProtectionPolicy?->isEnabled() ?? false;

            return $this->result(
                $enabled ? DiagnosticStatus::Good : DiagnosticStatus::Recommended,
                'Bastion: Login Protection',
                'Evidence: The per-site Login Protection setting is ' . ($enabled ? 'enabled.' : 'disabled.'),
                'Meaning: A Good result means only that the setting is enabled; it does not guarantee authentication availability or attack prevention. Standard wp-login and flows through wp_authenticate(), including ordinary XML-RPC, are covered. REST Application Passwords are not covered. Only REMOTE_ADDR identifies the direct peer; forwarded headers are not trusted, so shared proxy users can share a bucket. Transient eviction and read-modify-write races can weaken enforcement. This is not WAF or DDoS protection.',
                'Remediation: Review Tools > Bastion Security > Hardening, assess shared-address lockout risk, and retain an independent recovery path.',
            );
        } catch (Throwable) {
            return $this->notAssessed('Bastion: Login Protection');
        }
    }

    /** @return array<string, mixed> */
    public function xmlRpcPingbackProtection(): array
    {
        try {
            $state = $this->xmlRpcPingbackPolicy?->state() ?? ['assessed' => false, 'enabled' => false];
            if (! $state['assessed']) {
                return $this->result(
                    DiagnosticStatus::Recommended,
                    'Bastion: XML-RPC Pingback Protection',
                    'Evidence: The per-site XML-RPC Pingback Protection setting could not be read.',
                    'Meaning: Not assessed. Bastion made no claim about pingback method or header filtering.',
                    'Remediation: Retry Site Health, investigate the local option read, then review Tools > Bastion Security > Hardening.',
                );
            }

            return $this->result(
                $state['enabled'] ? DiagnosticStatus::Good : DiagnosticStatus::Recommended,
                'Bastion: XML-RPC Pingback Protection',
                'Evidence: The readable per-site XML-RPC Pingback Protection setting is ' . ($state['enabled'] ? 'enabled.' : 'disabled.'),
                'Meaning: A Good result means only that Bastion is configured to remove pingback.ping, pingback.extensions.getPingbacks, and WordPress-filtered X-Pingback headers. It is not absolute enforcement: later same-priority filters and direct server, proxy, or CDN headers are outside this result. Other authenticated XML-RPC methods remain available.',
                $state['enabled']
                    ? 'Remediation: Verify application compatibility and final headers independently; disable the setting under Tools > Bastion Security > Hardening if native pingback behavior is required.'
                    : 'Remediation: Review native pingback compatibility, then enable the per-site setting under Tools > Bastion Security > Hardening if the removals are appropriate.',
            );
        } catch (Throwable) {
            return $this->notAssessed('Bastion: XML-RPC Pingback Protection');
        }
    }

    /** @return array<string, mixed> */
    public function pluginActivityAlerts(): array
    {
        try {
            $state = $this->pluginActivityAlertPolicy?->state() ?? ['enabled' => false, 'recipients' => []];
            $recipientCount = count($state['recipients']);

            return $this->result(
                $state['enabled'] ? DiagnosticStatus::Good : DiagnosticStatus::Recommended,
                'Bastion: Plugin activity email alerts',
                sprintf(
                    'Evidence: The per-site plugin activity email alert setting is %s with %d configured %s.',
                    $state['enabled'] ? 'enabled' : 'disabled',
                    $recipientCount,
                    $recipientCount === 1 ? 'recipient' : 'recipients',
                ),
                'Meaning: An enabled result means Bastion will attempt sends for observed plugin installations and successful activations; it does not prove delivery.',
                'Remediation: Review recipients and event limitations under Tools > Bastion Security > Hardening, and verify the site wp_mail transport independently.',
            );
        } catch (Throwable) {
            return $this->notAssessed('Bastion: Plugin activity email alerts');
        }
    }

    /** @return array<string, mixed> */
    public function administratorAccountAlerts(): array
    {
        try {
            $state = $this->administratorAccountAlertPolicy?->diagnosticState()
                ?? ['assessed' => false, 'enabled' => false, 'recipients' => []];
            if (! $state['assessed']) {
                return $this->result(
                    DiagnosticStatus::Recommended,
                    'Bastion: Administrator account alerts',
                    'Evidence: The per-site Administrator Account Alerts configuration could not be read.',
                    'Meaning: Not assessed. Bastion makes no claim about alert configuration, email delivery, or complete administrator-event capture.',
                    'Remediation: Retry Site Health, investigate the local option read, then review Tools > Bastion Security > Hardening.',
                );
            }

            $recipientCount = count($state['recipients']);

            return $this->result(
                $state['enabled'] && $recipientCount > 0 ? DiagnosticStatus::Good : DiagnosticStatus::Recommended,
                'Bastion: Administrator account alerts',
                sprintf(
                    'Evidence: The readable per-site Administrator Account Alerts setting is %s with %d configured %s.',
                    $state['enabled'] ? 'enabled' : 'disabled',
                    $recipientCount,
                    $recipientCount === 1 ? 'recipient' : 'recipients',
                ),
                'Meaning: A Good result means only that the configuration is readable, enabled, and has recipients. It does not prove wp_mail delivery or complete event capture.',
                'Remediation: Review recipients, privacy, actor context, and event limitations under Tools > Bastion Security > Hardening, then verify mail transport independently.',
            );
        } catch (Throwable) {
            return $this->notAssessed('Bastion: Administrator account alerts');
        }
    }

    /** @return array<string, mixed> */
    public function securityHeaders(): array
    {
        try {
            $baselineEnabled = $this->securityHeadersPolicy?->isEnabled() ?? false;
            $groups = $this->securityHeadersPolicy?->enabledGroupIds() ?? [];
            $groupCount = count($groups);
            $groupSummary = $groupCount === 0 ? 'none' : implode(', ', $groups);
            $configured = $baselineEnabled || $groupCount > 0;

            return $this->result(
                $configured ? DiagnosticStatus::Good : DiagnosticStatus::Recommended,
                'Bastion: Security header preset',
                sprintf(
                    'Evidence: The per-site Bastion security-header baseline preference is %s; %d active optional %s (%s).',
                    $baselineEnabled ? 'enabled' : 'disabled',
                    $groupCount,
                    $groupCount === 1 ? 'group' : 'groups',
                    $groupSummary,
                ),
                'Meaning: A Good result only means at least one Bastion preference is configured; configuration is not end-to-end delivery proof.',
                'Remediation: Open Tools > Bastion Security to review the policies, then inspect final response headers at the browser or CDN edge.',
            );
        } catch (Throwable) {
            return $this->notAssessed('Bastion: Security header preset');
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
                'Bastion: Login Protection' => 'login_protection',
                'Bastion: XML-RPC Pingback Protection' => 'xmlrpc_pingback_protection',
                'Bastion: Plugin activity email alerts' => 'plugin_activity_alerts',
                'Bastion: Administrator account alerts' => 'administrator_account_alerts',
                'Bastion: Security header preset' => 'security_headers',
                'Bastion: File modification posture' => 'file_modifications',
                default => 'runtime',
            },
        ];
    }
}
