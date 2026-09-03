=== Bastion Security ===
Contributors: carlose119
Tags: security, hardening, login security, security headers, rest api
Requires at least: 6.8
Tested up to: 7.1
Stable tag: 0.2.0
Requires PHP: 8.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Review security diagnostics and apply reversible WordPress hardening controls with explicit compatibility guidance.

== Description ==

Bastion Security adds focused security diagnostics and reversible, opt-in controls under Tools > Bastion Security.

Current tools include:

* Security posture diagnostics with links to native WordPress Site Health.
* A file editor control that stores a plugin preference without editing wp-config.php.
* Best-effort login protection with temporary, progressive throttling.
* XML-RPC pingback protection that removes native inbound pingback methods and the WordPress-filtered X-Pingback header.
* Staged HTTP security header policies with baseline, optional groups, compatibility warnings, and rollback controls.
* Email alerts for supported plugin installation and activation events.
* Email alerts for supported administrator account lifecycle events.
* Selective REST API blocking by HTTP method and registered route template. Matching rules apply to all callers, including administrators and authenticated integrations.

Controls are designed to be reviewed, enabled, verified, and reversed individually. Coverage depends on the WordPress hooks and serving paths described in each tool. Login throttling is best-effort, email delivery depends on the site's mail transport, and headers must be verified at every cache, proxy, CDN, and origin edge.

Bastion Security is not a web application firewall or malware scanner. It does not certify a site or guarantee complete protection. Use it as one layer in a broader security and recovery plan.

Saved settings remain until you change them. Deactivation stops the plugin's runtime behavior but preserves its settings, metrics, and temporary state. The plugin currently provides no uninstall cleanup routine.

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/bastion-security/`, or install the plugin through the WordPress Plugins screen.
2. Activate Bastion Security through the Plugins screen.
3. Open Tools > Bastion Security.
4. Review the diagnostics before enabling controls.
5. Enable one control at a time, verify site behavior and integrations, and keep an independent recovery path available.

== Frequently Asked Questions ==

= Does Bastion Security guarantee that my site is secure? =

No. It provides diagnostics and bounded hardening controls. It is not a WAF, malware scanner, certification, or complete protection guarantee.

= Can I reverse the settings? =

Yes. The settings UI provides controls to disable or clear plugin-managed policies. Some effects outside WordPress, such as an HSTS policy already remembered by a browser or email already handed to a mail server, cannot be recalled immediately.

= Who is affected by a blocked REST route? =

Every caller whose request matches the selected HTTP method and registered route template. There are no administrator, capability, cookie, or Application Password exemptions.

= Does uninstalling remove saved data? =

No. This version has no uninstall cleanup routine, so plugin-owned settings remain unless they are changed or removed separately.

== Changelog ==

= 0.2.0 =

* Added an actionable security dashboard and staged HTTP security header policies.
* Added login protection and XML-RPC pingback protection.
* Added plugin activity and administrator account alerts.
* Added selective REST API blocking by HTTP method and registered route template.
* Improved WordPress.org packaging and directory compliance.

= 0.1.0 =

* Initial release.
