=== Cerrojo Security Toolkit ===
Contributors: carlose119
Tags: security, hardening, login security, security headers, rest api
Requires at least: 6.8
Tested up to: 7.1
Stable tag: 0.2.1
Requires PHP: 8.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Review security diagnostics and apply reversible WordPress hardening controls with explicit compatibility guidance.

== Description ==

Cerrojo Security Toolkit adds focused security diagnostics and reversible, opt-in controls under Tools > Cerrojo Security Toolkit.

Current tools include:

* Security posture diagnostics with links to native WordPress Site Health.
* A file editor control that stores a plugin preference without editing wp-config.php.
* Best-effort login protection with temporary, progressive throttling.
* XML-RPC pingback protection that removes native inbound pingback methods and the WordPress-filtered X-Pingback header.
* Staged HTTP security header policies with baseline, optional groups, compatibility warnings, and rollback controls.
* Email alerts for supported plugin installation and activation events.
* Email alerts for supported administrator account lifecycle events.
* URL Change Alerts for supported successful local WordPress Address and Site Address updates.
* Selective REST API blocking by HTTP method and registered route template. Matching rules apply to all callers, including administrators and authenticated integrations.

Controls are designed to be reviewed, enabled, verified, and reversed individually. Coverage depends on the WordPress hooks and serving paths described in each tool. Login throttling is best-effort, email delivery depends on the site's mail transport, and headers must be verified at every cache, proxy, CDN, and origin edge.

Cerrojo Security Toolkit is not a web application firewall or malware scanner. It does not certify a site or guarantee complete protection. Use it as one layer in a broader security and recovery plan.

Saved settings remain until you change them. Deactivation stops the plugin's runtime behavior but preserves its settings, metrics, and temporary state. The plugin currently provides no uninstall cleanup routine.

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/cerrojo-security-toolkit/`, or install the plugin through the WordPress Plugins screen.
2. Activate Cerrojo Security Toolkit through the Plugins screen.
3. Open Tools > Cerrojo Security Toolkit.
4. Review the diagnostics before enabling controls.
5. Enable one control at a time, verify site behavior and integrations, and keep an independent recovery path available.

== Frequently Asked Questions ==

= Does Cerrojo Security Toolkit guarantee that my site is secure? =

No. It provides diagnostics and bounded hardening controls. It is not a WAF, malware scanner, certification, or complete protection guarantee.

= Can I reverse the settings? =

Yes. The settings UI provides controls to disable or clear plugin-managed policies. Some effects outside WordPress, such as an HSTS policy already remembered by a browser or email already handed to a mail server, cannot be recalled immediately.

= Who is affected by a blocked REST route? =

Every caller whose request matches the selected HTTP method and registered route template. There are no administrator, capability, cookie, or Application Password exemptions.

= What do URL Change Alerts observe? =

URL Change Alerts are independently opt-in under Tools > Cerrojo Security Toolkit > Hardening. Enable the tool, enter one to 50 valid recipient addresses separated by commas or new lines, and save. There is no administrator-email fallback and no reuse of recipients from another alert tool. Disabling preserves recipients for a later re-enable.

The tool observes only successful update_option_home and update_option_siteurl hooks for the existing home and siteurl settings in the current local-blog context. They are separate settings, so each successful update is a separate event. It does not observe option additions, deletions, network options, direct SQL or file changes, or scheduled scans, and it does not switch sites or fan out on multisite.

A changed raw string is observed even when redaction or truncation makes the displayed references identical. Displayed values remove user information, query strings, and fragments; invalid values are Unavailable. Paths are retained when available and may be sensitive. Cerrojo makes one plain-text wp_mail attempt per recipient; an attempt is not delivery. Mail failures do not block a WordPress update or trigger automatic rollback.

= Does uninstalling remove saved data? =

No. This version has no uninstall cleanup routine, so plugin-owned settings remain unless they are changed or removed separately.

== Changelog ==

= 0.2.1 =

* Corrected the public name, text domain, and package slug to avoid an existing WordPress update identity collision.

= 0.2.0 =

* Added an actionable security dashboard and staged HTTP security header policies.
* Added login protection and XML-RPC pingback protection.
* Added plugin activity and administrator account alerts.
* Added selective REST API blocking by HTTP method and registered route template.
* Improved WordPress.org packaging and directory compliance.

= 0.1.0 =

* Initial release.
