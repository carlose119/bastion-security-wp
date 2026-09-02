# Bastion Security WP

Bastion Security WP is a defense-in-depth foundation for WordPress security posture diagnostics with one narrowly scoped remediation tool. It reports evidence and can manage a reversible dashboard file-editor lock; it must never be treated as a guarantee of invulnerability.

## Current scope

The plugin adds five deterministic direct tests to WordPress Site Health: HTTPS/admin transport, dashboard file editing, file modifications and updates, a runtime compatibility notice, and a read-only REST surface inventory. The assessments remain read-only, request-local, and fail open per check. WordPress has no unscored Site Health status, so unavailable or unsupported assessments use its supported `recommended` status rather than reporting a successful security observation.

Tools > Bastion Security provides a concise dashboard for the same five Bastion diagnostics in stable order, followed by the single remediation workflow. Each dashboard result shows its label, status, evidence, meaning, and recommended action. The page links to WordPress Site Health for the full native test suite instead of copying or replacing native tests. If the REST registry is not already available during the admin-page request, the inventory remains Not assessed and points users to Site Health; Bastion does not initialize or dispatch REST solely for the dashboard.

On single-site installations, an administrator with `manage_options` can enable or disable a plugin-owned file-editor preference through a nonce-protected POST action. When enabled, Bastion defines `DISALLOW_FILE_EDIT` as `true` early in each request only if the constant is not already defined. Bastion writes only its own WordPress option; it never edits `wp-config.php` or any filesystem/configuration file. If another source defines `DISALLOW_FILE_EDIT`, Bastion preserves that value, reports its effective result, and does not claim it can override or roll it back. The tool is unavailable on multisite and performs no policy mutation there.

The inventory exposes only registered namespaces, route patterns, and sorted unique HTTP methods. It reads only the required fields from an already initialized REST server's internal registry because the public route accessor applies filters and mutates route-options state; incompatible registry layouts are not assessed. It never initializes REST or invokes route callbacks. Output is escaped, capped at 100 deterministically sorted routes, and reports how many routes were omitted. Callback metadata, arguments, schemas, options, request data, credentials, paths, exceptions, and arbitrary configuration are never rendered.

No public endpoint, REST policy, dispatch hook, headers, login throttling, file integrity, audit, alerts, cron tasks, filesystem mutations, logs, or cache are included. The only menu, enforcement, settings UI, and database write are the Tools page and its plugin-owned file-editor option described above. Access relies on WordPress's native administrative capability and nonce protections.

## Compatibility target

- WordPress 6.8 through 7.0
- PHP 8.1 through 8.4 where those WordPress versions and upstream dependencies support it

Compatibility is a target for validation, not a claim that unsupported upstream combinations are safe.

## Development

Run commands from this plugin directory:

```shell
composer install
composer check
```

CI runs the same validation, full PHPUnit suite, dependency audit, and PHP syntax checks on Ubuntu with PHP 8.1, 8.2, 8.3, and 8.4. A separate hosted job installs WordPress, verifies its schema, activates both plugins, and has passed the non-interference assertions for PHP 8.4, WordPress 7.0.4, WooCommerce 11.0.1, and MariaDB 11.4.7. This is evidence for that exact tuple, not a general WooCommerce compatibility claim.

## Build

Build and verify the installable ZIP locally:

```shell
composer package
composer package:verify
```

The artifact is written to `.build/bastion-security-wp.zip`, rooted at `bastion-security-wp/`. The explicit distribution contains the plugin entry point, `src/`, README, Composer metadata, and a production-only authoritative autoloader generated in disposable staging. It excludes tests, development dependencies, PHPUnit configuration, Git metadata, GitHub workflows, caches, and local tooling.

Archive entries are sorted, use normalized `/` separators, fixed permissions, and a fixed 1980 timestamp. Identical bytes are expected with the same PHP, Composer, libzip, dependency lockfile, and source; ZIP compression implementations can differ across environments, so cross-toolchain byte identity is not claimed.

## Rollback

Disable the Bastion file-editor lock from Tools > Bastion Security to remove its effect on the next request, then deactivate the plugin to remove its five Site Health tests and runtime enforcement. Deactivation alone also stops future enforcement, but the plugin-owned option remains in the WordPress database for a later reactivation. An externally defined `DISALLOW_FILE_EDIT` value is outside Bastion ownership and remains unchanged. Bastion creates no cron, cache, log, or filesystem state requiring cleanup.

## License

GPL-2.0-or-later.
