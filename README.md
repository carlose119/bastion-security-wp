# Bastion Security WP

Bastion Security WP provides focused WordPress security posture diagnostics and two reversible hardening tools. It reports evidence, not a guarantee of invulnerability.

## Quick usage

1. Open **Tools > Bastion Security** as an administrator with `manage_options`.
2. Review the six Bastion diagnostics.
3. Enable either the WordPress file-editor lock or the conservative HTTP security-header preset.
4. For the header preset, verify the final response headers in browser developer tools and, when applicable, at the CDN edge.

## Current scope

The plugin adds six deterministic direct tests to WordPress Site Health, in stable order:

1. HTTPS and admin transport posture.
2. File editor posture.
3. Security header preset preference.
4. File modification and update posture.
5. Runtime compatibility notice.
6. Read-only REST surface inventory.

The assessments remain request-local and fail open per check. WordPress has no unscored Site Health status, so unavailable or unsupported assessments use its supported `recommended` status rather than reporting a successful security observation. The Bastion dashboard presents the same results with Site Health-inspired, accessible `details`/`summary` markup and links to native WordPress Site Health for the full suite.

## Reversible tools

### WordPress file-editor lock

On single-site installations, an administrator can enable or disable a plugin-owned preference through a nonce-protected POST action. When enabled, Bastion defines `DISALLOW_FILE_EDIT` as `true` early in each request only if the constant is not already defined.

Bastion writes only its own WordPress option; it never edits `wp-config.php` or another file. If another source defines `DISALLOW_FILE_EDIT`, Bastion preserves that value, reports its effective result, and does not claim it can override or roll it back. This tool is unavailable on multisite and performs no policy mutation there.

### HTTP security-header preset

The per-site preset adds exactly these headers through WordPress's `wp_headers` filter:

```text
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

The behavior is deliberately add-only:

- Disabled means the WordPress header array is returned unchanged.
- Enabled appends only missing preset headers, in the order shown above.
- Existing names are detected case-insensitively. Their original names, values, and ordering are preserved.
- Applying the preset repeatedly does not duplicate either header.
- The option remains per-site on multisite; Bastion does not claim network-wide enforcement.

This tool does **not** add CSP, HSTS, X-Frame-Options, Permissions-Policy, or any other header. It does not call PHP's `header()` directly.

#### Coverage and verification limit

`wp_headers` is applied by `WP::send_headers()`, so the preset covers standard front-end responses that pass through that WordPress path. It is not guaranteed for wp-admin, wp-login, REST responses, redirects, static files, CDN or cache responses, or headers emitted by the web server.

A Good Site Health result means only that Bastion's per-site preference is enabled. It does not verify end-to-end delivery. Check the final headers in browser developer tools and at the CDN edge when a CDN is present.

## REST inventory boundaries

The inventory exposes only registered namespaces, route patterns, and sorted unique HTTP methods. It reads only required fields from an already initialized REST server registry; incompatible layouts are not assessed. It never initializes REST or invokes route callbacks.

Output is escaped, capped at 100 deterministically sorted routes, and reports omitted routes. Callback metadata, arguments, schemas, options, request data, credentials, paths, exceptions, and arbitrary configuration are never rendered.

## Explicit non-goals

Bastion includes no public mutation endpoint, REST policy, login throttling, file integrity monitoring, audit log, alerts, cron tasks, filesystem writes, or cache. The only settings UI and database writes are the Tools page and the two plugin-owned options described above. Mutations use WordPress administrative capability and nonce protections; there is no AJAX or REST mutation path.

## Compatibility target

- WordPress 6.8 through 7.0
- PHP 8.1 through 8.4 where those WordPress versions and upstream dependencies support it

Compatibility is a validation target, not a claim that unsupported upstream combinations are safe.

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

- **Header preset:** disable it under **Tools > Bastion Security**. Bastion immediately stops adding its two headers. Headers supplied by WordPress, another plugin, a cache, CDN, proxy, or web server remain unchanged.
- **File-editor lock:** disable it on the same page to stop Bastion from defining the constant on the next request. Externally defined values remain unchanged.
- **Plugin:** deactivate Bastion to remove its six Site Health tests and future runtime enforcement. Plugin-owned options remain in the database for later reactivation.

Bastion creates no cron, cache, log, or filesystem state requiring cleanup.

## License

GPL-2.0-or-later.
