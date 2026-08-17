# Bastion Security WP

Bastion Security WP is a read-only, defense-in-depth foundation for WordPress security posture diagnostics. It reports evidence; it does not make security changes and must never be treated as a guarantee of invulnerability.

## Current scope

The plugin adds five deterministic direct tests to WordPress Site Health: HTTPS/admin transport, dashboard file editing, file modifications and updates, a runtime compatibility notice, and a read-only REST surface inventory. Results are request-local, fail open per check, and provide evidence without a guarantee. WordPress has no unscored Site Health status, so unavailable or unsupported assessments use its supported `recommended` status rather than reporting a successful security observation.

The inventory exposes only registered namespaces, route patterns, and sorted unique HTTP methods. It reads only the required fields from an already initialized REST server's internal registry because the public route accessor applies filters and mutates route-options state; incompatible registry layouts are not assessed. It never initializes REST or invokes route callbacks. Output is escaped, capped at 100 deterministically sorted routes, and reports how many routes were omitted. Callback metadata, arguments, schemas, options, request data, credentials, paths, exceptions, and arbitrary configuration are never rendered.

No public endpoint, menu, REST policy, enforcement, dispatch hook, headers, login throttling, file integrity, audit, alerts, settings UI, database writes, cron tasks, filesystem mutations, logs, or cache are included. Access relies on WordPress's native capability-protected Site Health administration surface.

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

Deactivate Bastion Security WP to remove its five Site Health tests, including the REST inventory, then remove its plugin directory if desired. The plugin creates no external state, so no database, cron, cache, log, or filesystem cleanup is required.

## License

GPL-2.0-or-later.
