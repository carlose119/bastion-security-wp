# Bastion Security WP

Bastion Security WP is a read-only, defense-in-depth foundation for WordPress security posture diagnostics. It reports evidence; it does not make security changes and must never be treated as a guarantee of invulnerability.

## Current scope

The plugin adds five deterministic direct tests to WordPress Site Health: HTTPS/admin transport, dashboard file editing, file modifications and updates, a runtime compatibility notice, and a read-only REST surface inventory. Results are request-local, fail open per check, and provide evidence without a guarantee. WordPress has no unscored Site Health status, so unavailable or unsupported assessments use its supported `recommended` status rather than reporting a successful security observation.

The inventory exposes only registered namespaces, route patterns, and sorted unique HTTP methods. It reads only the required fields from an already initialized REST server's internal registry because the public route accessor applies filters and mutates route-options state; incompatible registry layouts are not assessed. It never initializes REST or invokes route callbacks. Output is escaped, capped at 100 deterministically sorted routes, and reports how many routes were omitted. Callback metadata, arguments, schemas, options, request data, credentials, paths, exceptions, and arbitrary configuration are never rendered.

No public endpoint, menu, REST policy, enforcement, dispatch hook, headers, login throttling, file integrity, audit, alerts, settings UI, database writes, cron tasks, filesystem mutations, logs, or cache are included. Access relies on WordPress's native capability-protected Site Health administration surface. WooCommerce compatibility remains future matrix work and is not claimed without a real fixture.

## Compatibility target

- WordPress 6.8 through 7.0
- PHP 8.1 through 8.4 where those WordPress versions and upstream dependencies support it

Compatibility is a target for validation, not a claim that unsupported upstream combinations are safe.

## Development

Run commands from this plugin directory:

```shell
composer install
composer validate --strict
composer test
```

The repository excludes `vendor/`. Build an installable release artifact in a clean staging directory and run `composer install --no-dev --classmap-authoritative` there so runtime autoloading is included without development packages.

## Rollback

Deactivate Bastion Security WP to remove its five Site Health tests, including the REST inventory, then remove its plugin directory if desired. The plugin creates no external state, so no database, cron, cache, log, or filesystem cleanup is required.

## License

GPL-2.0-or-later.
