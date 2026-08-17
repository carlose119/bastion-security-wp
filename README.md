# Bastion Security WP

Bastion Security WP is a read-only, defense-in-depth foundation for WordPress security posture diagnostics. It reports evidence; it does not make security changes and must never be treated as a guarantee of invulnerability.

## Current scope

The plugin adds four deterministic direct tests to WordPress Site Health: HTTPS/admin transport, dashboard file editing, file modifications and updates, and a runtime compatibility notice. Results are request-local, fail open per check, and provide evidence, meaning, ownership, and manual remediation without a guarantee. WordPress has no unscored Site Health status, so unavailable or unsupported assessments use its supported `recommended` status rather than reporting a successful security observation.

No public endpoint, menu, REST policy or inventory, enforcement, headers, login throttling, file integrity, audit, alerts, settings UI, database writes, cron tasks, filesystem mutations, logs, or cache are included. Access relies on WordPress's native Site Health administration surface.

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

Deactivate Bastion Security WP to remove its four Site Health tests, then remove its plugin directory if desired. The plugin creates no external state, so no database, cron, cache, log, or filesystem cleanup is required.

## License

GPL-2.0-or-later.
