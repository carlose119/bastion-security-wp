# Bastion Security WP

Bastion Security WP is a read-only, defense-in-depth foundation for WordPress security posture diagnostics. It reports evidence; it does not make security changes and must never be treated as a guarantee of invulnerability.

## Current scope

This initial work unit provides immutable diagnostic values, a deterministic request-local registry, and a fail-open runner. It does not yet expose Site Health or REST integrations and performs no checks in production.

No headers, login throttling, REST policy or inventory, file integrity, audit, alerts, settings UI, database writes, cron tasks, filesystem mutations, or cache are included.

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

Deactivate Bastion Security WP and remove its plugin directory. This foundation creates no external state, so no database, cron, cache, or filesystem cleanup is required.

## License

GPL-2.0-or-later.
