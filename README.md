# Bastion Security WP

Bastion Security WP provides focused WordPress security posture diagnostics and three reversible hardening tools. It reports evidence, not a guarantee of invulnerability.

## Quick navigation

Open **Tools > Bastion Security** as an administrator with `manage_options`, then choose the tab for the job:

| Tab | Purpose |
|---|---|
| **Overview** | Summary counts, the eight Bastion diagnostics, and a link to native WordPress Site Health. |
| **Hardening** | The reversible WordPress file-editor lock and opt-in Login Protection. |
| **Security headers** | Baseline and optional policy state, selected batch actions, individual controls, coverage guidance, and rollback. |

Only the active tab is rendered. Unknown or malformed tab values fall back to **Overview**.

## Safe activation path

1. Review the eight diagnostics on **Overview**.
2. Open **Security headers**, select the conservative baseline, and choose **Enable selected**.
3. Verify final response headers and site behavior in browser developer tools and, when applicable, at the CDN edge.
4. Select only the optional groups you intend to enable. One aggregate acknowledgement covers the selected high-impact groups; it is not required for the baseline or `legacy_cross_domain` alone.
5. Treat HSTS as the final step. If `hsts_trial` is selected, Bastion confirms that the current request, WordPress Address, and Site Address all use HTTPS before writing any part of that enable-selected batch.

## Current scope

The plugin adds eight deterministic direct tests to WordPress Site Health, in stable order:

1. HTTPS and admin transport posture.
2. File editor posture.
3. Login Protection setting and limitations.
4. Security header preset preference.
5. File modification and update posture.
6. Runtime compatibility notice.
7. Read-only pending plugin-update compatibility.
8. Read-only REST surface inventory.

The assessments remain request-local and fail open per check. WordPress has no unscored Site Health status, so unavailable or unsupported assessments use its supported `recommended` status rather than reporting a successful security observation. The Bastion dashboard presents the same results with Site Health-inspired, accessible `details`/`summary` markup and links to native WordPress Site Health for the full suite.

## Plugin update compatibility boundaries

The diagnostic reads WordPress's existing plugin-update site transient and installed plugin metadata. It performs no network request, update check, install, update, package retrieval, plugin callback, or cache/option write, and it provides no update button or action.

Inventory is shown only to users who can update plugins. On multisite, the user must also be able to manage network plugins. Without those permissions, Bastion does not read or render plugin names or versions. The cache must be structurally complete, no more than 12 hours old, not implausibly future-dated, and consistent with installed versions; otherwise the result is **Not assessed**. Cache age describes freshness only and does not prove that a remote check succeeded.

Each installed plugin with a cached pending update receives exactly one conservative classification based only on the target update's declarations:

- **Declared requirements met:** valid WordPress and PHP minimums are present and met, and the publisher's tested-through WordPress version covers the current version. This does not guarantee compatibility or absence of conflicts.
- **Blocked by declared requirements:** the current WordPress or PHP version is below a valid declared minimum. Every failed minimum is named.
- **Compatibility unknown:** required metadata is missing or malformed, or the current WordPress version is newer than the publisher-tested-through value. Tested-through is not treated as a maximum.

Installed plugin headers are not used as fallback target requirements. Results are deterministically sorted, limited to 50 displayed updates, and report total, shown, and omitted counts. Cached entries that do not match an installed plugin are ignored without exposing their identifiers.

## Reversible tools

### WordPress file-editor lock

On single-site installations, an administrator can enable or disable a plugin-owned preference through a nonce-protected POST action. When enabled, Bastion defines `DISALLOW_FILE_EDIT` as `true` early in each request only if the constant is not already defined.

Bastion writes only its own WordPress option; it never edits `wp-config.php` or another file. If another source defines `DISALLOW_FILE_EDIT`, Bastion preserves that value, reports its effective result, and does not claim it can override or roll it back. This tool is unavailable on multisite and performs no policy mutation there.

### Login Protection

Login Protection is an opt-in, per-site, best-effort throttle for failed WordPress authentication. Enable it under **Tools > Bastion Security > Hardening** only after acknowledging that legitimate users can be temporarily blocked, especially when they use a shared proxy address. Disabling it stops enforcement and advances an internal generation so prior temporary buckets are abandoned. **Reset temporary blocks** also advances that generation, preserves the enabled setting, and preserves aggregate failed/throttled metrics.

Within a 15-minute rolling window, the policy uses these progressive thresholds:

| Dimension | Failures | Cooldown |
|---|---:|---:|
| Normalized username or email | 5 / 8 / 12 | 60 seconds / 5 minutes / 15 minutes |
| Direct peer address | 50 / 100 / 200 | 60 seconds / 5 minutes / 15 minutes |

There are no permanent locks or sleeps. A successful, non-blocked authentication clears only that normalized identity bucket; it never clears the shared address bucket. The same generic error is returned for either dimension so the response does not identify which bucket matched.

Bucket keys are HMAC SHA-256 values derived with the WordPress authentication secret. Raw usernames, email addresses, and IP addresses are not stored in buckets or rendered in the UI. Rotating that secret naturally abandons the old transient namespace.

Coverage includes standard `wp-login.php` and every flow through `wp_authenticate()`, including ordinary XML-RPC authentication. REST Application Password authentication is explicitly not covered. Final enforcement runs after normal authentication work, so it does not avoid WordPress user lookup or password hashing and is not pre-authentication cost protection.

Only the directly connected peer from `REMOTE_ADDR` is considered. `Forwarded` and `X-Forwarded-For` are never trusted. This avoids accepting caller-controlled forwarding data, but sites behind a reverse proxy can place many users in one shared address bucket. Confirm the deployment topology and retain independent recovery access before enabling the tool.

Enforcement uses expiring WordPress transients and read-modify-write updates. Transient eviction or concurrent requests can weaken enforcement, while aggregate metrics can undercount. Login Protection is not a WAF, DDoS defense, availability guarantee, or general security guarantee.

#### Safe smoke check

1. Keep a separate recovery path available, such as hosting control-panel or CLI access; do not test against the only administrator session.
2. Enable Login Protection and confirm its diagnostic changes to **Good**, meaning only that the setting is enabled.
3. Use a disposable non-administrator identity for any failed-login check, and stop before reaching a threshold unless you intentionally have recovery access.
4. Confirm **Reset temporary blocks** preserves metrics, then disable Login Protection to verify rollback.

### HTTP security-header policies

Bastion provides one backward-compatible baseline toggle and seven independent optional groups. All optional groups are **off by default**. They remain independent of the baseline, and the UI provides both selected batch actions and individual controls.

The selected batch form accepts only the baseline and seven allowlisted group IDs. Choose **Enable selected** or **Disable selected**; there is intentionally no enable-all action. Selections must be non-empty and unique, and Bastion canonicalizes them into policy order before writing. Optional groups are updated in one option write, while the baseline remains a separate option for backward compatibility.

The baseline adds exactly:

```text
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

The optional groups add these exact values, in this deterministic order when enabled:

| Group | Header emitted | Primary breakage risk |
|---|---|---|
| `framing` | `X-Frame-Options: SAMEORIGIN` | Breaks legitimate cross-origin iframe embedding. |
| `browser_capabilities` | `Permissions-Policy: camera=(), microphone=(), geolocation=()` | Disables those browser capabilities, including integrations that need them. |
| `legacy_cross_domain` | `X-Permitted-Cross-Domain-Policies: none` | Breaks any remaining legacy Adobe cross-domain policy dependency. |
| `mixed_content_upgrade` | `Content-Security-Policy: upgrade-insecure-requests;` | HTTPS-upgraded subresources fail when no HTTPS resource exists. |
| `hsts_trial` | `Strict-Transport-Security: max-age=86400` | Returning browsers can become unable to reach a site with broken HTTPS. |
| `opener_isolation` | `Cross-Origin-Opener-Policy: same-origin-allow-popups` | Changes popup/opener relationships used by authentication, payment, or integrations. |
| `resource_isolation` | `Cross-Origin-Resource-Policy: same-site` | Blocks intentional cross-site consumers of this site's resources. |

#### Activation and rollback rules

Enabling `framing`, `browser_capabilities`, `mixed_content_upgrade`, `hsts_trial`, `opener_isolation`, or `resource_isolation` requires an explicit risk acknowledgement. A selected batch uses one aggregate acknowledgement for any of those six groups. Disabling selected policies never requires acknowledgement or transport readiness.

HSTS enablement is also blocked unless the current administration request uses SSL and both the configured WordPress Address and Site Address begin with HTTPS. When an enable-selected batch includes `hsts_trial`, that readiness check is an all-or-nothing preflight: no selected baseline or group write begins unless it passes. Bastion skips HSTS emission on every non-HTTPS request even when its preference is enabled. Disabling HSTS stops future Bastion emission immediately, but browsers may retain the 24-hour policy until it expires; disabling the plugin cannot erase policy already remembered by a browser.

**Disable all Bastion headers** is a separate rollback action. It requires neither acknowledgement nor HSTS readiness and disables optional groups before the baseline. Because groups and baseline use two independent WordPress options, a mixed selected action or disable-all action is not transactional: one option write can succeed while the other fails. Bastion reports that partial failure and displays the resulting state instead of claiming a rollback or transaction. Individual baseline and group controls remain available for focused changes and recovery.

The behavior is deliberately add-only:

- A disabled baseline adds neither baseline header; disabled optional groups add nothing.
- Enabled policies append only missing header names in baseline-then-group order.
- Existing names are detected case-insensitively. Their original spelling, values, and ordering are preserved without removal or override.
- Applying the policies repeatedly does not duplicate a header.
- Preferences remain per-site on multisite; Bastion does not claim network-wide enforcement.

#### Intentionally omitted behavior

The optional set is limited to policies with a bounded, site-specific contract. Bastion intentionally avoids direct-header and multi-hook emission, along with policies that cannot be configured safely without additional site context.

Bastion does not emit `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, or `Access-Control-Allow-Origin` because no explicit origin contract is configured. It also omits `Cross-Origin-Opener-Policy: unsafe-none`, `Cross-Origin-Resource-Policy: cross-origin`, HSTS `includeSubDomains` and `preload`, and `Content-Security-Policy-Report-Only` without a configured reporting endpoint. Deprecated headers and other permissive or no-op values are excluded.

#### Coverage and edge verification

Bastion emits only through WordPress's `wp_headers` filter and never calls PHP's `header()` directly. `wp_headers` is applied by `WP::send_headers()`, so coverage is limited to standard PHP front-end responses that pass through that WordPress path. It is not guaranteed for wp-admin, wp-login, REST responses, redirects, static files, cache hits, CDN responses, or headers emitted by a proxy or web server.

The single **Bastion: Security header preset** diagnostic reports baseline state and active optional group names. A Good result means only that at least one Bastion preference is configured; configuration is not end-to-end delivery proof. Check final headers and behavior in the browser and at the CDN edge when a CDN is present.

## REST inventory boundaries

The inventory exposes only registered namespaces, route patterns, and sorted unique HTTP methods. It reads only required fields from an already initialized REST server registry; incompatible layouts are not assessed. It never initializes REST or invokes route callbacks.

Output is escaped, capped at 100 deterministically sorted routes, and reports omitted routes. Callback metadata, arguments, schemas, options, request data, credentials, paths, exceptions, and arbitrary configuration are never rendered.

## Explicit non-goals

Bastion includes no public mutation endpoint, REST policy, file integrity monitoring, audit log, alerts, cron tasks, filesystem writes, permanent login locks, allowlists, or email notifications. The only settings UI and database writes are the Tools page and the plugin-owned file-editor, Login Protection configuration/metrics/transients, header-baseline, and enabled-group state described above. Mutations use WordPress administrative capability, strict target allowlists, and target-bound nonce protections; there is no AJAX or REST mutation path.

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

- **Header policies:** open **Tools > Bastion Security > Security headers**, then disable selected policies, use an individual control, or use the isolated **Disable all Bastion headers** action. Recheck the displayed state if a two-option operation reports a partial failure. Bastion immediately stops future emission for preferences that were disabled. HSTS may remain in browsers for up to 24 hours after its last received policy. Headers supplied by WordPress, another plugin, a cache, CDN, proxy, or web server remain unchanged.
- **File-editor lock:** open **Tools > Bastion Security > Hardening** and disable it to stop Bastion from defining the constant on the next request. Externally defined values remain unchanged.
- **Login Protection:** open **Tools > Bastion Security > Hardening** and disable it. Disabling advances the generation and invalidates prior temporary blocks; aggregate metrics remain. Use **Reset temporary blocks** to invalidate blocks without disabling or clearing metrics.
- **Plugin:** deactivate Bastion to remove its eight Site Health tests and future runtime enforcement. Plugin-owned configuration, metrics, and transient state remain in the database for later reactivation. Uninstall behavior likewise preserves this state because the plugin provides no uninstall cleanup routine.

Bastion creates no cron, log, or filesystem state requiring cleanup. Login Protection transients are temporary and best-effort.

## License

GPL-2.0-or-later.
