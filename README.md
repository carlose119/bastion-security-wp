# Bastion Security

Bastion Security provides focused WordPress security posture diagnostics and seven reversible security tools: five under **Hardening**, plus dedicated **Security headers** and **REST API** tools. It reports evidence, not a guarantee of invulnerability.

## Quick navigation

Open **Tools > Bastion Security** as an administrator with `manage_options`, then choose the tab for the job:

| Tab | Purpose |
|---|---|
| **Overview** | Summary counts, the twelve Bastion diagnostics, and a link to native WordPress Site Health. |
| **Hardening** | Five reversible tools: the WordPress file-editor lock, Login Protection, XML-RPC Pingback Protection, plugin activity email alerts, and Administrator Account Alerts. |
| **Security headers** | Baseline and optional policy state, selected batch actions, individual controls, coverage guidance, and rollback. |
| **REST API** | Active registered route-template catalog, method checkboxes, selected/stale state, impact guidance, and clear-all rollback. |

Only the active tab is rendered. Unknown or malformed tab values fall back to **Overview**.

## Safe activation path

1. Review the twelve diagnostics on **Overview**.
2. Open **Security headers**, select the conservative baseline, and choose **Enable selected**.
3. Verify final response headers and site behavior in browser developer tools and, when applicable, at the CDN edge.
4. Select only the optional groups you intend to enable. One aggregate acknowledgement covers the selected high-impact groups; it is not required for the baseline or `legacy_cross_domain` alone.
5. Treat HSTS as the final step. If `hsts_trial` is selected, Bastion confirms that the current request, WordPress Address, and Site Address all use HTTPS before writing any part of that enable-selected batch.

## Current scope

The plugin adds twelve deterministic direct tests to WordPress Site Health, in stable order:

1. HTTPS and admin transport posture.
2. File editor posture.
3. Login Protection setting and limitations.
4. XML-RPC Pingback Protection setting and limitations.
5. REST Route Controls configuration and limitations.
6. Plugin activity email alert configuration.
7. Administrator Account Alerts configuration.
8. Security header preset preference.
9. File modification and update posture.
10. Runtime compatibility notice.
11. Read-only pending plugin-update compatibility.
12. Read-only REST surface inventory.

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

### XML-RPC Pingback Protection

XML-RPC Pingback Protection is an opt-in, per-site control under **Tools > Bastion Security > Hardening**. Enable it only after confirming that the site does not depend on native inbound pingbacks. No acknowledgement checkbox is required, but native pingback consumers stop working while the setting is enabled.

When enabled, Bastion registers surgical filters at `PHP_INT_MAX` with one accepted argument:

- `xmlrpc_methods` removes exactly `pingback.ping` and `pingback.extensions.getPingbacks`. Every other method key, callback/value, and order remains unchanged.
- `wp_headers` removes every case-insensitive `X-Pingback` key. Every other WordPress-filtered header spelling, value, and order remains unchanged.

Malformed filter inputs and unreadable or malformed option state fail open without exposing read or write exceptions. A **Good** Site Health result means only that the readable per-site setting is enabled; it is not proof of absolute enforcement. A later filter at the same priority can re-add a method or header. Theme-authored pingback links, RSD metadata, and headers emitted directly or supplied by a server, proxy, cache, or CDN are outside this filter boundary.

This tool does not disable `xmlrpc.php`, authenticated XML-RPC methods, REST, Application Passwords, trackbacks, outbound pings, theme-authored pingback links, or RSD metadata. It performs no request inspection, logging, counting, rate limiting, firewall action, or network-wide enforcement, and it does not provide WAF or DDoS protection.

On multisite, the option remains local to the current site. Bastion does not call `switch_to_blog`, fan out changes, provide a network setting, or claim network-wide enforcement.

#### Safe compatibility check

1. Confirm that no publishing workflow or integration requires inbound WordPress pingbacks.
2. Enable XML-RPC Pingback Protection and confirm its diagnostic changes to **Good**, meaning only that the setting is enabled.
3. Verify the site's authenticated XML-RPC, REST, and Application Password workflows that must remain available, and inspect final headers at every serving edge.
4. Disable the setting to stop Bastion filtering. Components other than Bastion may still remove the methods or header, so disabling cannot restore their changes.

### REST Route Controls

Open **Tools > Bastion Security > REST API** to load the active WordPress REST registry and select route-template/method pairs with checkboxes. The catalog includes effective core, plugin, hidden, and non-index routes registered for the current request. Namespaces are collapsed by default, selected namespaces open automatically, and browser Find is the initial search path. Unsupported-only templates remain visible with no configurable methods.

Catalog loading is intentionally active and admin-only. Calling `rest_get_server()->get_routes()` can initialize the request-local REST server, fire `rest_api_init` and `rest_endpoints`, and materialize route options. It does not execute endpoint callbacks or permission callbacks. Overview, Hardening, Security headers, Site Health, passive REST inventory, and request-time policy enforcement never load this catalog.

The supported methods are `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, and `DELETE`; `OPTIONS` is intentionally omitted. When a template registers `GET`, the catalog also shows synthesized `HEAD` to reflect WordPress core fallback, but the two remain independent selections. At most 100 method/template rules can be selected.

Templates are preserved exactly as registered and matched using WordPress-equivalent anchored, case-insensitive route regex semantics. A dynamic template such as `/wp/v2/posts/(?P<id>[\d]+)` therefore blocks every matching concrete post URL for its selected method. Users cannot submit arbitrary patterns, wildcards, or namespace-prefix rules: each saved selection must belong to the current catalog or be a previously stored stale rule.

A match returns HTTP 403 with `bastion_rest_route_disabled` before permission and endpoint callbacks. WordPress may already have completed authentication, validation, and sanitization. The block applies to **all users and integrations**, including administrators, cookie-authenticated requests, and Application Password clients. There are no identity or capability exemptions.

Selected rules that disappear from the active registry are shown in a separate open stale group. Keep them selected to preserve them or uncheck them to remove them. Adding any rule requires the compatibility acknowledgement; removal-only, equal, and empty saves do not. Only checked values are submitted, and invalid, duplicate, unknown, tampered, or oversized submissions reject the whole save.

Routes remain registered and discoverable because Bastion does not filter `rest_endpoints` or remove route metadata. Earlier `rest_pre_dispatch` responses, `OPTIONS`, later or after-filters, direct PHP callback calls, server/proxy/CDN/cache responses, and non-REST code are outside the guarantee. This is not a global REST switch, WAF, firewall, logger, rate limiter, or DDoS control. Application Password, JSONP, XML-RPC, cron, AJAX, and endpoint registration behavior are unchanged.

The canonical option is `bastion_security_wp_rest_route_controls`, with schema version 1 and sorted `method`/`route_pattern` rules. Missing state is an assessed empty configuration. Malformed, unreadable, noncanonical, or non-compiling state is **Not assessed** and enforcement fails open. Site Health reports only the readable selected-rule count and never loads the catalog or reveals patterns.

Use the distinct **Clear all REST Route Controls** form for emergency rollback. It does not load the catalog, so it remains available when discovery fails. Keep a tested non-REST recovery path able to clear `bastion_security_wp_rest_route_controls` if authenticated REST clients are blocked. Deactivating the plugin stops enforcement but preserves the option.

### Plugin activity email alerts

Plugin activity email alerts are opt-in and configured per-site under **Tools > Bastion Security > Hardening**. Select **Enable plugin activity email alerts**, enter at least one recipient separated by a comma or newline, and save. Every token must be a valid email address or Bastion rejects the entire write. Duplicate addresses are removed case-insensitively while the first valid spelling is preserved. Bastion never silently falls back to the WordPress administration email.

For recipient privacy, Bastion sends one plain-text email per recipient with one `wp_mail` call each; addresses are not placed together in a shared recipient field. Each message is limited to the event, plugin display name, version, basename, site name and URL, WordPress-local timestamp, and—for activation—the network-wide Yes/No value. Metadata may be unavailable, in which case the message uses a safe fallback.

The event semantics are exact:

- **Plugin installations:** observed through WordPress's completed upgrader hook only for plugin install actions. Plugin updates are excluded.
- **Activations:** every observed successful plugin activation produces an alert and records whether WordPress reported it as network-wide.
- **Install plus activation:** installing and then activating a plugin intentionally produces two separate notifications. There is no cross-event deduplication or exactly-once claim.

On multisite, configuration remains per-site. Bastion does not call `switch_to_blog`, query other sites, or fan out notifications. A network-wide activation produces at most one email per configured recipient from the current site context and marks the activation as network-wide.

Enabled means Bastion will attempt to send. It does not prove delivery: delivery depends on `wp_mail` and the site's mail transport. Bastion must be active when WordPress emits a supported hook. There are no historical events, no event-type toggles, no queue, no retry, no delivery receipt, no audit log, no attachments, and no HTML email. Hook observability depends on the installation or activation path reaching the standard WordPress hooks, and plugin metadata may be unavailable. Mail failures and integration errors fail open without reverting the plugin lifecycle or changing configuration.

To roll back, clear the enable checkbox and save. Disabling preserves the configured recipient list for a later re-enable and stops future Bastion attempts; it cannot retract email already handed to the mail transport.

### Administrator Account Alerts

Administrator Account Alerts are opt-in and configured independently per site under **Tools > Bastion Security > Hardening**. Select **Enable administrator account alerts**, enter at least one recipient separated by a comma or newline, and save. Each token must be a valid address, at most 254 bytes; the list is limited to 50 recipients. Any invalid token rejects the entire write. Duplicates are removed case-insensitively while preserving the first spelling. Bastion never falls back to `admin_email` and never reuses the Plugin activity email alert recipients.

The exact observed events are:

- **Administrator role granted:** the `add_user_role` hook with the exact `administrator` role.
- **Administrator role removed:** the `remove_user_role` hook with the exact `administrator` role.
- **Administrator account deleted:** the post-delete `deleted_user` hook only when its supplied deleted-user snapshot contains the exact `administrator` role.

Bastion intentionally does not observe `set_user_role`, `user_register`, or `delete_user`. In ordinary WordPress flows, role addition and removal hooks precede `set_user_role` and cover standard role transitions; administrator creation reaches `add_user_role` before `user_register`. Registering the later hooks would duplicate alerts. This is hook-based observation, not an exactly-once guarantee.

Each message includes only the event, target user ID, a bounded and control-character-stripped target login or **Unavailable**, the `administrator` role where applicable, contextual current WordPress user ID and login or **Unavailable**, current site name and URL, and WordPress-local timestamp. It excludes target and actor email addresses, display names, IP addresses, user agents, passwords, capability lists, deletion reassignment, and arbitrary metadata. The current user is contextual and may be absent; it does not prove who caused an event.

Bastion makes one plain-text `wp_mail` call per recipient with empty headers, preventing recipient-address disclosure. A failed or throwing send does not stop later recipients or the account lifecycle. There is no delivery claim, retry, queue, history, counter, audit log, rollback, enforcement, or account blocking.

On multisite, the option and observation remain in the current-blog context. Ordinary administrator grants through `add_user_to_blog` may reach the observed role-addition hook. `remove_user_from_blog` can call `remove_all_caps` and bypass `remove_user_role`; super-admin grant/revoke, network deletion, cross-site fan-out, and network settings are outside scope. Bastion does not call `switch_to_blog`.

To roll back, clear the enable checkbox and save. Disabling preserves recipients for a later re-enable and stops future attempts; it cannot recall email already handed to the mail transport or reverse account changes. Delete the `bastion_security_wp_administrator_account_alerts` option to remove its saved configuration completely.

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

Bastion includes no public mutation endpoint, user-authored regex/wildcard/namespace-prefix REST policy, global REST shutdown, route removal, file integrity monitoring, general audit log, cron tasks, filesystem writes, permanent login locks, or allowlists. Alerting is limited to the two independent, opt-in tools described above: plugin installation/activation notices and administrator account lifecycle notices. The settings UI and database writes are limited to the Tools page and plugin-owned file-editor preference, Login Protection configuration/metrics/transients, plugin activity alert configuration, Administrator Account Alerts configuration, XML-RPC pingback preference, REST Route Controls rules, header baseline, and enabled-group state. Administrator Account Alerts add no enforcement, role blocking, account rollback, logs, counters, history, retries, queues, REST/AJAX/cron endpoints, network settings, IP capture, or user-agent capture. Mutations require WordPress administrative capability, strict target allowlists, and target-bound nonce protections; there is no AJAX or REST mutation path.

## Compatibility target

- WordPress 6.8 through 7.1
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

The artifact is written to `.build/bastion-security.zip`, rooted at `bastion-security/`. The distribution contains `bastion-security-wp.php`, `readme.txt`, `LICENSE`, a sanitized production `composer.json`, `src/`, and a production-only authoritative `vendor/` generated in disposable staging. The packaged Composer manifest contains only runtime package identity, the PHP requirement, and the PSR-4 autoload mapping; `composer.lock`, development metadata, and development dependencies are excluded from the final ZIP.

Archive entries are sorted, use normalized `/` separators, fixed permissions, and the fixed local archive date 1981-01-01. The build creates that date with local-time calendar components so ZIP's DOS date remains stable across timezones. Identical bytes are expected with the same PHP, Composer, libzip, dependency lockfile, and source; ZIP compression implementations can differ across environments, so cross-toolchain byte identity is not claimed.

For release validation and deployment, extract the production ZIP first. Run WordPress.org Plugin Check and prepare the WordPress.org SVN submission from that extracted artifact, never from the development checkout.

## Rollback

- **Header policies:** open **Tools > Bastion Security > Security headers**, then disable selected policies, use an individual control, or use the isolated **Disable all Bastion headers** action. Recheck the displayed state if a two-option operation reports a partial failure. Bastion immediately stops future emission for preferences that were disabled. HSTS may remain in browsers for up to 24 hours after its last received policy. Headers supplied by WordPress, another plugin, a cache, CDN, proxy, or web server remain unchanged.
- **File-editor lock:** open **Tools > Bastion Security > Hardening** and disable it to stop Bastion from defining the constant on the next request. Externally defined values remain unchanged.
- **Login Protection:** open **Tools > Bastion Security > Hardening** and disable it. Disabling advances the generation and invalidates prior temporary blocks; aggregate metrics remain. Use **Reset temporary blocks** to invalidate blocks without disabling or clearing metrics.
- **XML-RPC Pingback Protection:** open **Tools > Bastion Security > Hardening** and disable it. Bastion stops removing the two pingback methods and WordPress-filtered `X-Pingback` headers on later requests, but it cannot restore removals made by another component or headers outside `wp_headers`.
- **REST Route Controls:** open **Tools > Bastion Security > REST API** and use the separate **Clear all REST Route Controls** action. This non-REST admin-post rollback does not load the catalog, so it remains available if catalog loading fails. Bastion stops blocking configured routes on later requests, but clearing its rules cannot restore behavior blocked by another component.
- **Plugin activity email alerts:** open **Tools > Bastion Security > Hardening**, clear the enable checkbox, and save. Disabling preserves recipients and stops future attempts; already handed-off email cannot be recalled.
- **Administrator Account Alerts:** open **Tools > Bastion Security > Hardening**, clear the enable checkbox, and save. Disabling preserves recipients and stops future attempts; it does not reverse account changes or recall handed-off email. Delete `bastion_security_wp_administrator_account_alerts` to remove this saved configuration.
- **Plugin:** deactivate Bastion to remove its twelve Site Health tests and future runtime enforcement and alert attempts. Plugin-owned configuration, metrics, and transient state remain in the database for later reactivation. Uninstall behavior likewise preserves this state because the plugin provides no uninstall cleanup routine.

Bastion creates no cron, queue, audit-log, or filesystem state requiring cleanup. Login Protection transients are temporary and best-effort.

## License

GPL-2.0-or-later.
