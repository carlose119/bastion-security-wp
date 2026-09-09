# Explore a bounded WordPress core integrity checker

## Executive summary

The plugin has clear seams for a read-only core integrity feature, but the product contract is not ready for proposal. Manual and scheduled checks are confirmed; repair/deletion and uploading file content are excluded. Schedule frequency, retention, recipients/notification conditions, multisite behavior, and whether “unexpected files” are compared remain explicit approval gates.

A safe design should separate orchestration, checksum retrieval, filesystem comparison, result storage, notifications, and admin rendering. It should treat network failures, unreadable files, version/locale ambiguity, filesystem changes during a run, and lock contention as **incomplete/not assessed**, never as clean. The likely implementation plus tests and public documentation exceeds the 400-line review budget and should be delivered in bounded slices.

## Repository evidence

| Area | Evidence | Consequence |
|---|---|---|
| Bootstrap | `src/Bootstrap.php::boot()` constructs policies/admin objects and registers filters, lifecycle observations, `admin_menu`, and `admin_post_*` handlers. It has no cron, activation, or deactivation registration. | A checker can follow dependency construction and hook registration here, but scheduling lifecycle needs a new explicit seam. |
| UI | `src/Admin/SecurityDashboard.php` exposes four allowlisted tabs, renders only the active tab, uses `manage_options`, native nav tabs/notices/forms, escaped output, summary cards, and bounded `details` panels. | A dedicated integrity tab is less likely to overload Hardening; adding it changes the tab allowlist, constructor, rendering, styles, and dashboard tests. This is a candidate, not an approved choice. |
| Mutations | `src/Admin/PluginActivityAlertAdmin.php::handle()` and `AdministratorAccountAlertAdmin.php::handle()` enforce POST, capability, exact target/command, operation-bound nonce, PRG redirect, and explicit notices. | Manual run/settings actions should reuse this shape and avoid AJAX/REST unless separately approved. |
| State | `PluginActivityAlertPolicy::state()` defaults malformed/unreadable state, while `AdministratorAccountAlertPolicy::diagnosticState()` preserves an explicit `assessed` distinction. `PluginUpdateCompatibility::report()` conservatively rejects stale, malformed, incomplete, or inconsistent cached state. | Integrity state should be schema-versioned and distinguish “never run,” complete clean/changed, incomplete, running, and stale rather than coercing failures to empty/clean. |
| Email | Both alert policies validate/deduplicate up to 50 addresses, preserve recipients when disabled, send one plain-text `wp_mail` call per recipient, continue after failure, and do not claim delivery. | Existing recipient parsing and mail semantics are conventions, but reuse versus an independent recipient list and notification trigger remain product decisions. |
| Trusted runtime version | `PluginUpdateCompatibility` injects a WordPress-version reader whose default reads global `$wp_version`; it validates versions before use. `SiteHealthDiagnostics::observe()` also reads `$wp_version`. | The installed runtime version has an established repository source/test seam. Do not trust a request parameter or checksum response to choose the target version. |
| Local-only diagnostics | `PluginUpdateCompatibility` reads the existing update transient without causing an update/network request and checks capability before inventory reads. `SiteHealthDiagnostics` wraps each report in `Throwable` handling and renders unavailable work as Not assessed/recommended. | A networked/manual integrity run must remain isolated from passive Overview rendering; opening Overview must not trigger download or scanning. |
| Multisite | Existing tools explicitly vary: file-editor management is unavailable; alerts and controls remain current-site and do not `switch_to_blog`; plugin update inventory requires network capability on multisite. README documents these boundaries. | Core files are network-shared while options/cron may be site- or network-scoped. Current-site fan-out would duplicate scans and messages, so multisite cannot be inferred from existing behavior. |
| Tests | PHPUnit 10.5 unit tests inject closures for WordPress APIs, clock, mail, storage, and metadata. `tests/Unit/SecurityDashboardTest.php` stubs WP functions and asserts active-tab isolation; `SiteHealthDiagnosticsTest` uses source assertions for exact hooks; policy/admin tests cover hostile state and exceptions. | New network, filesystem, clock, lock, schedule, storage, and mail dependencies should be injectable. Structural hook assertions need updating. |
| Packaging/docs | `tools/build.php` recursively packages `src/`; `tests/Unit/PackagingTest.php` enforces top-level archive boundaries. `README.md` and `readme.txt` currently state there is no file integrity monitoring, cron, audit log, or filesystem state. | New `src/` files package automatically, but public scope/non-goals and lifecycle statements must change. No checker output should be written into the plugin tree. |
| Existing containment precedent | `tools/build.php::sourcePath()` canonicalizes paths, rejects symlinks, and checks root/allowed prefixes before copying. | This is useful evidence for defensive path handling, but it is build-only code and should not be reused directly at runtime. |

CodeGraph note: the parent observed `.codegraph/` at the project root. The exploration executor had no CodeGraph/CLI tool and used targeted reads and greps; index validity was not assessed.

## Candidate behavior for proposal — not approved

### Run pipeline

1. Acquire a short-lived, atomic run lock before network or filesystem work.
2. Capture trusted installed core version and a separately justified package locale.
3. Request checksums only from the official WordPress.org checksum service; upload no local bytes and follow no user-supplied endpoint.
4. Validate HTTP status, decoded shape, algorithm/value format, bounded entry count/path lengths, and exact requested version/locale identity where the response supports it.
5. Normalize each remote relative path, resolve it beneath the canonical WordPress root, and reject absolute paths, drive/UNC paths, NULs, `.`/`..`, mixed-separator escapes, and paths crossing symlinks.
6. Hash only expected regular files. Record mismatches, missing files, unreadable files, rejected checksum entries, and operational errors separately.
7. If unexpected-file detection is approved, enumerate only explicitly approved core boundaries with exclusions and deterministic limits; do not drift into `wp-content`.
8. Re-check version/locale and detect update-time churn before publishing. Mark the run incomplete if the target changed or the filesystem could not be assessed consistently.
9. Store a bounded result, release the lock in `finally`, and notify only under an approved condition.

This pipeline is a proposal candidate, not a settled contract.

### Scheduling/lifecycle options

Repository evidence contains no scheduling precedent. WordPress-native candidate APIs are `wp_schedule_event`/`wp_next_scheduled` (recurrence), `wp_schedule_single_event` (self-rescheduling), and `wp_clear_scheduled_hook` or targeted unscheduling on disable/deactivation. A recurring event is simpler; self-rescheduling better represents a custom interval but requires careful duplicate prevention. Either depends on WP-Cron traffic and is not an execution-time guarantee.

Lifecycle candidates:

- register activation/deactivation callbacks in `bastion-security-wp.php`, because WordPress activation hooks must be registered from the plugin entrypoint; or
- reconcile the desired event lazily during normal boot and clear it when scheduling is disabled, with deactivation cleanup still registered at the entrypoint.

Deactivation should stop future scheduled execution without deleting retained results/settings unless retention semantics explicitly say otherwise. Uninstall cleanup is currently absent and should not be added implicitly.

### Result and concurrency model

A candidate result envelope should be bounded and schema-versioned, for example: run ID, trigger (`manual`/`scheduled`), started/completed timestamps, requested version/locale, completeness, category counts, capped/sorted path lists, omission counts, and generic errors. It should never store file contents, remote response bodies, stack traces, credentials, or unbounded paths.

Atomicity concerns:

- `get_option` + `update_option` is not an atomic lock. A uniquely named `add_option` can be the lock-acquisition primitive; stale-lock takeover needs owner token and age checks.
- Manual and cron runs can overlap, and multiple cron workers can start together.
- A core update can mutate files while hashing. A lock owned only by this plugin cannot lock WordPress updates, so target re-checks and an incomplete outcome are required.
- Concurrent completion must not let an older run overwrite a newer result. Compare run IDs/start times or use run-specific records plus a guarded latest pointer.
- Network success with local read failures is not a successful clean result. A prior complete result may remain visible but must be labeled historical, not current.

## Filesystem and trust risks

| Risk | Required design response for a later proposal |
|---|---|
| Remote path traversal | Treat checksum keys as hostile; normalize `/`, reject backslashes/absolute/drive/UNC/dot segments/NUL, and prove containment before every read. |
| Prefix confusion | String prefix checks require a canonical root plus trailing directory separator and platform-aware comparison; `C:\site-old` must not match `C:\site`. |
| Symlinks/junctions | `realpath()` each existing target and reject escape from canonical `ABSPATH`; decide whether any symlinked core file is unassessable rather than following it. Windows junction behavior needs tests. |
| TOCTOU | Metadata can change between containment check and hash. Compare pre/post metadata where practical and classify churn as incomplete; PHP cannot provide a perfect portable race-free open-beneath primitive. |
| Special/unreadable files | Hash regular readable files only; directories, devices, links, permission failures, disappearing files, and hash failures are explicit incomplete evidence. |
| Memory/time exhaustion | Stream hashes, cap response entries and stored detail, deterministic sort/limit, avoid loading file contents, and expect cron/request time limits. Chunking is a possible later design but expands state/concurrency substantially. |
| Secret/path disclosure | Render approved relative core paths only, escaped and bounded. Do not persist/display absolute server paths or raw exceptions. |
| Algorithm assumptions | The repository has no checksum precedent. The proposal must pin accepted algorithm/value formats based on the official response contract; do not silently interpret arbitrary digests. |

## Version, locale, and comparison boundaries

**Evidence:** `$wp_version` is the established local version source. The repository has no locale/package-locale reader and no checksum client. `README.md` currently says file integrity monitoring is out of scope.

**Candidate:** use the validated runtime `$wp_version`; capture it before and after the run. Package locale is harder: runtime `get_locale()` may reflect a site/user locale rather than the core package installed, while the core package marker (commonly exposed by WordPress during updates) may be unavailable or stale. A proposal should define a deterministic fallback sequence and make ambiguity incomplete rather than guessing.

**Boundary question:** official expected checksum keys can identify missing/modified expected core files. Detecting extra files requires local enumeration and an allow/exclude policy. Root-level WordPress files, `wp-admin`, and `wp-includes` are plausible boundaries; `wp-content`, host files, generated files, and unrelated root files create false positives and privacy exposure. Exact boundaries and whether unexpected files are reported remain unresolved.

## Bounded candidate edit surfaces

No implementation edits were made. Likely later surfaces are:

- `bastion-security-wp.php` — activation/deactivation scheduling callbacks if that lifecycle is chosen.
- `src/Bootstrap.php::boot()` — construct checker services and register cron/admin hooks.
- New focused classes under `src/` — checksum client, contained filesystem comparator, run coordinator/lock/result repository, optional notifier.
- New admin class under `src/Admin/` — nonce/capability-protected manual run and settings, following existing PRG conventions.
- `src/Admin/SecurityDashboard.php` — candidate dedicated tab, notices, status/results rendering.
- Possibly `src/SiteHealthDiagnostics.php` — only if an additional passive summary diagnostic is approved; it must never run a scan or network call.
- `tests/Unit/` — unit suites for client validation, hostile paths/containment, comparison outcomes, locks/races, state bounds, scheduling, mail, admin handling, dashboard isolation, and hook registration.
- `README.md`, `readme.txt`, and packaging assertions if public behavior/lifecycle claims change.

## Workload and review-budget risk

A secure vertical implementation is unlikely to fit the 400 changed-line review budget: containment and checksum validation alone need substantial adversarial tests; orchestration/storage/concurrency, UI, scheduling, notifications, and docs are separate concerns. Suggested approval-gated slices:

1. Pure checksum-response validation and filesystem comparison domain with adversarial unit tests; no hooks/UI/network side effects.
2. Coordinator, official HTTP adapter, bounded result storage, and lock semantics with tests.
3. Manual admin action and result UI with dashboard tests.
4. Scheduling lifecycle and cron tests.
5. Notifications after recipient/condition decisions, then documentation/packaging updates.

Each slice should remain non-repairing and must not touch the parent WordPress installation during development verification.

## Unresolved product decisions — proposal blockers

1. **Schedule:** interval, first-run timing, behavior when WP-Cron is disabled/late, and whether manual scheduling changes replace an existing event.
2. **Retention:** latest result only versus bounded history; count/age; treatment of incomplete runs; behavior on disable, deactivation, and uninstall.
3. **Notifications:** independent recipients or reuse; which outcomes notify (changed, incomplete, recovery to clean, every run); deduplication/reminders; scheduled-only versus manual too.
4. **Multisite:** network-only single shared scan, per-site controls, current-site only, or unavailable; capability and storage/cron ownership.
5. **Comparison scope:** expected files only versus extras; approved directories/root files; exclusions; symlink policy; whether locale-specific files are expected.
6. **Locale trust:** exact source and fallback when installed package locale cannot be established.
7. **Result UX:** visibility capability, detail caps, stale threshold, and whether a Site Health summary is desired.
8. **Operational limits:** network timeout, maximum checksum entries, maximum files/time per request, and whether chunked continuation is acceptable.

## Next step

Resolve the grouped product decisions above, then produce an approval-gated proposal. Do not implement until that proposal is explicitly approved.
