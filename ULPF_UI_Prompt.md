# Chetas Dashboard — UI Generation Prompt

Build a web dashboard for **Chetas** — a cybersecurity log ingestion and normalization platform (Universal Log Pre-Processing Framework). This is a SOC/security-operations tool, so the UI should feel like a **command center**, not a generic SaaS admin panel.

**Branding:** The product is called Chetas. Its mark is a circular tech emblem: an eight-color segmented ring (indigo → violet → blue → cyan → teal → green → amber → pink) around a dashed radar circle, with circuit traces connecting to a two-tone hexagon core. Use the logo in the top bar at small size (mark + wordmark lockup), and use it again, larger and at low opacity, as a subtle watermark on the Login screen. Do not otherwise scatter the full multi-color ring throughout the UI — the interface itself should read as calm and restrained, with the ring's colors reserved for the places described below.

**Core layout — reject the standard left-sidebar pattern.** Instead, use a **top command bar + contextual right drawer** layout:

* A slim, full-width **top bar** containing the Chetas logo + wordmark on the left, a live system-status strip in the center (source count, events/sec, error count — each with a small pulsing indicator dot), a global **search field** (see Search, below), and an **account menu** on the right (see Account menu, below).
* Primary navigation lives as a **horizontal segmented control** directly below the top bar (Overview / Sources / Logs / AI Mapping / Audit), styled like terminal tabs, not rounded pill buttons.
* Section content fills the full width below. Detail views (e.g. clicking a log entry, or reviewing an AI mapping suggestion) open in a **right-side sliding drawer** that overlays part of the screen, rather than navigating away — this keeps the operator's context intact.
* No persistent icon-only sidebar anywhere.

**Typography:** Use a monospace or geometric technical typeface throughout for data, labels, and headers — e.g. `IBM Plex Mono`, `JetBrains Mono`, or `Space Mono` for data/numbers/timestamps, paired with a clean grotesk sans (e.g. `Inter` or `Space Grotesk`) for body copy and longer text. Numbers and IDs should always render in the monospace face, even inline.

**Color palette — matched to the Chetas logo:**

* Background: near-black navy `#0B0F19`, with a very faint grid or dot-matrix texture at low opacity.
* Card/panel surfaces: one step lighter than background (`#111827`), with a **1px hairline border** in a subtle teal-gray rather than a drop shadow — this reads as "instrument panel," not "material design card."
* Primary brand accent (logo core): indigo `#4F46E5` through cyan `#06B6D4` — use this exact gradient for the Chetas wordmark, primary buttons, active nav-tab underline, and focus rings.
* Secondary accent: teal `#0891B2`, for links and secondary highlights.
* Status colors, drawn from the ring so status reads as on-brand rather than bolted on:

  * Healthy / active: green `#10B981`
  * Warning: amber `#F59E0B`
  * Error / critical: a red kept slightly outside the ring family for unambiguous alerting, `#E5484D` — reserve strictly for actual alerts, never decoration.
  * Info / AI-suggested: violet `#7C3AED`
* Text: off-white `#E6EDF3` primary, muted slate `#8B93A7` secondary (matches the logo's tagline gray).

**Animation (subtle, purposeful — this is a formal tool, not a game):**

* Status dots pulse gently (opacity 0.6→1→0.6, \~2s loop) when a source is actively sending data.
* New log rows entering a live table **fade + slide in** from the top, not pop in.
* The right-side detail drawer slides in with a slight ease-out, \~250ms, with a faint backdrop blur/dim on the underlying content.
* The account menu and any dropdown open with a quick \~150ms fade + scale from the trigger point.
* On the Overview screen, a **data-flow diagram** shows animated dots traveling along thin lines from "Log Sources" → "Format Detection" → "Normalization" → "Storage," representing the real pipeline — this doubles as a live architecture diagram and a system-health visual. Color the traveling dots using the ring's palette in sequence, echoing the logo's circuit traces.
* Numbers that update (events/sec, counts) should tick/count up smoothly rather than snap.
* Avoid glitch effects, scan-lines, or matrix-rain clichés — keep it closer to a Bloomberg terminal or aircraft cockpit than a hacker movie.

**Search — find an event by provenance ID:**

* The top bar's global search field accepts a provenance/trace ID (or partial match) and jumps straight to that event's detail drawer, showing both the raw and normalized record side by side (matching the Logs screen's split view).
* On the Logs screen itself, add a dedicated "Search by provenance ID" input above the table that filters the visible rows live as the person types, plus an exact-match jump when they press enter.
* If no match is found, show a clear inline empty state ("No event found for provenance ID `{id}`") rather than an empty table with no explanation.

**Export — download any table as CSV:**

* Every data table in the app (Sources, Logs/Raw Events, Normalized Events, Audit) gets a small "Export CSV" button in its header, next to any filter controls.
* Clicking it downloads the **currently filtered/visible rows** (not silently the whole table) as a `.csv` file named after the table and current date, e.g. `chetas\_logs\_2026-09-13.csv`.
* For the Logs/Normalized Events table specifically, the CSV must include at minimum: `timestamp`, `provenance\_id` (the trace/event ID linking raw and normalized versions), and the normalized log fields as separate columns (e.g. `event\_type`, `severity`, `source\_ip`, `destination\_ip`, `user\_name`, `action`, `outcome`, `message`, plus any `extra\_data` flattened into additional columns or a single JSON-string column if the field set is dynamic).
* For other tables (Sources, Audit), export all visible columns as-is.
* Show a brief toast confirmation ("Exported 214 rows to chetas\_logs\_2026-09-13.csv") after download.

**Account menu:**

* Clicking the profile picture/avatar in the top-right corner of the top bar opens a small dropdown menu, anchored to the avatar, containing: the user's name and role at the top (non-clickable), then **Settings**, then a divider, then **Sign out**.
* Sign out returns the person to the **Login** screen and clears their session.

**Key screens to generate:**

1. **Login** — centered card on the dark background, Chetas logo/wordmark above the form (large, low-opacity watermark version of the ring emblem behind it), username/email + password fields, "Sign in" button using the primary indigo-to-cyan gradient, and a subtle note area for auth errors. No sidebar or top bar on this screen.
2. **Overview** — animated pipeline diagram (above), plus summary tiles: total sources, events processed today, errors in last hour, pending AI-mapping approvals.
3. **Sources** — table of connected log sources (name, type, vendor, status, last seen), export button in the header, each row expandable into the right drawer for detail.
4. **Logs** — split view: raw log on the left, normalized JSON output on the right, connected visually by the shared provenance ID; provenance-ID search bar above the table; export button in the header.
5. **AI Mapping** — a review queue of AI-suggested field mappings awaiting human approval, shown as before/after field-mapping cards with clear Approve/Reject actions. Use the violet info accent for "AI-suggested" badges.
6. **Audit** — a clean, dense, monospace-heavy activity log table (who did what, when), export button in the header.
7. **Settings** — reached from the account menu. At minimum: an Account section (name, email, change password), and a Preferences section (e.g. default table page size, timezone for displayed timestamps). Same top bar and layout shell as the rest of the app, no segmented nav tabs since it's not one of the primary sections.

\---

### Notes for you

* If the tool you paste this into asks for a single starting screen, start with **Login** so the branding lands first, then **Overview**.
* CSV generation can use a small client-side library (e.g. `papaparse`'s unparse function) if the tool supports npm packages; otherwise a plain string-join CSV builder is fine for this scale.
* If you want a lighter "enterprise" mode instead of dark-mode-first, say so — the palette above assumes SOC dark-mode is default, matching the logo's dark backdrop.

