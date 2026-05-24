# JA-Bench UI Design Notes — 2026-05-23

This note captures the current UI direction for JA-Bench. It is meant to guide both the initial build and the future README / GitHub presentation.

## Design goals

- single-screen workflow
- wider overall layout than Suricata-Bench
- clean and uncluttered visual style, close in spirit to Suricata-Bench
- analyst-first usability over decorative UI
- copy-friendly output
- strong separation between observed data, derived data, and enrichment

## High-level UI philosophy

JA-Bench should feel like a workbench, not just a form.

The UI needs to support three primary jobs on one screen:

1. read and analyze a selected PCAP
2. inspect one selected conversation / flow in detail
3. search stored fingerprint data and compare it with prior observations

The design should stay on one screen, but use resizable panes so the user can prioritize the area they need.

## Single-screen layout

The current preferred layout is:

- **Top-left:** PCAP input row
- **Top-middle / upper center:** conversation selector
- **Top-right:** mode selector and quick search
- **Main left:** large analysis output pane
- **Main right:** database match results pane
- **Right-middle below matches:** JA / derived breakdown pane
- **Right-lower below JA breakdown:** compact session summary pane
- **Lower area:** error and log output
- **Lower utility area:** theme picker and export controls

The left and right sides do not need to be identical heights.

## PCAP input row

The PCAP input area should feel familiar to Suricata-Bench, but with a slightly wider overall treatment.

Preferred row layout:

- **Browse** button
- selected filename field / display
- **Read PCAP** button

Notes:

- the selected filename display should be wide enough to visually balance the buttons
- the row should feel stable and horizontal, not cramped
- the filename display and read action should clearly indicate what file is about to be parsed

## Conversation selector

After a PCAP is read, JA-Bench should require the user to choose the specific conversation / flow they want to analyze when multiple possibilities exist.

This matters because a PCAP may contain:

- multiple IP pairs
- multiple connections between the same pair
- different protocols on related flows
- multiple TLS sessions with similar endpoints

### UI behavior

- use a **dropdown selector**
- once the user makes a selection, the dropdown should close and show only the selected value
- the user can reopen it later to choose a different conversation

### Suggested conversation label format

Each dropdown entry should include enough context to disambiguate flows without opening a detail panel first.

Suggested elements:

- protocol
- source `ip:port`
- destination `ip:port`
- packet or record count when useful
- fingerprint hint when available

Example style:

`TLS | 10.0.0.5:49721 -> 104.18.12.55:443 | 42 packets | JA4=...`

If protocol-specific context is available, include it when it helps. For example, a TLS conversation label may include TLS version or a TLS fingerprint hint.

## Mode selector

A mode selector should live in the top-right area.

Current preference:

- use **radio buttons** if the number of modes stays small
- keep the backend flexible so the mode model can expand later if needed

This selector should remain visually simple.

## Main analysis output pane

The main output area is one of the most important panes in the application.

Requirements:

- large
- easy to read
- easy to copy from directly
- suitable for grabbing one answer or the full output
- simple formatting, attractive but not overly styled

The output should prioritize usability over decoration.

### Output behavior guidance

- do not make the main output card-heavy if that makes copying awkward
- preserve readable structure
- keep spacing clean
- allow direct text selection without fighting the UI

A later enhancement could allow both:

- formatted view
- plain text view

but that is not required for the first implementation.

## Database quick search

The top-right area should include a quick search input for looking up one value in the local dataset.

Examples:

- JA4
- JA3
- JA3S
- JARM
- certificate hash
- IP
- SNI

This quick search is intended for single-value lookups, not advanced multi-condition filtering.

### Search-result pane

The quick search should feed a dedicated results pane.

Requirements:

- wide presentation
- no word wrapping in result rows
- show same-row related values when possible
- easy side-by-side comparison of observed relationships
- avoid left/right scrolling inside bench windows where possible
- avoid browser-level horizontal scrolling as a normal workflow

Example desired result context:

If the user searches a JA4, they may want to see:

- other rows with the same JA4
- OS or platform attribution if present
- peer JA values
- related JARM values
- related IP / SNI / cert context

The pane should favor readable columns over wrapped text, but this creates a real layout constraint. We need to design the displayed fields carefully so search-result review still works without relying on horizontal scrolling.

## JA / derived breakdown pane

Below the match-results pane, there should be a dedicated pane for explaining JA and related derived values.

This pane should stay separate from the main analysis output.

### Behavior

- if the fingerprint has meaningful internal sections, break it down into those sections
- if the fingerprint is a one-way or simpler format, explain it in the best available way without forcing an artificial structure

Examples:

- for JA4SSH or similar structured fingerprints, explain the relevant parts
- for HASSH-style results, list the offered SSH algorithms or other available SSH handshake details when present

The goal is interpretation, not just display.

## Session summary pane

A compact session summary pane should live:

- **below the JA / derived breakdown pane**
- **above the theme and export controls**

This pane should:

- default to **open**
- be **collapsible**
- be **vertically resizable**

### Purpose

This pane gives quick orientation after parsing and selecting a flow.

Suggested contents:

- selected PCAP filename
- parse status
- number of conversations found
- protocol summary
- currently selected conversation
- possibly basic run metadata

This pane should remain compact and should not replace the main output or JA breakdown panes.

## Logs and error output

There should be a dedicated lower pane for logs and errors.

Requirements:

- clearly separated from the main analysis output
- useful for troubleshooting
- not visually dominant unless needed

Good default behavior would be:

- visible
- somewhat smaller than the main output area
- resizable
- collapsible if needed later

## Theme picker

A theme picker should exist, in the same general spirit as Suricata-Bench.

Placement can remain in the lower utility area.

The theme picker should stay lightweight and should not compete with the analysis UI.

## Export design

Export is required, but the control wording should stay compact.

### Export scope choices

Use these three export scopes:

- **Selected Conversation**
- **Search Results**
- **All**

### Export format choices

Use these format choices:

- **CSV**
- **JSON**

### UI control model

Preferred control pattern:

- **Scope** selector
- **Format** selector
- **Export** button

This is preferred over six separate export actions because it stays cleaner and scales better.

The selectors can collapse to show only the current choice, with a small dropdown arrow to change them.

## Search model decision

There should be **one quick-search input only** in the current design.

We are intentionally avoiding a second search box for now.

Reason:

- two separate search areas would likely make the first version feel cluttered
- quick search plus export scope covers the immediate need well enough
- users can shape or filter full exports later if they need more complex analysis

If advanced filtering becomes necessary later, it should likely become a dedicated advanced-search or filter-builder panel rather than a second basic search box.

## Data-source / enrichment key handling

Some enrichments may require API keys.

Current direction:

- **Shodan** support is useful and the key is easy for the user to provide
- **VirusTotal** is intentionally not planned for this UI right now

### Key behavior

Shodan should be treated as optional:

- if a Shodan key is present, enable Shodan enrichment
- if no Shodan key is present, skip Shodan silently
- core JA-Bench analysis must not depend on Shodan being configured

### Config direction

Use a local, git-ignored config mechanism for keys, such as an environment file or equivalent secrets/config path.

The UI may later show whether Shodan enrichment is enabled, but it should not block normal use when the key is absent.

## First implementation priorities

To keep the first build clean, the best first UI slice is:

1. PCAP input row
2. Read PCAP action
3. conversation dropdown after parse
4. mode selector
5. large main output pane
6. log/error pane
7. export controls

After that, add:

1. quick search
2. result pane
3. JA / derived breakdown pane
4. session summary pane
5. optional Shodan enrichment awareness

This is still one-screen design work, but it helps stage implementation without cluttering the first working version.

## README guidance

These design notes should also guide the README when JA-Bench is published.

The README should present JA-Bench as:

- a passive-first fingerprint analysis workbench
- able to read PCAPs, isolate one conversation, derive network fingerprints, and compare them with stored observations
- able to export selected conversation data, search-result data, or all data as CSV or JSON
- optionally able to enrich with Shodan when configured

## Current design summary

As of 2026-05-23, the UI direction is:

- one screen only
- wider than Suricata-Bench
- uncluttered and SB-like
- explicit conversation selection after parse
- separate panes for main output, search matches, JA/derived interpretation, session summary, and logs
- compact export controls using scope + format selectors
- one quick-search input only
- optional Shodan integration with silent skip when no key is present
