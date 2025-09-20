# Fight Fascists

This is a repository trying to help you fight fascists.

## Important safety note
Always put the safety of yourself and your family first. If you feel unsafe, do not engage.

If you can, please contribute. This repo relies on contributions.

## Features
- DNS blocklists (hosts format)
- uBlock Origin network lists (ABP syntax)
- Cosmetic lists to hide search results and links

---

## Build
- Prerequisite: Python 3.
- Run: `npm run build-blocklists` (this calls `python build_blocklists.py`).
- Outputs go to:
	- `dist/blocklists/ublock/` (uBlock lists + cosmetics)
	- `dist/blocklists/dns-lists/` (hosts format)

## Using with uBlock Origin
Firstly, install uBlock Origin from the official website: https://ublockorigin.com/

Then add the lists as Custom filter lists in uBO:
1) Open uBO Dashboard → “Filter lists” → “Custom” → “Import” or add file URLs.
2) Point to these generated files:
- Search result hider: `dist/blocklists/ublock/google-hide.txt`
- Global link hider: `dist/blocklists/ublock/link-hide.txt`
- Any of the compiled network lists in `dist/blocklists/ublock/*.txt` (e.g., `news-and-fascist.txt`)
- All-in-one (optional): `dist/blocklists/ublock/give-me-all.txt` (aggregates combined + google-hide + link-hide)

Notes
- The Search result hider hides Google and DuckDuckGo results that link to listed targets using cosmetic rules.
- The Global link hider hides any `<a>` element whose href contains a listed target anywhere on the web, and also adds on-platform rules.
- Matching for cosmetic rules is case-insensitive (uses CSS `[href*="…" i]` and `:matches-path(/…/i)`).

## What gets generated (overview)
- dist/blocklists/ublock/<source>.txt: Cleaned ABP/uBlock network rules
- dist/blocklists/dns-lists/<source>.txt: Hosts-format DNS list
- dist/blocklists/ublock/google-hide.txt: Cosmetic rules to hide search results
- dist/blocklists/ublock/link-hide.txt: Cosmetic rules to hide links globally and on-platform
- dist/blocklists/ublock/combined.txt: Union of all network rules
- dist/blocklists/ublock/give-me-all.txt: Aggregate of network + google-hide + link-hide
- dist/blocklists/dns-lists/combined.txt: Union of all DNS domains

## Adding entries (how to write source lists)
Add entries in the source files under `src/blocklists/*.txt`.

Accepted inputs
- Domains (either plain or uBO style):
	- `example.com`
	- `||example.com^`
- Specific host/path URLs for platform profiles/channels (no scheme needed):
	- `youtube.com/channel/UCxxxxxxxxxxxxxxxxxxxx`
	- `youtube.com/@handle`
	- `tiktok.com/@handle`
	- `x.com/SomeUser` (or `www.x.com/SomeUser`)

Behavior details
- Domain vs. path suppression: If a host has specific path targets (e.g., `youtube.com/channel/...` or `youtube.com/@handle`), the generator will NOT emit generic host-wide hide rules for that host in the cosmetic lists. This ensures we don’t hide all of `youtube.com` when only a channel/handle was intended.
- Variants: `www.` and non-`www` variants are added automatically for robustness.
- On-platform rules: For each host/path target, the Global link hider also emits:
	- `host##a[href*="/path"]` (relative link hider on that platform)
	- `host##html:matches-path(/path/)` (page-level hiding when you visit that profile/channel directly)

Opting out of search/link hide for a specific entry
- Append one of these flags to an entry to exclude it from the cosmetic lists:
	- `$noghide` or `$ghide=off`
- Examples:
	- `||example.com^$noghide` → still network/DNS-listed, but won’t add cosmetic search/link hide rules
	- `youtube.com/@somehandle$ghide=off` → won’t add cosmetic search/link hide rules for that path

## DNS Blocklists
Use the files in `dist/blocklists/dns-lists/` with your DNS sinkhole or Pi-hole/AdGuard Home.

## Contributing
- Add/edit entries in `src/blocklists/*.txt` and run the build.
- Keep entries clear and specific; prefer path-based entries for big platforms (YouTube, TikTok, etc.).
