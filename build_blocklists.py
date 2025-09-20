import os
import re
from typing import Optional, List

# Helpers for uBlock/ABP syntax parsing
DOMAIN_RE = re.compile(r"^(?:\*\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)\.?$", re.IGNORECASE)


def is_comment_or_blank(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith('!') or s.startswith('#')


def is_cosmetic_filter(line: str) -> bool:
    # Cosmetic filters include element hiding and scriptlet injections
    # Examples: example.com##.ad, example.com#@#.ad, ##+js(...), ##^, ###id
    s = line.strip()
    return ('##' in s) or ('#@#' in s)


def is_exception_filter(line: str) -> bool:
    return line.strip().startswith('@@')


def normalize_domain(domain: str) -> Optional[str]:
    if not domain:
        return None
    d = domain.strip().lower()
    if d.startswith('*.'):
        d = d[2:]
    if d.startswith('.'):
        d = d[1:]
    if d.endswith('.'):
        d = d[:-1]
    # Basic domain validation (allows punycode)
    if DOMAIN_RE.match(d) or d.startswith('xn--'):
        return d
    return None


def extract_domain_from_ublock_filter(line: str) -> Optional[str]:
    """Extract a domain suitable for DNS blocking from a uBlock/ABP network filter.
    Returns None if the filter isn't purely domain-based (e.g., regex, URL path, cosmetic, or exception).
    """
    s = line.strip()
    if not s or is_comment_or_blank(s) or is_cosmetic_filter(s) or is_exception_filter(s):
        return None

    # Regex filters like /ads\.js$/
    if (s.startswith('/') and s.endswith('/') and len(s) > 1):
        return None

    # Drop anchors at ends
    if s.startswith('|') and not s.startswith('||'):
        # Single '|' anchor often precedes URLs like |http://...
        return None

    # Remove options suffix (e.g., $image,third-party)
    if '$' in s:
        s = s.split('$', 1)[0]

    # Pure domain rule (e.g., example.com)
    if '//' not in s and '/' not in s and '^' not in s and s.count('|') == 0 and ':' not in s:
        return normalize_domain(s)

    # ||example.com^
    if s.startswith('||'):
        rest = s[2:]
        # Domain goes until separator ^ / |
        for sep in ['^', '/', '|', ':', '?']:
            idx = rest.find(sep)
            if idx != -1:
                rest = rest[:idx]
        return normalize_domain(rest)

    # http(s)://example.com/... -> too specific for DNS in this context
    if s.startswith('http://') or s.startswith('https://'):
        return None

    return None


_HOST_PATH_RE = re.compile(
    r"^(?:https?:\/\/)?([a-z0-9.-]+(?:\.[a-z0-9.-]+)+)(\/[A-Za-z0-9_\-\.%@\/]+)\s*$",
    re.IGNORECASE,
)


def extract_search_hide_target(line: str) -> Optional[str]:
    """Extract a host/path substring suitable for search-result hiding rules.
    Examples accepted:
      - youtube.com/channel/UCxxxx
      - https://youtube.com/@handle
      - www.example.com/path/part
    Returns host+path without scheme (e.g., "youtube.com/channel/UCxxxx").
    Returns None for cosmetic, exception, or pure domain-only/network-anchor rules.
    """
    s = line.strip()
    if not s or is_comment_or_blank(s) or is_cosmetic_filter(s) or is_exception_filter(s):
        return None

    # Remove options suffix (e.g., $image,third-party)
    if '$' in s:
        s = s.split('$', 1)[0].strip()

    # Ignore pure domain/network filters – those are handled separately as domains
    if s.startswith('||'):
        return None
    if s.startswith('|') and not s.startswith('||'):
        return None
    if '^' in s or '|' in s:
        return None

    m = _HOST_PATH_RE.match(s)
    if not m:
        return None
    host, path = m.group(1).lower(), m.group(2)
    # Normalize leading dots
    if host.startswith('*.'):
        host = host[2:]
    if host.startswith('.'):
        host = host[1:]
    # Avoid trailing dots
    if host.endswith('.'):
        host = host[:-1]
    # Be conservative: require at least one path segment beyond '/'
    if not path or path == '/':
        return None
    return f"{host}{path}"


def parse_dns_line(line: str) -> Optional[str]:
    s = line.strip()
    if not s or s.startswith('#') or s.startswith('!'):
        return None
    # Hosts file style: 0.0.0.0 domain or 127.0.0.1 domain
    parts = s.split()
    if len(parts) == 1:
        # Sometimes lists contain bare domains
        return normalize_domain(parts[0])
    if len(parts) >= 2 and parts[0] in {'0.0.0.0', '127.0.0.1'}:
        return normalize_domain(parts[1])
    return None


def clean_ublock_list(input_path, output_path):
    """Cleans a uBlock blocklist by removing comments, empty lines, and cosmetic rules.
    Keeps network filters and exceptions as-is (trimmed)."""
    seen = set()
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as infile, open(output_path, 'w', encoding='utf-8') as outfile:
        for raw in infile:
            line = raw.strip()
            if is_comment_or_blank(line) or is_cosmetic_filter(line):
                continue
            # Keep network filters and exception filters in uBlock list
            if line and line not in seen:
                outfile.write(line + '\n')
                seen.add(line)


def convert_to_dns_list(ublock_path, dns_path):
    """Converts a cleaned uBlock blocklist to a DNS blocklist, skipping entries that aren't domain-based."""
    domains = set()
    with open(ublock_path, 'r', encoding='utf-8', errors='ignore') as infile:
        for raw in infile:
            domain = extract_domain_from_ublock_filter(raw)
            if domain:
                domains.add(domain)
    # Write deduped, sorted domains
    with open(dns_path, 'w', encoding='utf-8') as outfile:
        for domain in sorted(domains):
            outfile.write(f"0.0.0.0 {domain}\n")


def ensure_dirs(*paths: str) -> None:
    for p in paths:
        os.makedirs(p, exist_ok=True)


def write_google_hide_cosmetic(all_domains: set, path_targets: set, out_path: str) -> None:
    """Write a uBlock cosmetic filter list to hide search results linking to listed domains or host/path targets."""
    if not all_domains and not path_targets:
        # Remove file if exists to avoid stale output
        try:
            if os.path.exists(out_path):
                os.remove(out_path)
        except OSError:
            pass
        return

    rules = []
    header = [
        "! Title: Search result hider (auto-generated)",
        "! Description: Hide search results linking to listed domains (Google + DuckDuckGo)",
        "! Syntax: uBlock Origin cosmetic filters",
        "! Homepage: https://github.com/Maingron/fight-fascists",
        "!"  # blank separator
    ]

    # Per-engine container selectors; add more engines/selectors as needed
    search_engines = {
        'google.*': [
            'div:is(.vt6azd, .SoaBEf:has(div>div>.WlydOe))'
        ],
        'duckduckgo.com': [
            'li>article'
        ]
        # 'www.bing.com': [ ':is(#b_results > .b_algo, #b_results > li.b_algo)' ],  # example
    }

    def rule_for_has(target: str) -> List[str]:
        # Make attribute match ASCII case-insensitive using CSS4 ' i' flag
        return [f"{engine}##{sel}:has(a[href*=\"://{target}\" i])" for engine, selectors in search_engines.items() for sel in selectors]

    # Keep output compact: only emit the :has(...) rule per domain.
    # The :upward(...) variant is omitted for size; re-add if robustness is needed.

    # Expand with www variants for more accurate matches
    expanded_domains = set(all_domains)
    for d in list(all_domains):
        if not d.startswith('www.'):
            expanded_domains.add('www.' + d)

    # Do not emit domain-level rules for hosts that have specific path targets
    hosts_with_paths = {t.split('/', 1)[0].lower() for t in path_targets if '/' in t}
    def base_host(x: str) -> str:
        return x[4:].lower() if x.lower().startswith('www.') else x.lower()

    for d in sorted(expanded_domains):
        if '/' in d or ':' in d:
            continue
        if base_host(d) in hosts_with_paths:
            continue
        rules.extend(rule_for_has(d))

    # Include host/path targets (and their www. variants)
    expanded_paths = set(path_targets)
    for t in list(path_targets):
        if t.startswith('www.'):
            continue
        # t format: host/path...
        if '/' in t:
            host, rest = t.split('/', 1)
            expanded_paths.add(f"www.{host}/{rest}")
    for t in sorted(expanded_paths):
        # Avoid accidental spaces or schemes
        if '://' in t or ' ' in t:
            continue
        rules.extend(rule_for_has(t))

    with open(out_path, 'w', encoding='utf-8') as f:
        for line in header:
            f.write(line + "\n")
        for r in rules:
            f.write(r.strip() + "\n")


def write_link_hide_cosmetic(all_domains: set, path_targets: set, out_path: str) -> None:
    """Write a uBlock cosmetic filter list to hide any anchor (<a>) whose href contains listed domains or host/path targets globally."""
    if not all_domains and not path_targets:
        try:
            if os.path.exists(out_path):
                os.remove(out_path)
        except OSError:
            pass
        return

    rules = []
    header = [
        "! Title: Global link hider (auto-generated)",
        "! Description: Hide any link (<a>) whose URL contains one of the listed domains or specific paths",
        "! Syntax: uBlock Origin cosmetic filters",
        "! Homepage: https://github.com/Maingron/fight-fascists",
        "!"
    ]

    # Exclude domain-level rules for hosts that also have path-specific targets
    hosts_with_paths = {t.split('/', 1)[0].lower() for t in path_targets if '/' in t}
    def base_host(x: str) -> str:
        return x[4:].lower() if x.lower().startswith('www.') else x.lower()

    # Domains (with www variants)
    expanded_domains = set(all_domains)
    for d in list(all_domains):
        if not d.startswith('www.'):
            expanded_domains.add('www.' + d)
    for d in sorted(expanded_domains):
        if '/' in d or ':' in d:
            continue
        if base_host(d) in hosts_with_paths:
            continue
    rules.append(f"##a[href*=\"://{d}\" i]")

    # Path targets (add www variants)
    expanded_paths = set(path_targets)
    for t in list(path_targets):
        if '/' in t and not t.startswith('www.'):
            host, rest = t.split('/', 1)
            expanded_paths.add(f"www.{host}/{rest}")
    for t in sorted(expanded_paths):
        if '://' in t or ' ' in t:
            continue
    rules.append(f"##a[href*=\"{t}\" i]")

    # Also add platform-scoped relative path rules for each host/path target
    # Example: for "youtube.com/channel/UC..." emit:
    #   youtube.com##a[href*="/channel/UC..."] and www.youtube.com variant
    seen_rel = set()
    for t in path_targets:
        if '/' not in t:
            continue
        host, rest = t.split('/', 1)
        rel = '/' + rest if not rest.startswith('/') else rest
        # consider both base and www host variants
        host_variants = {host}
        if host.startswith('www.'):
            host_variants.add(host[4:])
        else:
            host_variants.add('www.' + host)
        for h in host_variants:
            rule = f"{h}##a[href*=\"{rel}\" i]"
            if rule not in seen_rel:
                rules.append(rule)
                seen_rel.add(rule)

    # Add per-host page-hider rules for exact path hits using :matches-path
    # Example: tiktok.com##html:matches-path(/@real_german/)
    page_rules_seen = set()
    for t in path_targets:
        if '/' not in t:
            continue
        host, rest = t.split('/', 1)
        rel = '/' + rest if not rest.startswith('/') else rest
        # Build a safe regex for the path, avoid duplicating the delimiter '/'
        safe = re.escape(rel.lstrip('/'))  # escape but drop leading '/'
        # re.escape does not escape '/', but :matches-path uses '/' as delimiter, so escape slashes explicitly
        safe = safe.replace('/', r'\/')
        path_regex = f"/{safe}/i"
        host_variants = {host}
        if host.startswith('www.'):
            host_variants.add(host[4:])
        else:
            host_variants.add('www.' + host)
        for h in host_variants:
            rule = f"{h}##html:matches-path({path_regex})"
            if rule not in page_rules_seen:
                rules.append(rule)
                page_rules_seen.add(rule)

    # Also emit simple page-hider entries in requested format: host/path##html (and www variant)
    # This is in addition to matches-path and helps consumers expecting "tiktok.com/@handle##html" style
    simple_page_rules_seen = set()
    for t in path_targets:
        if '/' not in t:
            continue
        # Add the raw host/path and its www variant
        if not t.startswith('www.'):
            host, rest = t.split('/', 1)
            simple_variants = [t, f"www.{host}/{rest}"]
        else:
            host, rest = t.split('/', 1)
            simple_variants = [t, f"{host[4:]}/{rest}"]
        for v in simple_variants:
            rule = f"{v}##html"
            if '://' in v or ' ' in v:
                continue
            if rule not in simple_page_rules_seen:
                rules.append(rule)
                simple_page_rules_seen.add(rule)

    with open(out_path, 'w', encoding='utf-8') as f:
        for line in header:
            f.write(line + "\n")
        for r in rules:
            f.write(r.strip() + "\n")


def cleanup_outputs(out_dir: str, valid_names: set) -> None:
    """Remove .txt files in out_dir whose names are not in valid_names."""
    if not os.path.isdir(out_dir):
        return
    for fn in os.listdir(out_dir):
        if not fn.lower().endswith('.txt'):
            continue
        if fn not in valid_names:
            try:
                os.remove(os.path.join(out_dir, fn))
            except OSError:
                pass


def main():
    src_root = os.path.join('src', 'blocklists')

    out_ublock = os.path.join('dist', 'blocklists', 'ublock')
    out_dns = os.path.join('dist', 'blocklists', 'dns-lists')

    ensure_dirs(out_ublock, out_dns)

    # Collect sources by filename (only uBlock format now)
    lists_by_name = {}

    def add_src(dct, name, kind, path):
        if name not in dct:
            dct[name] = {'ublock': [], 'dns': []}  # keep keys for downstream compatibility
        dct[name][kind].append(path)

    if os.path.isdir(src_root):
        for root, _, files in os.walk(src_root):
            for fn in files:
                if fn.endswith('.txt'):
                    add_src(lists_by_name, fn, 'ublock', os.path.join(root, fn))

    # Accumulators for combined outputs
    combined_ublock_lines = set()
    combined_domains = set()

    # Domains/targets explicitly ignored for google-hide via flags in uBlock source lists
    ignored_hide_domains = set()
    ignored_hide_targets = set()

    # Process each logical list name
    all_domains_global = set()
    for name, kinds in lists_by_name.items():
        print(f"Processing {name}...")

        # 1) Build final uBlock list: cleaned union of all ublock sources plus converted DNS domains
        combined_ublock_tmp = os.path.join(out_ublock, f".tmp_{name}")
        final_ublock_path = os.path.join(out_ublock, name)

        # Start with cleaned lines from all ublock sources
        seen_lines = set()
        with open(combined_ublock_tmp, 'w', encoding='utf-8') as tmp_out:
            for src in kinds.get('ublock', []):
                # Clean each file and append
                with open(src, 'r', encoding='utf-8', errors='ignore') as infile:
                    for raw in infile:
                        original = raw.rstrip('\n')
                        line = original.strip()
                        if is_comment_or_blank(line) or is_cosmetic_filter(line):
                            continue

                        # Detect google-hide ignore flag in options: $noghide or $ghide=off
                        marker_present = False
                        cleaned_line = line
                        if '$' in line:
                            before, after = line.split('$', 1)
                            opts = after.split(',')
                            new_opts = []
                            for opt in opts:
                                low = opt.strip().lower()
                                if low in {"noghide", "ghide=off"}:
                                    marker_present = True
                                    continue
                                if low:
                                    new_opts.append(opt.strip())
                            cleaned_line = before if not new_opts else before + '$' + ','.join(new_opts)
                        # If marker present, extract domain and record for hide-ignore
                        if marker_present:
                            dom = extract_domain_from_ublock_filter(line)
                            if dom:
                                ignored_hide_domains.add(dom)
                            t = extract_search_hide_target(line)
                            if t:
                                ignored_hide_targets.add(t)

                        if cleaned_line and cleaned_line not in seen_lines:
                            tmp_out.write(cleaned_line + '\n')
                            seen_lines.add(cleaned_line)

            # Add converted from DNS sources as uBlock network rules (||domain^)
            dns_domains = set()
            for src in kinds.get('dns', []):
                with open(src, 'r', encoding='utf-8', errors='ignore') as infile:
                    for raw in infile:
                        d = parse_dns_line(raw)
                        if d:
                            dns_domains.add(d)
            for d in sorted(dns_domains):
                rule = f"||{d}^"
                if rule not in seen_lines:
                    tmp_out.write(rule + '\n')
                    seen_lines.add(rule)

        # Sort and dedupe final uBlock file for stability
        with open(combined_ublock_tmp, 'r', encoding='utf-8', errors='ignore') as tmp_in:
            lines = sorted({ln.strip() for ln in tmp_in if ln.strip()})
        with open(final_ublock_path, 'w', encoding='utf-8') as final_out:
            for ln in lines:
                final_out.write(ln + '\n')
        # Accumulate into combined uBlock
        combined_ublock_lines.update(lines)
        try:
            os.remove(combined_ublock_tmp)
        except OSError:
            pass

    # 2) Build final DNS list: union of DNS sources and domains extracted from uBlock network filters
        final_dns_path = os.path.join(out_dns, name)
        domains = set()

        # Domains from DNS sources
        for src in kinds.get('dns', []):
            with open(src, 'r', encoding='utf-8', errors='ignore') as infile:
                for raw in infile:
                    d = parse_dns_line(raw)
                    if d:
                        domains.add(d)

        # Domains from uBlock network filters (using the cleaned final uBlock file)
        with open(final_ublock_path, 'r', encoding='utf-8', errors='ignore') as infile:
            for raw in infile:
                d = extract_domain_from_ublock_filter(raw)
                if d:
                    domains.add(d)

        # Add www variants for DNS file writing
        expanded = set(domains)
        for d in list(domains):
            if not d.startswith('www.'):
                expanded.add('www.' + d)

        with open(final_dns_path, 'w', encoding='utf-8') as out_dns_f:
            for d in sorted(expanded):
                out_dns_f.write(f"0.0.0.0 {d}\n")

        # Accumulate into global sets
        all_domains_global.update(domains)
        combined_domains.update(domains)

        # Additionally, collect host/path targets for search-hider from the cleaned final uBlock file
        with open(final_ublock_path, 'r', encoding='utf-8', errors='ignore') as infile:
            for raw in infile:
                t = extract_search_hide_target(raw)
                if t:
                    # Store only as path target; don't add the bare host into domain set,
                    # to avoid hiding entire sites when only a specific path was intended.
                    pass

    # Build path target set by re-reading combined uBlock list lines
    path_targets_global = set()
    for ln in combined_ublock_lines:
        t = extract_search_hide_target(ln)
        if t:
            path_targets_global.add(t)

    # 3) Generate Search result hider list (combined) excluding flagged domains
    google_hide_path = os.path.join(out_ublock, 'google-hide.txt')
    hide_targets = path_targets_global.difference(ignored_hide_targets)
    # If we have specific host/path targets for a host, avoid hiding the whole host.
    # Build a set of hosts that have specific path targets; exclude both the host and its www/non-www variants
    base_hosts_with_paths = {t.split('/', 1)[0].lower() for t in hide_targets if '/' in t}
    hosts_with_path_targets = set()
    for h in base_hosts_with_paths:
        hosts_with_path_targets.add(h)
        if h.startswith('www.'):
            hosts_with_path_targets.add(h[4:])
        else:
            hosts_with_path_targets.add('www.' + h)
    hide_domains = {d for d in all_domains_global if '/' not in d and d.lower() not in hosts_with_path_targets}
    hide_domains = hide_domains.difference(ignored_hide_domains)
    write_google_hide_cosmetic(hide_domains, hide_targets, google_hide_path)

    # 3b) Generate Global link hider list (combined)
    link_hide_path = os.path.join(out_ublock, 'link-hide.txt')
    # Use the same domain suppression for hosts with path targets; reuse hide_domains/hide_targets
    write_link_hide_cosmetic(hide_domains, hide_targets, link_hide_path)

    # 4) Write combined outputs
    combined_ublock_path = os.path.join(out_ublock, 'combined.txt')
    with open(combined_ublock_path, 'w', encoding='utf-8') as f:
        for ln in sorted(combined_ublock_lines):
            f.write(ln + '\n')

    combined_dns_path = os.path.join(out_dns, 'combined.txt')
    expanded_all = set(combined_domains)
    for d in list(combined_domains):
        if not d.startswith('www.'):
            expanded_all.add('www.' + d)
    with open(combined_dns_path, 'w', encoding='utf-8') as f:
        for d in sorted(expanded_all):
            f.write(f"0.0.0.0 {d}\n")

    # 5) Aggregate an all-in-one uBlock list: combined + google-hide + link-hide
    give_all_path = os.path.join(out_ublock, 'give-me-all.txt')
    try:
        with open(give_all_path, 'w', encoding='utf-8') as out_f:
            out_f.write('! Title: Give me all (auto-generated)\n')
            out_f.write('! Description: Aggregate of network filters (combined) plus cosmetic google-hide and link-hide.\n')
            out_f.write('! Syntax: uBlock Origin filters (network + cosmetic)\n')
            out_f.write('! Homepage: https://github.com/Maingron/fight-fascists\n')
            out_f.write('!\n')

            # Network rules
            if os.path.exists(combined_ublock_path):
                with open(combined_ublock_path, 'r', encoding='utf-8', errors='ignore') as f_in:
                    for ln in f_in:
                        ln = ln.rstrip('\n')
                        if ln:
                            out_f.write(ln + '\n')
            out_f.write('\n')

            # Cosmetic: search result hider
            if os.path.exists(google_hide_path):
                with open(google_hide_path, 'r', encoding='utf-8', errors='ignore') as f_in:
                    for ln in f_in:
                        out_f.write(ln.rstrip('\n') + '\n')
            out_f.write('\n')

            # Cosmetic: global link hider
            if os.path.exists(link_hide_path):
                with open(link_hide_path, 'r', encoding='utf-8', errors='ignore') as f_in:
                    for ln in f_in:
                        out_f.write(ln.rstrip('\n') + '\n')
    except OSError:
        pass

    # Cleanup: remove outputs whose names no longer exist in sources (preserve google-hide.txt and combined.txt)
    valid_ublock_names = set(lists_by_name.keys()) | {os.path.basename(google_hide_path), os.path.basename(link_hide_path), 'combined.txt', 'give-me-all.txt'}
    cleanup_outputs(out_ublock, valid_ublock_names)
    valid_dns_names = set(lists_by_name.keys()) | {'combined.txt'}
    cleanup_outputs(out_dns, valid_dns_names)


if __name__ == "__main__":
    main()
