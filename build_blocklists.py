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


def write_google_hide_cosmetic(all_domains: set, out_path: str) -> None:
    """Write a uBlock cosmetic filter list to hide Google search results linking to any domain in all_domains."""
    if not all_domains:
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
        ],
        # 'www.bing.com': [ ':is(#b_results > .b_algo, #b_results > li.b_algo)' ],  # example
    }

    def rule_for_has(d: str) -> List[str]:
        return [f"{engine}##{sel}:has(a[href*=\"://{d}\"])" for engine, selectors in search_engines.items() for sel in selectors]

    # Keep output compact: only emit the :has(...) rule per domain.
    # The :upward(...) variant is omitted for size; re-add if robustness is needed.

    # Expand with www variants for more accurate matches
    expanded = set(all_domains)
    for d in list(all_domains):
        if not d.startswith('www.'):
            expanded.add('www.' + d)

    for d in sorted(expanded):
        # Skip obviously invalid leftovers
        if '/' in d or ':' in d:
            continue
        rules.extend(rule_for_has(d))

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
    src_ublock = os.path.join(src_root, 'ublock')
    src_dns = os.path.join(src_root, 'dns-lists')

    out_ublock = os.path.join('dist', 'blocklists', 'ublock')
    out_dns = os.path.join('dist', 'blocklists', 'dns-lists')

    ensure_dirs(out_ublock, out_dns)

    # Collect sources by filename, separated by type
    lists_by_name = {}

    def add_src(dct, name, kind, path):
        if name not in dct:
            dct[name] = {'ublock': [], 'dns': []}
        dct[name][kind].append(path)

    if os.path.isdir(src_ublock):
        for root, _, files in os.walk(src_ublock):
            for fn in files:
                if fn.endswith('.txt'):
                    add_src(lists_by_name, fn, 'ublock', os.path.join(root, fn))

    if os.path.isdir(src_dns):
        for root, _, files in os.walk(src_dns):
            for fn in files:
                if fn.endswith('.txt'):
                    add_src(lists_by_name, fn, 'dns', os.path.join(root, fn))

    # Accumulators for combined outputs
    combined_ublock_lines = set()
    combined_domains = set()

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
                        line = raw.strip()
                        if is_comment_or_blank(line) or is_cosmetic_filter(line):
                            continue
                        if line and line not in seen_lines:
                            tmp_out.write(line + '\n')
                            seen_lines.add(line)

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

    # 3) Generate Google search result hider list (combined)
    google_hide_path = os.path.join(out_ublock, 'google-hide.txt')
    write_google_hide_cosmetic(all_domains_global, google_hide_path)

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

    # Cleanup: remove outputs whose names no longer exist in sources (preserve google-hide.txt and combined.txt)
    valid_ublock_names = set(lists_by_name.keys()) | {os.path.basename(google_hide_path), 'combined.txt'}
    cleanup_outputs(out_ublock, valid_ublock_names)
    valid_dns_names = set(lists_by_name.keys()) | {'combined.txt'}
    cleanup_outputs(out_dns, valid_dns_names)


if __name__ == "__main__":
    main()
