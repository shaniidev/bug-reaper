#!/usr/bin/env python3
"""
analyze_scope.py — Web2 Bug Bounty Scope Analyzer

Parses a bug bounty program's scope/rules markdown file and extracts
structured information for the audit phase.

Usage:
    python analyze_scope.py <scope_file> [--output scope.json]
    python analyze_scope.py --help

Example:
    python analyze_scope.py hackerone_program.md
    python analyze_scope.py program_scope.md --output structured_scope.json
"""

import re
import sys
import json
import argparse
from pathlib import Path


def parse_scope_file(filepath: str) -> dict:
    """Parse a program scope/rules markdown file into structured data."""
    path = Path(filepath)
    if not path.exists():
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    content = path.read_text(encoding="utf-8")
    
    result = {
        "program_name": _extract_program_name(content, path.stem),
        "platform": _detect_platform(content),
        "in_scope": [],
        "out_of_scope": [],
        "excluded_vuln_types": [],
        "reward_tiers": [],
        "technology_hints": [],
        "focus_areas": [],
        "special_rules": [],
    }
    
    result["in_scope"] = _extract_scope_items(content, "in.?scope", out=False)
    result["out_of_scope"] = _extract_scope_items(content, "out.?of.?scope", out=True)
    result["excluded_vuln_types"] = _extract_excluded_vulns(content)
    result["reward_tiers"] = _extract_tiers(content)
    result["technology_hints"] = _extract_tech_hints(content)
    result["focus_areas"] = _extract_focus_areas(content)
    result["special_rules"] = _extract_special_rules(content)
    
    return result


def _extract_program_name(content: str, fallback: str) -> str:
    """Extract program name from first heading or filename."""
    match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    return match.group(1).strip() if match else fallback.replace("_", " ").title()


def _detect_platform(content: str) -> str:
    """Detect which bug bounty platform this program uses."""
    content_lower = content.lower()
    if "hackerone" in content_lower or "h1" in content_lower:
        return "hackerone"
    elif "bugcrowd" in content_lower:
        return "bugcrowd"
    elif "intigriti" in content_lower:
        return "intigriti"
    elif "yeswehack" in content_lower:
        return "yeswehack"
    return "unknown"


def _extract_scope_items(content: str, section_pattern: str, out: bool) -> list:
    """Extract in-scope or out-of-scope items."""
    items = []
    
    # Find section
    section_regex = rf"(?im)^#{1,3}\s+.*{section_pattern}.*$"
    matches = list(re.finditer(section_regex, content, re.IGNORECASE))
    
    if not matches:
        # Fallback: look for labeled lists
        fallback = "out.?of.?scope" if out else "in.?scope"
        bullet_pattern = rf"(?im)\*\s+\*\*{fallback}\*\*:?\s*(.+)"
        for m in re.finditer(bullet_pattern, content, re.IGNORECASE):
            items.append(m.group(1).strip())
        return items
    
    for match in matches:
        start = match.end()
        # Find next section
        next_section = re.search(r"(?m)^#{1,3}\s+", content[start:])
        end = start + next_section.start() if next_section else len(content)
        section_content = content[start:end]
        
        # Extract bullet points, table rows, and code blocks with domains
        for line in section_content.split("\n"):
            line = line.strip()
            # Bullet points
            if line.startswith(("- ", "* ", "+ ")):
                item = line[2:].strip()
                if item and len(item) > 2:
                    items.append(item)
            # Table rows
            elif "|" in line and not line.startswith("|---"):
                cells = [c.strip() for c in line.split("|") if c.strip()]
                for cell in cells:
                    # Look for domain-like or endpoint-like patterns
                    if re.search(r"[\w.-]+\.\w{2,}|/api/|\*\.\w", cell):
                        items.append(cell)
            # Code-formatted items
            elif line.startswith("`") and line.endswith("`"):
                items.append(line[1:-1])
    
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _extract_excluded_vulns(content: str) -> list:
    """Extract explicitly excluded vulnerability types."""
    excluded = []
    
    # Common exclusion keywords
    exclusion_classes = [
        "self.?xss", "clickjacking", "csrf.*(login|logout)", "rate.?limit",
        "missing.?header", "version.?disclosure", "ssl.?tls", "open.?redirect",
        "host.?header", "cache.?poisoning", "tab.?nabbing", "self.?ssrf",
        "physical.?attack", "social.?engineering", "dos", "ddos",
        "brute.?force", "spf.?dmarc", "email.?spoofing", "directory.?listing",
    ]
    
    for cls in exclusion_classes:
        pattern = rf"(?i){cls}"
        if re.search(pattern, content):
            # Check if it appears in a "not rewarded" or "excluded" context
            for match in re.finditer(pattern, content, re.IGNORECASE):
                start = max(0, match.start() - 100)
                context = content[start:match.end() + 100].lower()
                exclusion_keywords = ["not", "excluded", "won't", "will not", "out of scope", "n/a", "no reward"]
                if any(kw in context for kw in exclusion_keywords):
                    excluded.append(match.group(0))
                    break
    
    return list(set(excluded))


def _extract_tiers(content: str) -> list:
    """Extract reward tier information."""
    tiers = []
    
    # Match common reward tier patterns
    patterns = [
        r"(?i)(critical|high|medium|low|informational|p1|p2|p3|p4|p5)[:\s]+\$?([\d,]+)(?:\s*-\s*\$?([\d,]+))?",
        r"\|\s*(critical|high|medium|low|p[1-5])\s*\|\s*\$?([\d,]+)(?:\s*-\s*\$?([\d,]+))?\s*\|",
    ]
    
    for pattern in patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            groups = match.groups()
            tier = {"level": groups[0].strip()}
            if groups[1]:
                tier["min_reward"] = int(groups[1].replace(",", ""))
            if len(groups) > 2 and groups[2]:
                tier["max_reward"] = int(groups[2].replace(",", ""))
            tiers.append(tier)
    
    return tiers


def _extract_tech_hints(content: str) -> list:
    """Extract technology stack hints from scope description."""
    hints = []
    
    tech_patterns = {
        r"react|angular|vue|next\.js|nuxt": "JavaScript SPA Framework",
        r"node\.js|express|koa|fastify": "Node.js Backend",
        r"django|flask|fastapi": "Python Backend",
        r"rails|ruby": "Ruby on Rails",
        r"laravel|symfony|php": "PHP Backend",
        r"spring|java": "Java Backend",
        r"graphql": "GraphQL API",
        r"rest api|restful": "REST API",
        r"websocket|socket\.io": "WebSocket",
        r"aws|s3|lambda|cloudfront": "AWS Infrastructure",
        r"gcp|google cloud": "GCP Infrastructure",
        r"azure": "Azure Infrastructure",
        r"postgresql|mysql|mongodb|redis": "Database",
        r"oauth|oidc|saml": "Auth Protocol",
        r"jwt": "JWT Authentication",
    }
    
    for pattern, label in tech_patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            hints.append(label)
    
    return list(set(hints))


def _extract_focus_areas(content: str) -> list:
    """Extract areas the program specifically highlights for testing."""
    focus = []
    
    focus_keywords = [
        "authentication", "authorization", "payment", "admin", "api",
        "file upload", "search", "export", "import", "webhook",
        "mobile", "ios", "android", "2fa", "mfa", "sso",
    ]
    
    # Find if these appear in "focus", "priority", "we care about" sections
    priority_section = re.search(
        r"(?is)(priority|focus|we care|important|high.?value|especially).{0,500}",
        content
    )
    
    if priority_section:
        section_text = priority_section.group(0).lower()
        for kw in focus_keywords:
            if kw in section_text:
                focus.append(kw)
    
    # Also check for any marked HIGH priority explicitly
    for kw in focus_keywords:
        if re.search(rf"(?i)(critical|high|important).*{kw}", content):
            if kw not in focus:
                focus.append(kw)
    
    return focus


def _extract_special_rules(content: str) -> list:
    """Extract special rules, responsible disclosure requirements, etc."""
    rules = []
    
    rule_patterns = [
        r"(?im)do not.*attack.*production",
        r"(?im)no.*automated.*scanning",
        r"(?im)maximum.*\d+.*requests",
        r"(?im)must.*not.*social.?engineer",
        r"(?im)report.*within.*\d+.*days?",
        r"(?im)do not.*exfiltrate",
        r"(?im)stop.*after.*first.*instance",
    ]
    
    for pattern in rule_patterns:
        match = re.search(pattern, content)
        if match:
            rules.append(match.group(0).strip())
    
    return rules


def print_summary(data: dict) -> None:
    """Print a human-readable summary of the parsed scope."""
    print(f"\n{'='*60}")
    print(f"Program: {data['program_name']}")
    print(f"Platform: {data['platform'].upper()}")
    print(f"{'='*60}\n")
    
    if data["in_scope"]:
        print(f"IN SCOPE ({len(data['in_scope'])} items):")
        for item in data["in_scope"][:15]:
            print(f"  ✓ {item}")
        if len(data["in_scope"]) > 15:
            print(f"  ... and {len(data['in_scope']) - 15} more")
    
    if data["out_of_scope"]:
        print(f"\nOUT OF SCOPE ({len(data['out_of_scope'])} items):")
        for item in data["out_of_scope"][:10]:
            print(f"  ✗ {item}")
    
    if data["excluded_vuln_types"]:
        print(f"\nEXCLUDED VULN TYPES:")
        for v in data["excluded_vuln_types"]:
            print(f"  ✗ {v}")
    
    if data["reward_tiers"]:
        print(f"\nREWARD TIERS:")
        for tier in data["reward_tiers"]:
            reward_str = ""
            if "min_reward" in tier:
                reward_str = f"${tier['min_reward']:,}"
                if "max_reward" in tier:
                    reward_str += f" - ${tier['max_reward']:,}"
            print(f"  {tier['level'].upper()}: {reward_str}")
    
    if data["technology_hints"]:
        print(f"\nTECHNOLOGY STACK HINTS:")
        for tech in data["technology_hints"]:
            print(f"  • {tech}")
    
    if data["focus_areas"]:
        print(f"\nFOCUS AREAS (high priority):")
        for area in data["focus_areas"]:
            print(f"  → {area}")
    
    if data["special_rules"]:
        print(f"\nSPECIAL RULES:")
        for rule in data["special_rules"]:
            print(f"  ⚠ {rule}")
    
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Parse a bug bounty program scope file into structured data for auditing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze_scope.py hackerone_program.md
  python analyze_scope.py program_scope.md --output scope.json
  python analyze_scope.py scope.txt --json-only
        """
    )
    parser.add_argument("scope_file", help="Path to the program scope/rules markdown file")
    parser.add_argument("--output", "-o", help="Output JSON file path (default: print to stdout)")
    parser.add_argument("--json-only", action="store_true", help="Only output JSON, no human-readable summary")
    
    args = parser.parse_args()
    
    data = parse_scope_file(args.scope_file)
    
    if not args.json_only:
        print_summary(data)
    
    json_output = json.dumps(data, indent=2)
    
    if args.output:
        Path(args.output).write_text(json_output, encoding="utf-8")
        if not args.json_only:
            print(f"Structured scope saved to: {args.output}")
    else:
        if args.json_only:
            print(json_output)
        else:
            print("JSON output:")
            print(json_output)


if __name__ == "__main__":
    main()
