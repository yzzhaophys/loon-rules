#!/usr/bin/env python3
"""Build one Loon rule list for every rule provider in public home.yaml."""

import argparse
import concurrent.futures
import ipaddress
import re
import tempfile
import urllib.request
from pathlib import Path

import yaml


COMMENTED_PROVIDER = re.compile(r"^(\s*)#\s*([\w.!@-]+):\s*(\{.*)$")
COMMENTED_RULE = re.compile(r"^(\s*)#\s*(-\s*RULE-SET,.*)$")
DOMAIN_NAME = re.compile(r"^[A-Za-z0-9_\u0080-\uffff-]+(?:\.[A-Za-z0-9_\u0080-\uffff-]+)*$")
MAX_SOURCE_BYTES = 16 * 1024 * 1024


def definitions_from_home(content):
    """Read active and commented provider definitions and RULE-SET references."""
    lines = content.splitlines(keepends=True)
    try:
        first = next(i for i, line in enumerate(lines) if line.rstrip() == "rule-providers:")
        last = next(i for i in range(first + 1, len(lines)) if lines[i].rstrip() == "rules:")
    except StopIteration as exc:
        raise ValueError("home.yaml lacks rule-providers or rules") from exc
    commented_providers = []
    for i in range(first + 1, last):
        match = COMMENTED_PROVIDER.match(lines[i])
        if match and len(match.group(1)) == 2:
            commented_providers.append(match.group(2))
            lines[i] = f"{match.group(1)}{match.group(2)}: {match.group(3)}\n"
    commented_rules = []
    for i in range(last + 1, len(lines)):
        match = COMMENTED_RULE.match(lines[i])
        if match and len(match.group(1)) == 2:
            commented_rules.append(match.group(2).split(",", 2)[1].strip())
            lines[i] = f"{match.group(1)}{match.group(2)}\n"
    data = yaml.safe_load("".join(lines))
    providers = data.get("rule-providers")
    if not isinstance(providers, dict) or not providers:
        raise ValueError("rule-providers must be a nonempty mapping")
    if not set(commented_providers) <= set(providers):
        raise ValueError("a commented provider was not parsed")
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("rules must be a nonempty list")
    references = []
    for rule in rules:
        if not isinstance(rule, str):
            raise ValueError("rules must contain strings")
        if rule.startswith("RULE-SET,"):
            fields = [field.strip() for field in rule.split(",")]
            if len(fields) < 3 or not fields[1] or not fields[2]:
                raise ValueError("invalid RULE-SET reference")
            references.append(fields[1])
    if not set(commented_rules) <= set(references):
        raise ValueError("a commented rule was not parsed")
    missing = set(references) - set(providers)
    if missing:
        raise ValueError(f"RULE-SET references missing providers: {', '.join(sorted(missing))}")
    return providers, references, commented_providers, commented_rules


def source_url(provider):
    url = provider.get("url")
    if not isinstance(url, str) or not url.startswith("https://raw.githubusercontent.com/"):
        raise ValueError("provider URL must be a GitHub Raw HTTPS URL")
    fmt = provider.get("format")
    if fmt == "yaml":
        return url
    if fmt == "mrs" and url.endswith(".mrs"):
        # Both upstreams used here publish a same-name YAML source beside MRS.
        return url[:-4] + ".yaml"
    raise ValueError(f"unsupported provider format: {fmt!r}")


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "loon-rules-builder/1"})
    with urllib.request.urlopen(request, timeout=45) as response:
        content = response.read(MAX_SOURCE_BYTES + 1)
    if len(content) > MAX_SOURCE_BYTES:
        raise ValueError("upstream file exceeds size limit")
    return content.decode("utf-8-sig")


def convert_domain(value):
    if not isinstance(value, str) or not value or "," in value or "\n" in value:
        raise ValueError("invalid domain entry")
    if value.startswith("+."):
        name = value[2:]
        rule = "DOMAIN-SUFFIX"
    elif value.startswith("."):
        name = "*." + value[1:]
        rule = "DOMAIN-WILDCARD"
    elif "*" in value or "?" in value:
        # Mihomo's * matches exactly one label; Loon's * crosses dots.
        raise ValueError(f"Clash wildcard cannot be converted exactly: {value}")
    else:
        name = value
        rule = "DOMAIN"
    if not DOMAIN_NAME.fullmatch(name.removeprefix("*.")):
        raise ValueError(f"invalid domain entry: {value}")
    return f"{rule},{name}"


def convert_ip(value):
    if not isinstance(value, str):
        raise ValueError("invalid IP entry")
    network = ipaddress.ip_network(value, strict=False)
    kind = "IP-CIDR6" if network.version == 6 else "IP-CIDR"
    return f"{kind},{value},no-resolve"


def convert_provider(provider, source, name=None):
    data = yaml.safe_load(source)
    if not isinstance(data, dict) or "payload" not in data:
        raise ValueError("upstream YAML must contain payload")
    payload = data["payload"]
    if payload is None:
        return "# Upstream payload is empty.\n"
    if not isinstance(payload, list):
        raise ValueError("upstream payload must be a list")
    if not payload:
        return "# Upstream payload is empty.\n"
    behavior = provider.get("behavior")
    if behavior == "domain":
        convert = convert_domain
    elif behavior == "ipcidr":
        convert = convert_ip
    else:
        raise ValueError(f"unsupported behavior: {behavior!r}")
    result = []
    seen = set()
    for value in payload:
        if name == "R-fakeipfilter" and value == "+.Mijia Cloud":
            # This public upstream item contains a space and is not a domain.
            result.append("# Skipped invalid upstream item: +.Mijia Cloud")
            continue
        rule = convert(value)
        if rule not in seen:
            result.append(rule)
            seen.add(rule)
    return "\n".join(result) + "\n"


def build_one(item):
    name, provider = item
    try:
        return name, convert_provider(provider, download(source_url(provider)), name)
    except Exception as exc:
        raise ValueError(f"{name}: {exc}") from exc


def build(home, output, workers=12):
    providers, references, commented_providers, commented_rules = definitions_from_home(
        home.read_text(encoding="utf-8")
    )
    results = {}
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(build_one, item): item[0] for item in providers.items()}
        for future in concurrent.futures.as_completed(futures):
            try:
                name, content = future.result()
                results[name] = content
            except Exception as exc:
                failures.append(str(exc))
    if failures:
        raise ValueError("conversion failed; old lists kept:\n" + "\n".join(sorted(failures)))
    if len(results) != len(providers):
        raise ValueError("provider/list count mismatch")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".loon-build-", dir=output.parent) as tmp:
        candidate = Path(tmp) / "lists"
        candidate.mkdir()
        for name, content in results.items():
            if name in (".", "..") or "/" in name or "\\" in name:
                raise ValueError("invalid provider name")
            (candidate / f"{name}.list").write_text(content, encoding="utf-8")
        if output.exists():
            backup = Path(tmp) / "old-lists"
            output.rename(backup)
            try:
                candidate.rename(output)
            except Exception:
                backup.rename(output)
                raise
        else:
            candidate.rename(output)
    return len(results), len(references), commented_providers, commented_rules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("lists"))
    args = parser.parse_args()
    count, referenced, commented_providers, commented_rules = build(args.home, args.output)
    print(f"Generated {count} lists ({len(commented_providers)} commented providers included).")
    print(f"Validated {referenced} RULE-SET references ({len(commented_rules)} commented rules included).")


if __name__ == "__main__":
    main()
