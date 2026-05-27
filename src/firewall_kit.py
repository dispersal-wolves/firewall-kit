"""Render reviewable firewall profiles for nftables and UFW."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    description: str
    inbound: tuple[str, ...]


PROFILES = {
    "workstation": Profile("Default-deny inbound workstation", ()),
    "server": Profile("Remote administration server", ("tcp:22",)),
    "web-server": Profile("Remote administration plus HTTP and HTTPS", ("tcp:22", "tcp:80", "tcp:443")),
    "container-host": Profile("Container host management plane", ("tcp:22",)),
}

PORT_PATTERN = re.compile(r"^(tcp|udp):(\d{1,5})$")


def parse_port(value: str) -> tuple[str, int]:
    match = PORT_PATTERN.fullmatch(value.lower())
    if not match:
        raise ValueError(f"invalid port specification: {value}; expected tcp:443")
    protocol, raw_port = match.groups()
    port = int(raw_port)
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return protocol, port


def ports_for(profile: Profile, additions: list[str]) -> list[tuple[str, int]]:
    return sorted({parse_port(item) for item in (*profile.inbound, *additions)}, key=lambda item: (item[0], item[1]))


def render_nftables(profile_name: str, ports: list[tuple[str, int]]) -> str:
    rules = [
        "#!/usr/sbin/nft -f",
        f"# Dispersal Wolves Firewall Kit · {profile_name}",
        "# Review before loading. This ruleset replaces only the dw_filter table.",
        "table inet dw_filter {",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        "    iifname \"lo\" accept",
        "    ct state established,related accept",
        "    ct state invalid drop",
        "    ip protocol icmp accept",
        "    ip6 nexthdr ipv6-icmp accept",
    ]
    for protocol, port in ports:
        rules.append(f"    {protocol} dport {port} ct state new accept")
    rules.extend(["  }", "  chain forward { type filter hook forward priority 0; policy drop; }", "  chain output { type filter hook output priority 0; policy accept; }", "}"])
    return "\n".join(rules) + "\n"


def render_ufw(profile_name: str, ports: list[tuple[str, int]]) -> str:
    lines = [
        "#!/bin/sh",
        "set -eu",
        f"# Dispersal Wolves Firewall Kit · {profile_name}",
        "# Review, keep an existing administrative session open, then run explicitly.",
        "ufw default deny incoming",
        "ufw default allow outgoing",
    ]
    lines.extend(f"ufw allow {port}/{protocol}" for protocol, port in ports)
    lines.extend(["ufw logging low", "ufw enable"])
    return "\n".join(lines) + "\n"


def command_list(args: argparse.Namespace) -> int:
    data = {name: {"description": profile.description, "inbound": profile.inbound} for name, profile in PROFILES.items()}
    if args.format == "json":
        print(json.dumps(data, indent=2))
    else:
        for name, profile in PROFILES.items():
            print(f"{name:16} {profile.description}")
    return 0


def command_render(args: argparse.Namespace) -> int:
    try:
        ports = ports_for(PROFILES[args.profile], args.allow)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    output = render_nftables(args.profile, ports) if args.backend == "nftables" else render_ufw(args.profile, ports)
    if args.output:
        args.output.write_text(output, encoding="utf-8", newline="\n")
        print(f"Wrote reviewable policy to {args.output}")
    else:
        print(output, end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("list")
    listing.add_argument("--format", choices=("text", "json"), default="text")
    listing.set_defaults(func=command_list)
    render = sub.add_parser("render")
    render.add_argument("profile", choices=tuple(PROFILES))
    render.add_argument("--backend", choices=("nftables", "ufw"), required=True)
    render.add_argument("--allow", action="append", default=[], metavar="PROTO:PORT")
    render.add_argument("--output", type=Path)
    render.set_defaults(func=command_render)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
