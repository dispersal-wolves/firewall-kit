<p align="center">
  <img src="docs/banner.svg" alt="Firewall Kit — Dispersal Wolves" width="100%">
</p>

# Firewall Kit

**Readable firewall profiles built on the firewall you already have.**

Renders documented workstation, server, and container-host policies for nftables or UFW. Version 0.1 does not silently apply rules.

## Start

```console
python src/firewall_kit.py render workstation --backend nftables
```

For a global `firewall-kit` command, run `python -m pip install .`.

Run the command with `--help` for every option. The tool works locally, collects no telemetry, and supports machine-readable output where applicable.

## Principles

- **Local first.** Host data stays on the host unless you explicitly configure a webhook.
- **Safe by default.** Inspection is read-only and mutation requires a deliberate command.
- **Small contract.** The tool solves one defensive job and reports its limits plainly.
- **Scriptable.** Stable exit codes and structured output make automation practical.

## Platform

The initial release targets Linux. Portable behavior is also tested on Windows where the underlying operating-system facilities allow it. See [the threat model](docs/threat-model.md) for trust boundaries and non-goals.

## Development

This repository uses **Python** and the standard library only. Version 0.1 renders policies without applying them; review the generated rules in an active administrative session before loading them with the operating-system firewall.

```console
python -m compileall -q src
python -m unittest discover -s tests -v
```

## License

[MIT](LICENSE) © Dispersal Wolves.
