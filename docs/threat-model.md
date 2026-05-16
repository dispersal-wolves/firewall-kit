# Threat model

## Protects against

Renders documented workstation, server, and container-host policies for nftables or UFW. Version 0.1 does not silently apply rules.

## Trust boundaries

- The local operator and operating system are trusted.
- Input files, log lines, repository content, and command output are untrusted.
- Webhook destinations are contacted only when explicitly configured.
- Elevated privileges are never assumed to imply consent for unrelated changes.

## Non-goals

- Exploitation, persistence, credential collection, or access to third-party systems.
- Replacing operating-system security controls or professional incident response.
- Claiming that a clean report proves a host is uncompromised.

## Sensitive data

Generated reports can contain paths, usernames, process names, or network bindings. They are ignored by Git where the tool creates them. Review reports before sharing them.
