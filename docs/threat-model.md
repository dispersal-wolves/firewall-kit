# Threat model

## Protects against

Renders documented workstation, server, and container-host policies for nftables or UFW. Version 0.1 does not silently apply rules.

## Trust boundaries

- The local operator and operating system are trusted.
- Command-line arguments such as `--allow` values are untrusted and validated before they reach a rendered policy.
- The rendered policy is untrusted until a person reviews it; the tool never loads it.
- The tool needs no elevated privileges. Loading a policy does, and that step stays with the operator.

## Non-goals

- Exploitation, persistence, credential collection, or access to third-party systems.
- Replacing operating-system security controls or professional incident response.
- Auditing or reconciling rules already loaded on a host.

## Sensitive data

Rendered policies list the ports a host exposes. Treat them like other host configuration before sharing them.
