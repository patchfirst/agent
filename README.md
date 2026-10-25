# PatchFirst agent

The open-source collector behind [PatchFirst](https://patchfirst.dev), a service that tells you which vulnerabilities on your servers to patch first.

The agent runs on your server without root, lists the software stack, anonymizes it locally and sends only what vulnerability matching needs. Everything that identifies you is replaced or dropped before anything leaves the machine, and you can print the exact payload without sending it.

## What is sent

- OS release and installed packages with their versions.
- Versions of known server programs, container images and dependency lock files (npm, Composer, PyPI).
- The type of each listening service (for example, "web server" or "database") and whether it is reachable from the internet.
- A random server UUID.

## What is never sent

- Hostnames, IP addresses and port numbers.
- File paths, project names and private image names. They are replaced with irreversible labels: HMAC with a secret that stays on your server.
- Secrets, credentials and file contents.

Before sending, a final check rejects the payload if it still contains an address, a path or one of your identity words.

## See for yourself

Print the anonymized payload; nothing is sent:

```sh
python3 agent/agent.py check --json
```

With an installed config, `dry-run` shows what the scheduled run would send:

```sh
python3 agent/agent.py dry-run --config /etc/patchfirst.json
```

## Requirements

Python 3 standard library. `python3-cryptography` is optional: without it, data is still sent, but the encrypted dictionary of server names is not, and the dashboard shows server UUIDs.

## How it is used

The dashboard at [patchfirst.dev](https://patchfirst.dev) gives you an install command. It sets up a cron job that sends the inventory every 6 hours. The free one-time check needs no account.

Some strings in the code are in Russian. They are canonical report texts that the service translates into the reader's language by exact match, so they stay unchanged.

## Versions

`python3 agent/agent.py --version` prints the agent version; every request to the service carries it in the User-Agent. Each release is tagged `vX.Y.Z` here, and the site serves the agent built from that tag.

## Source of truth

This repository is a published copy of the agent from the PatchFirst service repository and is updated on every agent release. Issues and pull requests are welcome; accepted changes are applied upstream and appear here with the next sync.

## Security

Report vulnerabilities in the agent to support@patchfirst.dev.

## License

[Apache License 2.0](LICENSE)
