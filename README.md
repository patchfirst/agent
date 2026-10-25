# PatchFirst agent

The open-source collector behind [PatchFirst](https://patchfirst.dev), a service that tells you which vulnerabilities on your servers to patch first.

The agent runs on your server without root, lists the software stack, anonymizes it locally and sends only what vulnerability matching needs. You can print the exact payload without sending it.

## What is sent

- OS release and kernel version. A kernel suffix that is not a distribution or cloud build (for example `-acme-prod`) is cut to the upstream version.
- Packages from your distribution's repositories, and products from the PatchFirst catalogue, with their versions. Other packages (built locally or installed from other repositories) are sent only as a count.
- Versions of known server programs and container images. Images from private registries are sent as labels.
- Dependencies from lock files (npm, PyPI, Composer). Public packages are sent by name; private ones (private npm scopes, private PyPI indexes, Composer packages not from Packagist) as labels.
- The type of each listening service (for example, "web server" or "database") and whether it is reachable from the internet; whether a reboot is pending; whether the server has a public address (a yes/no flag, not the address).
- Labels instead of paths, program names and private package names: HMAC with a secret that stays on your server. The service can tell that a label is the same as last time, but cannot turn it back into the value.
- Identifiers: a random server UUID (fixed for an installed agent, new for every one-off check), the fleet ID and the write token from your config. They let the service link reports of the same server.
- The agent version, in the User-Agent header.

## What is never sent

- Hostnames or server names. The dashboard shows the server UUID, or a name you type there yourself; `patchfirst id` prints the UUID on the server.
- IP addresses and port numbers.
- File paths: every path leaves as a label.
- Names of packages outside the distribution and the catalogue.
- Secrets, credentials, registry URLs and file contents.

Before sending, a final check rejects the payload if it still contains an address, a path or one of your identity words (`identity_words` in the config: your company name, domain and so on).

## Network

Like any HTTPS request, the connection shows your IP address (or your NAT, VPN or proxy address) to the server that receives it. It is not part of the payload and is not stored: request logs are off, and addresses are kept only in memory for rate limiting. patchfirst.dev is served through Cloudflare, which also sees the connection address; ru.patchfirst.dev is not. The agent honours `HTTPS_PROXY` if you want to send through your own proxy.

## Limits

- Package origin comes from `apt-cache policy` (Debian, Ubuntu) and the package vendor (RPM-based systems). If apt metadata cannot be read in time, packages are sent by name. Alpine packages carry no origin and are sent by name.
- Python dependencies pinned without an index option are treated as public PyPI packages, because that is where pip installs them from.
- Versions keep only the words vendors and distributions use (`-1ubuntu0.1`, `-bookworm`, `.el9`); any other suffix and any internal address leave only the upstream release.
- Values the agent cannot classify are replaced with labels; anything that matches your identity words is replaced as well. Keep `identity_words` filled in.

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

Python 3 standard library.

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
