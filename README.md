# PatchFirst agent

The open-source collector behind [PatchFirst](https://patchfirst.dev), a service that tells you which vulnerabilities on your servers to patch first.

The agent runs on your server without root, lists the software stack, pseudonymizes it locally and sends only what vulnerability matching needs. You can print the exact payload without sending it.

## What is sent

- OS release and kernel version. A kernel suffix that is not a distribution or cloud build (for example `-acme-prod`) is cut to the upstream version.
- OS package names and versions only when the name appears in the public vulnerability-name list for that OS ecosystem, or the package matches a product in the PatchFirst catalogue. Other packages leave only a count. When a public list is available, filtered packages confirmed as coming from the distribution count as checked; other filtered packages count as a blind spot.
- A source package may appear by name when it matches the public list or catalogue even if its binary package name is hidden. In that case the binary name becomes a stable label, its version is withheld, and the source keeps its own source version. Public binary roles and yes/no matching facts may be retained without the hidden name.
- Versions of known server programs and container images. Images from private registries are sent as labels.
- Dependencies from lock files and Python environments (npm, PyPI, Composer). Names are sent only when the name appears in the public vulnerability-name list for its ecosystem or matches a catalogue product. Other dependencies leave only a count or a label, without their versions. Being on PyPI or Packagist, or having an unscoped npm name, is not enough to send a name. A listed name may be sent even when installed from a private source; the source URL stays local. Names known only from malicious-package reports (often internal names targeted by dependency confusion) leave by name only when the collected source confirms the public registry. A filtered dependency counts as checked only when its collected source confirms the public registry: an npm tarball URL, an explicit PyPI index/source, or a Packagist notification URL. An assumed default registry, requirements without an index, and Python environment metadata alone leave a blind spot.
- The type of each listening service (for example, "web server" or "database") and whether it is reachable from the internet; whether a reboot is pending; whether the server has a public address (a yes/no flag, not the address).
- Labels instead of paths, program names and private package names: HMAC with a secret that stays on your server. The service can tell that a label is the same as last time, but cannot turn it back into the value.
- Identifiers: a random server UUID (fixed for an installed agent, new for every one-off check), the fleet ID and the write token from your config. They let the service link reports of the same server.
- The agent version, in the User-Agent header.

## What is never sent

- Hostnames or server names. The dashboard shows the server UUID, or a name you type there yourself; `patchfirst id` prints the UUID on the server.
- IP addresses and port numbers.
- File paths: every path leaves as a label.
- Package and dependency names absent from both their ecosystem's public vulnerability-name list and the catalogue matching rules. Their versions and metadata that could expose those names are withheld too; an independently allowed source name keeps its own source version.
- Secrets, credentials, registry URLs and file contents.

Before sending, a final check rejects the payload if it still contains an address, a path or one of your identity words (`identity_words` in the config: your company name, domain and so on).

## Network

Before sending a report or printing `check --json`, the agent downloads `/agent/public-names.json.gz` from its regional site. This is one shared list for everyone, grouped by ecosystem: the request contains no package names or inventory, requires no account, and sends no report. The version 2 file is a UTF-8 line stream in gzip: its header is `#patchfirst-public-names 2 <revision>`, followed by sorted `ecosystem<TAB>name` rows. The agent atomically caches the original gzip bytes in its state directory (root uses `/var/cache/patchfirst`) and revalidates them with an ETag; an ETag is kept only when it equals the SHA-256 of the received file, so the server cannot tag a client. Redirects to another origin are refused before any request reaches it, for the list and for report and check requests. On each run it streams the file and keeps only the ecosystems for the collected OS and the dependencies found in that run; the request still downloads the same complete file for everyone. If the download fails, the last valid cache is used. Without a cache, only catalogue matches can leave as names and the agent prints a warning. Filtered packages then remain unchecked, including packages from the distribution. `check --json` uses `--api` first, then `api` from its config if present. Without either, it tries patchfirst.dev and falls back to ru.patchfirst.dev if that download fails. Explicit origins never change region automatically. Downloads have a 12-second shared network budget, with at most 6 seconds per origin; the timeout is checked between chunks so a trickling response cannot prevent fallback.

Use `check --json --offline` to skip the list download and ignore any cached copy. This conservatively hides all names except catalogue matches. With `--ssh`, the SSH connection and the port check of the target still run.

Like any HTTPS request, the connection shows your IP address (or your NAT, VPN or proxy address) to the server that receives it. It is not part of the payload and is not stored: request logs are off, and addresses are kept only in memory for rate limiting. patchfirst.dev is served through Cloudflare, which also sees the connection address; ru.patchfirst.dev is not. The agent honours `HTTPS_PROXY` if you want to send through your own proxy.

## Limits

- Packages that have never had a vulnerability entry are omitted from the dashboard unless they match the catalogue. A vulnerability for a new package name is detected after the next list refresh and agent run (normally within the 6-hour collection interval).
- The list proves that a name occurs in the vulnerability database; it does not prove where your installed copy came from. A private package whose name happens to match a listed public package can therefore leave by that public name.
- Versions keep only the words vendors and distributions use (`-1ubuntu0.1`, `-bookworm`, `.el9`); any other suffix and any internal address leave only the upstream release.
- Values the agent cannot classify are replaced with labels; anything that matches your identity words is replaced as well. Keep `identity_words` filled in.

## See for yourself

Print the pseudonymized payload; no inventory is sent (the shared public list is downloaded):

```sh
python3 agent/agent.py check --json
# With no network access and conservative name filtering:
python3 agent/agent.py check --json --offline
```

With an installed config, `dry-run` shows what the scheduled run would send:

```sh
python3 agent/agent.py dry-run --config /etc/patchfirst.json
```

## Requirements

Python 3.8 or later, standard library only.

## How it is used

The dashboard at [patchfirst.dev](https://patchfirst.dev) gives you an install command. It sets up a cron job that sends the inventory every 6 hours. The free one-time check needs no account.

Messages use the server's locale, in this order: `LC_ALL`, `LC_MESSAGES`, `LANG`.
English is the source language; Russian, German, French and Spanish are supported.
Unknown and non-UTF-8 locales fall back to English. Force a language with
`--lang en|ru|de|fr|es` or `PATCHFIRST_LANG`; the flag takes priority. An explicit
language uses UTF-8 output. The installer supports the same choices and preserves
an explicitly selected language for cron. Inventory fields and protocol markers
always use English and do not depend on the display language.

## Versions

`python3 agent/agent.py --version` prints the agent version; every request to the service carries it in the User-Agent. Each release is tagged `vX.Y.Z` here, and the site serves the agent built from that tag.

## Source of truth

This repository is a published copy of the agent from the PatchFirst service repository and is updated on every agent release. Issues and pull requests are welcome; accepted changes are applied upstream and appear here with the next sync.

## Security

Report vulnerabilities in the agent to support@patchfirst.dev.

## License

[Apache License 2.0](LICENSE)
