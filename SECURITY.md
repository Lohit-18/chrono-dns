# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Use GitHub's private reporting (Security → Report a vulnerability) on this repository, or email the
maintainer listed in `pyproject.toml`.

Please include:

- what the issue is and which component it affects
- reproduction steps, ideally a minimal DNS query or config that triggers it
- your assessment of the impact
- whether you have a fix in mind

You can expect an acknowledgement within 72 hours and an assessment within 7 days. Fixes for
anything scored high or critical are released as soon as they are ready and tested. If you want
credit in the release notes, say so.

## In scope

- Remote crash or hang of the gateway from a crafted DNS packet
- Detection bypass that is systematic rather than a single-sample miss
- SQL injection through any input path (domain names, intel imports, CLI arguments, REST bodies)
- Privilege or path escalation via the CLI, scripts or Docker image
- Secrets or personal data leaking into logs, the database or the dashboard
- Denial of service through unbounded memory growth (cache, state maps, alert buffer)

## Out of scope

- DoH/DoT clients that bypass this resolver entirely — a documented architectural limitation, not a
  vulnerability (see the README)
- Evasion of a *specific* detection threshold on a *specific* query. Detection is probabilistic;
  a generalisable evasion technique is a very welcome regular issue, and a genuinely valuable
  contribution
- Vulnerabilities in upstream dependencies — report those upstream; we will bump the pin
- Findings that require the attacker to already control the machine running Chrono-DNS

## Deploying safely

- **Do not expose the gateway to the internet.** It is a recursive forwarder for an internal
  network. An open resolver is an amplification weapon.
- **Bind to an internal interface.** The default is `127.0.0.1:5353` on purpose.
- **The dashboard has no authentication.** It binds to `127.0.0.1` by default. If you need it on a
  network, put it behind a reverse proxy with authentication, or use an SSH tunnel.
- **Change the default PostgreSQL credentials** before anything leaves your laptop. The values in
  `.env.example` and `docker-compose.yml` are for local development only.
- **Run as an unprivileged user.** The default port 5353 avoids needing root. If you must use port
  53, grant the capability rather than running the whole process as root:
  ```bash
  sudo setcap 'cap_net_bind_service=+ep' "$(readlink -f "$(which python3)")"
  ```
- **DNS logs are personal data.** They reveal what people read, which services they use, and their
  health and financial interests. Apply a retention policy (`SELECT fn_prune(30);`), restrict
  database access, and tell your users what you are collecting.
- **Start in monitor mode** (`CHRONODNS_ENFORCE=false`) and watch what *would* have been blocked for
  at least a week before enforcing.

## About the bundled simulators

`chronodns/datagen/` contains generators that produce query strings resembling DNS tunnelling, DGA
and C2 beaconing. They exist to train and evaluate the detector. They:

- generate strings only against RFC 2606 / RFC 6761 reserved names (`.example`, `.test`, `.invalid`)
- establish no tunnel, transmit no payload and contain no malware
- send no packets at all, except `scripts/attack_sim.sh`, which sends `dig` queries to a resolver
  address **you** supply

They are not an attack tool, and pull requests that would turn them into one will be declined.
