# PQ Sentinel

PQ Sentinel is a local Java honeypot and evidence collector. It scores decoy requests, records events in a hash chain, and forwards them over an authenticated encrypted channel. The dashboard lets you create synthetic events, inspect rule results, and check forwarding status.

> **Prototype only:** the included demo credentials and services are for local evaluation. Do not expose them to the Internet or use them to collect real users' data.

## Quick start

### Requirements

- Docker Desktop (Windows or macOS) or Docker Engine (Linux)
- Docker Compose v2
- An Internet connection for the first image build

You do **not** need Java or Maven installed on the host for this quick start. Docker builds the app with Java 25 and runs the test suite as part of the image build.

### Start the complete application

Clone or download this repository, open a terminal in its root directory, then run:

```shell
docker compose -f compose.quickstart.yml up --build -d
```

The first build may take a few minutes. When the containers have started, open:

- Dashboard: <http://localhost:8080>
- Collector verification: <http://localhost:9090/api/verify>

The quick-start stack uses local-only demo settings, ML-KEM-768, and `CHAIN` integrity mode. It starts two MySQL databases and both Spring Boot services. The databases use named Docker volumes, so normal stops and restarts retain their data.

Check startup or investigate errors:

```shell
docker compose -f compose.quickstart.yml ps
docker compose -f compose.quickstart.yml logs -f honeypot collector
```

Stop the stack without deleting its databases:

```shell
docker compose -f compose.quickstart.yml down
```

**Do not add `-v`** to the `down` command unless you intentionally want to delete the quick-start database volumes.

### Try the dashboard

1. Use **Try your own event** or a sample case to create a local synthetic event.
2. Review its score and matched rules in the dashboard.
3. Use **Forward** to send the pending batch to the collector. The control sends pending events, not only the event just created.
4. Confirm collector acceptance and check <http://localhost:9090/api/verify>.
5. **Export evidence** downloads a local JSON snapshot; it does not transmit the file. Review it for sensitive details before sharing.

The dashboard has no reset control. The tamper demonstration alters a pending event and is intended only for isolated testing. Never run reset-based research scripts against this quick-start database or any database containing data you want to keep.

## Ports and configuration

| Service | Local URL | Purpose |
|---|---|---|
| Honeypot dashboard | `http://localhost:8080` | Dashboard and synthetic-event input |
| Collector | `http://localhost:9090` | Evidence API and verification |

The quick-start Compose file binds application ports to `127.0.0.1`; its databases are not published to the host. If ports 8080 or 9090 are already in use, copy `.env.example` to `.env` and change `HONEYPOT_HOST_PORT` and/or `COLLECTOR_HOST_PORT`.

PowerShell:

```powershell
Copy-Item .env.example .env
```

macOS/Linux:

```shell
cp .env.example .env
```

Then run the Quick start command again. The `.env` values are demo-only; use your own secrets for any non-demo deployment.

## Development and tests

For Java development, install JDK 25 and Maven 3.9 or later. Run the unit tests with:

```shell
mvn test
```

The complete local stack is easiest to run with the quick-start Compose file. For a host-run Maven setup, both Spring profiles need database URLs, the same `APP_PSK`, and the collector URL configured; `application.yml` documents the environment-variable names and defaults. `CHAIN` mode is the no-key setup. `FULL` mode additionally requires an ML-DSA-65 checkpoint key pair.

## Research and reproducibility

- [Research paper](research-paper.md)
- [Limitations and implementation status](LIMITATIONS.md)
- [Consolidated result tables](results/tables.md)
- [Captured environment](results/environment.json)

The paper contains the methods, workflow diagram, measured results, model-only results, discussion, and references. Figures 1–6 and 8 are regenerated with `python generate-research-figures.py`; the live-service comparison is regenerated with `python generate-live-service-figure.py`. Tables are regenerated with `python generate-research-tables.py`.

The quick start does not require Python. To regenerate research figures on your host, install Python 3.8 or later and install the dependency in [requirements.txt](requirements.txt):

```shell
python -m pip install -r requirements.txt
```

`.\reproduce-research.ps1` runs the Windows research workflow. The live detector and service benchmark scripts create or reset data in their designated demo databases. The tamper and benchmark scripts are destructive to the isolated demo state they target. Use them only with dedicated research databases—never with the quick-start volumes, retained evidence, or production data.

The exposure-window sweep and attack matrix are simulations/reference models, not live security measurements. Live measurements are single-host exploratory results and do not establish superiority over another system. Review [LIMITATIONS.md](LIMITATIONS.md) and the paper before citing any result.

## Integrity modes

The quick-start stack uses `CHAIN` mode to avoid requiring key generation. To use `FULL` integrity mode, provision an ML-DSA-65 key pair first. Keep the private key only on the honeypot; configure the public key on both services. Never commit or share the private key.

On a JDK 25/Maven development machine, generate owner-restricted key files with:

```powershell
$keys = Join-Path $env:USERPROFILE ".pqh"
$privateKey = Join-Path $keys "checkpoint-private.key"
$publicKey = Join-Path $keys "checkpoint-public.key"
mvn spring-boot:run "-Dspring-boot.run.main-class=pqh.research.CheckpointKeygenMain" "-Dspring-boot.run.arguments=$privateKey $publicKey"
```

Configure the honeypot with `PQH_CHECKPOINT_PRIVATE_KEY_FILE` and `PQH_CHECKPOINT_PUBLIC_KEY_FILE`; configure the collector with `PQH_CHECKPOINT_PUBLIC_KEY_FILE`. File-based and inline Base64 key settings cannot be used together. The key generator refuses to overwrite existing files.

## Existing research database Compose setup

`docker-compose.yml` remains the database-only setup used by the research scripts. It publishes MySQL on ports 3308 and 3307 for local research workflows; it is **not** the recommended application quick start. Use `compose.quickstart.yml` for a fresh local install.
