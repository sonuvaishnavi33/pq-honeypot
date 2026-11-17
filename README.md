# PQ Sentinel

A Java honeypot and evidence collector with a local dashboard. It scores decoy requests, keeps a hash-linked event log, and forwards events through an authenticated encrypted channel.

## Features

- Interactive dashboard with synthetic-event input and rule results
- Hash-chain integrity and collector verification
- ML-KEM-768 key exchange and AES-GCM protected forwarding
- Local event export and forwarding status

## Requirements

- Docker Desktop or Docker Engine with Docker Compose v2
- Git, to clone the repository
- Python 3.8+ only if you want to regenerate the project figures

Java and Maven do not need to be installed for the Docker quick start.

## Get started

### 1. Clone the repository

On GitHub, select **Code → HTTPS → Copy URL**, then run:

```shell
git clone <repository-url>
cd <repository-folder>
```

Replace the placeholders with the URL and folder name for this repository.

### 2. Install the optional Python dependency

This is only needed to regenerate figures; skip it if you just want to run the application.

```shell
python -m pip install -r requirements.txt
```

### 3. Start the application

Run this command from the repository root:

```shell
docker compose -f compose.quickstart.yml up --build -d
```

The first build may take a few minutes. Once the containers are running, you can access the services on these ports:

| Port | Service | URL |
|---:|---|---|
| 8080 | Dashboard | <http://localhost:8080> |
| 9090 | Collector API / verification | <http://localhost:9090/api/verify> |

The quick start uses local demo settings, `CHAIN` integrity mode, and ML-KEM-768. Both application ports are bound to your computer only. The databases use persistent Docker volumes.

## Try it

1. Use **Try your own event** or choose a sample to create a synthetic event.
2. Review the event's score and matched rules.
3. Select **Forward** to send the pending batch to the collector.
4. Confirm acceptance in the dashboard and check `/api/verify`.

**Export evidence** downloads a local JSON file; it does not send the file anywhere. Review exported data before sharing. The dashboard has no reset control.

## Stop the application

```shell
docker compose -f compose.quickstart.yml down
```

This stops and removes the containers but keeps the database volumes. Do not add `-v` unless you intend to delete those volumes.

To view startup logs:

```shell
docker compose -f compose.quickstart.yml logs -f honeypot collector
```

## Development

To run tests on your machine, install JDK 25 and Maven, then run:

```shell
mvn test
```

The Docker image build also runs the test suite. Application settings are in [application.yml](src/main/resources/application.yml). The quick start uses `CHAIN` mode; `FULL` mode requires an ML-DSA-65 checkpoint key pair.

## Configuration

The defaults are suitable for local demonstration only. To change ports or demo credentials, copy `.env.example` to `.env`, edit the values, and restart the Compose stack. Never publish demo credentials or expose the demo services to the public Internet.

