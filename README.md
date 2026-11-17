# PQ Sentinel

A Java honeypot and evidence collector with a local dashboard. It scores decoy requests, keeps a hash-linked event log, and forwards events through an authenticated encrypted channel.

## Features

- Interactive dashboard with synthetic-event input and rule results
- Hash-chain integrity and collector verification
- ML-KEM-768 key exchange and AES-GCM protected forwarding
- Local event export and forwarding status

## Requirements

| Use | Requirements |
|---|---|
| Run the app with Docker (recommended) | Docker Desktop/Engine with Compose v2; Internet for the first build; local ports 8080 and 9090 available |
| Build or test Java on your computer | JDK 25 (tested with Eclipse Temurin 25.0.5) and Maven 3.9.x (tested with 3.9.6) |
| Run the app directly on your computer | The Java requirements above plus MySQL 8.4, or use the Compose database services |
| Regenerate project figures | Python 3.8+ and pip; install the Python package from `requirements.txt` |

The Docker quick start does not require Java, Maven, Python, or a separately installed MySQL server. The Compose stack builds with Java 25/Maven 3.9.x, runs MySQL 8.4, and executes `mvn verify` during the image build.

Java libraries are managed by Maven in [pom.xml](pom.xml): Spring Boot 3.5.16 Web and JDBC starters, MySQL Connector/J at runtime, and Spring Boot Test for tests. The `requirements.txt` file is Python-only; it is not the Java dependency list.

## Get started

### 1. Clone the repository

Clone the repository and enter its folder:

```shell
git clone https://github.com/sonuvaishnavi33/pq-honeypot.git
cd pq-honeypot
```

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

To run tests on your machine, install JDK 25 and Maven 3.9.x. Check the installed versions and run the unit tests with:

```shell
java -version
mvn -version
mvn test
```

The Docker image build also runs the test suite. Application settings are in [application.yml](src/main/resources/application.yml). The quick start uses `CHAIN` mode; `FULL` mode requires an ML-DSA-65 checkpoint key pair.

## Configuration

The defaults are suitable for local demonstration only. To change ports or demo credentials, copy `.env.example` to `.env`, edit the values, and restart the Compose stack. Never publish demo credentials or expose the demo services to the public Internet.

