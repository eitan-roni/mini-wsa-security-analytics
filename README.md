# Mini WSA – Security Analytics Pipeline

Mini WSA is a simplified security analytics backend inspired by large-scale Web Security Analytics systems.

The service will ingest security events, validate and enrich them, persist them, and expose analytical REST APIs for statistics and event samples.

## Planned Technology Stack

* Java 21
* Spring Boot
* Maven
* PostgreSQL
* Flyway
* Docker Compose
* JUnit 5
* Testcontainers

## Planned Milestones

* `v0.1-ingestion` – event ingestion and validation
* `v0.2-enrichment` – classification and threat-score calculation
* `v0.3-stats` – summary statistics API
* `v0.4-samples` – event filtering and pagination
* `v0.5-generator` – security-event and attack-wave generator

## Project Status

Initial project setup, including a local PostgreSQL development environment managed through Docker Compose.

## Local Development Environment

### Prerequisites

* Java 21
* Docker Desktop

### Start PostgreSQL

```powershell
docker compose up -d
```

Check that the PostgreSQL container is running and healthy:

```powershell
docker compose ps
```

### Run the Application on Windows

```powershell
.\mvnw.cmd spring-boot:run
```

### Check Application Health

Open:

```text
http://localhost:8080/actuator/health
```

The endpoint should return a response containing:

```json
{
  "status": "UP"
}
```

### Stop the Local Environment

```powershell
docker compose down
```

## Implementation Assumptions

* In the incoming security-event schema, `city` (on `GeoLocationRequest`) and `userAgent` (on `SecurityEventRequest`) are optional; every other field is required.
* Batch ingestion (once implemented) will use all-or-nothing validation: if any event in a batch fails validation, the whole batch is rejected.
* Timestamps are represented as ISO-8601 strings on the wire and parsed into `java.time.Instant`.
