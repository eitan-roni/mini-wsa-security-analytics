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

Milestone `v0.1-ingestion` is complete: events are validated, persisted to PostgreSQL via Flyway-managed schema, and returned in the ingestion response. Classification, threat scoring, and repeat-offender logic are not implemented yet and are planned for milestone `v0.2-enrichment` via a later Flyway migration.

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

## Event Ingestion

### `POST /v1/events/ingest`

Accepts either a single JSON security-event object or a JSON array of events — both are normalized internally to the same list and processed identically. Batch validation is **all-or-nothing**: if any event in the request fails validation, the entire request is rejected with `400 Bad Request` and no events are processed. On success, the server assigns a UTC `receivedAt` timestamp to every accepted event, persists the batch to PostgreSQL, and returns `201 Created`.

Batch persistence is also **all-or-nothing**: if any event in an already-validated batch fails to persist (for example, a duplicate `eventId`), the entire batch is rolled back and no events are stored.

Enrichment, threat scoring, and analytics APIs are not implemented yet — see [Planned Milestones](#planned-milestones).

#### Successful request

```powershell
curl -X POST http://localhost:8080/v1/events/ingest `
  -H "Content-Type: application/json" `
  -d '{
    "eventId": "evt-001",
    "timestamp": "2026-07-11T10:15:30Z",
    "configId": 14227,
    "policyId": "policy-1",
    "clientIp": "203.0.113.10",
    "hostname": "example.com",
    "path": "/login",
    "method": "POST",
    "statusCode": 403,
    "userAgent": "Mozilla/5.0",
    "rule": { "id": "950001", "name": "SQL_INJECTION", "message": "SQL Injection Attack Detected", "severity": "CRITICAL", "category": "INJECTION" },
    "action": "DENY",
    "geoLocation": { "country": "US", "city": "San Francisco" },
    "requestSize": 512,
    "responseSize": 0
  }'
```

`201 Created`:

```json
{
  "acceptedCount": 1,
  "events": [
    { "eventId": "evt-001", "receivedAt": "2026-07-11T10:16:00Z" }
  ]
}
```

#### Invalid request

```powershell
curl -X POST http://localhost:8080/v1/events/ingest `
  -H "Content-Type: application/json" `
  -d '{ "eventId": "evt-002" }'
```

`400 Bad Request`:

```json
{
  "status": 400,
  "error": "VALIDATION_FAILED",
  "path": "/v1/events/ingest",
  "violations": [
    { "field": "events[0].timestamp", "message": "must not be null" },
    { "field": "events[0].configId", "message": "must not be null" }
  ]
}
```

#### Duplicate event

```powershell
curl -X POST http://localhost:8080/v1/events/ingest `
  -H "Content-Type: application/json" `
  -d '{ "eventId": "evt-001", ... }'
```

`409 Conflict` (when `eventId` already exists):

```json
{
  "status": 409,
  "error": "DUPLICATE_EVENT",
  "path": "/v1/events/ingest",
  "violations": [
    { "field": "eventId", "message": "One or more submitted event IDs already exist" }
  ]
}
```

## Persistence

* PostgreSQL is now used to persist accepted security events; start it with `docker compose up -d` before running the application (see [Start PostgreSQL](#start-postgresql)).
* Flyway manages the schema (`src/main/resources/db/migration`); Hibernate runs with `ddl-auto: validate` and never generates DDL itself.
* Accepted events are flattened into a single `security_events` table — nested `rule` and `geoLocation` fields become columns, not related tables.

## Implementation Assumptions

* In the incoming security-event schema, `city` (on `GeoLocationRequest`) and `userAgent` (on `SecurityEventRequest`) are optional; every other field is required.
* Batch ingestion uses all-or-nothing validation: if any event in a batch fails validation, the whole batch is rejected and the ingestion service is never invoked.
* Timestamps are represented as ISO-8601 strings on the wire and parsed into `java.time.Instant`.
* A single JSON object and a JSON array are both accepted by `POST /v1/events/ingest` and are normalized to the same internal list, so single-event requests report validation errors as `events[0].*`.

### Provisional persistence assumptions (pending assignment clarification)

* `eventId` is assumed unique and is enforced with a database unique constraint.
* A duplicate `eventId` currently returns `409 Conflict` with error code `DUPLICATE_EVENT`. This may change to idempotent (no-op success) behavior once the assignment clarification is available.
* Batch persistence is atomic and all-or-nothing: a failure while saving any single event in a batch rolls back the entire batch, and no partial batches are ever stored.
* Repeat-offender detection and event-time semantics (e.g. handling of out-of-order or backdated `timestamp` values) are explicitly out of scope for `v0.1-ingestion` and are not yet implemented.
* These are documented, easily reversible assumptions, not final design decisions.
