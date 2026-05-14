# Rate Limiting

## Summary

`psst-rs` applies application-side rate limiting in addition to Cloudflare Turnstile.

Current limits per hashed IP:

- creation: `5` per minute;
- creation: `30` per hour;
- read: `60` per minute.

These values are configurable through environment variables.

## Configuration Variables

- `SECRET_RS_IP_HASH_SALT`
  Required server-side salt used to pseudonymize the client IP before storing or counting it.

- `SECRET_RS_CREATE_RATE_LIMIT_PER_MINUTE`
  Creation limit per minute. Default: `5`.

- `SECRET_RS_CREATE_RATE_LIMIT_PER_HOUR`
  Creation limit per hour. Default: `30`.

- `SECRET_RS_READ_RATE_LIMIT_PER_MINUTE`
  Soft read limit per minute. Default: `60`.

## Counting Key

Rate limiting never stores the raw IP.

The server:

- extracts the client IP through trusted proxies;
- computes a pseudonymized identifier from the IP and `SECRET_RS_IP_HASH_SALT`;
- uses that identifier as the logical key for rate-limit buckets.

Secrets themselves also keep `requester_ip_hash` in the database for future abuse-mitigation use cases.

## Stored Buckets

Counters are persisted in SQLite in the `rate_limits` table.

Current buckets:

- `create-minute:<ip-hash>`
- `create-hour:<ip-hash>`
- `read-minute:<ip-hash>`

Counting is therefore persistent across service restarts.

## HTTP Responses

- `429 Too Many Requests`
  Returned when an IP-based limit is exceeded.

- `503 Service Unavailable`
  Returned for global unavailability, for example:
  - creation disabled;
  - active secret global quota exceeded;
  - global storage quota exceeded;
  - Turnstile verification service unavailable.

## Implementation Notes

- Creation attempts are counted before final Turnstile verification. Invalid or abusive submissions therefore also consume the creation budget.
- If no usable client IP is available in the request, IP-based limits do not apply.
- Automatic cleanup of old buckets is not yet documented as fully finalized; the SQLite primitives already exist to support that step.
