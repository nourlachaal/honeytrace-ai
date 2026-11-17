# Event Schema & Identity

## Event identity
- **SHA-256 Event Hash:** Computed from normalized core fields to ensure idempotency and prevent duplicates.
- **Juice Shop Request ID:** Nginx includes `$request_id` in `access.jsonl` so identical HTTP requests within the same second produce distinct `event_id` hashes.
- **Run Tags Exclusion:** `scenario_id` and `test_run_id` are excluded from the hash so re-importing labeled runs does not create duplicate events.