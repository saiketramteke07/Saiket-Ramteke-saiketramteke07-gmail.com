# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation

Cloned the repo. Node 26 is too new for better-sqlite3@11.10.0 — the native addon fails
to compile against v8 API changes (GetPrototype removed). Switched to Node 22 LTS via nvm.
Ran the three suites against the untouched skeleton: 43 JWT failures (stub throws), permissions
failures (stub), api failures (no routes). That is the expected starting line.

Key observation: `check-jwt.js` is designed so a stub that throws unconditionally fails ALL
cases, not just the rejection cases. The valid-token round-trip cases also fail. This means
you cannot get free marks by leaving the stub in place — the suite is adversarial by design.

## Phase 1 — token verification

Implemented `verifyAccessToken` in `server/auth.js`. The 7 checks in order:
1. Structure (3 segments)
2. Parse (valid base64url JSON objects)
3. Algorithm pin — allowlist HS256+JWT only, never trust the header's alg claim
4. Signature — HMAC-SHA256 recomputed, compared with timingSafeEqual
5. Expiry — half-open: exp <= now is expired (D7)
6. iss + aud validation
7. jti non-empty

Key decision: the alg check is an allowlist (`=== 'HS256'`), not a denylist (`!== 'none'`).
A denylist misses algorithm substitution attacks (HS512, RS256, etc). An allowlist rejects
everything not explicitly trusted — same default-deny posture as the permission model.

## Phase 2 — caller context and the resolution engine

Built `permissions.js` — the single source of truth for allow/deny. Key design decisions:

1. Wildcards are expanded at resolution time against the live permissions table, not hardcoded.
   This is what makes the personalised org (undocumented role + permission) work correctly.

2. Deny wins regardless of scope (D1). An org-wide deny cannot be carved out by a device-scoped
   allow. The check-permissions.js suite has an explicit test for this: `g_carve` grant.

3. `resolveOrgLevel` takes the union across all devices — a permission is allowed at org level
   if it is allowed on ANY device. This is what drives nav visibility in the SPA.

4. `assertCanStartSession` throws with specific reason strings (`missing_permission` vs
   `missing_device_permission`) because the shipped tests assert those exact strings.

## Phase 3 — orgs, members, invites

Built all org/member/invite routes. Key things that were not obvious from the docs:

Invite accept returns `{token, accessToken, role}` — same shape as login. The test reads
`accept.body.role` directly, so the role must be at the top level, not nested under a user object.
The raw invite token is returned once at creation as `inviteToken` (not `token`) — the field name
matters because the test reads `inv.body.inviteToken`.

Owner rank rule: PERMISSIONS.md §6 says non-owners need strictly lower rank to modify a target.
My first read was that owners also needed lower rank. The test `demoting a NON-last owner is allowed`
disproved that — owners can modify any other member including other owners, except themselves.
`assertCanModify` now only applies the rank check for non-owners.

Audit pagination: limit must be 1–200 inclusive; offset must be >= 0. `limit=0` and `offset=99999`
are both tested — the former is a 400, the latter is a 200 (large offset is valid, just returns
an empty page). Clamping would have passed the 400 cases and silently broken the 200 case.

## Phase 4 — devices and grants

The unknown-permission check must happen BEFORE the laundering check. My first implementation
inserted the grant and relied on the FK constraint to catch bad permission strings. That produced
a 500 (unhandled FK error) instead of a 400. Moving the catalogue validation loop before the
laundering loop fixed it.

The second issue: the FK-path fallback also used `Object.assign(new Error(), {...})` instead of
`new HttpError(...)`. `sendError` checks `instanceof HttpError` — a plain Error with a `.status`
property is not an instance, so it fell through to the 500 branch. All error throws in the grants
route now use `new HttpError(status, code, message, reason)` directly.

Grant scope: a device-scoped grant only applies when `deviceId` matches. The resolution engine
already handles this (D1 deny wins regardless of scope), so the grant route just needs to store
`device_id` correctly and let `resolve()` do the rest.

## Phase 5 — sessions

`assertCanStartSession` must distinguish two failure reasons: `missing_permission` (caller lacks
`session:start` at org level) vs `missing_device_permission` (caller has `session:start` but not
`device:control` or `device:view` on the specific device). The check order matters — org-level
check first, then device-level, so the reason string is always the most specific one that applies.

Exclusive session conflict (D10): a second `control` session on a device that already has an
active `control` session returns 409 `DEVICE_BUSY`. `view` sessions are not exclusive — two
concurrent view sessions on the same device return 201. The session start route queries
`active_sessions` for an existing exclusive session before inserting.

The GET /sessions/:id test reads flat fields (`session.mode`, `session.device_id`) directly on
the response body, not nested under a `session` key. Returning `{session: {...}}` caused the
test to fail; returning `{...session}` (spread) fixed it.

## Phase 6 — audit

Every state-changing action writes an audit event: login, token refresh, org create, member
role change, suspend/reinstate/remove, invite create/accept, device provision/update/delete/
transfer, grant create/revoke, session start/end. Read-only GETs are not audited.

Denied attempts are also audited — `check-api.js` asserts that a failed session start appears
in the audit log with `result: 'deny'` and a `reason` field. The audit write happens in the
route handler after the permission check throws, inside the catch block, before re-throwing.

The `reason` column carries the same reason string as the error response so the audit log is
self-contained without joining to the error table.

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
