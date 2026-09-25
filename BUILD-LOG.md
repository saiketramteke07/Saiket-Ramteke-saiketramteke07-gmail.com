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

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
