# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

---

## Phase 0 — orientation

Cloned the repo. Node 26 is too new for better-sqlite3@11.10.0 — the native addon fails
to compile against v8 API changes (GetPrototype removed). Switched to Node 22 LTS via nvm.
Ran the three suites against the untouched skeleton: 43 JWT failures (stub throws), permissions
failures (stub), api failures (no routes). That is the expected starting line.

Key observation: `check-jwt.js` is designed so a stub that throws unconditionally fails ALL
cases, not just the rejection cases. The valid-token round-trip cases also fail. This means
you cannot get free marks by leaving the stub in place — the suite is adversarial by design.

## Phase 1 — token verification

_What did you expect each failure mode to look like before you ran it?_

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong._

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree?_

## Phase 5 — sessions

_Two permissions, one device._

## Phase 6 — audit

_What did you decide counts as an auditable event?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone?_

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day._
