// Append-only audit log writer (PERMISSIONS.md invariant 10).
// The schema enforces append-only via BEFORE UPDATE / BEFORE DELETE triggers —
// this module just writes rows. It never reads them; that is the route's job.
//
// Records BOTH allowed and denied attempts. A denied session start is as auditable
// as a successful one — the audit log is not a success log.

import { newId } from './db.js';

// Write one audit event. All fields except action and result are optional.
export function writeAudit(db, {
  orgId,
  actorId   = null,
  action,
  targetType = null,
  targetId   = null,
  result,           // 'allow' | 'deny'
  reasonCode = null,
  requestId  = null,
}) {
  db.prepare(
    `INSERT INTO audit_events
       (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    newId('aud'),
    orgId,
    actorId,
    action,
    targetType,
    targetId,
    result,
    reasonCode,
    requestId,
  );
}
