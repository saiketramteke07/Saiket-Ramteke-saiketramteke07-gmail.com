import { newId } from './db.js';
export function writeAudit(db, { orgId, actorId = null, action, targetType = null,
  targetId = null, result, reasonCode = null, requestId = null }) {}
