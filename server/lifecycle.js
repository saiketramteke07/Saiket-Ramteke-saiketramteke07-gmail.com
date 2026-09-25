import { forbidden, conflict, lastOwner, selfRoleChange } from './http.js';
import { nowIso } from './db.js';
export function assertCanModify(db, callerRole, targetRole, callerId, targetId) {
  throw new Error('not implemented');
}
export function assertCanAssignRole(db, callerRole, newRole) {
  throw new Error('not implemented');
}
export function assertNotLastOwner(db, orgId, userId) {
  throw new Error('not implemented');
}
export function endUserSessions(db, orgId, userId, endReason) {}
export function endDeviceSessions(db, deviceId, endReason) {}
