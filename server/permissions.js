import { forbidden } from './http.js';
export function resolve(db, { userId, orgId, deviceId = null }) {
  throw new Error('not implemented');
}
export function can(db, { userId, orgId }, permission, deviceId = null) {
  throw new Error('not implemented');
}
export function resolveOrgLevel(db, { userId, orgId }) {
  throw new Error('not implemented');
}
export function assertCanStartSession(db, { userId, orgId }, mode, deviceId) {
  throw new Error('not implemented');
}
