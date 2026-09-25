// Role ranks, last-owner protection, and session-ending cascades.
// PERMISSIONS.md §6 (modification authority) and §7 (session lifecycle).
//
// Role rank is used ONLY for modification authority (D8).
// It must NEVER be used to answer a permission question — use permissions.js for that.

import { forbidden, conflict, lastOwner, selfRoleChange, notFound } from './http.js';
import { nowIso } from './db.js';

// Rank map loaded from the DB at module level would require a db reference.
// Instead, each function that needs ranks accepts db and queries it — this keeps
// the module stateless and ensures we always read the live reference data.
function getRank(db, role) {
  const row = db.prepare('SELECT rank FROM roles WHERE key = ?').get(role);
  if (!row) throw new Error(`unknown role: ${role}`);
  return row.rank;
}

// Assert the caller may modify the target user (PERMISSIONS.md §6).
// Rules: owner may modify anyone except themselves; others need strictly lower rank.
export function assertCanModify(db, callerRole, targetRole, callerId, targetId) {
  if (callerId === targetId) throw selfRoleChange();

  // Owners may modify anyone (including other owners), except themselves.
  if (callerRole === 'owner') return;

  const callerRank = getRank(db, callerRole);
  const targetRank = getRank(db, targetRole);

  // Non-owners must strictly outrank the target.
  if (callerRank <= targetRank) throw forbidden('insufficient rank to modify this user');
}

// Assert the caller may assign a given role (only owners may assign owner).
export function assertCanAssignRole(db, callerRole, newRole) {
  if (newRole === 'owner' && callerRole !== 'owner') {
    throw forbidden('only owners may assign the owner role');
  }
  const callerRank = getRank(db, callerRole);
  const newRank    = getRank(db, newRole);
  if (callerRank <= newRank) throw forbidden('cannot assign a role equal to or above your own');
}

// Assert the org will still have at least one owner after this operation.
// Call BEFORE the membership change, passing the userId being changed/removed.
export function assertNotLastOwner(db, orgId, userId) {
  const ownerCount = db.prepare(
    `SELECT count(*) AS n FROM memberships
      WHERE org_id = ? AND role = 'owner' AND status = 'active'`
  ).get(orgId).n;

  const isOwner = db.prepare(
    `SELECT role FROM memberships WHERE org_id = ? AND user_id = ?`
  ).get(orgId, userId)?.role === 'owner';

  if (isOwner && ownerCount <= 1) throw lastOwner();
}

// End all active sessions for a user in an org, with a given reason.
// Used on: suspension, membership removal, device transfer (PERMISSIONS.md §7).
export function endUserSessions(db, orgId, userId, endReason) {
  const now = nowIso();
  db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
      WHERE org_id = ? AND user_id = ? AND state = 'active'`
  ).run(endReason, now, orgId, userId);
}

// End all active sessions on a specific device (used on transfer/decommission).
export function endDeviceSessions(db, deviceId, endReason) {
  const now = nowIso();
  db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
      WHERE device_id = ? AND state = 'active'`
  ).run(endReason, now, deviceId);
}
