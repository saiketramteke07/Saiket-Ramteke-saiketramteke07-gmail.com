// Session routes.
// Starting a session requires TWO permissions on the same device (AUTH-DATA-MODEL.md §9).
// control/terminal are exclusive per device; view is not (D10).
// Sessions are grandfathered — permission changes never end a session in flight (PERMISSIONS.md §7).

import { send, badRequest, notFound, forbidden, conflict } from '../http.js';
import { newId, nowIso } from '../db.js';
import { can, assertCanStartSession, resolve } from '../permissions.js';
import { writeAudit } from '../audit.js';

function assertOrg(caller, orgId) {
  if (caller.orgId !== orgId) throw notFound();
}

function requirePerm(db, caller, permission, deviceId = null) {
  if (!can(db, { userId: caller.userId, orgId: caller.orgId }, permission, deviceId)) {
    throw forbidden(`requires ${permission}`);
  }
}

export function registerSessionRoutes(router, { db }) {

  // POST /v1/orgs/:org/sessions — start a session.
  router.post('/v1/orgs/:org/sessions', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);

    const { deviceId, mode } = ctx.body;
    if (!deviceId || !mode) throw badRequest('deviceId and mode are required');
    if (!['view', 'control', 'terminal'].includes(mode)) throw badRequest('invalid mode');

    const device = db.prepare(
      `SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`
    ).get(deviceId, orgId);
    if (!device) throw notFound('device not found');

    // Compound permission check — throws with specific reason if either is missing.
    try {
      assertCanStartSession(db, { userId: ctx.caller.userId, orgId }, mode, deviceId);
    } catch (err) {
      writeAudit(db, { orgId, actorId: ctx.caller.userId, action: 'session.start',
        targetType: 'device', targetId: deviceId, result: 'deny',
        reasonCode: err.reason, requestId: ctx.requestId });
      throw err;
    }

    // Snapshot the authorization at start time — this is what makes sessions grandfathered.
    const { role, permissions } = resolve(db, { userId: ctx.caller.userId, orgId, deviceId });
    const authorizedBy = JSON.stringify({
      role,
      grantIds: Object.values(permissions)
        .filter(p => p.source?.startsWith('grant:'))
        .map(p => p.source.slice(6)),
      snapshotAt: nowIso(),
    });

    const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
    const expiresAt = new Date(Date.now() + org.max_session_minutes * 60 * 1000).toISOString();
    const sessionId = newId('ses');

    // The partial unique index one_exclusive_session_per_device handles the race for
    // control/terminal — two concurrent inserts produce exactly one 201 and one 409.
    try {
      db.prepare(
        `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, expires_at)
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`
      ).run(sessionId, orgId, ctx.caller.userId, deviceId, mode, authorizedBy, expiresAt);
    } catch (e) {
      if (e.message?.includes('UNIQUE')) {
        const holder = db.prepare(
          `SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control','terminal')`
        ).get(deviceId);
        throw conflict(`device already has an exclusive session${holder ? ` (${holder.id})` : ''}`, 'DEVICE_BUSY');
      }
      throw e;
    }

    writeAudit(db, { orgId, actorId: ctx.caller.userId, action: 'session.start',
      targetType: 'device', targetId: deviceId, result: 'allow', requestId: ctx.requestId });

    send(res, 201, { session: { id: sessionId, deviceId, mode, state: 'active', expiresAt } });
  });

  // GET /v1/orgs/:org/sessions — requires session:view.
  router.get('/v1/orgs/:org/sessions', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'session:view');

    const sessions = db.prepare(
      `SELECT id, user_id, device_id, mode, state, end_reason, started_at, expires_at, ended_at
         FROM sessions WHERE org_id = ? ORDER BY started_at DESC LIMIT 100`
    ).all(orgId);

    send(res, 200, { sessions });
  });

  // GET /v1/sessions/:id — participant or session:view.
  router.get('/v1/sessions/:id', async (ctx, { id }, res) => {
    const session = db.prepare(
      `SELECT id, org_id, user_id, device_id, mode, state, end_reason, started_at, expires_at, ended_at
         FROM sessions WHERE id = ?`
    ).get(id);
    if (!session) throw notFound();

    // Must be in the caller's active org.
    if (session.org_id !== ctx.caller.orgId) throw notFound();

    const isParticipant = session.user_id === ctx.caller.userId;
    if (!isParticipant) requirePerm(db, ctx.caller, 'session:view');

    send(res, 200, { ...session });
  });

  // DELETE /v1/sessions/:id — own session or session:terminate.
  router.delete('/v1/sessions/:id', async (ctx, { id }, res) => {
    const session = db.prepare(
      `SELECT id, org_id, user_id, state FROM sessions WHERE id = ?`
    ).get(id);
    if (!session) throw notFound();
    if (session.org_id !== ctx.caller.orgId) throw notFound();
    if (session.state !== 'active') throw notFound('session is not active');

    const isOwn = session.user_id === ctx.caller.userId;
    if (!isOwn) requirePerm(db, ctx.caller, 'session:terminate');

    const endReason = isOwn ? 'user_stopped' : 'admin_terminated';
    db.prepare(
      `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ?`
    ).run(endReason, nowIso(), id);

    writeAudit(db, { orgId: session.org_id, actorId: ctx.caller.userId, action: 'session.terminate',
      targetType: 'session', targetId: id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, {});
  });
}
