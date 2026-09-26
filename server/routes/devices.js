// Device and grant routes.
//
// Device list carries the caller's resolved permissions per row (BRIEF.md §5.2) —
// this is what lets the console render buttons without a follow-up request per device.

import { send, badRequest, notFound, forbidden, conflict, HttpError } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { can, resolve } from '../permissions.js';
import { endDeviceSessions } from '../lifecycle.js';
import { writeAudit } from '../audit.js';
import { normalizeTs } from '../http.js';

function assertOrg(caller, orgId) {
  if (caller.orgId !== orgId) throw notFound();
}

function requirePerm(db, caller, permission, deviceId = null) {
  if (!can(db, { userId: caller.userId, orgId: caller.orgId }, permission, deviceId)) {
    throw forbidden(`requires ${permission}`);
  }
}

// The device permissions the console cares about per row.
const DEVICE_PERMS = [
  'device:view', 'device:control', 'device:terminal',
  'device:file_transfer', 'device:provision', 'device:update',
  'session:start',
];

export function registerDeviceRoutes(router, { db }) {

  // GET /v1/orgs/:org/devices — requires device:list.
  // Each row carries the caller's resolved permissions for that device.
  router.get('/v1/orgs/:org/devices', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'device:list');

    const devices = db.prepare(
      `SELECT id, name, kind, online FROM devices WHERE org_id = ? AND deleted_at IS NULL`
    ).all(orgId);

    // Resolve permissions per device in one pass — no N+1 queries.
    // device:view deny removes the row entirely (PERMISSIONS.md §2).
    const rows = [];
    for (const device of devices) {
      const { permissions } = resolve(db, {
        userId: ctx.caller.userId, orgId, deviceId: device.id,
      });
      if (permissions['device:view']?.effect !== 'allow') continue; // invisible row

      const perms = {};
      for (const p of DEVICE_PERMS) perms[p] = permissions[p];

      rows.push({ ...device, permissions: perms });
    }

    send(res, 200, { devices: rows });
  });

  // GET /v1/orgs/:org/devices/:id — requires device:view on that device.
  router.get('/v1/orgs/:org/devices/:id', async (ctx, { org: orgId, id }, res) => {
    assertOrg(ctx.caller, orgId);

    const device = db.prepare(
      `SELECT id, name, kind, online FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`
    ).get(id, orgId);
    if (!device) throw notFound();

    requirePerm(db, ctx.caller, 'device:view', id);

    const { permissions } = resolve(db, { userId: ctx.caller.userId, orgId, deviceId: id });
    const perms = {};
    for (const p of DEVICE_PERMS) perms[p] = permissions[p];

    send(res, 200, { device: { ...device, permissions: perms } });
  });

  // POST /v1/orgs/:org/devices — requires device:provision.
  router.post('/v1/orgs/:org/devices', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'device:provision');

    const { name, kind } = ctx.body;
    if (!name || !kind) throw badRequest('name and kind are required');

    const VALID_KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];
    if (!VALID_KINDS.includes(kind)) throw badRequest(`kind must be one of: ${VALID_KINDS.join(', ')}`);

    const id = newId('dev');
    db.prepare(
      `INSERT INTO devices (id, org_id, name, kind) VALUES (?, ?, ?, ?)`
    ).run(id, orgId, name.trim(), kind);

    writeAudit(db, { orgId, actorId: ctx.caller.userId, action: 'device.provision',
      targetType: 'device', targetId: id, result: 'allow', requestId: ctx.requestId });

    send(res, 201, { device: { id, name: name.trim(), kind, online: 0 } });
  });

  // PATCH /v1/orgs/:org/devices/:id — requires device:update.
  router.patch('/v1/orgs/:org/devices/:id', async (ctx, { org: orgId, id }, res) => {
    assertOrg(ctx.caller, orgId);

    const device = db.prepare(
      `SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`
    ).get(id, orgId);
    if (!device) throw notFound();

    requirePerm(db, ctx.caller, 'device:update', id);

    const { name, online } = ctx.body;
    if (name) db.prepare('UPDATE devices SET name = ? WHERE id = ?').run(name.trim(), id);
    if (online !== undefined) db.prepare('UPDATE devices SET online = ? WHERE id = ?').run(online ? 1 : 0, id);

    send(res, 200, {});
  });

  // DELETE /v1/orgs/:org/devices/:id — soft-delete; requires device:provision.
  router.delete('/v1/orgs/:org/devices/:id', async (ctx, { org: orgId, id }, res) => {
    assertOrg(ctx.caller, orgId);

    const device = db.prepare(
      `SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`
    ).get(id, orgId);
    if (!device) throw notFound();

    requirePerm(db, ctx.caller, 'device:provision', id);

    db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), id);
    endDeviceSessions(db, id, 'device_transferred');

    send(res, 200, {});
  });

  // POST /v1/orgs/:org/devices/:id/transfer — requires device:provision in BOTH orgs.
  router.post('/v1/orgs/:org/devices/:id/transfer', async (ctx, { org: orgId, id }, res) => {
    assertOrg(ctx.caller, orgId);

    const device = db.prepare(
      `SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`
    ).get(id, orgId);
    if (!device) throw notFound();

    requirePerm(db, ctx.caller, 'device:provision', id);

    const { targetOrgId } = ctx.body;
    if (!targetOrgId) throw badRequest('targetOrgId is required');

    // Must also hold device:provision in the target org.
    if (!can(db, { userId: ctx.caller.userId, orgId: targetOrgId }, 'device:provision')) {
      throw forbidden('requires device:provision in the target org');
    }

    db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(targetOrgId, id);
    endDeviceSessions(db, id, 'device_transferred');

    send(res, 200, {});
  });

  // POST /v1/orgs/:org/grants — create a grant; requires grant:create.
  router.post('/v1/orgs/:org/grants', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'grant:create');

    const { userId, deviceId = null, effect, permissions, startsAt, expiresAt } = ctx.body;

    if (!userId || !effect || !Array.isArray(permissions) || permissions.length === 0) {
      throw badRequest('userId, effect, and permissions[] are required');
    }
    if (!['allow', 'deny'].includes(effect)) throw badRequest('effect must be allow or deny');

    // No self-grants (D9).
    if (userId === ctx.caller.userId) throw forbidden('cannot grant to yourself');

    // Target must be an active member.
    const target = db.prepare(
      `SELECT status FROM memberships WHERE org_id = ? AND user_id = ?`
    ).get(orgId, userId);
    if (!target || target.status !== 'active') throw notFound('user not found in this org');

    // Device must belong to this org if specified.
    if (deviceId) {
      const dev = db.prepare(
        `SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`
      ).get(deviceId, orgId);
      if (!dev) throw notFound('device not found in this org');
    }

    // Normalise timestamps.
    const normStarts  = normalizeTs(startsAt, 'startsAt');
    const normExpires = normalizeTs(expiresAt, 'expiresAt');
    const now = nowIso();

    if (normExpires && normExpires <= now) {
      throw new HttpError(400, 'GRANT_EXPIRED', 'grant is already expired', 'expired_grant');
    }

    // Validate all permissions exist in the catalogue BEFORE the laundering check (D19).
    // The FK on grant_permissions would catch this too, but we need a 400 not a 500,
    // and we need reason:'unknown_permission' not reason:'missing_permission'.
    const validPatterns = new Set(
      db.prepare('SELECT pattern FROM permission_patterns').all().map(r => r.pattern)
    );
    for (const perm of permissions) {
      if (!validPatterns.has(perm)) {
        throw new HttpError(400, 'VALIDATION', `unknown permission: ${perm}`, 'unknown_permission');
      }
    }

    // No laundering: caller must hold every permission being granted at that scope (D9).
    for (const perm of permissions) {
      if (!can(db, { userId: ctx.caller.userId, orgId }, perm, deviceId)) {
        throw forbidden(`you do not hold ${perm} at this scope`);
      }
    }

    const grantId = newId('grt');
    db.prepare(
      `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(grantId, orgId, userId, deviceId, effect, normStarts, normExpires, ctx.caller.userId);

    for (const perm of permissions) {
      try {
        db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)').run(grantId, perm);
      } catch (e) {
        // FK violation means unknown permission string (D19).
        db.prepare('DELETE FROM grants WHERE id = ?').run(grantId);
        throw new HttpError(400, 'VALIDATION', `unknown permission: ${perm}`, 'unknown_permission');
      }
    }

    bumpPermVersion(db, { orgId, userId });

    writeAudit(db, { orgId, actorId: ctx.caller.userId, action: 'grant.create',
      targetType: 'grant', targetId: grantId, result: 'allow', requestId: ctx.requestId });

    send(res, 201, { grant: { id: grantId } });
  });

  // GET /v1/orgs/:org/grants — requires user:read.
  router.get('/v1/orgs/:org/grants', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'user:read');

    const grants = db.prepare(
      `SELECT g.id, g.user_id, g.device_id, g.effect, g.starts_at, g.expires_at, g.created_at,
              group_concat(gp.permission) AS permissions
         FROM grants g
         JOIN grant_permissions gp ON gp.grant_id = g.id
        WHERE g.org_id = ? AND g.revoked_at IS NULL
        GROUP BY g.id`
    ).all(orgId).map(g => ({ ...g, permissions: g.permissions.split(',') }));

    send(res, 200, { grants });
  });

  // DELETE /v1/orgs/:org/grants/:id — revoke; requires grant:revoke.
  router.delete('/v1/orgs/:org/grants/:id', async (ctx, { org: orgId, id }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'grant:revoke');

    const grant = db.prepare(
      `SELECT id, user_id FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL`
    ).get(id, orgId);
    if (!grant) throw notFound();

    db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), id);
    bumpPermVersion(db, { orgId, userId: grant.user_id });

    writeAudit(db, { orgId, actorId: ctx.caller.userId, action: 'grant.revoke',
      targetType: 'grant', targetId: id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, {});
  });
}
