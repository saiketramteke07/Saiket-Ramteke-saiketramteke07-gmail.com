// Org routes: org CRUD, members, effective permissions, audit log.
// All member-mutating operations bump perm_version and end sessions where required.

import { send, badRequest, notFound, forbidden } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { can, resolve, resolveOrgLevel } from '../permissions.js';
import { assertCanModify, assertCanAssignRole, assertNotLastOwner, endUserSessions } from '../lifecycle.js';
import { writeAudit } from '../audit.js';

// Guard: caller's token org must match the URL org — cross-org is 404.
function assertOrg(caller, orgId) {
  if (caller.orgId !== orgId) throw notFound();
}

// Guard: require a permission at org level, throw 403 if missing.
function requirePerm(db, caller, permission, deviceId = null) {
  if (!can(db, { userId: caller.userId, orgId: caller.orgId }, permission, deviceId)) {
    throw forbidden(`requires ${permission}`);
  }
}

export function registerOrgRoutes(router, { db, secret }) {

  // GET /v1/orgs — all orgs the caller is an active member of.
  router.get('/v1/orgs', async (ctx, _p, res) => {
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(ctx.caller.userId);
    send(res, 200, { orgs });
  });

  // POST /v1/orgs — create org; creator becomes owner.
  router.post('/v1/orgs', async (ctx, _p, res) => {
    const { name, theme = 'cobalt' } = ctx.body;
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      throw badRequest('name is required');
    }

    const orgId = newId('org');
    const memId = newId('mem');
    const now   = nowIso();

    db.prepare(
      `INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)`
    ).run(orgId, name.trim(), theme);

    db.prepare(
      `INSERT INTO memberships (id, org_id, user_id, role, status, joined_at)
       VALUES (?, ?, ?, 'owner', 'active', ?)`
    ).run(memId, orgId, ctx.caller.userId, now);

    send(res, 201, { org: { id: orgId, name: name.trim(), theme }, role: 'owner', id: orgId });
  });

  // PATCH /v1/orgs/:org — rename/reconfigure; requires org:update.
  router.patch('/v1/orgs/:org', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'org:update');

    const { name, theme } = ctx.body;
    if (!name && !theme) throw badRequest('nothing to update');

    const org = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
    if (!org) throw notFound();

    if (name) db.prepare('UPDATE organizations SET name = ? WHERE id = ?').run(name.trim(), orgId);
    if (theme) db.prepare('UPDATE organizations SET theme = ? WHERE id = ?').run(theme, orgId);

    const updated = db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(orgId);
    send(res, 200, { org: updated });
  });

  // DELETE /v1/orgs/:org — soft-delete; requires org:delete.
  router.delete('/v1/orgs/:org', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'org:delete');

    db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), orgId);
    send(res, 200, {});
  });

  // GET /v1/orgs/:org/members — requires user:read.
  router.get('/v1/orgs/:org/members', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'user:read');

    const members = db.prepare(
      `SELECT u.id, u.email, u.name, m.role, m.status, m.joined_at
         FROM memberships m
         JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status != 'removed'`
    ).all(orgId);

    send(res, 200, { members });
  });

  // PATCH /v1/orgs/:org/members/:userId — change role; requires user:role:update.
  router.patch('/v1/orgs/:org/members/:userId', async (ctx, { org: orgId, userId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'user:role:update');

    const { role } = ctx.body;
    if (!role) throw badRequest('role is required');

    const target = db.prepare(
      `SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?`
    ).get(orgId, userId);
    if (!target || target.status === 'removed') throw notFound();

    assertCanModify(db, ctx.caller.role, target.role, ctx.caller.userId, userId);
    assertCanAssignRole(db, ctx.caller.role, role);
    assertNotLastOwner(db, orgId, userId);

    db.prepare(`UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?`)
      .run(role, orgId, userId);
    bumpPermVersion(db, { orgId, userId });

    send(res, 200, {});
  });

  // POST /v1/orgs/:org/members/:userId/suspend — requires user:remove.
  router.post('/v1/orgs/:org/members/:userId/suspend', async (ctx, { org: orgId, userId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'user:remove');

    const target = db.prepare(
      `SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?`
    ).get(orgId, userId);
    if (!target || target.status === 'removed') throw notFound();

    assertCanModify(db, ctx.caller.role, target.role, ctx.caller.userId, userId);

    db.prepare(`UPDATE memberships SET status = 'suspended' WHERE org_id = ? AND user_id = ?`)
      .run(orgId, userId);
    bumpPermVersion(db, { orgId, userId });
    endUserSessions(db, orgId, userId, 'user_suspended');

    writeAudit(db, { orgId, actorId: ctx.caller.userId, action: 'member.suspend',
      targetType: 'user', targetId: userId, result: 'allow', requestId: ctx.requestId });

    send(res, 200, {});
  });

  // DELETE /v1/orgs/:org/members/:userId/suspend — reinstate; requires user:remove.
  router.delete('/v1/orgs/:org/members/:userId/suspend', async (ctx, { org: orgId, userId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'user:remove');

    const target = db.prepare(
      `SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?`
    ).get(orgId, userId);
    if (!target || target.status === 'removed') throw notFound();

    db.prepare(`UPDATE memberships SET status = 'active' WHERE org_id = ? AND user_id = ?`)
      .run(orgId, userId);
    bumpPermVersion(db, { orgId, userId });

    send(res, 200, {});
  });

  // DELETE /v1/orgs/:org/members/me — self-leave; not the last owner.
  router.delete('/v1/orgs/:org/members/me', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    assertNotLastOwner(db, orgId, ctx.caller.userId);

    db.prepare(`UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?`)
      .run(orgId, ctx.caller.userId);
    bumpPermVersion(db, { orgId, userId: ctx.caller.userId });
    endUserSessions(db, orgId, ctx.caller.userId, 'membership_removed');

    send(res, 200, {});
  });

  // DELETE /v1/orgs/:org/members/:userId — remove member; requires user:remove.
  router.delete('/v1/orgs/:org/members/:userId', async (ctx, { org: orgId, userId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'user:remove');

    const target = db.prepare(
      `SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?`
    ).get(orgId, userId);
    if (!target || target.status === 'removed') throw notFound();

    assertCanModify(db, ctx.caller.role, target.role, ctx.caller.userId, userId);
    assertNotLastOwner(db, orgId, userId);

    db.prepare(`UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?`)
      .run(orgId, userId);
    bumpPermVersion(db, { orgId, userId });
    endUserSessions(db, orgId, userId, 'membership_removed');

    writeAudit(db, { orgId, actorId: ctx.caller.userId, action: 'member.remove',
      targetType: 'user', targetId: userId, result: 'allow', requestId: ctx.requestId });

    send(res, 200, {});
  });

  // GET /v1/orgs/:org/users/:userId/effective — resolved permissions for a user.
  // Accessible by the user themselves or anyone with user:read.
  router.get('/v1/orgs/:org/users/:userId/effective', async (ctx, { org: orgId, userId }, res) => {
    assertOrg(ctx.caller, orgId);

    const isSelf = ctx.caller.userId === userId;
    if (!isSelf) requirePerm(db, ctx.caller, 'user:read');

    const target = db.prepare(
      `SELECT status FROM memberships WHERE org_id = ? AND user_id = ?`
    ).get(orgId, userId);
    if (!target || target.status === 'removed') throw notFound();

    const { role, permissions } = resolveOrgLevel(db, { userId, orgId });
    send(res, 200, { role, permissions });
  });

  // GET /v1/orgs/:org/audit — requires audit:read.
  router.get('/v1/orgs/:org/audit', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'audit:read');

    const limitParam  = ctx.query.get('limit')  ?? '50';
    const offsetParam = ctx.query.get('offset') ?? '0';
    const limit  = Number(limitParam);
    const offset = Number(offsetParam);

    // Defined boundaries — not clamped, rejected (check-api.js pagination block).
    if (!Number.isInteger(limit)  || limit  < 1 || limit  > 200) throw badRequest('limit must be 1–200');
    if (!Number.isInteger(offset) || offset < 0)                  throw badRequest('offset must be >= 0');

    const events = db.prepare(
      `SELECT id, actor_id, action, target_type, target_id, result, reason_code, request_id, at
         FROM audit_events WHERE org_id = ? ORDER BY at DESC LIMIT ? OFFSET ?`
    ).all(orgId, limit, offset);

    send(res, 200, { events });
  });
}
