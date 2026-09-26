// Invite routes. Invites are the only way to add a person (D14).
// The raw token is returned once, hashed at rest, never logged.
//
// POST   /v1/orgs/:org/invites          — create; requires user:invite
// GET    /v1/orgs/:org/invites          — list; requires user:invite
// DELETE /v1/orgs/:org/invites/:id      — cancel; requires user:invite
// GET    /v1/invites/:token             — public: peek at invite details
// POST   /v1/invites/:token/accept      — public: accept and join

import { send, badRequest, notFound, gone, conflict } from '../http.js';
import { newId, nowIso } from '../db.js';
import { newInviteToken, hashInviteToken, issueAccessToken, newRefreshToken, hashRefreshToken, hashPassword, REFRESH_TTL_SECONDS } from '../auth.js';
import { can } from '../permissions.js';
import { assertCanAssignRole } from '../lifecycle.js';
import { writeAudit } from '../audit.js';
import { forbidden } from '../http.js';

function assertOrg(caller, orgId) {
  if (caller.orgId !== orgId) throw notFound();
}

function requirePerm(db, caller, permission) {
  if (!can(db, { userId: caller.userId, orgId: caller.orgId }, permission)) {
    throw forbidden(`requires ${permission}`);
  }
}

export function registerInviteRoutes(router, { db, secret }) {

  // POST /v1/orgs/:org/invites
  router.post('/v1/orgs/:org/invites', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'user:invite');

    const { email, role } = ctx.body;
    if (!email || !role) throw badRequest('email and role are required');

    const normalEmail = String(email).toLowerCase().trim();

    // Validate the role exists.
    const roleRow = db.prepare('SELECT key FROM roles WHERE key = ?').get(role);
    if (!roleRow) throw badRequest('invalid role');

    // Caller must be able to assign this role.
    assertCanAssignRole(db, ctx.caller.role, role);

    // Check for existing active membership.
    const existing = db.prepare(
      `SELECT status FROM memberships WHERE org_id = ? AND user_id =
         (SELECT id FROM users WHERE email = ?)`
    ).get(orgId, normalEmail);
    if (existing && existing.status === 'active') throw conflict('user is already a member');

    const raw       = newInviteToken();
    const tokenHash = hashInviteToken(raw);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    const inviteId  = newId('inv');

    // The partial unique index one_live_invite_per_email handles the duplicate case.
    try {
      db.prepare(
        `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(inviteId, orgId, normalEmail, role, tokenHash, ctx.caller.userId, expiresAt);
    } catch (e) {
      if (e.message?.includes('UNIQUE')) throw conflict('a pending invite already exists for this email');
      throw e;
    }

    writeAudit(db, { orgId, actorId: ctx.caller.userId, action: 'invite.create',
      targetType: 'invite', targetId: inviteId, result: 'allow', requestId: ctx.requestId });

    // Return the raw token exactly once as `inviteToken` — never stored, never logged.
    send(res, 201, { invite: { id: inviteId, email: normalEmail, role, expiresAt }, inviteToken: raw });
  });

  // GET /v1/orgs/:org/invites
  router.get('/v1/orgs/:org/invites', async (ctx, { org: orgId }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'user:invite');

    const invites = db.prepare(
      `SELECT id, email, role, expires_at, accepted_at, revoked_at, created_at
         FROM invites WHERE org_id = ? AND revoked_at IS NULL AND accepted_at IS NULL
         ORDER BY created_at DESC`
    ).all(orgId);

    send(res, 200, { invites });
  });

  // DELETE /v1/orgs/:org/invites/:id
  router.delete('/v1/orgs/:org/invites/:id', async (ctx, { org: orgId, id }, res) => {
    assertOrg(ctx.caller, orgId);
    requirePerm(db, ctx.caller, 'user:invite');

    const invite = db.prepare(
      `SELECT id FROM invites WHERE id = ? AND org_id = ? AND revoked_at IS NULL AND accepted_at IS NULL`
    ).get(id, orgId);
    if (!invite) throw notFound();

    db.prepare(`UPDATE invites SET revoked_at = ? WHERE id = ?`).run(nowIso(), id);
    send(res, 200, {});
  });

  // GET /v1/invites/:token — public: just enough to render the accept screen.
  router.get('/v1/invites/:token', async (ctx, { token }, res) => {
    const hash   = hashInviteToken(token);
    const invite = db.prepare(
      `SELECT i.id, i.email, i.role, i.expires_at, i.accepted_at, i.revoked_at, o.name AS org_name
         FROM invites i JOIN organizations o ON o.id = i.org_id
        WHERE i.token_hash = ?`
    ).get(hash);

    if (!invite) throw notFound();
    if (invite.revoked_at || invite.accepted_at) throw gone();
    if (invite.expires_at <= nowIso()) throw gone();

    // Return only what the accept screen needs — no org data, no member list.
    send(res, 200, {
      orgName:   invite.org_name,
      role:      invite.role,
      email:     invite.email,
      expiresAt: invite.expires_at,
    });
  });

  // POST /v1/invites/:token/accept — public: upsert user, activate membership, issue tokens.
  router.post('/v1/invites/:token/accept', async (ctx, { token }, res) => {
    const hash   = hashInviteToken(token);
    const invite = db.prepare(
      `SELECT id, org_id, email, role, expires_at, accepted_at, revoked_at
         FROM invites WHERE token_hash = ?`
    ).get(hash);

    if (!invite) throw notFound();
    if (invite.revoked_at) throw gone();
    if (invite.accepted_at) throw conflict('invite already accepted');
    if (invite.expires_at <= nowIso()) throw gone();

    const { name, password } = ctx.body;
    if (!name || !password) throw badRequest('name and password are required');

    // Everything in one transaction: upsert user, activate membership, mark invite used.
    const result = db.transaction(() => {
      // Upsert user — existing platform user gets attached, not duplicated (D14).
      let user = db.prepare('SELECT id FROM users WHERE email = ?').get(invite.email);
      if (!user) {
        const userId = newId('usr');
        db.prepare(
          `INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)`
        ).run(userId, invite.email, name, hashPassword(password));
        user = { id: userId };
      }

      // Upsert membership: invited -> active.
      const existing = db.prepare(
        `SELECT id FROM memberships WHERE org_id = ? AND user_id = ?`
      ).get(invite.org_id, user.id);

      const now = nowIso();
      if (existing) {
        db.prepare(
          `UPDATE memberships SET role = ?, status = 'active', joined_at = ? WHERE id = ?`
        ).run(invite.role, now, existing.id);
      } else {
        db.prepare(
          `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at)
           VALUES (?, ?, ?, ?, 'active', ?, ?)`
        ).run(newId('mem'), invite.org_id, user.id, invite.role,
              db.prepare('SELECT invited_by FROM invites WHERE id = ?').get(invite.id)?.invited_by,
              now);
      }

      db.prepare(`UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ?`)
        .run(now, user.id, invite.id);

      return user.id;
    })();

    const membership = db.prepare(
      `SELECT role, perm_version FROM memberships WHERE org_id = ? AND user_id = ?`
    ).get(invite.org_id, result);

    const accessToken = issueAccessToken({
      userId: result,
      orgId: invite.org_id,
      role: membership.role,
      permVersion: membership.perm_version,
    }, secret);

    const raw       = newRefreshToken();
    const rtHash    = hashRefreshToken(raw);
    const rtId      = newId('rtk');
    const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?)`
    ).run(rtId, result, rtHash, rtId, expiresAt);

    const COOKIE_OPTS = 'HttpOnly; SameSite=Strict; Path=/v1/auth/refresh';
    res.setHeader('Set-Cookie',
      `refresh_token=${raw}; ${COOKIE_OPTS}; Expires=${new Date(expiresAt).toUTCString()}`);

    send(res, 200, { token: accessToken, accessToken, role: membership.role });
  });
}
