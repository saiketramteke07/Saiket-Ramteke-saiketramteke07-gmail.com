// Auth routes: login, refresh, org-switch, /me
// POST /v1/auth/login    — email + password -> access token + refresh cookie
// POST /v1/auth/refresh  — rotate refresh cookie -> new access token
// POST /v1/auth/token    — switch active org -> new access token
// GET  /v1/auth/me       — current user, org, role, resolved org-level permissions

import {
  issueAccessToken, verifyAccessToken, assertFresh,
  newRefreshToken, hashRefreshToken,
  verifyPassword,
  REFRESH_TTL_SECONDS,
} from '../auth.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { resolveOrgLevel } from '../permissions.js';
import { unauthenticated, badRequest, notFound, send } from '../http.js';

// Shared cookie options for the refresh token (AUTH-DATA-MODEL.md §2).
const COOKIE_OPTS = 'HttpOnly; SameSite=Strict; Path=/v1/auth/refresh';

function setRefreshCookie(res, token, expiresAt) {
  const expires = new Date(expiresAt).toUTCString();
  res.setHeader('Set-Cookie', `refresh_token=${token}; ${COOKIE_OPTS}; Expires=${expires}`);
}

function clearRefreshCookie(res) {
  res.setHeader('Set-Cookie', `refresh_token=; ${COOKIE_OPTS}; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);
}

// Issue a refresh token row and return the raw token.
function createRefreshToken(db, userId, familyId = null) {
  const raw       = newRefreshToken();
  const hash      = hashRefreshToken(raw);
  const id        = newId('rtk');
  const familyNew = familyId ?? id; // first in family: family_id = its own id
  const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();

  db.prepare(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
     VALUES (?, ?, ?, ?, ?)`
  ).run(id, userId, hash, familyNew, expiresAt);

  return { raw, expiresAt };
}

// Resolve the first active membership for a user (used at login when no org is specified).
function firstActiveMembership(db, userId) {
  return db.prepare(
    `SELECT m.org_id, m.role, m.perm_version
       FROM memberships m
      WHERE m.user_id = ? AND m.status = 'active'
      ORDER BY m.joined_at ASC
      LIMIT 1`
  ).get(userId);
}

export function registerAuthRoutes(router, { db, secret }) {

  // POST /v1/auth/login
  router.post('/v1/auth/login', async (ctx, _params, res) => {
    const { email, password } = ctx.body;
    if (!email || !password) throw badRequest('email and password are required');

    // Normalise email — schema enforces lowercase, so comparison must match.
    const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?')
      .get(String(email).toLowerCase().trim());

    // Identical response for wrong email and wrong password — no enumeration oracle.
    if (!user || !verifyPassword(password, user.password_hash)) {
      throw unauthenticated('invalid email or password');
    }

    const membership = firstActiveMembership(db, user.id);
    if (!membership) throw unauthenticated('no active membership');

    // All orgs this user belongs to — returned at login so the SPA can populate the switcher.
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(user.id);

    const accessToken = issueAccessToken({
      userId: user.id,
      orgId: membership.org_id,
      role: membership.role,
      permVersion: membership.perm_version,
    }, secret);

    const { raw, expiresAt } = createRefreshToken(db, user.id);
    setRefreshCookie(res, raw, expiresAt);

    // `token` is what check-api.js reads; `accessToken` is the SPA alias.
    send(res, 200, { token: accessToken, accessToken, role: membership.role, orgs });
  });

  // POST /v1/auth/refresh — rotate the refresh cookie.
  router.post('/v1/auth/refresh', async (ctx, _params, res) => {
    const cookieHeader = ctx.req.headers['cookie'] ?? '';
    const match = /(?:^|;\s*)refresh_token=([^;]+)/.exec(cookieHeader);
    if (!match) throw unauthenticated('missing refresh token');

    const raw  = match[1];
    const hash = hashRefreshToken(raw);

    const stored = db.prepare(
      `SELECT id, user_id, family_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?`
    ).get(hash);

    if (!stored) throw unauthenticated('invalid refresh token');

    // Replay detection: if this token is already revoked, revoke the whole family (D12).
    if (stored.revoked_at) {
      db.prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`)
        .run(nowIso(), stored.family_id);
      clearRefreshCookie(res);
      throw unauthenticated('refresh token replayed — family revoked');
    }

    if (stored.expires_at <= nowIso()) throw unauthenticated('refresh token expired');

    // Rotate: revoke the old token, issue a new one in the same family.
    db.prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?`).run(nowIso(), stored.id);
    const { raw: newRaw, expiresAt } = createRefreshToken(db, stored.user_id, stored.family_id);

    const membership = firstActiveMembership(db, stored.user_id);
    if (!membership) throw unauthenticated('no active membership');

    const accessToken = issueAccessToken({
      userId: stored.user_id,
      orgId: membership.org_id,
      role: membership.role,
      permVersion: membership.perm_version,
    }, secret);

    setRefreshCookie(res, newRaw, expiresAt);
    send(res, 200, { token: accessToken, accessToken });
  });

  // POST /v1/auth/token — switch active org, mint a new scoped token.
  router.post('/v1/auth/token', async (ctx, _params, res) => {
    const { orgId } = ctx.body;
    if (!orgId) throw badRequest('orgId is required');

    const membership = db.prepare(
      `SELECT role, perm_version FROM memberships
        WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(orgId, ctx.caller.userId);

    if (!membership) throw notFound('org not found or not a member');

    const accessToken = issueAccessToken({
      userId: ctx.caller.userId,
      orgId,
      role: membership.role,
      permVersion: membership.perm_version,
    }, secret);

    send(res, 200, { token: accessToken, accessToken, role: membership.role });
  });

  // GET /v1/auth/me — current user, active org, role, all orgs, org-level permissions.
  router.get('/v1/auth/me', async (ctx, _params, res) => {
    const { userId, orgId } = ctx.caller;

    const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(userId);

    // All orgs this user is an active member of.
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(userId);

    // Org-level resolved permissions for the active org (used for nav gating in the SPA).
    const { role, permissions } = resolveOrgLevel(db, { userId, orgId });

    send(res, 200, {
      user: { id: user.id, email: user.email, name: user.name },
      org: { id: orgId },
      role,
      orgs,
      permissions,
    });
  });
}
