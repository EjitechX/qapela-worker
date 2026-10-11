/**
 * QAPELA — Cloudflare Worker (single-file bundle, v24)
 * v24: Email header now uses the real Qapela logo image (hosted at
 * assets/qapela-wordmark.png on GitHub Pages) instead of a plain
 * color block — update the URL in auth.js's brandedEmailHtml if the
 * site ever moves off ejitechx.github.io/qapela-worker/.
 *
 * v23: Proper branded HTML email template, reusable wrapper.
 * v22: Password reset via Resend. v21: task_catalogue CRUD + admin
 * oversight. v20: music marketplace. v19: affiliate/listings/mine.
 * v18: business profile. v17: profile name update. v16: referral
 * commissions fixed at root. v15: disputes.js. v14: wallet/withdrawal
 * history. v13: business dashboard reads. v12: reads.js, account/roles.
 * v11: auth/me, public/settings. v10: real signup flow.
 * Bindings: D1 "DB" -> capella-db. Secrets (Runtime vars, not Build):
 * PAYSTACK_SECRET_KEY, AUTH_SECRET, RESEND_API_KEY. Cron: 0 * * * *
 */


// Withdrawal safety limits (₦). Change here only.
const WITHDRAWAL_LIMITS = {
  maxSingle: 200000,   // largest single withdrawal
  maxPerDay: 500000,   // total in any rolling 24 hours
  maxPerDayCount: 5,   // withdrawal attempts in any rolling 24 hours
  staleMinutes: 10,    // a transfer still "processing" after this long gets checked and settled by the hourly job
};

// Platform revenue streams, each withdrawable on its own. "reserve" is money set aside
// from task payouts (platform_treasury); every other key is a platform_revenue.type.
const REVENUE_STREAMS = [
  { key: "registration_fee", label: "Activation fees" },
  { key: "campaign_service_revenue", label: "Task service margin" },
  { key: "music_platform_fee", label: "Music sales fees" },
  { key: "affiliate_platform_fee", label: "Affiliate fees" },
  { key: "reserve", label: "Reserve from task payouts" },
];
const REVENUE_ACTIVE = "('processing','completed','needs_review')";

// Business balance refunds to a bank account (₦). Money added by card in the last
// `holdHours` can't be refunded yet (stops card-testing / money-laundering loops).
const BUSINESS_REFUND_LIMITS = {
  maxSingle: 1000000,
  maxPerDay: 2000000,
  maxPerDayCount: 3,
  holdHours: 24,
};

// FROM: auth.js
const auth = (function() {
/**
 * Qapela — Real Authentication (Cloudflare Workers + D1)
 * -----------------------------------------------------------
 * Replaces the temporary x-qapela-user-id header (which anyone could
 * fake) with real password auth + signed session tokens, built entirely
 * on Web Crypto — no external auth service needed.
 *
 *   - Passwords: PBKDF2-SHA256, 100,000 iterations, random 16-byte salt
 *     per user. Never store or log plaintext passwords.
 *   - Sessions: a compact signed token (like a JWT, hand-rolled since
 *     Workers don't ship a JWT library by default) — base64url(header)
 *     + "." + base64url(payload) + "." + base64url(HMAC-SHA256
 *     signature). Payload carries { uid, exp }. Verifying recomputes
 *     the signature and checks expiry — nobody can forge a token
 *     without env.AUTH_SECRET (set via `wrangler secret put AUTH_SECRET`).
 *   - Token lifetime: 30 days, but sessions effectively never expire for
 *     anyone actively using the app: see maybeRenewToken below — every
 *     API response quietly includes a fresh token once the current one
 *     is within 7 days of expiring, so the client can swap it in
 *     without the user ever noticing or re-entering a password. Only
 *     an account untouched for 30+ full days actually needs to log in
 *     again — a genuinely inactive session, not an active user getting
 *     kicked out.
 *
 * Every other module's requireAuth(request, env) (see auth-helpers.js)
 * now runs through verifyToken() here instead of trusting a header.
 *
 * Routes (mounted in worker.js):
 *   POST /auth/register   { email?, phone?, password, referredBy? }
 *   POST /auth/login      { identifier, password }   (identifier = email or phone)
 *
 * Client integration note for the silent-renewal mechanism: every
 * response from the Worker may carry an `X-Renewed-Token` header. If
 * present, the client should overwrite its stored token with that
 * value immediately — it's a fresh 30-day token for the same account,
 * issued because the old one was getting close to expiring.
 */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

const TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const PBKDF2_ITERATIONS = 100000;

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes.buffer;
}
function b64url(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new TextEncoder().encode(buf);
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecodeToString(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return atob(str);
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16)).buffer;
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return { hash: bufToHex(bits), salt: saltHex || bufToHex(salt) };
}

async function verifyPassword(password, storedHashHex, saltHex) {
  const { hash } = await hashPassword(password, saltHex);
  // constant-time-ish compare
  if (hash.length !== storedHashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ storedHashHex.charCodeAt(i);
  return diff === 0;
}

async function hmac(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", key, enc.encode(data));
}

async function signToken(uid, secret) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS;
  const payload = b64url(JSON.stringify({ uid, exp }));
  const signature = b64url(await hmac(`${header}.${payload}`, secret));
  return `${header}.${payload}.${signature}`;
}

// Shared by verifyToken and maybeRenewToken — decodes and checks the
// signature, but does NOT check expiry itself (callers decide what to
// do with an expired-but-validly-signed token).
async function decodeValidToken(token, secret) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  const expectedSig = b64url(await hmac(`${header}.${payload}`, secret));
  if (signature !== expectedSig) return null;
  try {
    const data = JSON.parse(b64urlDecodeToString(payload));
    if (!data.uid || !data.exp) return null;
    return data;
  } catch {
    return null;
  }
}

async function verifyToken(token, secret) {
  const data = await decodeValidToken(token, secret);
  if (!data) return null;
  if (data.exp < Math.floor(Date.now() / 1000)) return null;
  return data.uid;
}

// Within this many seconds of expiring, a still-valid token gets
// silently replaced with a fresh 30-day one on every request. 7 days
// gives plenty of margin for someone who opens the app roughly weekly.
const RENEWAL_WINDOW_SECONDS = 7 * 24 * 60 * 60;

// Returns a fresh signed token if the request's current one is valid
// but getting close to expiring, otherwise null (nothing to renew —
// either no token was sent, it's already expired, or it's not due yet).
async function maybeRenewToken(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;

  const data = await decodeValidToken(match[1], env.AUTH_SECRET);
  if (!data) return null;

  const now = Math.floor(Date.now() / 1000);
  if (data.exp < now) return null; // already expired — must log in again, not renewed
  if (data.exp - now > RENEWAL_WINDOW_SECONDS) return null; // not due yet

  return signToken(data.uid, env.AUTH_SECRET);
}

// Called by every other module instead of reading x-qapela-user-id directly.
async function requireAuth(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const uid = await verifyToken(match[1], env.AUTH_SECRET);
  if (!uid) return null;
  // A deleted account's old session tokens must stop working immediately.
  const row = await env.DB.prepare("SELECT status FROM users WHERE uid = ?").bind(uid).first();
  if (!row || row.status === "deleted") return null;
  return uid;
}

// ---------------------------------------------------------------------
// POST /auth/register
// { email?, phone?, password, name, role: 'worker'|'business', companyName?, referralCode? }
//
// referralCode here is the CODE someone typed in (e.g. "QAP-A1B2C3"),
// not a raw uid — resolving it to an actual referrer now happens here,
// server-side, since the client can no longer query the database
// directly the way it could with Firestore. An unresolvable code
// doesn't block signup, same as the original behavior — just proceeds
// without a referral rather than failing over a bad/old link.
// ---------------------------------------------------------------------
async function register(request, env) {
  const db = env.DB;
  const { email, phone, password, name, role, companyName, referralCode } = await request.json();

  if (!password || password.length < 8) {
    return json({ success: false, message: "Password must be at least 8 characters." }, 400);
  }
  if (!email && !phone) {
    return json({ success: false, message: "Provide an email or phone number." }, 400);
  }
  const cleanName = typeof name === "string" ? name.trim() : "";
  if (!cleanName) return json({ success: false, message: "Enter your full name." }, 400);

  const cleanRole = role === "business" ? "business" : "worker"; // default worker, matches original page's default
  const cleanCompany = typeof companyName === "string" ? companyName.trim() : "";
  if (cleanRole === "business" && !cleanCompany) {
    return json({ success: false, message: "Enter your company name." }, 400);
  }

  const cleanEmail = email ? String(email).trim().toLowerCase() : null;
  const cleanPhone = phone ? String(phone).trim() : null;

  if (cleanEmail) {
    const existing = await db.prepare("SELECT uid FROM users WHERE email = ?").bind(cleanEmail).first();
    if (existing) return json({ success: false, message: "An account with this email already exists." });
  }
  if (cleanPhone) {
    const existing = await db.prepare("SELECT uid FROM users WHERE phone = ?").bind(cleanPhone).first();
    if (existing) return json({ success: false, message: "An account with this phone number already exists." });
  }

  // Resolve a referral code to an actual referrer, if one was given.
  let referrerUid = null;
  if (referralCode && typeof referralCode === "string" && referralCode.trim()) {
    const referrer = await db.prepare("SELECT uid FROM users WHERE referralCode = ?").bind(referralCode.trim().toUpperCase()).first();
    if (referrer) referrerUid = referrer.uid;
  }

  const uid = crypto.randomUUID();
  const { hash, salt } = await hashPassword(password);
  const now = new Date().toISOString();
  const myReferralCode = "QAP-" + uid.slice(0, 6).toUpperCase();

  const statements = [
    db
      .prepare(
        `INSERT INTO users (uid, email, phone, passwordHash, passwordSalt, displayName, referralCode, roleWorker, roleBusiness, referredBy, status, createdAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`
      )
      .bind(
        uid,
        cleanEmail,
        cleanPhone,
        hash,
        salt,
        cleanName,
        myReferralCode,
        cleanRole === "worker" ? 1 : 0,
        cleanRole === "business" ? 1 : 0,
        referrerUid,
        now
      ),
  ];

  if (cleanRole === "business") {
    statements.push(
      db.prepare("INSERT INTO businesses (uid, name, createdAt) VALUES (?, ?, ?) ON CONFLICT(uid) DO NOTHING").bind(uid, cleanCompany, now)
    );
  } else {
    statements.push(
      db
        .prepare(
          `INSERT INTO worker_profiles (uid, level, levelProgressPct, tasksCompleted, tasksRejected, successRatePct, accuracyPct, reputationScore, kycStatus)
           VALUES (?, 1, 0, 0, 0, 100, 100, 0, 'none') ON CONFLICT(uid) DO NOTHING`
        )
        .bind(uid)
    );
  }

  if (referrerUid) {
    statements.push(
      db
        .prepare(
          `INSERT INTO referrals (id, referrerId, referredId, status, commissionAmount, createdAt)
           VALUES (?, ?, ?, 'pending', NULL, ?)`
        )
        .bind(crypto.randomUUID(), referrerUid, uid, now)
    );
  }

  await db.batch(statements);

  const token = await signToken(uid, env.AUTH_SECRET);
  return json({ success: true, uid, referralCode: myReferralCode, token });
}

// ---------------------------------------------------------------------
// POST /auth/login
// ---------------------------------------------------------------------
async function login(request, env) {
  const db = env.DB;
  const { identifier, password } = await request.json();
  if (!identifier || !password) {
    return json({ success: false, message: "identifier and password are required." }, 400);
  }
  const clean = String(identifier).trim().toLowerCase();

  const user = await db.prepare("SELECT * FROM users WHERE email = ? OR phone = ?").bind(clean, identifier.trim()).first();
  if (!user) return json({ success: false, message: "Invalid credentials." }, 401);

  const ok = await verifyPassword(password, user.passwordHash, user.passwordSalt);
  if (!ok) return json({ success: false, message: "Invalid credentials." }, 401);

  const token = await signToken(user.uid, env.AUTH_SECRET);
  return json({
    success: true,
    uid: user.uid,
    token,
    profile: {
      displayName: user.displayName,
      email: user.email,
      phone: user.phone,
      referralCode: user.referralCode,
      roleWorker: !!user.roleWorker,
      roleBusiness: !!user.roleBusiness,
      accountActivated: !!user.accountActivated,
    },
  });
}

// ---------------------------------------------------------------------
// GET /auth/me — current, fresh profile for whoever's token is sent.
// Every page that needs to know "who am I / am I activated / what
// roles do I have" calls this, rather than trusting a possibly-stale
// value cached from login time.
// ---------------------------------------------------------------------
async function getMe(request, env) {
  const uid = await requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const user = await db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first();
  if (!user) return json({ message: "User not found." }, 404);

  return json({
    uid: user.uid,
    displayName: user.displayName,
    email: user.email,
    phone: user.phone,
    referralCode: user.referralCode,
    roleWorker: !!user.roleWorker,
    roleBusiness: !!user.roleBusiness,
    accountActivated: !!user.accountActivated,
    workerActivated: !!user.workerActivated,
    businessActivated: !!user.businessActivated,
    status: user.status,
  });
}

// ---------------------------------------------------------------------
// POST /account/roles — self-service: add worker or business access to
// an existing account (e.g. "Switch to Business" from the worker
// dashboard). One account can hold both; this just flips the flag and
// creates the corresponding profile row if it doesn't already exist —
// same self-service pattern as the original page, minus re-registering.
// ---------------------------------------------------------------------
async function addRole(request, env) {
  const uid = await requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { role } = await request.json();
  if (role !== "worker" && role !== "business") {
    return json({ success: false, message: "role must be 'worker' or 'business'." }, 400);
  }

  const user = await db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first();
  if (!user) return json({ message: "User not found." }, 404);

  if (role === "worker") {
    await db.batch([
      db.prepare("UPDATE users SET roleWorker = 1 WHERE uid = ?").bind(uid),
      db
        .prepare(
          `INSERT INTO worker_profiles (uid, level, levelProgressPct, tasksCompleted, tasksRejected, successRatePct, accuracyPct, reputationScore, kycStatus)
           VALUES (?, 1, 0, 0, 0, 100, 100, 0, 'none') ON CONFLICT(uid) DO NOTHING`
        )
        .bind(uid),
    ]);
  } else {
    await db.batch([
      db.prepare("UPDATE users SET roleBusiness = 1 WHERE uid = ?").bind(uid),
      db
        .prepare("INSERT INTO businesses (uid, name, createdAt) VALUES (?, ?, ?) ON CONFLICT(uid) DO NOTHING")
        .bind(uid, user.displayName || user.email || "My Business", new Date().toISOString()),
    ]);
  }

  return json({ success: true, role });
}

// ---------------------------------------------------------------------
// POST /account/profile — update editable profile fields. Currently
// just displayName; email/phone aren't editable here since changing
// those would need re-verification, not built yet.
// ---------------------------------------------------------------------
async function updateProfile(request, env) {
  const uid = await requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { name } = await request.json();
  const cleanName = typeof name === "string" ? name.trim() : "";
  if (!cleanName) return json({ success: false, message: "Name can't be empty." }, 400);

  await db.prepare("UPDATE users SET displayName = ? WHERE uid = ?").bind(cleanName, uid).run();
  return json({ success: true, displayName: cleanName });
}

// ---------------------------------------------------------------------
// POST /account/business-profile — update the businesses table's name
// field (the profile page rewritten from qapela-business-profile.html).
// ---------------------------------------------------------------------
async function updateBusinessProfile(request, env) {
  const uid = await requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { name } = await request.json();
  const cleanName = typeof name === "string" ? name.trim() : "";
  if (!cleanName) return json({ success: false, message: "Company name can't be empty." }, 400);

  await db
    .prepare(
      `INSERT INTO businesses (uid, name, createdAt) VALUES (?, ?, ?)
       ON CONFLICT(uid) DO UPDATE SET name = ?`
    )
    .bind(uid, cleanName, new Date().toISOString(), cleanName)
    .run();

  return json({ success: true, name: cleanName });
}

// ---------------------------------------------------------------------
// Password reset — email-based. RESET_BASE_URL points at where the
// site is actually hosted (GitHub Pages); update if that ever changes.
// Sending goes through Resend (env.RESEND_API_KEY). A reset token is
// single-use and expires after 1 hour.
// ---------------------------------------------------------------------
// GitHub Pages address of the site. Update only here if the GitHub username or repo name ever changes.
const SITE_BASE = "https://ejitechx.github.io/qapela-worker/";
const RESET_BASE_URL = SITE_BASE;
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

function randomToken() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return b64url(bytes.buffer);
}

// ---------------------------------------------------------------------
// Branded email wrapper — every Qapela email (just the password reset
// one today, but built so a welcome email or a receipt could reuse it
// later) shares this shell. Table-based layout and inline styles only:
// <style> blocks get stripped by a lot of email clients (Gmail
// included), and CSS gradients/flexbox are unreliable in email — so
// this deliberately doesn't try to reuse the app's actual CSS.
//   heading   — the big line under the logo
//   bodyHtml  — arbitrary HTML for the message body
//   ctaLabel / ctaUrl — optional button; omit both to skip it
// ---------------------------------------------------------------------
function brandedEmailHtml({ heading, bodyHtml, ctaLabel, ctaUrl }) {
  const button = ctaLabel && ctaUrl
    ? `
      <tr>
        <td align="center" style="padding:28px 0 8px;">
          <a href="${ctaUrl}" style="display:inline-block;background-color:#0B5CFF;color:#ffffff;font-family:Segoe UI,Arial,sans-serif;font-size:15px;font-weight:bold;text-decoration:none;padding:14px 32px;border-radius:10px;">${ctaLabel}</a>
        </td>
      </tr>
      <tr>
        <td align="center" style="padding:0 24px 8px;">
          <p style="font-family:Segoe UI,Arial,sans-serif;font-size:11.5px;color:#9AA3BC;word-break:break-all;margin:0;">Or paste this link into your browser:<br>${ctaUrl}</p>
        </td>
      </tr>`
    : "";

  return `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background-color:#F8FAFF;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#F8FAFF;padding:32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:460px;background-color:#ffffff;border-radius:16px;overflow:hidden;border:1px solid #E6EAF2;">
          <tr>
            <td style="background-color:#0E2A6B;padding:26px 28px;" align="center">
              <img src="${SITE_BASE}assets/qapela-wordmark.png" height="34" alt="Qapela" style="display:block;height:34px;width:auto;border:0;">
            </td>
          </tr>
          <tr>
            <td style="padding:30px 28px 6px;">
              <h1 style="font-family:Segoe UI,Arial,sans-serif;font-size:19px;color:#1B2559;margin:0 0 14px;">${heading}</h1>
              <div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.6;color:#2A3560;">${bodyHtml}</div>
            </td>
          </tr>
          ${button}
          <tr>
            <td style="padding:22px 28px 26px;">
              <hr style="border:none;border-top:1px solid #E6EAF2;margin:0 0 16px;">
              <p style="font-family:Segoe UI,Arial,sans-serif;font-size:11.5px;color:#9AA3BC;margin:0;line-height:1.6;">Qapela — work, earn, grow. This is a transactional email sent because of activity on your account; you can't unsubscribe from account-security emails like this one.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

async function sendResetEmail(env, toEmail, resetUrl) {
  // Sender shows up as just "Qapela" in the inbox. Two providers are supported:
  //  - Brevo (no domain needed): set secret BREVO_API_KEY, and verify the sender address in Brevo.
  //    Sender address = EMAIL_FROM_ADDRESS if set, otherwise the support email below.
  //  - Resend (needs a verified domain for real users): set RESEND_API_KEY and optionally EMAIL_FROM.
  // Brevo is used first when its key exists.
  const SUPPORT_EMAIL = "qapela.zrofeet@gmail.com";
  if (!env.BREVO_API_KEY && !env.RESEND_API_KEY) {
    // Fails loudly rather than silently pretending an email went out —
    // the caller still returns a generic success message to the client
    // either way (see requestPasswordReset), but this gets logged.
    console.error("No email provider key set (BREVO_API_KEY or RESEND_API_KEY) — cannot send password reset email.");
    return false;
  }
  const html = brandedEmailHtml({
    heading: "Reset your password",
    bodyHtml: `
      <p style="margin:0 0 10px;">We got a request to reset the password on your Qapela account.</p>
      <p style="margin:0;">This link expires in <strong>1 hour</strong>. If you didn't request this, you can safely ignore this email — your password won't change.</p>
    `,
    ctaLabel: "Reset Password",
    ctaUrl: resetUrl,
  });
  const subject = "Reset your Qapela password";
  let res;
  if (env.BREVO_API_KEY) {
    res = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": env.BREVO_API_KEY, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        sender: { name: "Qapela", email: env.EMAIL_FROM_ADDRESS || SUPPORT_EMAIL },
        to: [{ email: toEmail }],
        replyTo: { email: SUPPORT_EMAIL },
        subject,
        htmlContent: html,
      }),
    });
  } else {
    res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: env.EMAIL_FROM || "Qapela <onboarding@resend.dev>",
        to: toEmail,
        reply_to: SUPPORT_EMAIL,
        subject,
        html,
      }),
    });
  }
  if (!res.ok) {
    // Surface the provider's reason (unverified sender, bad key, recipient not allowed…) in Workers Logs.
    let detail = "";
    try { detail = await res.text(); } catch (e) {}
    console.error("Email provider rejected the reset email:", res.status, detail);
  }
  return res.ok;
}

async function requestPasswordReset(request, env) {
  const db = env.DB;
  const { email } = await request.json();
  const cleanEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
  if (!cleanEmail) return json({ success: false, message: "Enter your email address." }, 400);

  const user = await db.prepare("SELECT uid, email FROM users WHERE email = ?").bind(cleanEmail).first();

  // Always return the same success message whether or not the account
  // exists — otherwise this endpoint becomes a way to check which
  // emails are registered on Qapela.
  const genericResponse = json({ success: true, message: "If an account exists for that email, a reset link is on its way." });
  if (!user) return genericResponse;

  const token = randomToken();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + RESET_TOKEN_TTL_MS).toISOString();

  await db
    .prepare("INSERT INTO password_resets (id, uid, token, expiresAt, used, createdAt) VALUES (?, ?, ?, ?, 0, ?)")
    .bind(crypto.randomUUID(), user.uid, token, expiresAt, now.toISOString())
    .run();

  const resetUrl = `${RESET_BASE_URL}qapela-reset-password.html?token=${token}`;
  await sendResetEmail(env, user.email, resetUrl);

  return genericResponse;
}

async function confirmPasswordReset(request, env) {
  const db = env.DB;
  const { token, newPassword } = await request.json();

  if (!token) return json({ success: false, message: "Reset link is missing its token." }, 400);
  if (!newPassword || newPassword.length < 8) {
    return json({ success: false, message: "Password must be at least 8 characters." }, 400);
  }

  const row = await db.prepare("SELECT * FROM password_resets WHERE token = ?").bind(token).first();
  if (!row) return json({ success: false, message: "This reset link is invalid." }, 400);
  if (row.used) return json({ success: false, message: "This reset link has already been used." }, 400);
  if (new Date(row.expiresAt).getTime() < Date.now()) {
    return json({ success: false, message: "This reset link has expired — request a new one." }, 400);
  }

  const { hash, salt } = await hashPassword(newPassword);

  await db.batch([
    db.prepare("UPDATE users SET passwordHash = ?, passwordSalt = ? WHERE uid = ?").bind(hash, salt, row.uid),
    db.prepare("UPDATE password_resets SET used = 1 WHERE id = ?").bind(row.id),
  ]);

  return json({ success: true });
}

// ---------------------------------------------------------------------
// Account self-service: change email/phone, change password, delete account.
// Every one of these re-asks for the CURRENT password, so a stolen or
// left-open session can't be used to lock the owner out or wipe the account.
// ---------------------------------------------------------------------
async function checkCurrentPassword(db, uid, password) {
  const user = await db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first();
  if (!user || !password) return null;
  const ok = await verifyPassword(String(password), user.passwordHash, user.passwordSalt);
  return ok ? user : null;
}

// POST /account/contact { email?, phone?, currentPassword }
async function changeContact(request, env) {
  const uid = await requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  let body; try { body = await request.json(); } catch (e) { body = {}; }

  const user = await checkCurrentPassword(db, uid, body.currentPassword);
  if (!user) return json({ success: false, message: "Your current password is incorrect." }, 403);

  let email = user.email;
  let phone = user.phone;
  if (body.email !== undefined) {
    const e = String(body.email || "").trim().toLowerCase();
    if (e && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return json({ success: false, message: "Enter a valid email address." }, 400);
    email = e || null;
  }
  if (body.phone !== undefined) {
    const ph = String(body.phone || "").trim();
    if (ph && !/^\+?[0-9][0-9 \-]{6,18}$/.test(ph)) return json({ success: false, message: "Enter a valid phone number." }, 400);
    phone = ph || null;
  }
  if (!email && !phone) return json({ success: false, message: "Keep at least an email or a phone number on your account." }, 400);

  if (email && email !== user.email) {
    const taken = await db.prepare("SELECT uid FROM users WHERE email = ? AND uid != ?").bind(email, uid).first();
    if (taken) return json({ success: false, message: "Another account already uses this email." });
  }
  if (phone && phone !== user.phone) {
    const taken = await db.prepare("SELECT uid FROM users WHERE phone = ? AND uid != ?").bind(phone, uid).first();
    if (taken) return json({ success: false, message: "Another account already uses this phone number." });
  }

  await db.prepare("UPDATE users SET email = ?, phone = ? WHERE uid = ?").bind(email, phone, uid).run();
  return json({ success: true, email, phone });
}

// POST /account/password { currentPassword, newPassword }
async function changePassword(request, env) {
  const uid = await requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  let body; try { body = await request.json(); } catch (e) { body = {}; }

  if (!body.newPassword || String(body.newPassword).length < 8) {
    return json({ success: false, message: "New password must be at least 8 characters." }, 400);
  }
  const user = await checkCurrentPassword(db, uid, body.currentPassword);
  if (!user) return json({ success: false, message: "Your current password is incorrect." }, 403);

  const { hash, salt } = await hashPassword(String(body.newPassword));
  await db.prepare("UPDATE users SET passwordHash = ?, passwordSalt = ? WHERE uid = ?").bind(hash, salt, uid).run();
  return json({ success: true });
}

// Things that must be settled before an account can be deleted, so nobody
// loses money or escapes an open obligation by deleting.
async function getDeletionBlockers(db, uid) {
  const blockers = [];
  const n = (v) => Number(v || 0);
  const naira = (v) => "₦" + Number(v || 0).toLocaleString();

  const admin = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  if (admin) blockers.push("Admin accounts can't be deleted from here.");

  const wd = await db.prepare("SELECT id FROM withdrawals WHERE userId = ? AND status IN ('processing','needs_review') LIMIT 1").bind(uid).first();
  if (wd) blockers.push("You have a withdrawal in progress. Wait for it to finish first.");

  const w = await db.prepare("SELECT availableBalance, pendingBalance FROM wallets WHERE uid = ?").bind(uid).first();
  const held = n(w?.availableBalance) + n(w?.pendingBalance);
  if (held > 0) blockers.push(`Withdraw your wallet balance first (${naira(held)} left).`);

  const bw = await db.prepare("SELECT availableBalance, reservedFunds, campaignFunds FROM business_wallets WHERE uid = ?").bind(uid).first();
  if (n(bw?.availableBalance) > 0) blockers.push(`Refund your business wallet balance to your bank first (${naira(bw.availableBalance)} left) — use "Refund to bank" on the business page.`);
  if (n(bw?.reservedFunds) + n(bw?.campaignFunds) > 0) blockers.push(`${naira(n(bw?.reservedFunds) + n(bw?.campaignFunds))} is still committed to your campaigns. Wait for them to finish first.`);
  const refundBusy = await db.prepare("SELECT id FROM business_refunds WHERE userId = ? AND status IN ('processing','needs_review') LIMIT 1").bind(uid).first();
  if (refundBusy) blockers.push("You have a refund in progress. Wait for it to finish first.");

  const sub = await db.prepare("SELECT id FROM submissions WHERE workerId = ? AND status IN ('pending','needs_review','processing') LIMIT 1").bind(uid).first();
  if (sub) blockers.push("You have submitted tasks still waiting to be reviewed. Wait for the result first.");

  const dis = await db.prepare("SELECT id FROM disputes WHERE raisedBy = ? AND status = 'open' LIMIT 1").bind(uid).first();
  if (dis) blockers.push("You have an open dispute. It needs to be resolved first.");

  const sale = await db.prepare("SELECT id FROM affiliate_sales WHERE (workerId = ? OR businessId = ?) AND status = 'processing' LIMIT 1").bind(uid, uid).first();
  if (sale) blockers.push("An affiliate sale involving you is still being paid out. Try again shortly.");

  return blockers;
}

// GET /account/delete-check
async function deleteCheck(request, env) {
  const uid = await requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const blockers = await getDeletionBlockers(env.DB, uid);
  return json({ canDelete: blockers.length === 0, blockers });
}

// POST /account/delete { password, confirm: "DELETE" }
// Removes personal data and signs the person out everywhere. Money records
// (ledger, payments, withdrawals) are kept for accounting but stripped of
// personal details.
async function deleteAccount(request, env) {
  const uid = await requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  let body; try { body = await request.json(); } catch (e) { body = {}; }

  if (String(body.confirm || "").trim() !== "DELETE") {
    return json({ success: false, message: 'Type DELETE to confirm.' }, 400);
  }
  const user = await checkCurrentPassword(db, uid, body.password);
  if (!user) return json({ success: false, message: "Your password is incorrect." }, 403);

  const blockers = await getDeletionBlockers(db, uid);
  if (blockers.length) return json({ success: false, message: blockers[0], blockers });

  const now = new Date().toISOString();
  await db.batch([
    db.prepare(
      "UPDATE users SET email = NULL, phone = NULL, displayName = 'Deleted user', passwordHash = 'deleted', passwordSalt = 'deleted', referralCode = NULL, status = 'deleted' WHERE uid = ?"
    ).bind(uid),
    db.prepare("DELETE FROM notifications WHERE userId = ?").bind(uid),
    db.prepare("DELETE FROM password_resets WHERE uid = ?").bind(uid),
    db.prepare("DELETE FROM worker_profiles WHERE uid = ?").bind(uid),
    db.prepare("DELETE FROM task_proof_files WHERE workerId = ?").bind(uid),
    db.prepare("UPDATE businesses SET name = 'Deleted business' WHERE uid = ?").bind(uid),
    db.prepare("UPDATE musicians SET name = 'Deleted artist', bio = NULL WHERE uid = ?").bind(uid),
    db.prepare("UPDATE unreleased_songs SET status = 'removed' WHERE musicianId = ? AND status = 'active'").bind(uid),
    db.prepare("UPDATE affiliate_links SET status = 'inactive', bankName = NULL, accountNumber = NULL, accountName = NULL WHERE workerId = ?").bind(uid),
    db.prepare("UPDATE affiliate_listings SET status = 'inactive', deletedAt = ?, bankName = NULL, accountNumber = NULL, accountName = NULL WHERE businessId = ?").bind(now, uid),
    db.prepare("UPDATE withdrawals SET accountNumber = '******' || SUBSTR(accountNumber, -4), accountName = 'Deleted' WHERE userId = ?").bind(uid),
    db.prepare("UPDATE business_refunds SET accountNumber = '******' || SUBSTR(accountNumber, -4), accountName = 'Deleted' WHERE userId = ?").bind(uid),
  ]);
  return json({ success: true });
}

  return {
  register,
  login,
  requireAuth,
  maybeRenewToken,
  getMe,
  addRole,
  updateProfile,
  updateBusinessProfile,
  changeContact,
  changePassword,
  deleteCheck,
  deleteAccount,
  requestPasswordReset,
  confirmPasswordReset,
  signToken,
  verifyToken,
  hashPassword,
  verifyPassword,
};
})();


// FROM: withdrawal.js
const withdrawal = (function() {
/**
 * Qapela — Withdrawal Endpoints (Cloudflare Workers + D1)
 * ----------------------------------------------------------
 * Ported from functions/withdrawal.js. Same behavior, different plumbing:
 *
 *   - Firestore transactions -> D1 doesn't have multi-row transactions the
 *     same way, so each "atomic" step is done as a single UPDATE with a
 *     WHERE guard (e.g. WHERE availableBalance >= ?) so two simultaneous
 *     requests can't both succeed. We check `meta.changes` after the write
 *     to know if the guard passed.
 *   - admin.firestore.FieldValue.increment(-amt) -> plain SQL arithmetic
 *     in the UPDATE statement itself.
 *   - Firestore auto IDs -> crypto.randomUUID().
 *   - Cloud Function secrets -> Worker secrets (env.PAYSTACK_SECRET_KEY),
 *     set via `wrangler secret put PAYSTACK_SECRET_KEY`.
 *   - onCall auth (request.auth.uid) -> the uid comes from a verified
 *     session token (see auth.js), passed as "Authorization: Bearer <token>".
 *
 * Routes handled here (mounted in worker.js):
 *   GET  /banks
 *   POST /banks/resolve
 *   POST /withdrawals
 *   POST /admin/reserve-withdrawals
 *   POST /webhooks/paystack-transfer
 */


const DEFAULT_MIN_WITHDRAWAL = 500; // NGN fallback if platform_settings has none

async function isAdmin(db, uid) {
  const row = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  return !!row;
}

async function getMinWithdrawal(db) {
  const row = await db.prepare("SELECT minWithdrawal FROM platform_settings WHERE id = 'config'").first();
  return row?.minWithdrawal ?? DEFAULT_MIN_WITHDRAWAL;
}

async function paystackFetch(path, secret, options = {}) {
  const res = await fetch(`https://api.paystack.co${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const json = await res.json();
  if (!res.ok || json.status === false) {
    throw new Error(json.message || "Request failed");
  }
  return json;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ---------------------------------------------------------------------
// 1. List banks — cached in D1 for a day instead of Firestore's _cache
//    collection. Table: platform_settings isn't right for this since
//    it's not per-key; use a tiny dedicated cache table instead.
//    (Create once: CREATE TABLE IF NOT EXISTS kv_cache (key TEXT PRIMARY
//    KEY, value TEXT, fetchedAt TEXT); — add this if not already present.)
// ---------------------------------------------------------------------
async function listBanks(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const ONE_DAY_MS = 24 * 60 * 60 * 1000;
  const cached = await env.DB.prepare("SELECT value, fetchedAt FROM kv_cache WHERE key = 'ngnBanks'").first();
  if (cached && Date.now() - new Date(cached.fetchedAt).getTime() < ONE_DAY_MS) {
    return json({ banks: JSON.parse(cached.value) });
  }

  const res = await paystackFetch("/bank?country=nigeria&currency=NGN", env.PAYSTACK_SECRET_KEY);
  const banks = (res.data || []).map((b) => ({ name: b.name, code: b.code }));
  await env.DB.prepare(
    "INSERT INTO kv_cache (key, value, fetchedAt) VALUES ('ngnBanks', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, fetchedAt = excluded.fetchedAt"
  ).bind(JSON.stringify(banks), new Date().toISOString()).run();

  return json({ banks });
}

// ---------------------------------------------------------------------
// 2. Resolve account number -> account name
// ---------------------------------------------------------------------
async function resolveBankAccount(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { accountNumber, bankCode } = await request.json();
  if (!accountNumber || !bankCode) {
    return json({ message: "accountNumber and bankCode are required." }, 400);
  }

  try {
    const res = await paystackFetch(
      `/bank/resolve?account_number=${encodeURIComponent(accountNumber)}&bank_code=${encodeURIComponent(bankCode)}`,
      env.PAYSTACK_SECRET_KEY
    );
    return json({ accountName: res.data.account_name });
  } catch (err) {
    return json({ message: err.message }, 400);
  }
}

// ---------------------------------------------------------------------
// 3. Request withdrawal
//    Step 1 (guarded UPDATE) replaces the Firestore transaction: the
//    WHERE availableBalance >= ? clause means the row only updates if
//    there's enough money, and D1 reports back how many rows changed —
//    that's our success/failure signal, atomically, no race condition.
// ---------------------------------------------------------------------
// Raw Paystack call: returns { ok, status, body } for ANY HTTP answer and
// only throws if the network itself failed. That difference matters for
// money: an answer means we know what happened, a thrown error means we don't.
async function psRequest(path, secret, options = {}) {
  const res = await fetch(`https://api.paystack.co${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${secret}`, "Content-Type": "application/json", ...(options.headers || {}) },
  });
  let body = null;
  try { body = await res.json(); } catch (e) {}
  return { ok: res.ok && !!body && body.status !== false, status: res.status, body };
}

async function logMoneyAlert(db, userId, type, details) {
  try {
    await db
      .prepare("INSERT INTO fraud_events (id, userId, type, details, createdAt) VALUES (?, ?, ?, ?, ?)")
      .bind(crypto.randomUUID(), userId || null, type, typeof details === "string" ? details : JSON.stringify(details), new Date().toISOString())
      .run();
  } catch (e) {}
}

// One-shot settlement. Each helper flips status 'processing' -> final in the
// SAME transaction as the wallet change, and the wallet/ledger/notification
// statements only run if THIS call is the one that flipped the status (matched
// by a fresh random settleToken). So webhook retries, double deliveries and the
// hourly job can all call these safely — money moves exactly once.
async function settleWithdrawalSuccess(db, w) {
  const token = crypto.randomUUID();
  const now = new Date().toISOString();
  const r = await db.batch([
    db.prepare("UPDATE withdrawals SET status = 'completed', processedAt = ?, settleToken = ? WHERE id = ? AND status = 'processing'").bind(now, token, w.id),
    db.prepare("UPDATE wallets SET pendingBalance = pendingBalance - ? WHERE uid = ? AND EXISTS (SELECT 1 FROM withdrawals WHERE id = ? AND settleToken = ?)").bind(w.amount, w.userId, w.id, token),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         SELECT ?, ?, 'withdrawal_completed', 'Withdrawal completed', ?, ?, 0, ?
         WHERE EXISTS (SELECT 1 FROM withdrawals WHERE id = ? AND settleToken = ?)`
      )
      .bind(crypto.randomUUID(), w.userId, `₦${Number(w.amount).toLocaleString()} was sent to your bank account.`, w.id, now, w.id, token),
  ]);
  return r[0].meta.changes === 1;
}

async function settleWithdrawalFailed(db, w, reason) {
  const token = crypto.randomUUID();
  const now = new Date().toISOString();
  const r = await db.batch([
    db.prepare("UPDATE withdrawals SET status = 'failed', processedAt = ?, failureReason = ?, settleToken = ? WHERE id = ? AND status = 'processing'").bind(now, String(reason || "failed").slice(0, 300), token, w.id),
    db
      .prepare("UPDATE wallets SET availableBalance = availableBalance + ?, pendingBalance = pendingBalance - ? WHERE uid = ? AND EXISTS (SELECT 1 FROM withdrawals WHERE id = ? AND settleToken = ?)")
      .bind(w.amount, w.amount, w.userId, w.id, token),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
         SELECT ?, ?, 'worker', 'withdrawal_refund', ?, (SELECT availableBalance FROM wallets WHERE uid = ?), ?, ?
         WHERE EXISTS (SELECT 1 FROM withdrawals WHERE id = ? AND settleToken = ?)`
      )
      .bind(crypto.randomUUID(), w.userId, w.amount, w.userId, w.id, now, w.id, token),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         SELECT ?, ?, 'withdrawal_failed', 'Withdrawal failed', ?, ?, 0, ?
         WHERE EXISTS (SELECT 1 FROM withdrawals WHERE id = ? AND settleToken = ?)`
      )
      .bind(crypto.randomUUID(), w.userId, `Your ₦${Number(w.amount).toLocaleString()} withdrawal didn't go through — the amount is back in your available balance.`, w.id, now, w.id, token),
  ]);
  return r[0].meta.changes === 1;
}

// ---------------------------------------------------------------------
// 3. Request withdrawal — automatic (no admin step), with strict guards:
//    - signed-in, account status 'active'
//    - whole-naira amount within min / per-withdrawal / daily limits
//    - only ONE withdrawal in flight per user
//    - bank account name is resolved HERE (never trusted from the browser)
//    - the debit is one atomic transaction: the withdrawal row and the
//      wallet deduction only happen if availableBalance covers the amount
//      right now, so a balance can never go negative or be spent twice
//    - if the payout can't be confirmed either way, the money stays held
//      and the hourly job settles it — we never refund a transfer that
//      might actually have gone out
// ---------------------------------------------------------------------
async function requestWithdrawal(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  const L = WITHDRAWAL_LIMITS;
  const fail = (message) => json({ success: false, message });

  let body;
  try { body = await request.json(); } catch (e) { return fail("Invalid request."); }
  const { bankCode, bankName } = body || {};
  const accountNumber = String(body?.accountNumber || "").trim();
  const amt = Number(body?.amount);

  const minWithdrawal = await getMinWithdrawal(db);
  if (!Number.isInteger(amt) || amt <= 0) return fail("Enter a valid amount in whole naira.");
  if (amt < minWithdrawal) return fail(`Minimum withdrawal is ₦${minWithdrawal.toLocaleString()}.`);
  if (amt > L.maxSingle) return fail(`Maximum per withdrawal is ₦${L.maxSingle.toLocaleString()}.`);
  if (typeof bankCode !== "string" || !bankCode || !/^\d{10}$/.test(accountNumber)) {
    return fail("Choose a bank and enter a valid 10-digit account number.");
  }

  const user = await db.prepare("SELECT status FROM users WHERE uid = ?").bind(uid).first();
  if (!user || user.status !== "active") return fail("This account can't make withdrawals right now. Please contact support.");

  const inflight = await db.prepare("SELECT id FROM withdrawals WHERE userId = ? AND status = 'processing' LIMIT 1").bind(uid).first();
  if (inflight) return fail("You already have a withdrawal in progress. Wait for it to finish before starting another.");

  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const day = await db
    .prepare("SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN status IN ('processing','completed') THEN amount ELSE 0 END), 0) AS total FROM withdrawals WHERE userId = ? AND requestedAt >= ?")
    .bind(uid, since)
    .first();
  if ((day?.n || 0) >= L.maxPerDayCount) return fail("You've reached the limit of withdrawal attempts for today. Try again tomorrow.");
  if ((day?.total || 0) + amt > L.maxPerDay) {
    const left = Math.max(0, L.maxPerDay - (day?.total || 0));
    return fail(`Daily withdrawal limit is ₦${L.maxPerDay.toLocaleString()}. You can withdraw up to ₦${left.toLocaleString()} more in the next 24 hours.`);
  }

  const wallet = await db.prepare("SELECT availableBalance FROM wallets WHERE uid = ?").bind(uid).first();
  if (!wallet || wallet.availableBalance < amt) return fail("Insufficient balance.");

  // Make sure the payment account can actually cover this payout BEFORE touching the wallet.
  const cash = await getPayoutBalanceNaira(env);
  if (cash !== null && cash < amt) {
    await logMoneyAlert(db, uid, "payout_balance_low", { amt, paystackBalance: cash });
    return fail("Withdrawals are temporarily unavailable. Your money is safe in your balance — please try again later.");
  }

  // Resolve the account name on the server — what the browser says doesn't count.
  let accountName;
  try {
    const r = await psRequest(
      `/bank/resolve?account_number=${encodeURIComponent(accountNumber)}&bank_code=${encodeURIComponent(bankCode)}`,
      env.PAYSTACK_SECRET_KEY
    );
    accountName = r.body?.data?.account_name;
    if (!r.ok || !accountName) return fail("We couldn't verify this bank account. Check the bank and account number.");
  } catch (e) {
    return fail("We couldn't reach the bank verification service. Please try again in a moment.");
  }

  // Atomic debit: insert the withdrawal AND take the money in one transaction,
  // each conditional on the balance covering it and no other withdrawal in flight.
  const withdrawalId = crypto.randomUUID();
  const now = new Date().toISOString();
  const debit = await db.batch([
    db
      .prepare(
        `INSERT INTO withdrawals (id, userId, amount, provider, bankCode, bankName, accountNumber, accountName, status, requestedAt)
         SELECT ?, ?, ?, 'paystack', ?, ?, ?, ?, 'processing', ?
         WHERE (SELECT availableBalance FROM wallets WHERE uid = ?) >= ?
           AND NOT EXISTS (SELECT 1 FROM withdrawals WHERE userId = ? AND status = 'processing')`
      )
      .bind(withdrawalId, uid, amt, bankCode, bankName || null, accountNumber, accountName, now, uid, amt, uid),
    db
      .prepare(
        "UPDATE wallets SET availableBalance = availableBalance - ?, pendingBalance = pendingBalance + ? WHERE uid = ? AND availableBalance >= ? AND EXISTS (SELECT 1 FROM withdrawals WHERE id = ?)"
      )
      .bind(amt, amt, uid, amt, withdrawalId),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
         SELECT ?, ?, 'worker', 'withdrawal', ?, (SELECT availableBalance FROM wallets WHERE uid = ?), ?, ?
         WHERE EXISTS (SELECT 1 FROM withdrawals WHERE id = ?)`
      )
      .bind(crypto.randomUUID(), uid, -amt, uid, withdrawalId, now, withdrawalId),
  ]);
  if (debit[0].meta.changes !== 1) {
    return fail("This withdrawal couldn't be started. Check your balance and that no other withdrawal is in progress.");
  }
  if (debit[1].meta.changes !== 1) {
    // Should be impossible (same transaction) — never leave a held row without a deduction.
    await db.prepare("DELETE FROM withdrawals WHERE id = ? AND status = 'processing'").bind(withdrawalId).run();
    await db.prepare("DELETE FROM ledger_transactions WHERE relatedId = ? AND type = 'withdrawal'").bind(withdrawalId).run();
    await logMoneyAlert(db, uid, "withdrawal_debit_mismatch", { withdrawalId, amt });
    return fail("This withdrawal couldn't be started. Please try again.");
  }

  const w = { id: withdrawalId, userId: uid, amount: amt };
  const unavailable = "Withdrawals are temporarily unavailable. Your money is safe in your balance — please try again later.";

  try {
    // 1) payout recipient
    const rec = await psRequest("/transferrecipient", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({ type: "nuban", name: accountName, account_number: accountNumber, bank_code: bankCode, currency: "NGN" }),
    });
    if (!rec.ok) {
      await settleWithdrawalFailed(db, w, "recipient: " + (rec.body?.message || rec.status));
      return fail("We couldn't set up this bank account for payout. Check the details and try again.");
    }

    // 2) the transfer — reference = our withdrawal id, so it can never be sent twice
    const tr = await psRequest("/transfer", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({
        source: "balance",
        amount: amt * 100,
        recipient: rec.body.data.recipient_code,
        reason: "Qapela withdrawal",
        reference: withdrawalId,
      }),
    });

    if (!tr.ok) {
      // Paystack answered "no": no transfer exists, so refunding is safe.
      await settleWithdrawalFailed(db, w, "transfer: " + (tr.body?.message || tr.status));
      if (/balance/i.test(tr.body?.message || "")) {
        await logMoneyAlert(db, uid, "payout_balance_low", { withdrawalId, amt, message: tr.body?.message });
      }
      return fail(unavailable);
    }

    const status = tr.body.data.status;
    await db
      .prepare("UPDATE withdrawals SET providerRef = ?, paystackStatus = ? WHERE id = ?")
      .bind(tr.body.data.transfer_code, status, withdrawalId)
      .run();

    if (status === "otp") {
      // The payout account is set to ask for a manual confirmation, which would
      // mean a human approving every withdrawal. We don't allow that: refund and alert.
      await settleWithdrawalFailed(db, w, "payout provider asked for manual confirmation");
      await logMoneyAlert(db, uid, "payout_otp_required", { withdrawalId, amt, hint: "Turn off 'Confirm transfers before sending' in the Paystack dashboard (Settings > Preferences)." });
      return fail(unavailable);
    }
    if (status === "success") {
      await settleWithdrawalSuccess(db, w);
      return json({ success: true, message: "Withdrawal sent. It should reach your bank shortly." });
    }
    if (status === "failed" || status === "reversed") {
      await settleWithdrawalFailed(db, w, "transfer " + status);
      return fail("The transfer couldn't be completed. Your money is back in your balance.");
    }
    return json({ success: true, message: "Withdrawal is on its way to your bank. We'll notify you once it lands." });
  } catch (err) {
    // Network trouble: we do NOT know whether the transfer went out. Keep the
    // money held ('processing'); the webhook or the hourly check settles it.
    await logMoneyAlert(db, uid, "withdrawal_unconfirmed", { withdrawalId, amt, error: String(err?.message || err) });
    return json({ success: true, message: "Withdrawal is being processed. We'll notify you as soon as it's confirmed." });
  }
}

// ---- Platform revenue: separate streams, each withdrawable, plus "withdraw all" ----
async function getRevenueStreams(db) {
  const { results: earnedRows } = await db.prepare("SELECT type, COALESCE(SUM(amount), 0) AS earned FROM platform_revenue GROUP BY type").all();
  const { results: takenRows } = await db
    .prepare(
      `SELECT i.category, COALESCE(SUM(i.amount), 0) AS taken
       FROM revenue_withdrawal_items i JOIN revenue_withdrawals w ON w.id = i.withdrawalId
       WHERE w.status IN ${REVENUE_ACTIVE} GROUP BY i.category`
    )
    .all();
  const treasury = await db.prepare("SELECT lockedReserve FROM platform_treasury WHERE id = 'main'").first();
  const earned = new Map((earnedRows || []).map((r) => [r.type, r.earned]));
  const taken = new Map((takenRows || []).map((r) => [r.category, r.taken]));

  const known = REVENUE_STREAMS.map((x) => x.key);
  const extra = [...earned.keys()].filter((k) => !known.includes(k));
  const defs = [
    ...REVENUE_STREAMS,
    ...extra.map((k) => ({ key: k, label: k.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase()) })),
  ];

  return defs.map((d) => {
    if (d.key === "reserve") {
      const available = treasury?.lockedReserve || 0;
      const withdrawn = taken.get("reserve") || 0;
      return { key: d.key, label: d.label, earned: available + withdrawn, withdrawn, available };
    }
    const e = earned.get(d.key) || 0;
    const w = taken.get(d.key) || 0;
    return { key: d.key, label: d.label, earned: e, withdrawn: w, available: Math.max(0, e - w) };
  });
}

// GET /admin/revenue
async function getAdminRevenue(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const streams = await getRevenueStreams(db);
  const totalAvailable = streams.reduce((a, x) => a + x.available, 0);
  const cover = await getPayoutCover(env);
  const maxNow = cover.surplus === null ? null : Math.max(0, Math.min(totalAvailable, cover.surplus));
  const { results: recent } = await db
    .prepare("SELECT id, scope, amount, bankName, accountNumber, accountName, status, requestedAt, failureReason FROM revenue_withdrawals ORDER BY requestedAt DESC LIMIT 20")
    .all();
  const inflight = await db.prepare("SELECT id FROM revenue_withdrawals WHERE status = 'processing' LIMIT 1").first();
  return json({
    streams,
    totalAvailable,
    cashAboveOwed: cover.surplus,
    paystackBalance: cover.paystackBalance,
    owedToUsers: cover.owedToUsers,
    withdrawableNow: maxNow,
    withdrawalInProgress: !!inflight,
    recent: recent || [],
  });
}

async function settleRevenueSuccess(db, w) {
  const token = crypto.randomUUID();
  const now = new Date().toISOString();
  const r = await db
    .prepare("UPDATE revenue_withdrawals SET status = 'completed', processedAt = ?, settleToken = ? WHERE id = ? AND status = 'processing'")
    .bind(now, token, w.id)
    .run();
  return r.meta.changes === 1;
}

async function settleRevenueFailed(db, w, reason) {
  const token = crypto.randomUUID();
  const now = new Date().toISOString();
  const r = await db.batch([
    db.prepare("UPDATE revenue_withdrawals SET status = 'failed', processedAt = ?, failureReason = ?, settleToken = ? WHERE id = ? AND status = 'processing'").bind(now, String(reason || "failed").slice(0, 300), token, w.id),
    // Revenue streams free up automatically (a failed withdrawal no longer counts). Only the reserve needs its money put back.
    db
      .prepare(
        `UPDATE platform_treasury
         SET lockedReserve = lockedReserve + (SELECT COALESCE(SUM(amount), 0) FROM revenue_withdrawal_items WHERE withdrawalId = ? AND category = 'reserve'), updatedAt = ?
         WHERE id = 'main' AND EXISTS (SELECT 1 FROM revenue_withdrawals WHERE id = ? AND settleToken = ?)`
      )
      .bind(w.id, now, w.id, token),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, createdAt)
         SELECT ?, 'platformRevenue', 'platform', 'revenue_withdrawal_reversed', ?, ?, ?
         WHERE EXISTS (SELECT 1 FROM revenue_withdrawals WHERE id = ? AND settleToken = ?)`
      )
      .bind(crypto.randomUUID(), w.amount, w.id, now, w.id, token),
  ]);
  return r[0].meta.changes === 1;
}

// POST /admin/revenue/withdraw { scope: "<stream key>" | "all", amount?, bankCode, bankName, accountNumber }
// - a stream withdraws up to that stream's available revenue (all of it unless an amount is given)
// - "all" withdraws everything available across every stream
// - never more than the cash that sits ABOVE what is owed to users, so revenue can't be paid out of users' money
// - account name looked up by the server, atomic debit, one revenue withdrawal at a time, exactly-once settlement
async function requestRevenueWithdrawal(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);
  const fail = (message) => json({ success: false, message });

  let body;
  try { body = await request.json(); } catch (e) { return fail("Invalid request."); }
  const scope = String(body?.scope || "");
  const { bankCode, bankName } = body || {};
  const accountNumber = String(body?.accountNumber || "").trim();
  if (typeof bankCode !== "string" || !bankCode || !/^\d{10}$/.test(accountNumber)) {
    return fail("Choose a bank and enter a valid 10-digit account number.");
  }

  const streams = await getRevenueStreams(db);
  let items = [];
  if (scope === "all") {
    items = streams.filter((x) => x.available > 0).map((x) => ({ category: x.key, amount: x.available }));
  } else {
    const st = streams.find((x) => x.key === scope);
    if (!st) return fail("Unknown revenue stream.");
    const amt = body?.amount === undefined || body?.amount === null || body?.amount === "" ? st.available : Number(body.amount);
    if (!Number.isInteger(amt) || amt <= 0) return fail("Enter a valid amount in whole naira.");
    if (amt > st.available) return fail(`Only ₦${st.available.toLocaleString()} is available in ${st.label}.`);
    items = [{ category: st.key, amount: amt }];
  }
  const total = items.reduce((a, x) => a + x.amount, 0);
  if (total < 100) return fail("There's nothing to withdraw there yet (minimum ₦100).");

  const inflight = await db.prepare("SELECT id FROM revenue_withdrawals WHERE status = 'processing' LIMIT 1").first();
  if (inflight) return fail("A revenue withdrawal is already in progress. Wait for it to finish.");

  // Revenue must come from cash that is NOT owed to users.
  const cover = await getPayoutCover(env);
  if (cover.surplus === null) return fail("Couldn't check the payment account balance right now. Try again in a moment.");
  if (total > cover.surplus) {
    return fail(`Only ₦${Math.max(0, cover.surplus).toLocaleString()} of cash is above what is owed to users right now. Withdraw less, or top up the payment account.`);
  }

  let accountName;
  try {
    const r = await psRequest(
      `/bank/resolve?account_number=${encodeURIComponent(accountNumber)}&bank_code=${encodeURIComponent(bankCode)}`,
      env.PAYSTACK_SECRET_KEY
    );
    accountName = r.body?.data?.account_name;
    if (!r.ok || !accountName) return fail("We couldn't verify this bank account. Check the bank and account number.");
  } catch (e) {
    return fail("We couldn't reach the bank verification service. Please try again in a moment.");
  }

  // Atomic: the withdrawal row exists only if EVERY stream still covers its part, then the
  // parts are recorded (and the reserve is deducted) in the same transaction.
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const conds = [];
  const condBinds = [];
  for (const it of items) {
    if (it.category === "reserve") {
      conds.push("COALESCE((SELECT lockedReserve FROM platform_treasury WHERE id = 'main'), 0) >= ?");
      condBinds.push(it.amount);
    } else {
      conds.push(
        `(COALESCE((SELECT SUM(amount) FROM platform_revenue WHERE type = ?), 0)
          - COALESCE((SELECT SUM(i.amount) FROM revenue_withdrawal_items i JOIN revenue_withdrawals w ON w.id = i.withdrawalId
                      WHERE i.category = ? AND w.status IN ${REVENUE_ACTIVE}), 0)) >= ?`
      );
      condBinds.push(it.category, it.category, it.amount);
    }
  }
  const stmts = [
    db
      .prepare(
        `INSERT INTO revenue_withdrawals (id, scope, amount, bankCode, bankName, accountNumber, accountName, status, requestedBy, requestedAt)
         SELECT ?, ?, ?, ?, ?, ?, ?, 'processing', ?, ?
         WHERE NOT EXISTS (SELECT 1 FROM revenue_withdrawals WHERE status = 'processing')
           AND ${conds.join(" AND ")}`
      )
      .bind(id, scope, total, bankCode, bankName || null, accountNumber, accountName, uid, now, ...condBinds),
  ];
  for (const it of items) {
    stmts.push(
      db
        .prepare("INSERT INTO revenue_withdrawal_items (withdrawalId, category, amount) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM revenue_withdrawals WHERE id = ?)")
        .bind(id, it.category, it.amount, id)
    );
    if (it.category === "reserve") {
      stmts.push(
        db
          .prepare("UPDATE platform_treasury SET lockedReserve = lockedReserve - ?, updatedAt = ? WHERE id = 'main' AND lockedReserve >= ? AND EXISTS (SELECT 1 FROM revenue_withdrawals WHERE id = ?)")
          .bind(it.amount, now, it.amount, id)
      );
    }
  }
  stmts.push(
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, createdAt)
         SELECT ?, 'platformRevenue', 'platform', 'revenue_withdrawal', ?, ?, ?
         WHERE EXISTS (SELECT 1 FROM revenue_withdrawals WHERE id = ?)`
      )
      .bind(crypto.randomUUID(), -total, id, now, id)
  );
  const res = await db.batch(stmts);
  if (res[0].meta.changes !== 1) {
    return fail("This withdrawal couldn't be started — the available revenue changed or another withdrawal is in progress. Refresh and try again.");
  }

  const w = { id, amount: total };
  const unavailable = "Payouts are temporarily unavailable. Nothing was taken — please try again later.";
  try {
    const rec = await psRequest("/transferrecipient", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({ type: "nuban", name: accountName, account_number: accountNumber, bank_code: bankCode, currency: "NGN" }),
    });
    if (!rec.ok) {
      await settleRevenueFailed(db, w, "recipient: " + (rec.body?.message || rec.status));
      return fail("We couldn't set up this bank account for payout. Check the details and try again.");
    }
    const tr = await psRequest("/transfer", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({ source: "balance", amount: total * 100, recipient: rec.body.data.recipient_code, reason: "Qapela revenue withdrawal", reference: id }),
    });
    if (!tr.ok) {
      await settleRevenueFailed(db, w, "transfer: " + (tr.body?.message || tr.status));
      return fail(unavailable);
    }
    const status = tr.body.data.status;
    await db.prepare("UPDATE revenue_withdrawals SET providerRef = ?, paystackStatus = ? WHERE id = ?").bind(tr.body.data.transfer_code, status, id).run();
    if (status === "otp") {
      await settleRevenueFailed(db, w, "payout provider asked for manual confirmation");
      await logMoneyAlert(db, uid, "payout_otp_required", { revenueWithdrawalId: id });
      return fail("Paystack is asking for a manual confirmation. Turn off 'Confirm transfers before sending' in your Paystack dashboard (Settings > Preferences), then try again.");
    }
    if (status === "success") {
      await settleRevenueSuccess(db, w);
      return json({ success: true, message: "Revenue withdrawal sent to your bank." });
    }
    if (status === "failed" || status === "reversed") {
      await settleRevenueFailed(db, w, "transfer " + status);
      return fail("The transfer couldn't be completed. Nothing was taken.");
    }
    return json({ success: true, message: "Revenue withdrawal is on its way to your bank." });
  } catch (err) {
    await logMoneyAlert(db, uid, "revenue_withdrawal_unconfirmed", { id, total, error: String(err?.message || err) });
    return json({ success: true, message: "Revenue withdrawal is being processed. It will show as completed once confirmed." });
  }
}

// ---- Payout cover: is there enough cash in the payment account to pay people out? ----
async function getPayoutBalanceNaira(env) {
  try {
    const r = await psRequest("/balance", env.PAYSTACK_SECRET_KEY);
    const ngn = (r.body?.data || []).find((b) => b.currency === "NGN");
    if (r.ok && ngn) return Math.floor(Number(ngn.balance) / 100);
  } catch (e) {}
  return null; // couldn't tell: don't block anyone on a lookup failure
}

// Cash in the payment account vs. everything the platform owes users
// (all worker wallets + all business wallet money, incl. money committed to campaigns).
async function getPayoutCover(env) {
  const paystackBalance = await getPayoutBalanceNaira(env);
  const row = await env.DB
    .prepare(
      `SELECT COALESCE((SELECT SUM(availableBalance + pendingBalance) FROM wallets), 0) AS workers,
              COALESCE((SELECT SUM(availableBalance + reservedFunds + campaignFunds) FROM business_wallets), 0) AS businesses`
    )
    .first();
  const owedToUsers = (row?.workers || 0) + (row?.businesses || 0);
  return { paystackBalance, owedToUsers, surplus: paystackBalance === null ? null : paystackBalance - owedToUsers };
}

// Hourly: if the cash no longer covers what's owed, leave a visible alert (once a day).
async function checkPayoutCover(env) {
  try {
    const c = await getPayoutCover(env);
    if (c.surplus === null || c.surplus >= 0) return;
    const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
    const recent = await env.DB.prepare("SELECT id FROM fraud_events WHERE type = 'payout_balance_below_owed' AND createdAt >= ? LIMIT 1").bind(since).first();
    if (!recent) await logMoneyAlert(env.DB, null, "payout_balance_below_owed", c);
  } catch (e) {}
}

// ---- Business balance refund to bank (same one-shot settlement design as withdrawals) ----
async function settleRefundSuccess(db, r) {
  const token = crypto.randomUUID();
  const now = new Date().toISOString();
  const res = await db.batch([
    db.prepare("UPDATE business_refunds SET status = 'completed', processedAt = ?, settleToken = ? WHERE id = ? AND status = 'processing'").bind(now, token, r.id),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         SELECT ?, ?, 'refund_completed', 'Refund sent', ?, ?, 0, ?
         WHERE EXISTS (SELECT 1 FROM business_refunds WHERE id = ? AND settleToken = ?)`
      )
      .bind(crypto.randomUUID(), r.userId, `₦${Number(r.amount).toLocaleString()} was refunded to your bank account.`, r.id, now, r.id, token),
  ]);
  return res[0].meta.changes === 1;
}

async function settleRefundFailed(db, r, reason) {
  const token = crypto.randomUUID();
  const now = new Date().toISOString();
  const res = await db.batch([
    db.prepare("UPDATE business_refunds SET status = 'failed', processedAt = ?, failureReason = ?, settleToken = ? WHERE id = ? AND status = 'processing'").bind(now, String(reason || "failed").slice(0, 300), token, r.id),
    db
      .prepare("UPDATE business_wallets SET availableBalance = availableBalance + ? WHERE uid = ? AND EXISTS (SELECT 1 FROM business_refunds WHERE id = ? AND settleToken = ?)")
      .bind(r.amount, r.userId, r.id, token),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
         SELECT ?, ?, 'business', 'bank_refund_reversed', ?, (SELECT availableBalance FROM business_wallets WHERE uid = ?), ?, ?
         WHERE EXISTS (SELECT 1 FROM business_refunds WHERE id = ? AND settleToken = ?)`
      )
      .bind(crypto.randomUUID(), r.userId, r.amount, r.userId, r.id, now, r.id, token),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         SELECT ?, ?, 'refund_failed', 'Refund failed', ?, ?, 0, ?
         WHERE EXISTS (SELECT 1 FROM business_refunds WHERE id = ? AND settleToken = ?)`
      )
      .bind(crypto.randomUUID(), r.userId, `Your ₦${Number(r.amount).toLocaleString()} refund didn't go through — the amount is back in your wallet.`, r.id, now, r.id, token),
  ]);
  return res[0].meta.changes === 1;
}

// How much of the wallet can be refunded right now: available balance minus
// card top-ups still inside the hold window.
async function getRefundable(db, uid) {
  const since = new Date(Date.now() - BUSINESS_REFUND_LIMITS.holdHours * 3600 * 1000).toISOString();
  const row = await db
    .prepare(
      `SELECT COALESCE((SELECT availableBalance FROM business_wallets WHERE uid = ?), 0) AS available,
              COALESCE((SELECT SUM(amount) FROM deposits WHERE businessId = ? AND status = 'success' AND createdAt >= ?), 0) AS held`
    )
    .bind(uid, uid, since)
    .first();
  const available = row?.available || 0;
  const held = row?.held || 0;
  return { available, held, refundable: Math.max(0, available - held), since };
}

// GET /business/refunds — refundable amount + history
async function getMyBusinessRefunds(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const info = await getRefundable(env.DB, uid);
  const { results } = await env.DB
    .prepare("SELECT id, amount, bankName, accountNumber, status, requestedAt FROM business_refunds WHERE userId = ? ORDER BY requestedAt DESC LIMIT 30")
    .bind(uid)
    .all();
  return json({
    availableBalance: info.available,
    refundable: info.refundable,
    heldBalance: info.held,
    holdHours: BUSINESS_REFUND_LIMITS.holdHours,
    maxRefund: BUSINESS_REFUND_LIMITS.maxSingle,
    dailyRefundLimit: BUSINESS_REFUND_LIMITS.maxPerDay,
    refunds: results || [],
  });
}

// POST /business/refund { amount, bankCode, bankName, accountNumber }
// Same guards as worker withdrawals (server-resolved account name, atomic debit,
// one at a time, limits, confirm-before-refund-on-failure) plus the top-up hold.
async function requestBusinessRefund(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  const L = BUSINESS_REFUND_LIMITS;
  const fail = (message) => json({ success: false, message });

  let body;
  try { body = await request.json(); } catch (e) { return fail("Invalid request."); }
  const { bankCode, bankName } = body || {};
  const accountNumber = String(body?.accountNumber || "").trim();
  const amt = Number(body?.amount);

  const minAmount = await getMinWithdrawal(db);
  if (!Number.isInteger(amt) || amt <= 0) return fail("Enter a valid amount in whole naira.");
  if (amt < minAmount) return fail(`Minimum refund is ₦${minAmount.toLocaleString()}.`);
  if (amt > L.maxSingle) return fail(`Maximum per refund is ₦${L.maxSingle.toLocaleString()}.`);
  if (typeof bankCode !== "string" || !bankCode || !/^\d{10}$/.test(accountNumber)) {
    return fail("Choose a bank and enter a valid 10-digit account number.");
  }

  const user = await db.prepare("SELECT status FROM users WHERE uid = ?").bind(uid).first();
  if (!user || user.status !== "active") return fail("This account can't request refunds right now. Please contact support.");

  const inflight = await db.prepare("SELECT id FROM business_refunds WHERE userId = ? AND status = 'processing' LIMIT 1").bind(uid).first();
  if (inflight) return fail("You already have a refund in progress. Wait for it to finish before starting another.");

  const since24 = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const day = await db
    .prepare("SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN status IN ('processing','completed') THEN amount ELSE 0 END), 0) AS total FROM business_refunds WHERE userId = ? AND requestedAt >= ?")
    .bind(uid, since24)
    .first();
  if ((day?.n || 0) >= L.maxPerDayCount) return fail("You've reached the limit of refund attempts for today. Try again tomorrow.");
  if ((day?.total || 0) + amt > L.maxPerDay) {
    const left = Math.max(0, L.maxPerDay - (day?.total || 0));
    return fail(`Daily refund limit is ₦${L.maxPerDay.toLocaleString()}. You can refund up to ₦${left.toLocaleString()} more in the next 24 hours.`);
  }

  const info = await getRefundable(db, uid);
  if (amt > info.refundable) {
    if (amt > info.available) return fail("Insufficient balance.");
    return fail(`You can refund up to ₦${info.refundable.toLocaleString()} right now. Money added in the last ${L.holdHours} hours can be refunded after ${L.holdHours} hours.`);
  }

  const cash = await getPayoutBalanceNaira(env);
  if (cash !== null && cash < amt) {
    await logMoneyAlert(db, uid, "payout_balance_low", { amt, paystackBalance: cash });
    return fail("Refunds are temporarily unavailable. Your money is safe in your wallet — please try again later.");
  }

  let accountName;
  try {
    const r = await psRequest(
      `/bank/resolve?account_number=${encodeURIComponent(accountNumber)}&bank_code=${encodeURIComponent(bankCode)}`,
      env.PAYSTACK_SECRET_KEY
    );
    accountName = r.body?.data?.account_name;
    if (!r.ok || !accountName) return fail("We couldn't verify this bank account. Check the bank and account number.");
  } catch (e) {
    return fail("We couldn't reach the bank verification service. Please try again in a moment.");
  }

  // Atomic debit: the refund row and the wallet deduction happen together, only if
  // (available - recent top-ups) still covers the amount and nothing else is in flight.
  const refundId = crypto.randomUUID();
  const now = new Date().toISOString();
  const debit = await db.batch([
    db
      .prepare(
        `INSERT INTO business_refunds (id, userId, amount, bankCode, bankName, accountNumber, accountName, status, requestedAt)
         SELECT ?, ?, ?, ?, ?, ?, ?, 'processing', ?
         WHERE (COALESCE((SELECT availableBalance FROM business_wallets WHERE uid = ?), 0)
                - COALESCE((SELECT SUM(amount) FROM deposits WHERE businessId = ? AND status = 'success' AND createdAt >= ?), 0)) >= ?
           AND NOT EXISTS (SELECT 1 FROM business_refunds WHERE userId = ? AND status = 'processing')`
      )
      .bind(refundId, uid, amt, bankCode, bankName || null, accountNumber, accountName, now, uid, uid, info.since, amt, uid),
    db
      .prepare("UPDATE business_wallets SET availableBalance = availableBalance - ? WHERE uid = ? AND availableBalance >= ? AND EXISTS (SELECT 1 FROM business_refunds WHERE id = ?)")
      .bind(amt, uid, amt, refundId),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
         SELECT ?, ?, 'business', 'bank_refund', ?, (SELECT availableBalance FROM business_wallets WHERE uid = ?), ?, ?
         WHERE EXISTS (SELECT 1 FROM business_refunds WHERE id = ?)`
      )
      .bind(crypto.randomUUID(), uid, -amt, uid, refundId, now, refundId),
  ]);
  if (debit[0].meta.changes !== 1) return fail("This refund couldn't be started. Check your refundable balance and that no other refund is in progress.");
  if (debit[1].meta.changes !== 1) {
    await db.prepare("DELETE FROM business_refunds WHERE id = ? AND status = 'processing'").bind(refundId).run();
    await db.prepare("DELETE FROM ledger_transactions WHERE relatedId = ? AND type = 'bank_refund'").bind(refundId).run();
    await logMoneyAlert(db, uid, "refund_debit_mismatch", { refundId, amt });
    return fail("This refund couldn't be started. Please try again.");
  }

  const r = { id: refundId, userId: uid, amount: amt };
  const unavailable = "Refunds are temporarily unavailable. Your money is safe in your wallet — please try again later.";
  try {
    const rec = await psRequest("/transferrecipient", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({ type: "nuban", name: accountName, account_number: accountNumber, bank_code: bankCode, currency: "NGN" }),
    });
    if (!rec.ok) {
      await settleRefundFailed(db, r, "recipient: " + (rec.body?.message || rec.status));
      return fail("We couldn't set up this bank account for payout. Check the details and try again.");
    }
    const tr = await psRequest("/transfer", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({ source: "balance", amount: amt * 100, recipient: rec.body.data.recipient_code, reason: "Qapela balance refund", reference: refundId }),
    });
    if (!tr.ok) {
      await settleRefundFailed(db, r, "transfer: " + (tr.body?.message || tr.status));
      if (/balance/i.test(tr.body?.message || "")) await logMoneyAlert(db, uid, "payout_balance_low", { refundId, amt });
      return fail(unavailable);
    }
    const status = tr.body.data.status;
    await db.prepare("UPDATE business_refunds SET providerRef = ?, paystackStatus = ? WHERE id = ?").bind(tr.body.data.transfer_code, status, refundId).run();
    if (status === "otp") {
      await settleRefundFailed(db, r, "payout provider asked for manual confirmation");
      await logMoneyAlert(db, uid, "payout_otp_required", { refundId, amt });
      return fail(unavailable);
    }
    if (status === "success") {
      await settleRefundSuccess(db, r);
      return json({ success: true, message: "Refund sent. It should reach your bank shortly." });
    }
    if (status === "failed" || status === "reversed") {
      await settleRefundFailed(db, r, "transfer " + status);
      return fail("The transfer couldn't be completed. Your money is back in your wallet.");
    }
    return json({ success: true, message: "Refund is on its way to your bank. We'll notify you once it lands." });
  } catch (err) {
    await logMoneyAlert(db, uid, "refund_unconfirmed", { refundId, amt, error: String(err?.message || err) });
    return json({ success: true, message: "Refund is being processed. We'll notify you as soon as it's confirmed." });
  }
}

// Hourly safety net: settle any withdrawal still 'processing' after a while.
async function reconcileWithdrawals(env) {
  const db = env.DB;
  const cutoff = new Date(Date.now() - WITHDRAWAL_LIMITS.staleMinutes * 60 * 1000).toISOString();
  const { results } = await db
    .prepare("SELECT * FROM withdrawals WHERE status = 'processing' AND requestedAt <= ? LIMIT 50")
    .bind(cutoff)
    .all();
  for (const w of results || []) {
    try {
      const r = await psRequest(`/transfer/verify/${encodeURIComponent(w.id)}`, env.PAYSTACK_SECRET_KEY);
      if (r.ok) {
        const st = r.body?.data?.status;
        if (st === "success") await settleWithdrawalSuccess(db, w);
        else if (st === "failed" || st === "reversed") await settleWithdrawalFailed(db, w, "transfer " + st);
        else if (st === "otp") {
          await settleWithdrawalFailed(db, w, "payout provider asked for manual confirmation");
          await logMoneyAlert(db, w.userId, "payout_otp_required", { withdrawalId: w.id });
        }
        // 'pending' / 'queued' etc: leave it, the webhook will finish it.
      } else if (r.status === 404) {
        // Paystack has no such transfer, so nothing was sent: safe to refund.
        await settleWithdrawalFailed(db, w, "transfer never created");
      }
      // any other answer: stay held and look again next hour.
    } catch (e) { /* network issue: try again next hour */ }
  }

  // Same safety net for business refunds.
  const { results: refunds } = await db
    .prepare("SELECT * FROM business_refunds WHERE status = 'processing' AND requestedAt <= ? LIMIT 50")
    .bind(cutoff)
    .all();
  for (const r of refunds || []) {
    try {
      const v = await psRequest(`/transfer/verify/${encodeURIComponent(r.id)}`, env.PAYSTACK_SECRET_KEY);
      if (v.ok) {
        const st = v.body?.data?.status;
        if (st === "success") await settleRefundSuccess(db, r);
        else if (st === "failed" || st === "reversed") await settleRefundFailed(db, r, "transfer " + st);
        else if (st === "otp") {
          await settleRefundFailed(db, r, "payout provider asked for manual confirmation");
          await logMoneyAlert(db, r.userId, "payout_otp_required", { refundId: r.id });
        }
      } else if (v.status === 404) {
        await settleRefundFailed(db, r, "transfer never created");
      }
    } catch (e) { /* try again next hour */ }
  }

  // Same safety net for revenue withdrawals.
  const { results: revs } = await db
    .prepare("SELECT * FROM revenue_withdrawals WHERE status = 'processing' AND requestedAt <= ? LIMIT 20")
    .bind(cutoff)
    .all();
  for (const rv of revs || []) {
    try {
      const v = await psRequest(`/transfer/verify/${encodeURIComponent(rv.id)}`, env.PAYSTACK_SECRET_KEY);
      if (v.ok) {
        const st = v.body?.data?.status;
        if (st === "success") await settleRevenueSuccess(db, rv);
        else if (st === "failed" || st === "reversed") await settleRevenueFailed(db, rv, "transfer " + st);
        else if (st === "otp") await settleRevenueFailed(db, rv, "payout provider asked for manual confirmation");
      } else if (v.status === 404) {
        await settleRevenueFailed(db, rv, "transfer never created");
      }
    } catch (e) { /* try again next hour */ }
  }

  await checkPayoutCover(env);
}

// ---------------------------------------------------------------------
// 4. Admin reserve withdrawal
// ---------------------------------------------------------------------
async function requestReserveWithdrawal(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const { amount, bankCode, bankName, accountNumber, accountName, reason } = await request.json();
  const amt = Math.floor(Number(amount));
  if (!amt || amt <= 0) return json({ success: false, message: "Enter a valid reserve withdrawal amount." });
  if (!bankCode || !accountNumber || !accountName || !reason?.trim()) {
    return json({ success: false, message: "Amount, bank details and a reason are required." });
  }

  const reserveId = crypto.randomUUID();
  const now = new Date().toISOString();

  const lock = await db
    .prepare("UPDATE platform_treasury SET lockedReserve = lockedReserve - ?, updatedAt = ? WHERE id = 'main' AND lockedReserve >= ?")
    .bind(amt, now, amt)
    .run();

  if (lock.meta.changes === 0) {
    return json({ success: false, message: "Insufficient locked reserve." });
  }

  await db
    .prepare(
      `INSERT INTO reserve_withdrawals (id, amount, bankCode, bankName, accountNumber, accountName, reason, status, requestedBy, requestedAt, provider)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'processing', ?, ?, 'paystack')`
    )
    .bind(reserveId, amt, bankCode, bankName || null, accountNumber, accountName, reason.trim(), uid, now)
    .run();

  await db
    .prepare(
      `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, reason, createdAt)
       VALUES (?, 'platformTreasury', 'platform', 'reserve_withdrawal_hold', ?, ?, ?, ?)`
    )
    .bind(crypto.randomUUID(), -amt, reserveId, reason.trim(), now)
    .run();

  try {
    const recipientRes = await paystackFetch("/transferrecipient", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({ type: "nuban", name: accountName, account_number: accountNumber, bank_code: bankCode, currency: "NGN" }),
    });
    const transferRes = await paystackFetch("/transfer", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({
        source: "balance",
        amount: amt * 100,
        recipient: recipientRes.data.recipient_code,
        reason: "Qapela reserve withdrawal",
        reference: reserveId,
      }),
    });
    await db
      .prepare("UPDATE reserve_withdrawals SET providerRef = ?, paystackStatus = ? WHERE id = ?")
      .bind(transferRes.data.transfer_code, transferRes.data.status, reserveId)
      .run();
    if (transferRes.data.status === "otp") {
      throw new Error("Paystack is asking for an OTP. Turn off 'Confirm transfers before sending' in your Paystack dashboard (Settings > Preferences), then try again.");
    }
    return json({ success: true, status: transferRes.data.status, reference: reserveId });
  } catch (err) {
    const rollbackTime = new Date().toISOString();
    await db
      .prepare("UPDATE platform_treasury SET lockedReserve = lockedReserve + ?, updatedAt = ? WHERE id = 'main'")
      .bind(amt, rollbackTime)
      .run();
    await db
      .prepare("UPDATE reserve_withdrawals SET status = 'failed', processedAt = ?, failureReason = ? WHERE id = ?")
      .bind(rollbackTime, err.message, reserveId)
      .run();
    await db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, createdAt)
         VALUES (?, 'platformTreasury', 'platform', 'reserve_withdrawal_rollback', ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), amt, reserveId, rollbackTime)
      .run();
    return json({ success: false, message: "Could not initiate reserve transfer: " + err.message });
  }
}

// ---------------------------------------------------------------------
// 5. Paystack transfer webhook — same signature check, same "webhook is
//    the real source of truth" logic, now against D1 rows instead of
//    Firestore docs.
// ---------------------------------------------------------------------
async function transferWebhook(request, env) {
  const rawBody = await request.text();
  const signature = request.headers.get("x-paystack-signature");

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(env.PAYSTACK_SECRET_KEY),
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"]
  );
  const sigBuffer = await crypto.subtle.sign("HMAC", key, encoder.encode(rawBody));
  const expected = [...new Uint8Array(sigBuffer)].map((b) => b.toString(16).padStart(2, "0")).join("");

  if (signature !== expected) {
    return new Response("Invalid signature", { status: 401 });
  }

  const event = JSON.parse(rawBody);
  const db = env.DB;

  if (["transfer.success", "transfer.failed", "transfer.reversed"].includes(event.event)) {
    const reference = event.data.reference;
    const now = new Date().toISOString();

    // Check reserve withdrawals first
    const reserveRow = await db.prepare("SELECT * FROM reserve_withdrawals WHERE id = ?").bind(reference).first();
    if (reserveRow) {
      if (reserveRow.status !== "processing") return new Response("OK (already handled)", { status: 200 });

      if (event.event === "transfer.success") {
        await db.prepare("UPDATE reserve_withdrawals SET status = 'completed', processedAt = ? WHERE id = ?").bind(now, reference).run();
      } else {
        await db
          .prepare("UPDATE platform_treasury SET lockedReserve = lockedReserve + ?, updatedAt = ? WHERE id = 'main'")
          .bind(reserveRow.amount, now)
          .run();
        await db
          .prepare("UPDATE reserve_withdrawals SET status = 'failed', processedAt = ?, failureReason = ? WHERE id = ?")
          .bind(now, event.data.failure_reason || event.event, reference)
          .run();
        await db
          .prepare(
            `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, createdAt)
             VALUES (?, 'platformTreasury', 'platform', 'reserve_withdrawal_rollback', ?, ?, ?)`
          )
          .bind(crypto.randomUUID(), reserveRow.amount, reference, now)
          .run();
      }
      return new Response("OK", { status: 200 });
    }

    // Revenue withdrawal?
    const revRow = await db.prepare("SELECT * FROM revenue_withdrawals WHERE id = ?").bind(reference).first();
    if (revRow) {
      if (revRow.status === "processing") {
        if (event.event === "transfer.success") await settleRevenueSuccess(db, revRow);
        else await settleRevenueFailed(db, revRow, event.data.failure_reason || event.event);
      } else if (revRow.status === "failed" && event.event === "transfer.success") {
        await db.prepare("UPDATE revenue_withdrawals SET status = 'needs_review' WHERE id = ? AND status = 'failed'").bind(reference).run();
        await logMoneyAlert(db, revRow.requestedBy, "transfer_success_after_refund", { revenueWithdrawalId: reference, amount: revRow.amount });
      }
      return new Response("OK", { status: 200 });
    }

    // Business balance refund?
    const refundRow = await db.prepare("SELECT * FROM business_refunds WHERE id = ?").bind(reference).first();
    if (refundRow) {
      if (refundRow.status === "processing") {
        if (event.event === "transfer.success") await settleRefundSuccess(db, refundRow);
        else await settleRefundFailed(db, refundRow, event.data.failure_reason || event.event);
      } else if (refundRow.status === "failed" && event.event === "transfer.success") {
        await db.prepare("UPDATE business_refunds SET status = 'needs_review' WHERE id = ? AND status = 'failed'").bind(reference).run();
        await logMoneyAlert(db, refundRow.userId, "transfer_success_after_refund", { refundId: reference, amount: refundRow.amount });
      }
      return new Response("OK", { status: 200 });
    }

    // Otherwise a normal worker withdrawal
    const withdrawalRow = await db.prepare("SELECT * FROM withdrawals WHERE id = ?").bind(reference).first();
    if (!withdrawalRow) return new Response("OK (unknown reference, ignored)", { status: 200 });

    if (withdrawalRow.status === "processing") {
      if (event.event === "transfer.success") await settleWithdrawalSuccess(db, withdrawalRow);
      else await settleWithdrawalFailed(db, withdrawalRow, event.data.failure_reason || event.event);
    } else if (withdrawalRow.status === "failed" && event.event === "transfer.success") {
      // The bank money went out AFTER we had already refunded the user. Never auto-debit;
      // park it for a human to review.
      await db.prepare("UPDATE withdrawals SET status = 'needs_review' WHERE id = ? AND status = 'failed'").bind(reference).run();
      await logMoneyAlert(db, withdrawalRow.userId, "transfer_success_after_refund", { withdrawalId: reference, amount: withdrawalRow.amount });
    }
    // anything else is a repeat delivery of something already settled: ignore.
  }

  return new Response("OK", { status: 200 });
}

  return { listBanks, resolveBankAccount, requestWithdrawal, requestReserveWithdrawal, transferWebhook, reconcileWithdrawals, requestBusinessRefund, getMyBusinessRefunds, getPayoutCover, getAdminRevenue, requestRevenueWithdrawal };
})();


// FROM: finance.js
const finance = (function() {
/**
 * Qapela — Finance Endpoints (Cloudflare Workers + D1)
 * -------------------------------------------------------
 * Ported from functions/finance.js. This is the money-split core of the
 * platform, so the porting rules here matter:
 *
 *   - Firestore db.runTransaction(...) -> env.DB.batch([...]) . D1's
 *     batch() runs every statement in one real SQL transaction: either
 *     all of them commit or none do. That gives us the same all-or-
 *     nothing guarantee Firestore transactions gave us.
 *   - Because batch() can't branch mid-way (no "read a value, then decide
 *     what to write" inside the batch itself), every precondition is
 *     checked with plain SELECTs *before* building the batch, exactly
 *     like the tx.get() calls at the top of each Firestore transaction.
 *     The batch itself then also carries WHERE guards (e.g.
 *     availableBalance >= ?) so a race between two requests still can't
 *     overdraw anything, even though the pre-check already looked safe.
 *   - FieldValue.increment(x) -> "col = col + x" in the UPDATE.
 *   - FieldValue.serverTimestamp() -> new Date().toISOString(), computed
 *     once per request so every row in the batch shares the same time.
 *   - Firestore auto IDs -> crypto.randomUUID().
 *
 * Routes handled here (mounted in worker.js):
 *   POST /campaigns                (createCampaign)
 *   POST /campaigns/:id/cancel     (cancelCampaign)
 *   POST /admin/submissions/:id/approve
 *   POST /admin/submissions/:id/reject
 */


function n(v) {
  const x = Number(v);
  return Number.isFinite(x) ? x : 0;
}
function safeText(v) {
  return typeof v === "string" ? v.slice(0, 5000) : "";
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
async function isAdmin(db, uid) {
  const row = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  return !!row;
}

// ---------------------------------------------------------------------
// createCampaign — business funds a campaign from its wallet
// ---------------------------------------------------------------------
async function createCampaign(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const d = await request.json();
  const taskTypeId = String(d.taskTypeId || "");
  const qty = Math.floor(n(d.quantity));
  const requirements = safeText(d.requirements).trim();
  const platform = d.platform ? safeText(d.platform).trim() : null;

  if (!taskTypeId || qty < 1 || !requirements) {
    return json({ success: false, message: "Task, quantity and requirements are required." });
  }

  const [user, task, wallet] = await Promise.all([
    db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first(),
    db.prepare("SELECT * FROM task_catalogue WHERE id = ?").bind(taskTypeId).first(),
    db.prepare("SELECT * FROM business_wallets WHERE uid = ?").bind(uid).first(),
  ]);

  if (!user || !user.accountActivated || !user.roleBusiness) {
    return json({ success: false, message: "Business access is not activated." });
  }
  if (!task || task.active === 0) {
    return json({ success: false, message: "Task type is unavailable." });
  }

  const minQty = Math.max(1, Math.floor(n(task.minCampaignSize)));
  if (qty < minQty) return json({ success: false, message: `Minimum campaign size is ${minQty}.` });

  const workerReward = Math.floor(n(task.workerReward));
  const businessPrice = Math.floor(n(task.businessPrice));
  if (businessPrice <= 0 || workerReward <= 0 || workerReward !== Math.floor(businessPrice * 0.7)) {
    return json({ success: false, message: "This task pricing is not configured for the 70/15/5/10 split." });
  }

  const total = qty * businessPrice;
  const available = n(wallet?.availableBalance);
  if (available < total) {
    return json({ success: false, message: `Insufficient wallet balance. You need ₦${total.toLocaleString()}.` });
  }

  const campaignId = crypto.randomUUID();
  const now = new Date().toISOString();
  const title = task.name + (platform ? ` — ${platform}` : "");

  const statements = [
    db
      .prepare(
        "UPDATE business_wallets SET availableBalance = availableBalance - ?, reservedFunds = reservedFunds + ? WHERE uid = ? AND availableBalance >= ?"
      )
      .bind(total, total, uid, total),
    db
      .prepare(
        `INSERT INTO campaigns (id, businessId, taskTypeId, title, requirements, targetAudience, platform, category, quantityTarget, quantityCompleted, quantityRejected, workerRewardSnapshot, businessPriceSnapshot, totalDeposit, remainingBudget, status, createdAt, launchedAt)
         VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, 0, 0, ?, ?, ?, ?, 'active', ?, ?)`
      )
      .bind(campaignId, uid, taskTypeId, title, requirements, platform, task.category, qty, workerReward, businessPrice, total, total, now, now),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
         VALUES (?, ?, 'business', 'campaign_funding', ?, ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), uid, -total, available - total, campaignId, now),
  ];

  const results = await db.batch(statements);
  if (results[0].meta.changes === 0) {
    return json({ success: false, message: "Insufficient wallet balance (balance changed, please retry)." });
  }

  return json({ success: true, campaignId, total });
}

// ---------------------------------------------------------------------
// cancelCampaign — refund remaining budget back to available balance
// ---------------------------------------------------------------------
async function cancelCampaign(request, env, campaignId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  if (!campaignId) return json({ success: false, message: "campaignId is required." });

  const camp = await db.prepare("SELECT * FROM campaigns WHERE id = ?").bind(campaignId).first();
  if (!camp) return json({ success: false, message: "Campaign not found." });
  if (camp.businessId !== uid) return json({ success: false, message: "Not your campaign." });
  if (camp.status !== "active") return json({ success: false, message: "Only active campaigns can be cancelled." });

  const refund = Math.max(0, n(camp.remainingBudget));
  const wallet = await db.prepare("SELECT * FROM business_wallets WHERE uid = ?").bind(uid).first();
  if (!wallet) return json({ success: false, message: "Business wallet not found." });
  if (n(wallet.reservedFunds) < refund) {
    return json({ success: false, message: "Reserved funds are inconsistent; cancellation blocked." });
  }

  const now = new Date().toISOString();
  const statements = [
    db
      .prepare("UPDATE campaigns SET status = 'cancelled', completedAt = ? WHERE id = ? AND status = 'active'")
      .bind(now, campaignId),
  ];

  if (refund > 0) {
    statements.push(
      db
        .prepare(
          "UPDATE business_wallets SET availableBalance = availableBalance + ?, reservedFunds = reservedFunds - ? WHERE uid = ? AND reservedFunds >= ?"
        )
        .bind(refund, refund, uid, refund),
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
           VALUES (?, ?, 'business', 'refund', ?, ?, ?, ?)`
        )
        .bind(crypto.randomUUID(), uid, refund, n(wallet.availableBalance) + refund, campaignId, now)
    );
  }

  statements.push(
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         VALUES (?, ?, 'campaign_cancelled', 'Campaign cancelled', ?, ?, 0, ?)`
      )
      .bind(
        crypto.randomUUID(),
        uid,
        `Your campaign was cancelled. ₦${refund.toLocaleString()} was returned to your available wallet.`,
        campaignId,
        now
      )
  );

  const results = await db.batch(statements);
  if (results[0].meta.changes === 0) {
    return json({ success: false, message: "Campaign state changed, please retry." });
  }

  return json({ success: true, refund });
}

// ---------------------------------------------------------------------
// reviewSubmission — the 70/15/5/10 split payout on approval, or a
// rejection that updates the worker's track record.
// ---------------------------------------------------------------------
async function reviewSubmission(request, env, submissionId, approve) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);
  if (!submissionId) return json({ success: false, message: "submissionId is required." });

  const sub = await db.prepare("SELECT * FROM submissions WHERE id = ?").bind(submissionId).first();
  if (!sub) return json({ success: false, message: "Submission not found." });
  if (!["pending", "needs_review"].includes(sub.status)) {
    return json({ success: false, message: "Submission has already been reviewed." });
  }

  const now = new Date().toISOString();

  // ---- Rejection path ----
  if (!approve) {
    const prof = await db.prepare("SELECT * FROM worker_profiles WHERE uid = ?").bind(sub.workerId).first();
    const rejected = n(prof?.tasksRejected) + 1;
    const completed = n(prof?.tasksCompleted);
    const rate = completed + rejected ? Math.round((completed / (completed + rejected)) * 100) : 100;

    const statements = [
      db
        .prepare("UPDATE submissions SET status = 'rejected', verificationMode = 'human', verifiedAt = ?, rewardPaid = 0 WHERE id = ? AND status IN ('pending','needs_review')")
        .bind(now, submissionId),
      db
        .prepare(
          `INSERT INTO worker_profiles (uid, tasksRejected, successRatePct) VALUES (?, ?, ?)
           ON CONFLICT(uid) DO UPDATE SET tasksRejected = ?, successRatePct = ?`
        )
        .bind(sub.workerId, rejected, rate, rejected, rate),
      db
        .prepare(
          `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
           VALUES (?, ?, 'submission_rejected', 'Task rejected', 'Your task submission was rejected. You may raise a dispute if you believe this was a mistake.', ?, 0, ?)`
        )
        .bind(crypto.randomUUID(), sub.workerId, submissionId, now),
    ];

    const results = await db.batch(statements);
    if (results[0].meta.changes === 0) return json({ success: false, message: "Submission state changed, please retry." });
    return json({ success: true, status: "rejected" });
  }

  // ---- Approval path ----
  const [task, camp] = await Promise.all([
    db.prepare("SELECT * FROM task_catalogue WHERE id = ?").bind(sub.taskTypeId).first(),
    db.prepare("SELECT * FROM campaigns WHERE id = ?").bind(sub.campaignId).first(),
  ]);
  if (!task || !camp) return json({ success: false, message: "Task or campaign is missing." });
  if (camp.status !== "active") return json({ success: false, message: "Campaign is no longer active." });

  const workerReward = Math.floor(n(sub.workerRewardSnapshot ?? task.workerReward));
  const businessPrice = Math.floor(n(sub.businessPriceSnapshot ?? camp.businessPriceSnapshot ?? task.businessPrice));
  if (workerReward <= 0 || businessPrice <= 0 || workerReward !== Math.floor(businessPrice * 0.7)) {
    return json({ success: false, message: "Invalid 70/15/5/10 campaign pricing." });
  }
  if (n(camp.remainingBudget) < businessPrice) {
    return json({ success: false, message: "Campaign has insufficient remaining funds." });
  }

  const [workerWallet, bizWallet, treasury] = await Promise.all([
    db.prepare("SELECT * FROM wallets WHERE uid = ?").bind(sub.workerId).first(),
    db.prepare("SELECT * FROM business_wallets WHERE uid = ?").bind(camp.businessId).first(),
    db.prepare("SELECT * FROM platform_treasury WHERE id = 'main'").first(),
  ]);
  if (!bizWallet || n(bizWallet.reservedFunds) < businessPrice) {
    return json({ success: false, message: "Business reserved funds are inconsistent; payout blocked." });
  }

  const referrerId = sub.referrerId || null;
  const referralAmount = referrerId ? Math.floor(businessPrice * 0.1) : 0;
  const reserveAmount = Math.floor(businessPrice * 0.05);
  const platformAmount = businessPrice - workerReward - referralAmount - reserveAmount;

  const completed = n(camp.quantityCompleted) + 1;
  const rejected = n(camp.quantityRejected);
  const target = n(camp.quantityTarget);
  const exhausted = completed + rejected >= target;
  const remaining = n(camp.remainingBudget) - businessPrice;

  const wAvail = n(workerWallet?.availableBalance);
  const bwAvail = n(bizWallet.availableBalance);

  const statements = [
    db
      .prepare(
        "UPDATE submissions SET status = 'approved', verificationMode = 'human', verifiedAt = ?, rewardPaid = 1 WHERE id = ? AND status IN ('pending','needs_review')"
      )
      .bind(now, submissionId),
    db
      .prepare(
        `INSERT INTO wallets (uid, availableBalance, totalEarned, todayEarnings, breakdownTaskEarnings) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(uid) DO UPDATE SET availableBalance = availableBalance + ?, totalEarned = totalEarned + ?, todayEarnings = todayEarnings + ?, breakdownTaskEarnings = breakdownTaskEarnings + ?`
      )
      .bind(sub.workerId, workerReward, workerReward, workerReward, workerReward, workerReward, workerReward, workerReward, workerReward),
    db
      .prepare(
        `INSERT INTO worker_profiles (uid, tasksCompleted) VALUES (?, 1)
         ON CONFLICT(uid) DO UPDATE SET tasksCompleted = tasksCompleted + 1`
      )
      .bind(sub.workerId),
    db
      .prepare(
        `UPDATE campaigns SET quantityCompleted = quantityCompleted + 1, remainingBudget = remainingBudget - ?, status = ?, completedAt = ? WHERE id = ? AND remainingBudget >= ?`
      )
      .bind(businessPrice, exhausted ? "completed" : camp.status, exhausted ? now : camp.completedAt, sub.campaignId, businessPrice),
    db
      .prepare(
        `UPDATE business_wallets SET reservedFunds = reservedFunds - ?${exhausted && remaining > 0 ? ", availableBalance = availableBalance + ?" : ""} WHERE uid = ? AND reservedFunds >= ?`
      )
      .bind(...(exhausted && remaining > 0 ? [businessPrice, remaining, camp.businessId, businessPrice] : [businessPrice, camp.businessId, businessPrice])),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, verificationMode, createdAt)
         VALUES (?, ?, 'worker', 'task_reward', ?, ?, ?, 'human', ?)`
      )
      .bind(crypto.randomUUID(), sub.workerId, workerReward, wAvail + workerReward, submissionId, now),
    db
      .prepare(
        `INSERT INTO platform_revenue (id, type, amount, grossAmount, workerAmount, referralAmount, reserveAmount, netPlatformRevenue, unassignedReferralAmount, businessId, workerId, campaignId, submissionId, verificationMode, createdAt)
         VALUES (?, 'campaign_service_revenue', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'human', ?)`
      )
      .bind(
        crypto.randomUUID(),
        platformAmount,
        businessPrice,
        workerReward,
        referralAmount,
        reserveAmount,
        platformAmount,
        referrerId ? 0 : Math.floor(businessPrice * 0.1),
        camp.businessId,
        sub.workerId,
        sub.campaignId,
        submissionId,
        now
      ),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         VALUES (?, ?, 'submission_approved', 'Task approved', ?, ?, 0, ?)`
      )
      .bind(crypto.randomUUID(), sub.workerId, `Your submission was approved — ₦${workerReward.toLocaleString()} added to your wallet.`, submissionId, now),
  ];

  if (reserveAmount) {
    statements.push(
      db
        .prepare(
          `INSERT INTO platform_treasury (id, lockedReserve, updatedAt) VALUES ('main', ?, ?)
           ON CONFLICT(id) DO UPDATE SET lockedReserve = lockedReserve + ?, updatedAt = ?`
        )
        .bind(reserveAmount, now, reserveAmount, now),
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, createdAt)
           VALUES (?, 'platformTreasury', 'platform', 'reserve_allocation', ?, ?, ?)`
        )
        .bind(crypto.randomUUID(), reserveAmount, submissionId, now)
    );
  }

  if (referrerId) {
    const refWallet = await db.prepare("SELECT * FROM wallets WHERE uid = ?").bind(referrerId).first();
    const pending = n(refWallet?.pendingBalance);
    statements.push(
      db
        .prepare(
          `INSERT INTO wallets (uid, pendingBalance) VALUES (?, ?)
           ON CONFLICT(uid) DO UPDATE SET pendingBalance = ?`
        )
        .bind(referrerId, pending + referralAmount, pending + referralAmount),
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
           VALUES (?, ?, 'worker', 'referral_commission_pending', ?, ?, ?, ?)`
        )
        .bind(crypto.randomUUID(), referrerId, referralAmount, pending + referralAmount, submissionId, now),
      db
        .prepare(
          `UPDATE referrals SET commissionAmount = COALESCE(commissionAmount, 0) + ?, status = 'active' WHERE referrerId = ? AND referredId = ?`
        )
        .bind(referralAmount, referrerId, sub.workerId)
    );
  }

  if (exhausted && remaining > 0) {
    statements.push(
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, reason, createdAt)
           VALUES (?, ?, 'business', 'refund', ?, ?, ?, 'unused_campaign_budget', ?)`
        )
        .bind(crypto.randomUUID(), camp.businessId, remaining, bwAvail + remaining, sub.campaignId, now)
    );
  }

  const results = await db.batch(statements);
  if (results[0].meta.changes === 0) {
    return json({ success: false, message: "Submission state changed, please retry." });
  }
  if (results[3].meta.changes === 0) {
    return json({ success: false, message: "Campaign budget changed concurrently — payout aborted, please retry the review." });
  }

  return json({ success: true, status: "approved", reward: workerReward, referralAmount, reserveAmount, platformAmount });
}

  return { createCampaign, cancelCampaign, reviewSubmission };
})();


// FROM: activation.js
const activation = (function() {
/**
 * Qapela — Activation Endpoint (Cloudflare Workers + D1)
 * -----------------------------------------------------------
 * Ported from functions/activation.js. Same security-critical rule as
 * the original: never trust amount/status from the client. This
 * endpoint re-verifies the transaction directly with Paystack using the
 * secret key before writing anything.
 *
 * Route (mounted in worker.js):
 *   POST /activations/verify   { reference }
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
const DEFAULT_REGISTRATION_FEE = 5000; // NGN

async function getRegistrationFee(db) {
  const row = await db.prepare("SELECT registrationFee FROM platform_settings WHERE id = 'config'").first();
  return row?.registrationFee ?? DEFAULT_REGISTRATION_FEE;
}

async function verifyActivationPayment(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "You must be signed in." }, 401);
  const db = env.DB;

  const { reference } = await request.json();
  if (!reference || typeof reference !== "string") {
    return json({ success: false, message: "Missing payment reference." }, 400);
  }

  // Idempotency: same as the Firestore version — if we've already
  // processed this reference, don't do it again.
  const existing = await db.prepare("SELECT id FROM activations WHERE id = ?").bind(reference).first();
  if (existing) return json({ success: true, alreadyProcessed: true });

  const user = await db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first();
  if (!user) return json({ success: false, message: "User record not found." }, 404);
  if (user.accountActivated) return json({ success: true, alreadyProcessed: true });

  const expectedAmountNaira = await getRegistrationFee(db);
  const expectedAmountKobo = expectedAmountNaira * 100;

  // ---- The real check: ask Paystack directly, don't trust the client ----
  const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}` },
  });
  const verifyJson = await verifyRes.json();

  if (!verifyRes.ok || !verifyJson.status) {
    return json({ success: false, message: "We could not verify the payment right now. Please try again in a moment." }, 502);
  }
  const txn = verifyJson.data;
  if (txn.status !== "success") {
    return json({ success: false, message: `Payment was not successful (status: ${txn.status}).` });
  }
  if (txn.currency !== "NGN") {
    return json({ success: false, message: "Unexpected currency on transaction." });
  }
  if (txn.amount !== expectedAmountKobo) {
    return json({
      success: false,
      message: `Amount mismatch: expected ₦${expectedAmountNaira}, the payment was ₦${txn.amount / 100}.`,
    });
  }
  if (txn.metadata?.userId !== uid) {
    return json({ message: "This payment reference belongs to a different account." }, 403);
  }

  // ---- Verified. Now write the actual state changes, atomically. ----
  const now = new Date().toISOString();
  const statements = [
    db
      .prepare(
        `INSERT INTO activations (id, userId, role, amount, provider, providerRef, status, createdAt)
         VALUES (?, ?, 'account', ?, 'paystack', ?, 'success', ?)`
      )
      .bind(reference, uid, expectedAmountNaira, reference, now),
    db
      .prepare(
        `UPDATE users SET accountActivated = 1, accountActivatedAt = ?, workerActivated = 1, workerActivatedAt = ?, businessActivated = 1, businessActivatedAt = ? WHERE uid = ? AND accountActivated = 0`
      )
      .bind(now, now, now, uid),
    db
      .prepare(
        `INSERT INTO platform_revenue (id, type, amount, userId, relatedId, createdAt)
         VALUES (?, 'registration_fee', ?, ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), expectedAmountNaira, uid, reference, now),
    db
      .prepare(
        `INSERT INTO worker_profiles (uid, level, tasksCompleted, tasksRejected, successRatePct, accuracyPct, reputationScore, kycStatus)
         VALUES (?, 1, 0, 0, 100, 100, 0, 'none')
         ON CONFLICT(uid) DO NOTHING`
      )
      .bind(uid),
    db
      .prepare(
        `INSERT INTO business_wallets (uid, availableBalance, reservedFunds, campaignFunds) VALUES (?, 0, 0, 0)
         ON CONFLICT(uid) DO NOTHING`
      )
      .bind(uid),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         VALUES (?, ?, 'activation_success', 'Account activated', ?, ?, 0, ?)`
      )
      .bind(
        crypto.randomUUID(),
        uid,
        `Your ₦${expectedAmountNaira.toLocaleString()} one-time activation was verified. Worker and Business modes are now unlocked.`,
        reference,
        now
      ),
  ];

  const results = await db.batch(statements);
  // If the user row didn't actually flip (e.g. a concurrent request already
  // activated the account between our check and now), treat as already done
  // rather than erroring — same spirit as the Firestore idempotency check.
  if (results[1].meta.changes === 0) {
    return json({ success: true, alreadyProcessed: true });
  }

  return json({ success: true });
}

  return { verifyActivationPayment };
})();


// FROM: task.js
const task = (function() {
/**
 * Qapela — Task Submission + Auto-Verification (Cloudflare Workers + D1)
 * ---------------------------------------------------------------------------
 * Ported from functions/task.js — with one real architectural change:
 *
 *   Firestore had onDocumentCreated('submissions/{id}') fire automatically
 *   the instant a worker wrote a submission doc. Cloudflare has no
 *   equivalent — there's no "run this when a row appears" hook for D1.
 *   So the client now calls ONE endpoint, POST /submissions, which both
 *   creates the submission AND runs the exact same verification logic
 *   the trigger used to run, in the same request. From the client's
 *   point of view the behavior is identical (submit -> get back
 *   approved/needs_review); it just happens synchronously now instead
 *   of via a background trigger.
 *
 * Two bugs in the original source were NOT carried over:
 *   1. approveAtomically() referenced `tx` without ever receiving it as
 *      a parameter — would have thrown at runtime.
 *   2. `qapelaGross` was used but never defined (should have been
 *      businessPrice). This port uses businessPrice, matching the
 *      70/15/5/10 split used everywhere else (see finance.js).
 *
 * Route (mounted in worker.js):
 *   POST /submissions   { campaignId, taskTypeId, proofData, verificationResult? }
 */


function n(v) {
  const x = Number(v);
  return Number.isFinite(x) ? x : 0;
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
function levelFor(completed) {
  if (completed >= 100) return { level: 5, progressPct: 100 };
  if (completed >= 50) return { level: 4, progressPct: Math.round(((completed - 50) / 50) * 100) };
  if (completed >= 20) return { level: 3, progressPct: Math.round(((completed - 20) / 30) * 100) };
  if (completed >= 5) return { level: 2, progressPct: Math.round(((completed - 5) / 15) * 100) };
  return { level: 1, progressPct: Math.round((completed / 5) * 100) };
}

async function createSubmission(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const d = await request.json();
  const campaignId = String(d.campaignId || "");
  const taskTypeId = String(d.taskTypeId || "");
  const proofData = d.proofData ?? null;
  const verificationResult = d.verificationResult ?? null; // only meaningful if it came from a trusted server-side adapter

  if (!campaignId || !taskTypeId) {
    return json({ success: false, message: "campaignId and taskTypeId are required." });
  }

  const [task, campaign, workerUser] = await Promise.all([
    db.prepare("SELECT * FROM task_catalogue WHERE id = ?").bind(taskTypeId).first(),
    db.prepare("SELECT * FROM campaigns WHERE id = ?").bind(campaignId).first(),
    db.prepare("SELECT referredBy FROM users WHERE uid = ?").bind(uid).first(),
  ]);
  // Whoever referred this worker (if anyone) earns a commission when this
  // submission is approved — see finance.js's reviewSubmission. Resolved
  // here at submission time, not left null: a submission's referrerId
  // being unpopulated silently meant referral commissions could never
  // actually fire, regardless of approval path.
  const referrerIdForSubmission = workerUser?.referredBy || null;

  const submissionId = `${campaignId}_${uid}`;
  const now = new Date().toISOString();

  if (!task || !campaign) {
    await db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, verificationMode, verificationReason, verificationCheckedAt, referrerId, createdAt)
         VALUES (?, ?, ?, ?, 'rejected', ?, 'automatic', 'Missing task or campaign.', ?, ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
      .bind(submissionId, uid, campaignId, taskTypeId, JSON.stringify(proofData), now, referrerIdForSubmission, now)
      .run();
    return json({ success: false, status: "rejected", message: "Missing task or campaign." });
  }

  // Deterministic precondition checks — same list as the original trigger.
  const reasons = [];
  if (campaign.status !== "active") reasons.push("campaign_not_active");
  if (campaign.businessId == null) reasons.push("campaign_owner_missing");
  const businessPriceSnapshot = n(campaign.businessPriceSnapshot ?? task.businessPrice);
  if (n(campaign.remainingBudget) < businessPriceSnapshot) reasons.push("insufficient_campaign_funding");
  if (proofData == null) reasons.push("missing_proof");

  const workerRewardSnapshot = n(task.workerReward);

  if (reasons.length) {
    await db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, workerRewardSnapshot, businessPriceSnapshot, verificationMode, verificationReason, verificationCheckedAt, referrerId, createdAt)
         VALUES (?, ?, ?, ?, 'needs_review', ?, ?, ?, 'automatic', ?, ?, ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
      .bind(
        submissionId,
        uid,
        campaignId,
        taskTypeId,
        JSON.stringify(proofData),
        workerRewardSnapshot,
        businessPriceSnapshot,
        reasons.join(", "),
        now,
        referrerIdForSubmission,
        now
      )
      .run();
    return json({ success: true, status: "needs_review", reason: reasons.join(", ") });
  }

  const method = String(task.verificationMethod || "screenshot").toLowerCase();

  // proofData.proofFileId points at a row this worker actually uploaded via
  // POST /task-proofs (see storage.js). We verify it's real and theirs, then
  // tag it with this submission so admin review can pull it up later.
  let hasScreenshot = false;
  if (proofData?.type === "screenshot" && proofData.proofFileId) {
    const proofRow = await db
      .prepare("SELECT id FROM task_proof_files WHERE id = ? AND workerId = ?")
      .bind(proofData.proofFileId, uid)
      .first();
    if (proofRow) {
      hasScreenshot = true;
      await db.prepare("UPDATE task_proof_files SET submissionId = ? WHERE id = ?").bind(submissionId, proofData.proofFileId).run();
    }
  }
  const hasForm = proofData?.type === "form_response" && typeof proofData.text === "string" && proofData.text.trim().length >= 3;
  const trustedAdapterPassed = verificationResult?.trusted === true && verificationResult?.passed === true;

  const formAuto = method.includes("form submission") && task.aiVerifiable === "yes" && hasForm;
  const trustedAuto = method.includes("automated check") && trustedAdapterPassed;

  if (!formAuto && !trustedAuto) {
    // Screenshot / ambiguous tasks always go to human review — same rule
    // as the original: a file existing is not proof the action happened.
    await db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, workerRewardSnapshot, businessPriceSnapshot, verificationMode, verificationReason, verificationCheckedAt, referrerId, createdAt)
         VALUES (?, ?, ?, ?, 'needs_review', ?, ?, ?, 'automatic', ?, ?, ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
      .bind(
        submissionId,
        uid,
        campaignId,
        taskTypeId,
        JSON.stringify(proofData),
        workerRewardSnapshot,
        businessPriceSnapshot,
        hasScreenshot ? "Screenshot requires semantic verification or human review." : "Task evidence requires human review.",
        now,
        referrerIdForSubmission,
        now
      )
      .run();
    return json({ success: true, status: "needs_review" });
  }

  // ---- Auto-approve path: same 70/15/5/10 split as human review ----
  if (businessPriceSnapshot <= 0 || workerRewardSnapshot <= 0 || workerRewardSnapshot !== Math.floor(businessPriceSnapshot * 0.7)) {
    await db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, workerRewardSnapshot, businessPriceSnapshot, verificationMode, verificationReason, verificationCheckedAt, referrerId, createdAt)
         VALUES (?, ?, ?, ?, 'needs_review', ?, ?, ?, 'automatic', 'Invalid 70/15/5/10 campaign pricing.', ?, ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
      .bind(submissionId, uid, campaignId, taskTypeId, JSON.stringify(proofData), workerRewardSnapshot, businessPriceSnapshot, now, referrerIdForSubmission, now)
      .run();
    return json({ success: true, status: "needs_review", reason: "invalid_pricing" });
  }

  const [workerWallet, workerProfile, bizWallet] = await Promise.all([
    db.prepare("SELECT * FROM wallets WHERE uid = ?").bind(uid).first(),
    db.prepare("SELECT * FROM worker_profiles WHERE uid = ?").bind(uid).first(),
    db.prepare("SELECT * FROM business_wallets WHERE uid = ?").bind(campaign.businessId).first(),
  ]);

  if (!bizWallet || n(bizWallet.reservedFunds) < businessPriceSnapshot) {
    await db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, workerRewardSnapshot, businessPriceSnapshot, verificationMode, verificationReason, verificationCheckedAt, referrerId, createdAt)
         VALUES (?, ?, ?, ?, 'needs_review', ?, ?, ?, 'automatic', 'Business reserved funds inconsistent.', ?, ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
      .bind(submissionId, uid, campaignId, taskTypeId, JSON.stringify(proofData), workerRewardSnapshot, businessPriceSnapshot, now, referrerIdForSubmission, now)
      .run();
    return json({ success: true, status: "needs_review", reason: "insufficient_reserved_funds" });
  }

  const referrerId = referrerIdForSubmission;
  const referralAmount = referrerId ? Math.floor(businessPriceSnapshot * 0.1) : 0;
  const reserveAmount = Math.floor(businessPriceSnapshot * 0.05);
  const netPlatformRevenue = businessPriceSnapshot - workerRewardSnapshot - referralAmount - reserveAmount;

  const completed = n(workerProfile?.tasksCompleted) + 1;
  const rejected = n(workerProfile?.tasksRejected);
  const level = levelFor(completed);
  const successRatePct = completed + rejected ? Math.round((completed / (completed + rejected)) * 100) : 100;

  const newCompleted = n(campaign.quantityCompleted) + 1;
  const newRemaining = n(campaign.remainingBudget) - businessPriceSnapshot;
  const exhausted = newCompleted + n(campaign.quantityRejected) >= n(campaign.quantityTarget);

  const wAvail = n(workerWallet?.availableBalance);
  const bwAvail = n(bizWallet.availableBalance);
  const verificationMeta = JSON.stringify({ reason: formAuto ? "deterministic_form_validation" : "trusted_automated_adapter" });

  const statements = [
    db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, verificationResult, verificationMode, verificationMeta, verifiedAt, rewardPaid, workerRewardSnapshot, businessPriceSnapshot, referrerId, createdAt)
         VALUES (?, ?, ?, ?, 'approved', ?, ?, 'automatic', ?, ?, 1, ?, ?, ?, ?)`
      )
      .bind(
        submissionId,
        uid,
        campaignId,
        taskTypeId,
        JSON.stringify(proofData),
        JSON.stringify(verificationResult),
        verificationMeta,
        now,
        workerRewardSnapshot,
        businessPriceSnapshot,
        referrerId,
        now
      ),
    db
      .prepare(
        `INSERT INTO wallets (uid, availableBalance, totalEarned, todayEarnings, breakdownTaskEarnings) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(uid) DO UPDATE SET availableBalance = availableBalance + ?, totalEarned = totalEarned + ?, todayEarnings = todayEarnings + ?, breakdownTaskEarnings = breakdownTaskEarnings + ?`
      )
      .bind(
        uid,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot
      ),
    db
      .prepare(
        `INSERT INTO worker_profiles (uid, level, levelProgressPct, tasksCompleted, successRatePct, tasksRejected, accuracyPct, reputationScore, kycStatus)
         VALUES (?, ?, ?, 1, ?, 0, 100, 0, 'none')
         ON CONFLICT(uid) DO UPDATE SET level = ?, levelProgressPct = ?, tasksCompleted = tasksCompleted + 1, successRatePct = ?`
      )
      .bind(uid, level.level, level.progressPct, successRatePct, level.level, level.progressPct, successRatePct),
    db
      .prepare(
        `UPDATE campaigns SET quantityCompleted = quantityCompleted + 1, remainingBudget = remainingBudget - ?, status = ?, completedAt = ? WHERE id = ? AND remainingBudget >= ?`
      )
      .bind(businessPriceSnapshot, exhausted ? "completed" : campaign.status, exhausted ? now : campaign.completedAt, campaignId, businessPriceSnapshot),
    db
      .prepare(
        `UPDATE business_wallets SET reservedFunds = reservedFunds - ?${exhausted && newRemaining > 0 ? ", availableBalance = availableBalance + ?" : ""} WHERE uid = ? AND reservedFunds >= ?`
      )
      .bind(...(exhausted && newRemaining > 0 ? [businessPriceSnapshot, newRemaining, campaign.businessId, businessPriceSnapshot] : [businessPriceSnapshot, campaign.businessId, businessPriceSnapshot])),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, verificationMode, createdAt)
         VALUES (?, ?, 'worker', 'task_reward', ?, ?, ?, 'automatic', ?)`
      )
      .bind(crypto.randomUUID(), uid, workerRewardSnapshot, wAvail + workerRewardSnapshot, submissionId, now),
    db
      .prepare(
        `INSERT INTO platform_revenue (id, type, amount, grossAmount, workerAmount, referralAmount, reserveAmount, netPlatformRevenue, businessId, workerId, campaignId, submissionId, verificationMode, createdAt)
         VALUES (?, 'campaign_service_revenue', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'automatic', ?)`
      )
      .bind(
        crypto.randomUUID(),
        netPlatformRevenue,
        businessPriceSnapshot,
        workerRewardSnapshot,
        referralAmount,
        reserveAmount,
        netPlatformRevenue,
        campaign.businessId,
        uid,
        campaignId,
        submissionId,
        now
      ),
  ];

  if (referrerId) {
    const refWallet = await db.prepare("SELECT * FROM wallets WHERE uid = ?").bind(referrerId).first();
    const pending = n(refWallet?.pendingBalance);
    statements.push(
      db
        .prepare(
          `INSERT INTO wallets (uid, pendingBalance) VALUES (?, ?)
           ON CONFLICT(uid) DO UPDATE SET pendingBalance = ?`
        )
        .bind(referrerId, pending + referralAmount, pending + referralAmount),
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, verificationMode, createdAt)
           VALUES (?, ?, 'worker', 'referral_commission_pending', ?, ?, ?, 'automatic', ?)`
        )
        .bind(crypto.randomUUID(), referrerId, referralAmount, pending + referralAmount, submissionId, now),
      // Keeps the referrals table (used by the referrals page) in sync
      // with commissions actually earned — this used to never update at
      // all, since referrerId itself was never populated on submissions.
      db
        .prepare(
          `UPDATE referrals SET commissionAmount = COALESCE(commissionAmount, 0) + ?, status = 'active' WHERE referrerId = ? AND referredId = ?`
        )
        .bind(referralAmount, referrerId, uid)
    );
  }

  if (reserveAmount > 0) {
    statements.push(
      db
        .prepare(
          `INSERT INTO platform_treasury (id, lockedReserve, updatedAt) VALUES ('main', ?, ?)
           ON CONFLICT(id) DO UPDATE SET lockedReserve = lockedReserve + ?, updatedAt = ?`
        )
        .bind(reserveAmount, now, reserveAmount, now),
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, verificationMode, createdAt)
           VALUES (?, 'platformTreasury', 'platform', 'reserve_allocation', ?, ?, 'automatic', ?)`
        )
        .bind(crypto.randomUUID(), reserveAmount, submissionId, now)
    );
  }

  if (exhausted && newRemaining > 0) {
    statements.push(
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, reason, createdAt)
           VALUES (?, ?, 'business', 'refund', ?, ?, ?, 'unused_campaign_budget', ?)`
        )
        .bind(crypto.randomUUID(), campaign.businessId, newRemaining, bwAvail + newRemaining, campaignId, now)
    );
  }

  const results = await db.batch(statements);
  if (results[3].meta.changes === 0) {
    // Campaign budget moved between our check and now — fail safe to
    // needs_review rather than risk a bad payout. (The submission insert
    // above already committed as 'approved' inside the batch, so undo it.)
    await db
      .prepare(
        "UPDATE submissions SET status = 'needs_review', verificationReason = 'Campaign budget changed concurrently.' WHERE id = ?"
      )
      .bind(submissionId)
      .run();
    return json({ success: true, status: "needs_review", reason: "concurrent_budget_change" });
  }

  return json({ success: true, status: "approved", reward: workerRewardSnapshot });
}

  return { createSubmission };
})();


// FROM: topup.js
const topup = (function() {
/**
 * Qapela — Business Wallet Top-Up (Cloudflare Workers + D1)
 * ---------------------------------------------------------------
 * Ported from functions/topup.js. Same Paystack-verify-then-credit
 * pattern as activation.js, just against business_wallets instead of
 * the user's activation flag.
 *
 * Route (mounted in worker.js):
 *   POST /wallet/topup   { reference }
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
const MIN_TOPUP = 500; // NGN

async function topUpBusinessWallet(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "You must be signed in." }, 401);
  const db = env.DB;

  const { reference } = await request.json();
  if (!reference || typeof reference !== "string") {
    return json({ success: false, message: "Missing payment reference." }, 400);
  }

  const existing = await db.prepare("SELECT id FROM deposits WHERE id = ?").bind(reference).first();
  if (existing) return json({ success: true, alreadyProcessed: true });

  const user = await db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first();
  if (!user) return json({ success: false, message: "User record not found." }, 404);
  if (!user.roleBusiness) {
    return json({ message: "Only accounts with business access set up can top up a campaign wallet." }, 403);
  }
  if (!user.accountActivated) {
    return json({ success: false, message: "Activate your business account before adding funds." });
  }

  const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}` },
  });
  const verifyJson = await verifyRes.json();
  if (!verifyRes.ok || !verifyJson.status) {
    return json({ success: false, message: "We could not verify the payment right now. Please try again in a moment." }, 502);
  }
  const txn = verifyJson.data;
  if (txn.status !== "success") return json({ success: false, message: `Payment was not successful (status: ${txn.status}).` });
  if (txn.currency !== "NGN") return json({ success: false, message: "Unexpected currency on transaction." });

  const amountNaira = txn.amount / 100;
  if (amountNaira < MIN_TOPUP) return json({ success: false, message: `Minimum top-up is ₦${MIN_TOPUP}.` });
  if (txn.metadata?.userId !== uid) {
    return json({ message: "This payment reference belongs to a different account." }, 403);
  }

  const wallet = await db.prepare("SELECT * FROM business_wallets WHERE uid = ?").bind(uid).first();
  const currentBalance = wallet?.availableBalance ?? 0;
  const newBalance = currentBalance + amountNaira;
  const now = new Date().toISOString();

  const statements = [
    db
      .prepare(
        `INSERT INTO deposits (id, businessId, amount, provider, providerRef, status, createdAt)
         VALUES (?, ?, ?, 'paystack', ?, 'success', ?)`
      )
      .bind(reference, uid, amountNaira, reference, now),
    db
      .prepare(
        `INSERT INTO business_wallets (uid, availableBalance, reservedFunds, campaignFunds) VALUES (?, ?, 0, 0)
         ON CONFLICT(uid) DO UPDATE SET availableBalance = availableBalance + ?`
      )
      .bind(uid, amountNaira, amountNaira),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
         VALUES (?, ?, 'business', 'deposit', ?, ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), uid, amountNaira, newBalance, reference, now),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         VALUES (?, ?, 'wallet_topup', 'Wallet funded', ?, ?, 0, ?)`
      )
      .bind(crypto.randomUUID(), uid, `₦${amountNaira.toLocaleString()} was added to your campaign wallet.`, reference, now),
  ];

  await db.batch(statements);
  return json({ success: true, amount: amountNaira });
}

  return { topUpBusinessWallet };
})();




// FROM: music.js
const music = (function() {
/**
 * Qapela — Unreleased Music Marketplace (Cloudflare Workers + D1)
 * ---------------------------------------------------------------------
 * Purchase logic ported from functions/music.js. Listing creation is new
 * — the original had no server-side function for it at all (musicians
 * likely wrote listings straight to Firestore from the client). Since
 * clients can't talk to D1 directly, this fills that gap.
 *
 * Every listing requires a releaseDate. Once that date passes, the
 * hourly cleanup Cron Trigger (see cleanup.js) marks the listing
 * 'expired' and deletes the actual audio bytes from song_files — the
 * idea being that by the official release date, the track is on real
 * streaming platforms and doesn't need to keep taking up storage here.
 * Past purchasers simply lose in-app playback after that point, same
 * as the song leaving the "unreleased" marketplace makes sense to.
 *
 * File upload and serving live in storage.js (D1 BLOBs, since R2 needs
 * a card on file to enable). See storage.js for uploadSongFile /
 * streamSongFile.
 *
 * Routes (mounted in worker.js):
 *   POST /musicians/songs       { title, description?, price, releaseDate }
 *   POST /music/purchase        { reference, songId }
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
const DEFAULT_MUSIC_FEE_PCT = 10;

async function getMusicFeePct(db) {
  const row = await db.prepare("SELECT musicPlatformFeePct FROM platform_settings WHERE id = 'config'").first();
  return typeof row?.musicPlatformFeePct === "number" && row.musicPlatformFeePct >= 0 ? row.musicPlatformFeePct : DEFAULT_MUSIC_FEE_PCT;
}

// Public browse — active, unexpired songs, with the artist name joined
// in. No fileUrl/audio bytes here, obviously — that's gated behind an
// actual purchase (see storage.js streamSongFile).
async function listActiveSongs(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { results } = await db
    .prepare(
      `SELECT s.id, s.title, s.description, s.price, s.previewUrl, s.totalSales, s.releaseDate, s.createdAt, m.name as artistName
       FROM unreleased_songs s LEFT JOIN musicians m ON m.uid = s.musicianId
       WHERE s.status = 'active' ORDER BY s.createdAt DESC LIMIT 100`
    )
    .all();

  const { results: myPurchases } = await db
    .prepare("SELECT songId FROM song_purchases WHERE fanId = ? AND status = 'success'")
    .bind(uid)
    .all();

  return json({ songs: results, myPurchasedSongIds: myPurchases.map((p) => p.songId) });
}

// A fan's purchased songs — their "library."
async function getMyPurchasedSongs(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare(
      `SELECT p.id as purchaseId, p.songId, p.amount, p.createdAt, s.title, s.description, m.name as artistName
       FROM song_purchases p JOIN unreleased_songs s ON s.id = p.songId LEFT JOIN musicians m ON m.uid = s.musicianId
       WHERE p.fanId = ? AND p.status = 'success' ORDER BY p.createdAt DESC LIMIT 100`
    )
    .bind(uid)
    .all();
  return json({ purchases: results });
}

async function createSongListing(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { title, description, price, releaseDate } = await request.json();
  const cleanTitle = typeof title === "string" ? title.trim() : "";
  const cleanPrice = Math.floor(Number(price));

  if (!cleanTitle) return json({ success: false, message: "Song title is required." }, 400);
  if (!cleanPrice || cleanPrice <= 0) return json({ success: false, message: "Enter a valid price." }, 400);
  if (!releaseDate) return json({ success: false, message: "Select the official release date for this song." }, 400);

  const releaseDateObj = new Date(releaseDate);
  if (isNaN(releaseDateObj.getTime())) return json({ success: false, message: "That release date isn't valid." }, 400);
  if (releaseDateObj.getTime() <= Date.now()) {
    return json({ success: false, message: "Release date must be in the future — this marketplace is for unreleased tracks only." }, 400);
  }

  const songId = crypto.randomUUID();
  const now = new Date().toISOString();

  // Musicians don't need a separate signup step — the first listing they
  // create establishes their musicians profile row.
  await db
    .prepare(`INSERT INTO musicians (uid, name, bio, createdAt) VALUES (?, NULL, NULL, ?) ON CONFLICT(uid) DO NOTHING`)
    .bind(uid, now)
    .run();

  await db
    .prepare(
      `INSERT INTO unreleased_songs (id, musicianId, title, description, price, previewUrl, status, totalSales, totalRevenue, createdAt, releaseDate)
       VALUES (?, ?, ?, ?, ?, NULL, 'active', 0, 0, ?, ?)`
    )
    .bind(songId, uid, cleanTitle, description ? String(description).trim() : null, cleanPrice, now, releaseDateObj.toISOString())
    .run();

  // Client should follow up with POST /musicians/songs/{songId}/file to
  // actually upload the audio bytes (see storage.js).
  return json({ success: true, songId });
}

// ---------------------------------------------------------------------
// setArtistProfile — musician sets/updates their public artist name.
// Previously only ever set to NULL via createSongListing's lazy insert
// — there was no way to actually set a real name.
// ---------------------------------------------------------------------
async function setArtistProfile(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { artistName, bio } = await request.json();
  const cleanName = typeof artistName === "string" ? artistName.trim() : "";
  if (!cleanName) return json({ success: false, message: "Enter an artist name." }, 400);

  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO musicians (uid, name, bio, createdAt) VALUES (?, ?, ?, ?)
       ON CONFLICT(uid) DO UPDATE SET name = ?, bio = ?`
    )
    .bind(uid, cleanName, bio ? String(bio).trim() : null, now, cleanName, bio ? String(bio).trim() : null)
    .run();

  return json({ success: true, artistName: cleanName });
}

async function getMyArtistProfile(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const row = await env.DB.prepare("SELECT * FROM musicians WHERE uid = ?").bind(uid).first();
  return json(row || { uid, name: null, bio: null });
}

// A musician's own tracks, any status — unlike the public marketplace
// browse, which (once built) will only show active ones.
async function getMySongs(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare("SELECT * FROM unreleased_songs WHERE musicianId = ? ORDER BY createdAt DESC LIMIT 100")
    .bind(uid)
    .all();
  return json({ songs: results });
}

// Manual early unpublish — until now the only way a song ever left
// 'active' was its releaseDate passing (see cleanup.js). This lets a
// musician pull a track down themselves, same storage-reclaiming
// behavior as the automatic expiry.
async function removeSongListing(request, env, songId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!songId) return json({ success: false, message: "songId is required." }, 400);

  const song = await db.prepare("SELECT * FROM unreleased_songs WHERE id = ?").bind(songId).first();
  if (!song) return json({ success: false, message: "Song not found." }, 404);
  if (song.musicianId !== uid) return json({ success: false, message: "Not your song." }, 403);
  if (song.status !== "active") return json({ success: false, message: "This song is already unpublished." });

  await db.batch([
    db.prepare("UPDATE unreleased_songs SET status = 'removed' WHERE id = ? AND status = 'active'").bind(songId),
    db.prepare("DELETE FROM song_files WHERE songId = ?").bind(songId),
  ]);

  return json({ success: true });
}

async function purchaseSong(request, env) {
  const fanId = await auth.requireAuth(request, env);
  if (!fanId) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { reference, songId } = await request.json();
  if (!reference || !songId) return json({ message: "reference and songId are required." }, 400);

  const existing = await db.prepare("SELECT id FROM song_purchases WHERE id = ?").bind(reference).first();
  if (existing) return json({ success: true, alreadyProcessed: true });

  const song = await db.prepare("SELECT * FROM unreleased_songs WHERE id = ?").bind(songId).first();
  if (!song) return json({ message: "Song not found." }, 404);
  if (song.status !== "active") return json({ success: false, message: "This song isn't available for purchase right now — it may already be officially released." });
  if (song.musicianId === fanId) return json({ success: false, message: "You can't buy your own song — you already have access." });

  const expectedAmountKobo = Math.round(song.price * 100);

  const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}` },
  });
  const verifyJson = await verifyRes.json();
  if (!verifyRes.ok || !verifyJson.status) return json({ message: "We could not verify the payment right now. Please try again in a moment." }, 502);

  const txn = verifyJson.data;
  if (txn.status !== "success") return json({ success: false, message: `Payment was not successful (status: ${txn.status}).` });
  if (txn.currency !== "NGN") return json({ success: false, message: "Unexpected currency on transaction." });
  if (txn.amount !== expectedAmountKobo) {
    return json({
      success: false,
      message: `Amount mismatch: expected ₦${song.price}, the payment was ₦${txn.amount / 100}. The song's price may have changed after checkout opened.`,
    });
  }
  if (txn.metadata?.fanId !== fanId || (txn.metadata?.songId && txn.metadata.songId !== songId)) {
    return json({ message: "This payment reference belongs to a different account." }, 403);
  }

  const feePct = await getMusicFeePct(db);
  const platformFee = Math.round(song.price * (feePct / 100));
  const musicianPayout = song.price - platformFee;

  const wallet = await db.prepare("SELECT * FROM wallets WHERE uid = ?").bind(song.musicianId).first();
  const currentBalance = wallet?.availableBalance ?? 0;
  const newBalance = currentBalance + musicianPayout;
  const now = new Date().toISOString();

  const statements = [
    db
      .prepare(
        `INSERT INTO song_purchases (id, songId, musicianId, fanId, amount, platformFeePct, platformFee, musicianPayout, provider, providerRef, status, createdAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'paystack', ?, 'success', ?)`
      )
      .bind(reference, songId, song.musicianId, fanId, song.price, feePct, platformFee, musicianPayout, reference, now),
    db.prepare("UPDATE unreleased_songs SET totalSales = totalSales + 1, totalRevenue = totalRevenue + ? WHERE id = ?").bind(song.price, songId),
    db
      .prepare(
        `INSERT INTO wallets (uid, availableBalance, pendingBalance, totalEarned, todayEarnings, breakdownMusicSales)
         VALUES (?, ?, 0, ?, ?, ?)
         ON CONFLICT(uid) DO UPDATE SET availableBalance = availableBalance + ?, totalEarned = totalEarned + ?, todayEarnings = todayEarnings + ?, breakdownMusicSales = breakdownMusicSales + ?`
      )
      .bind(
        song.musicianId,
        musicianPayout,
        musicianPayout,
        musicianPayout,
        musicianPayout,
        musicianPayout,
        musicianPayout,
        musicianPayout,
        musicianPayout
      ),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
         VALUES (?, ?, 'worker', 'music_sale', ?, ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), song.musicianId, musicianPayout, newBalance, reference, now),
    db
      .prepare(
        `INSERT INTO platform_revenue (id, type, amount, userId, relatedId, createdAt)
         VALUES (?, 'music_platform_fee', ?, ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), platformFee, song.musicianId, reference, now),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         VALUES (?, ?, 'song_sale', 'Someone unlocked your song', ?, ?, 0, ?)`
      )
      .bind(
        crypto.randomUUID(),
        song.musicianId,
        `"${song.title}" sold for ₦${song.price.toLocaleString()} — ₦${musicianPayout.toLocaleString()} was added to your wallet.`,
        songId,
        now
      ),
  ];

  await db.batch(statements);
  return json({ success: true, musicianPayout, platformFee });
}

  return {
  createSongListing,
  setArtistProfile,
  getMyArtistProfile,
  getMySongs,
  removeSongListing,
  listActiveSongs,
  getMyPurchasedSongs,
  purchaseSong,
};
})();


// FROM: storage.js
const storage = (function() {
/**
 * Qapela — File Storage (D1 BLOBs, no R2)
 * --------------------------------------------
 * R2 needs a card on file to even enable (Cloudflare's dashboard blocks
 * API access to it otherwise), so files live directly in D1 as BLOB
 * columns instead. Two very different retention needs, two tables:
 *
 *   task_proof_files — screenshots proving a worker did a task. These
 *   are meant to be short-lived: cleanup.js deletes any row older than
 *   24 hours, every hour, via a Cron Trigger. Ties to submissions via
 *   proofData.proofFileId (see task.js).
 *
 *   song_files — a musician's actual audio file for sale. These must
 *   persist forever (it's the product being sold), so nothing ever
 *   auto-deletes them. Because D1's free tier is 5GB total, keep an
 *   eye on this table specifically as more songs get uploaded — this
 *   is the one place worth moving to R2 first, once a card is available.
 *
 * Upload size caps below are deliberately conservative given the
 * shared 5GB ceiling — raise them once you have real usage data.
 *
 * Routes (mounted in worker.js):
 *   POST /task-proofs                      (raw binary body, header: x-mime-type)
 *   POST /musicians/songs/:songId/file      (raw binary body, header: x-mime-type)
 *   GET  /music/file/:songId                (streams the audio bytes back)
 *   GET  /task-proofs/:id                    (streams a screenshot back — worker who
 *                                              uploaded it, the business whose campaign
 *                                              it's attached to, or an admin)
 */


const MAX_PROOF_BYTES = 5 * 1024 * 1024; // 5MB per screenshot
const MAX_SONG_BYTES = 15 * 1024 * 1024; // 15MB per song file

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

async function uploadTaskProof(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const mimeType = request.headers.get("x-mime-type") || "application/octet-stream";
  const bytes = await request.arrayBuffer();
  if (!bytes.byteLength) return json({ success: false, message: "Empty upload." }, 400);
  if (bytes.byteLength > MAX_PROOF_BYTES) {
    return json({ success: false, message: `Screenshot too large — max ${MAX_PROOF_BYTES / 1024 / 1024}MB.` }, 413);
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.prepare(
    "INSERT INTO task_proof_files (id, submissionId, workerId, mimeType, sizeBytes, data, createdAt) VALUES (?, NULL, ?, ?, ?, ?, ?)"
  )
    .bind(id, uid, mimeType, bytes.byteLength, bytes, now)
    .run();

  // Client attaches this id as proofData.proofFileId when it calls POST /submissions.
  return json({ success: true, proofFileId: id });
}

async function uploadSongFile(request, env, songId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const song = await db.prepare("SELECT musicianId FROM unreleased_songs WHERE id = ?").bind(songId).first();
  if (!song) return json({ message: "Song not found." }, 404);
  if (song.musicianId !== uid) return json({ message: "Only the musician who owns this song can upload its file." }, 403);

  const mimeType = request.headers.get("x-mime-type") || "audio/mpeg";
  const bytes = await request.arrayBuffer();
  if (!bytes.byteLength) return json({ success: false, message: "Empty upload." }, 400);
  if (bytes.byteLength > MAX_SONG_BYTES) {
    return json({ success: false, message: `File too large — max ${MAX_SONG_BYTES / 1024 / 1024}MB.` }, 413);
  }

  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO song_files (songId, mimeType, sizeBytes, data) VALUES (?, ?, ?, ?)
       ON CONFLICT(songId) DO UPDATE SET mimeType = ?, sizeBytes = ?, data = ?`
    )
    .bind(songId, mimeType, bytes.byteLength, bytes, mimeType, bytes.byteLength, bytes)
    .run();

  return json({ success: true });
}

async function streamSongFile(request, env, songId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const song = await db.prepare("SELECT musicianId FROM unreleased_songs WHERE id = ?").bind(songId).first();
  if (!song) return json({ message: "Song not found." }, 404);

  let authorized = song.musicianId === uid;
  if (!authorized) {
    const purchase = await db
      .prepare("SELECT id FROM song_purchases WHERE songId = ? AND fanId = ? AND status = 'success' LIMIT 1")
      .bind(songId, uid)
      .first();
    authorized = !!purchase;
  }
  if (!authorized) return json({ message: "You haven't unlocked this song yet." }, 403);

  const file = await db.prepare("SELECT data, mimeType, sizeBytes FROM song_files WHERE songId = ?").bind(songId).first();
  if (!file || !file.data) return json({ message: "This song's file hasn't been uploaded yet." }, 404);

  return new Response(file.data, {
    status: 200,
    headers: {
      "Content-Type": file.mimeType || "audio/mpeg",
      "Content-Length": String(file.sizeBytes || file.data.byteLength),
      "Cache-Control": "private, max-age=0, no-store",
    },
  });
}

async function isAdmin(db, uid) {
  const row = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  return !!row;
}

async function streamTaskProof(request, env, proofId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!proofId) return json({ message: "proofId is required." }, 400);

  const file = await db.prepare("SELECT * FROM task_proof_files WHERE id = ?").bind(proofId).first();
  if (!file) return json({ message: "This proof no longer exists — screenshots auto-clear after 24 hours." }, 404);

  let authorized = file.workerId === uid;
  if (!authorized) authorized = await isAdmin(db, uid);
  if (!authorized && file.submissionId) {
    const owner = await db
      .prepare(
        `SELECT c.businessId FROM submissions s JOIN campaigns c ON c.id = s.campaignId WHERE s.id = ?`
      )
      .bind(file.submissionId)
      .first();
    authorized = owner?.businessId === uid;
  }
  if (!authorized) return json({ message: "You don't have access to this file." }, 403);

  return new Response(file.data, {
    status: 200,
    headers: {
      "Content-Type": file.mimeType || "application/octet-stream",
      "Content-Length": String(file.sizeBytes || file.data.byteLength),
      "Cache-Control": "private, max-age=0, no-store",
    },
  });
}

  return { uploadTaskProof, uploadSongFile, streamSongFile, streamTaskProof, MAX_PROOF_BYTES, MAX_SONG_BYTES };
})();


// FROM: cleanup.js
const cleanup = (function() {
/**
 * Qapela — Retention Cleanup (Cloudflare Workers Cron Trigger)
 * -----------------------------------------------------------------
 * Runs hourly via a Cron Trigger, configured in wrangler.toml:
 *
 *   [triggers]
 *   crons = ["0 * * * *"]
 *
 * and wired up via the `scheduled` handler exported from worker.js.
 *
 * Two independent cleanup jobs live here:
 *
 *   1. Task-proof screenshots (ported from functions/cleanup.js).
 *      Screenshots live as BLOBs in D1 (see storage.js) rather than R2
 *      — R2 needs a card on file to enable at all — so this deletes
 *      expired rows from task_proof_files directly. Submission rows
 *      themselves are NOT touched: only the image bytes are deleted,
 *      the row (and the fact that a proof once existed) stays for audit.
 *
 *   2. Unreleased-song expiry (new). Once a song's releaseDate has
 *      passed, it's presumably out on real streaming platforms now, so
 *      there's no reason to keep hosting the audio file here. This
 *      marks the listing 'expired' (removing it from the marketplace)
 *      and deletes the actual audio bytes from song_files to reclaim
 *      storage. The unreleased_songs row itself stays, same spirit as
 *      the screenshot cleanup — sales history and totals are kept.
 */

const RETENTION_MS = 24 * 60 * 60 * 1000; // 24 hours

async function deleteExpiredTaskProofs(env) {
  const cutoff = new Date(Date.now() - RETENTION_MS).toISOString();
  const result = await env.DB.prepare("DELETE FROM task_proof_files WHERE createdAt < ?").bind(cutoff).run();
  console.log(`Qapela proof cleanup: deleted ${result.meta.changes} expired screenshot row(s).`);
}

async function expireReleasedSongs(env) {
  const now = new Date().toISOString();
  const db = env.DB;

  const expired = await db
    .prepare("UPDATE unreleased_songs SET status = 'expired' WHERE status = 'active' AND releaseDate <= ? RETURNING id")
    .bind(now)
    .all();

  const ids = (expired.results || []).map((r) => r.id);
  if (ids.length === 0) {
    console.log("Qapela song expiry: no songs past their release date.");
    return;
  }

  const placeholders = ids.map(() => "?").join(",");
  const fileResult = await db.prepare(`DELETE FROM song_files WHERE songId IN (${placeholders})`).bind(...ids).run();
  console.log(`Qapela song expiry: expired ${ids.length} listing(s), cleared ${fileResult.meta.changes} audio file row(s).`);
}

  return { deleteExpiredTaskProofs, expireReleasedSongs };
})();


// FROM: affiliate.js
const affiliate = (function() {
/**
 * Qapela — Affiliate Marketplace (Cloudflare Workers + D1)
 * -----------------------------------------------------------------
 * New functionality — the original Firebase codebase never implemented
 * this. Built from scratch, direct-to-bank model (no in-app wallet
 * holding, no pre-funding):
 *
 *   1. A business creates a listing: product amount + their OWN bank
 *      account details (required upfront — no listing without a
 *      payout destination). The listing stays live until the business
 *      deletes it — no budget, nothing to run out.
 *   2. A worker picks a listing and creates a link: their OWN bank
 *      details for THIS specific link, plus whatever commission amount
 *      they want to add on top of the product price. Different links
 *      (even for the same listing) can have different banks/commissions
 *      — a worker might run several campaigns differently.
 *   3. A customer only ever sees ONE price — productAmount +
 *      workerCommission, added together server-side before checkout.
 *      They never see the breakdown; only the worker (and, for their
 *      own side, the business) knows how it's composed.
 *   4. The customer pays that single combined price through Paystack.
 *      The instant that payment is verified (same server-side
 *      verify-with-Paystack pattern used everywhere else in Qapela —
 *      never trust the client's word for a payment), Qapela:
 *        - keeps its cut, a % of productAmount only (never touches the
 *          worker's commission) — platform_settings.affiliatePlatformFeePct,
 *          default 5%, editable via /admin/settings
 *        - transfers (productAmount - platformFee) straight to the
 *          business's bank
 *        - transfers the full workerCommission straight to the
 *          worker's bank
 *      Both transfers reuse the exact recipient+transfer code already
 *      built and proven for withdrawal.js — no new Paystack primitive
 *      introduced (deliberately not using Paystack's native "Split
 *      Payment" feature here: for a 3-way split with amounts that
 *      differ on every single sale, Paystack requires creating a new
 *      split configuration object per transaction, which is real added
 *      complexity for no benefit over just sending two transfers
 *      ourselves — see PAYSTACK_SPLIT_DECISION note below.).
 *   5. Everything is logged in affiliate_sales regardless of payout
 *      outcome, so businesses and workers can always see their sales
 *      history in-app even though funds never sit in an internal wallet.
 *      If one of the two transfers fails while the other succeeds
 *      (Paystack transfers can fail independently), that sale is
 *      marked 'needs_attention' rather than silently lost — nobody has
 *      built a retry UI for this yet, so for now it just needs a human
 *      to notice and act via the transfer webhook/logs.
 *
 * PAYSTACK_SPLIT_DECISION: Paystack's Transaction Split API is built
 * for exactly this kind of multi-party payout, but it's optimized for
 * splits that stay the same across many transactions (dashboard-
 * configured percentage/flat splits) or accept the overhead of creating
 * a fresh split object per charge for dynamic amounts. Since every
 * single sale here has a different worker commission, we'd be creating
 * a new split object on every sale anyway — no simpler than just
 * calling the transfer API twice, which we already have working code
 * for. Revisit this if transfer volume gets high enough that Paystack's
 * settlement-time batching becomes worth the added complexity.
 *
 * Routes (mounted in worker.js):
 *   POST /affiliate/listings                    (business creates a listing)
 *   DELETE /affiliate/listings/:id               (business deletes — soft delete)
 *   GET  /affiliate/listings                     (browse active listings — no bank details exposed)
 *   GET  /affiliate/listings/mine/sales          (business's own sales history)
 *   POST /affiliate/links                        (worker creates a link — sets bank + commission)
 *   GET  /affiliate/links/mine                   (worker's own links)
 *   GET  /affiliate/links/mine/sales             (worker's own sales history)
 *   GET  /affiliate/checkout/:code               (customer preview — single combined price only)
 *   POST /affiliate/purchase                     { reference, code } — verifies payment, pays out both sides
 */


function n(v) {
  const x = Number(v);
  return Number.isFinite(x) ? x : 0;
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
async function getAffiliateFeePct(db) {
  const row = await db.prepare("SELECT affiliatePlatformFeePct FROM platform_settings WHERE id = 'config'").first();
  return typeof row?.affiliatePlatformFeePct === "number" && row.affiliatePlatformFeePct >= 0 ? row.affiliatePlatformFeePct : 5;
}
function randomCode() {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 10).toUpperCase();
}
async function paystackFetch(path, secret, options = {}) {
  const res = await fetch(`https://api.paystack.co${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${secret}`, "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const j = await res.json();
  if (!res.ok || j.status === false) throw new Error(j.message || "Request failed");
  return j;
}
async function sendTransfer(secret, { amount, accountNumber, bankCode, accountName, reason, reference }) {
  const recipientRes = await paystackFetch("/transferrecipient", secret, {
    method: "POST",
    body: JSON.stringify({ type: "nuban", name: accountName, account_number: accountNumber, bank_code: bankCode, currency: "NGN" }),
  });
  const transferRes = await paystackFetch("/transfer", secret, {
    method: "POST",
    body: JSON.stringify({ source: "balance", amount: amount * 100, recipient: recipientRes.data.recipient_code, reason, reference }),
  });
  return { transferCode: transferRes.data.transfer_code, status: transferRes.data.status };
}

// ---------------------------------------------------------------------
// createListing — business lists a product. Bank details are required
// up front: "no listing without a payout destination" is the whole
// point of setting this up before anything can be sold.
// ---------------------------------------------------------------------
async function createListing(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const d = await request.json();
  const title = typeof d.title === "string" ? d.title.trim() : "";
  const description = typeof d.description === "string" ? d.description.trim() : null;
  const productAmount = Math.floor(n(d.productAmount));
  const { bankCode, bankName, accountNumber, accountName } = d;

  if (!title) return json({ success: false, message: "Title is required." }, 400);
  if (!productAmount || productAmount <= 0) return json({ success: false, message: "Enter a valid product amount." }, 400);
  if (!bankCode || !accountNumber || !accountName) {
    return json({ success: false, message: "Bank account details are required before you can list a product — this is where your share of every sale gets paid." }, 400);
  }

  const user = await db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first();
  if (!user || !user.accountActivated || !user.roleBusiness) {
    return json({ success: false, message: "Business access is not activated." });
  }

  const feePct = await getAffiliateFeePct(db);
  const platformFee = Math.floor(productAmount * (feePct / 100));
  const businessReceives = productAmount - platformFee;

  const listingId = crypto.randomUUID();
  const now = new Date().toISOString();

  await db
    .prepare(
      `INSERT INTO affiliate_listings (id, businessId, title, description, productAmount, bankCode, bankName, accountNumber, accountName, status, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`
    )
    .bind(listingId, uid, title, description, productAmount, bankCode, bankName || null, accountNumber, accountName, now)
    .run();

  // Tell the business up front exactly what they'll net per sale —
  // "any percentage set by admin should automatically get explained."
  return json({
    success: true,
    listingId,
    productAmount,
    platformFeePct: feePct,
    platformFeeAmount: platformFee,
    youWillReceivePerSale: businessReceives,
  });
}

// ---------------------------------------------------------------------
// listMyListings — a business's own listings, any status (unlike
// listActiveListings, which only shows what's currently live platform-
// wide). Needed so a brand-new listing with zero sales yet is still
// visible to the business that created it.
// ---------------------------------------------------------------------
async function listMyListings(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare("SELECT * FROM affiliate_listings WHERE businessId = ? ORDER BY createdAt DESC LIMIT 100")
    .bind(uid)
    .all();
  return json({ listings: results });
}

// ---------------------------------------------------------------------
// deleteListing — soft delete, business only. Existing links to it
// simply stop being purchasable (checked at purchase time).
// ---------------------------------------------------------------------
async function deleteListing(request, env, listingId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!listingId) return json({ success: false, message: "listingId is required." });

  const listing = await db.prepare("SELECT * FROM affiliate_listings WHERE id = ?").bind(listingId).first();
  if (!listing) return json({ success: false, message: "Listing not found." });
  if (listing.businessId !== uid) return json({ success: false, message: "Not your listing." });
  if (listing.status !== "active") return json({ success: false, message: "This listing is already deleted." });

  const now = new Date().toISOString();
  await db.prepare("UPDATE affiliate_listings SET status = 'deleted', deletedAt = ? WHERE id = ? AND status = 'active'").bind(now, listingId).run();
  return json({ success: true });
}

// ---------------------------------------------------------------------
// listActiveListings — browse (workers looking for products to promote).
// Bank details never go in this response — those are private.
// ---------------------------------------------------------------------
async function listActiveListings(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare(
      `SELECT id, title, description, productAmount, createdAt
       FROM affiliate_listings WHERE status = 'active' ORDER BY createdAt DESC LIMIT 50`
    )
    .all();

  return json({ listings: results });
}

// ---------------------------------------------------------------------
// business's own sales history
// ---------------------------------------------------------------------
async function myListingSales(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare(
      `SELECT s.id, s.listingId, al.title, s.totalAmount, s.businessPayout, s.businessTransferStatus, s.status, s.createdAt
       FROM affiliate_sales s JOIN affiliate_listings al ON al.id = s.listingId
       WHERE s.businessId = ? ORDER BY s.createdAt DESC LIMIT 100`
    )
    .bind(uid)
    .all();

  return json({ sales: results });
}

// ---------------------------------------------------------------------
// createLink — worker sets up their own bank + commission for a listing
// ---------------------------------------------------------------------
async function createLink(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const d = await request.json();
  const { listingId, bankCode, bankName, accountNumber, accountName } = d;
  const commission = Math.floor(n(d.commission));

  if (!listingId) return json({ success: false, message: "listingId is required." }, 400);
  if (!commission || commission <= 0) return json({ success: false, message: "Enter the commission you want to add." }, 400);
  if (!bankCode || !accountNumber || !accountName) {
    return json({ success: false, message: "Bank account details are required before you can share this link — this is where your commission gets paid." }, 400);
  }

  const user = await db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first();
  if (!user || !user.accountActivated || !user.roleWorker) {
    return json({ success: false, message: "Worker access is not activated." });
  }

  const listing = await db.prepare("SELECT * FROM affiliate_listings WHERE id = ?").bind(listingId).first();
  if (!listing || listing.status !== "active") return json({ success: false, message: "This listing isn't available." });

  const linkId = crypto.randomUUID();
  const code = randomCode();
  const now = new Date().toISOString();

  await db
    .prepare(
      `INSERT INTO affiliate_links (id, workerId, listingId, code, commission, bankCode, bankName, accountNumber, accountName, status, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`
    )
    .bind(linkId, uid, listingId, code, commission, bankCode, bankName || null, accountNumber, accountName, now)
    .run();

  return json({ success: true, linkId, code, totalCustomerPrice: n(listing.productAmount) + commission });
}

// ---------------------------------------------------------------------
// worker's own links + sales history
// ---------------------------------------------------------------------
async function myLinks(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare(
      `SELECT l.id as linkId, l.code, l.listingId, l.commission, l.status, l.createdAt, al.title, al.productAmount,
              (al.productAmount + l.commission) as totalCustomerPrice
       FROM affiliate_links l JOIN affiliate_listings al ON al.id = l.listingId
       WHERE l.workerId = ? ORDER BY l.createdAt DESC`
    )
    .bind(uid)
    .all();

  return json({ links: results });
}

async function myLinkSales(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare(
      `SELECT s.id, s.listingId, al.title, s.totalAmount, s.workerCommission, s.workerTransferStatus, s.status, s.createdAt
       FROM affiliate_sales s JOIN affiliate_listings al ON al.id = s.listingId
       WHERE s.workerId = ? ORDER BY s.createdAt DESC LIMIT 100`
    )
    .bind(uid)
    .all();

  return json({ sales: results });
}

// ---------------------------------------------------------------------
// checkoutPreview — what a customer sees before paying: ONE price,
// never the breakdown. This is the only endpoint here that doesn't
// require a Qapela account, since the customer clicking a shared link
// may not be a Qapela user at all.
// ---------------------------------------------------------------------
async function checkoutPreview(request, env, code) {
  if (!code) return json({ message: "code is required." }, 400);
  const db = env.DB;

  const link = await db.prepare("SELECT * FROM affiliate_links WHERE code = ?").bind(String(code).trim().toUpperCase()).first();
  if (!link || link.status !== "active") return json({ message: "This link is no longer valid." }, 404);

  const listing = await db.prepare("SELECT * FROM affiliate_listings WHERE id = ?").bind(link.listingId).first();
  if (!listing || listing.status !== "active") return json({ message: "This product is no longer available." }, 404);

  // Single combined price only — no productAmount/commission breakdown here.
  return json({
    title: listing.title,
    description: listing.description,
    price: n(listing.productAmount) + n(link.commission),
  });
}

// ---------------------------------------------------------------------
// purchase — the customer pays, we verify with Paystack, then pay both
// the business and the worker directly. No wallet crediting at all.
// ---------------------------------------------------------------------
async function purchase(request, env) {
  const db = env.DB;
  const { reference, code } = await request.json();
  if (!reference || !code) return json({ success: false, message: "reference and code are required." }, 400);

  const existing = await db.prepare("SELECT id FROM affiliate_sales WHERE paymentRef = ?").bind(reference).first();
  if (existing) return json({ success: true, alreadyProcessed: true });

  const link = await db.prepare("SELECT * FROM affiliate_links WHERE code = ?").bind(String(code).trim().toUpperCase()).first();
  if (!link || link.status !== "active") return json({ success: false, message: "This link is no longer valid." }, 404);

  const listing = await db.prepare("SELECT * FROM affiliate_listings WHERE id = ?").bind(link.listingId).first();
  if (!listing || listing.status !== "active") return json({ success: false, message: "This product is no longer available." }, 404);

  const productAmount = n(listing.productAmount);
  const workerCommission = n(link.commission);
  const totalAmount = productAmount + workerCommission;
  const expectedAmountKobo = totalAmount * 100;

  // ---- Verify the payment directly with Paystack — never trust the client ----
  const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}` },
  });
  const verifyJson = await verifyRes.json();
  if (!verifyRes.ok || !verifyJson.status) return json({ success: false, message: "We could not verify the payment right now. Please try again in a moment." }, 502);

  const txn = verifyJson.data;
  if (txn.status !== "success") return json({ success: false, message: `Payment was not successful (status: ${txn.status}).` });
  if (txn.currency !== "NGN") return json({ success: false, message: "Unexpected currency on transaction." });
  if (txn.amount !== expectedAmountKobo) {
    return json({ success: false, message: `Amount mismatch: expected ₦${totalAmount}, the payment was ₦${txn.amount / 100}.` });
  }
  if (String(txn.metadata?.affiliateCode || "").trim().toUpperCase() !== String(code).trim().toUpperCase()) {
    return json({ success: false, message: "This payment doesn't match this product link." }, 403);
  }

  const feePct = await getAffiliateFeePct(db);
  const platformFee = Math.floor(productAmount * (feePct / 100));
  const businessPayout = productAmount - platformFee;

  const saleId = crypto.randomUUID();
  const now = new Date().toISOString();

  // Log the sale as 'processing' BEFORE attempting transfers, so a sale
  // is never lost even if something goes wrong sending the money out.
  // Atomic claim of this payment: only one request can ever create the sale for a reference,
  // so two simultaneous calls can't both trigger the payouts below.
  const claim = await db
    .prepare(
      `INSERT INTO affiliate_sales (id, linkId, listingId, workerId, businessId, totalAmount, productAmount, workerCommission, platformFeePct, platformFee, businessPayout, provider, paymentRef, status, createdAt)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'paystack', ?, 'processing', ?
       WHERE NOT EXISTS (SELECT 1 FROM affiliate_sales WHERE paymentRef = ?)`
    )
    .bind(saleId, link.id, listing.id, link.workerId, listing.businessId, totalAmount, productAmount, workerCommission, feePct, platformFee, businessPayout, reference, now, reference)
    .run();
  if (claim.meta.changes !== 1) return json({ success: true, alreadyProcessed: true });

  await db
    .prepare(
      `INSERT INTO platform_revenue (id, type, amount, businessId, workerId, relatedId, createdAt)
       VALUES (?, 'affiliate_platform_fee', ?, ?, ?, ?, ?)`
    )
    .bind(crypto.randomUUID(), platformFee, listing.businessId, link.workerId, saleId, now)
    .run();

  // ---- Two independent transfers. Each can fail on its own. ----
  let businessTransfer = null;
  let businessError = null;
  try {
    businessTransfer = await sendTransfer(env.PAYSTACK_SECRET_KEY, {
      amount: businessPayout,
      accountNumber: listing.accountNumber,
      bankCode: listing.bankCode,
      accountName: listing.accountName,
      reason: `Qapela affiliate sale — ${listing.title}`,
      reference: `${saleId}-biz`,
    });
  } catch (err) {
    businessError = err.message;
  }

  let workerTransfer = null;
  let workerError = null;
  try {
    workerTransfer = await sendTransfer(env.PAYSTACK_SECRET_KEY, {
      amount: workerCommission,
      accountNumber: link.accountNumber,
      bankCode: link.bankCode,
      accountName: link.accountName,
      reason: `Qapela affiliate commission — ${listing.title}`,
      reference: `${saleId}-worker`,
    });
  } catch (err) {
    workerError = err.message;
  }

  const bothOk = businessTransfer && workerTransfer;
  const finalStatus = bothOk ? "completed" : "needs_attention";

  await db
    .prepare(
      `UPDATE affiliate_sales SET
         businessTransferRef = ?, businessTransferStatus = ?,
         workerTransferRef = ?, workerTransferStatus = ?,
         status = ?, completedAt = ?
       WHERE id = ?`
    )
    .bind(
      businessTransfer?.transferCode || null,
      businessTransfer?.status || `failed: ${businessError}`,
      workerTransfer?.transferCode || null,
      workerTransfer?.status || `failed: ${workerError}`,
      finalStatus,
      new Date().toISOString(),
      saleId
    )
    .run();

  return json({
    success: true,
    saleId,
    status: finalStatus,
    businessTransfer: businessTransfer ? businessTransfer.status : `failed: ${businessError}`,
    workerTransfer: workerTransfer ? workerTransfer.status : `failed: ${workerError}`,
  });
}

  return {
  createListing,
  deleteListing,
  listActiveListings,
  listMyListings,
  myListingSales,
  createLink,
  myLinks,
  myLinkSales,
  checkoutPreview,
  purchase,
};
})();


// FROM: admin.js
const admin = (function() {
/**
 * Qapela — Admin Settings (Cloudflare Workers + D1)
 * -----------------------------------------------------------
 * Every platform-wide number (registration fee, fee percentages,
 * minimum withdrawal) lives in the single-row platform_settings table.
 * Until now nothing ever wrote to it after the initial seed — this
 * gives admins an actual way to change those values without touching
 * the database directly.
 *
 * Routes (mounted in worker.js):
 *   GET  /admin/settings   — view current values
 *   POST /admin/settings   — update one or more values
 *   GET  /admin/wallet     — Qapela's total earnings, for the admin panel
 *   GET  /public/settings  — the handful of settings client pages need
 *                            to display (fees, minimums) without
 *                            requiring admin access — e.g. the
 *                            activation page showing the current fee.
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

async function isAdmin(db, uid) {
  const row = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  return !!row;
}

// Every editable field, with the bounds worth enforcing. Money fields
// (registrationFee, minWithdrawal) just need to be non-negative
// integers; percentage fields need to stay within 0-100.
const EDITABLE_FIELDS = {
  registrationFee: { type: "int", min: 0 },
  referralPlatformSharePct: { type: "pct" },
  reservePctOfPlatformRevenue: { type: "pct" },
  minWithdrawal: { type: "int", min: 0 },
  musicPlatformFeePct: { type: "pct" },
  affiliatePlatformFeePct: { type: "pct" },
};

async function getSettings(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const row = await db.prepare("SELECT * FROM platform_settings WHERE id = 'config'").first();
  if (!row) return json({ message: "Settings row not found." }, 500);
  return json({ settings: row });
}

async function updateSettings(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const body = await request.json();
  const setClauses = [];
  const values = [];
  const errors = [];

  for (const [field, rule] of Object.entries(EDITABLE_FIELDS)) {
    if (!(field in body)) continue;
    const raw = body[field];
    const num = Number(raw);
    if (!Number.isFinite(num)) {
      errors.push(`${field} must be a number.`);
      continue;
    }
    if (rule.type === "pct" && (num < 0 || num > 100)) {
      errors.push(`${field} must be between 0 and 100.`);
      continue;
    }
    if (rule.type === "int" && num < (rule.min ?? -Infinity)) {
      errors.push(`${field} must be at least ${rule.min}.`);
      continue;
    }
    setClauses.push(`${field} = ?`);
    values.push(Math.floor(num));
  }

  if (errors.length) return json({ success: false, message: errors.join(" ") }, 400);
  if (setClauses.length === 0) return json({ success: false, message: "No recognized settings fields were provided." }, 400);

  values.push("config");
  await db.prepare(`UPDATE platform_settings SET ${setClauses.join(", ")} WHERE id = ?`).bind(...values).run();

  const updated = await db.prepare("SELECT * FROM platform_settings WHERE id = 'config'").first();
  return json({ success: true, settings: updated });
}

// ---------------------------------------------------------------------
// getWallet — Qapela's total earnings across every revenue source.
// This is a read-only dashboard number: the money itself already sits
// in Qapela's own Paystack balance automatically (every payout flow
// only ever transfers OUT the other parties' shares, never Qapela's
// own cut), so this doesn't move any money — it just adds up the
// platform_revenue ledger so there's something to look at in-app
// instead of only checking the Paystack dashboard directly.
// ---------------------------------------------------------------------
async function getWallet(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const totalRow = await db.prepare("SELECT COALESCE(SUM(amount), 0) as total FROM platform_revenue").first();

  const { results: byType } = await db
    .prepare(
      `SELECT type, COUNT(*) as count, COALESCE(SUM(amount), 0) as total
       FROM platform_revenue GROUP BY type ORDER BY total DESC`
    )
    .all();

  const { results: recent } = await db
    .prepare("SELECT id, type, amount, createdAt FROM platform_revenue ORDER BY createdAt DESC LIMIT 20")
    .all();

  // Kept as a separate figure from totalRevenue on purpose: the reserve
  // is money set aside from task payouts (see finance.js / task.js),
  // not freely-earned revenue — merging the two would make it look like
  // more money is available to spend than actually is. Pull it out via
  // POST /admin/reserve-withdrawals (withdrawal.js), same as always.
  const treasuryRow = await db.prepare("SELECT lockedReserve, updatedAt FROM platform_treasury WHERE id = 'main'").first();

  return json({
    totalRevenue: totalRow?.total ?? 0,
    breakdown: byType,
    recent,
    lockedReserve: treasuryRow?.lockedReserve ?? 0,
    lockedReserveUpdatedAt: treasuryRow?.updatedAt ?? null,
  });
}

// ---------------------------------------------------------------------
// getPublicSettings — the subset of settings a signed-in-but-not-admin
// user needs to see, e.g. the activation page showing the current
// registration fee. Deliberately does NOT require admin access — these
// numbers aren't sensitive, and hiding them would just mean every
// client page has to hardcode a guess instead of showing the real,
// current, server-enforced value.
// ---------------------------------------------------------------------
async function getPublicSettings(request, env) {
  const row = await env.DB.prepare("SELECT * FROM platform_settings WHERE id = 'config'").first();
  if (!row) return json({ message: "Settings row not found." }, 500);
  return json({
    registrationFee: row.registrationFee,
    minWithdrawal: row.minWithdrawal,
    maxWithdrawal: WITHDRAWAL_LIMITS.maxSingle,
    dailyWithdrawalLimit: WITHDRAWAL_LIMITS.maxPerDay,
    paystackPublicKey: env.PAYSTACK_PUBLIC_KEY || "",
    musicPlatformFeePct: row.musicPlatformFeePct,
    affiliatePlatformFeePct: row.affiliatePlatformFeePct,
  });
}

  return { getSettings, updateSettings, getWallet, getPublicSettings };
})();


// FROM: reads.js
const reads = (function() {
/**
 * Qapela — "My Data" Reads (Cloudflare Workers + D1)
 * -----------------------------------------------------------
 * Everything here is a read-only "show me my own stuff" endpoint —
 * the kind of thing Firestore's client SDK could do directly with
 * security rules, but which now needs an actual endpoint since the
 * client can't query D1 directly. Built as dashboard pages surface
 * the need, not pre-built speculatively.
 *
 * Routes (mounted in worker.js):
 *   GET  /wallet/mine                    — worker wallet balance + earnings
 *   GET  /wallet/business/mine           — business wallet balance
 *   GET  /wallet/business/transactions   — business wallet ledger history
 *   GET  /worker-profile/mine            — level, stats
 *   GET  /task-catalogue                 — active task types (for campaign creation)
 *   GET  /campaigns/active                — task feed: active campaigns + which
 *                                     ones this worker already submitted to
 *   GET  /campaigns/mine                 — a business's own campaigns, any status
 *   GET  /campaigns/:id/submissions      — a business viewing one campaign's participants
 *   GET  /notifications/mine       — list + unread count
 *   POST /notifications/mark-read  — mark all (or one) read
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

async function getMyWallet(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const wallet = await env.DB.prepare("SELECT * FROM wallets WHERE uid = ?").bind(uid).first();
  return json(
    wallet || {
      uid,
      availableBalance: 0,
      pendingBalance: 0,
      totalEarned: 0,
      todayEarnings: 0,
      breakdownTaskEarnings: 0,
      breakdownReferralCommissions: 0,
      breakdownAffiliateEarnings: 0,
      breakdownMusicSales: 0,
      breakdownBonuses: 0,
    }
  );
}

async function getMyWalletTransactions(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare("SELECT * FROM ledger_transactions WHERE walletId = ? AND walletType = 'worker' ORDER BY createdAt DESC LIMIT 30")
    .bind(uid)
    .all();
  return json({ transactions: results });
}

async function getMyWithdrawals(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare("SELECT * FROM withdrawals WHERE userId = ? ORDER BY requestedAt DESC LIMIT 20")
    .bind(uid)
    .all();
  return json({ withdrawals: results });
}

async function getMyBusinessWallet(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const wallet = await env.DB.prepare("SELECT * FROM business_wallets WHERE uid = ?").bind(uid).first();
  return json(wallet || { uid, availableBalance: 0, reservedFunds: 0, campaignFunds: 0 });
}

async function getMyBusinessProfile(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const biz = await env.DB.prepare("SELECT * FROM businesses WHERE uid = ?").bind(uid).first();
  return json(biz || { uid, name: null });
}

async function getMyBusinessTransactions(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare("SELECT * FROM ledger_transactions WHERE walletId = ? AND walletType = 'business' ORDER BY createdAt DESC LIMIT 30")
    .bind(uid)
    .all();
  return json({ transactions: results });
}

async function getTaskCatalogue(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB.prepare("SELECT * FROM task_catalogue WHERE active = 1 ORDER BY category, name").all();
  return json({ tasks: results });
}

async function getMyWorkerProfile(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const profile = await env.DB.prepare("SELECT * FROM worker_profiles WHERE uid = ?").bind(uid).first();
  return json(
    profile || {
      uid,
      level: 1,
      levelProgressPct: 0,
      tasksCompleted: 0,
      tasksRejected: 0,
      successRatePct: 100,
      accuracyPct: 100,
      reputationScore: 0,
      kycStatus: "none",
    }
  );
}

// The task feed. Only shows campaigns with real capacity left, joined
// with task_catalogue for display details the campaign row itself
// doesn't carry, plus which ones this worker has already submitted to
// (one attempt per campaign per worker, enforced by submissions.id
// being `${campaignId}_${workerId}` — see task.js).
async function getActiveCampaigns(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { results: campaigns } = await db
    .prepare(
      `SELECT c.*, t.name as taskName, t.difficulty, t.estMinutes, t.minUserLevel,
              t.dailyLimitPerWorker, t.fraudRiskTier, t.effortTier, t.verificationMethod
       FROM campaigns c LEFT JOIN task_catalogue t ON t.id = c.taskTypeId
       WHERE c.status = 'active' AND (c.quantityCompleted + c.quantityRejected) < c.quantityTarget
       ORDER BY c.createdAt DESC LIMIT 100`
    )
    .all();

  const { results: mySubs } = await db.prepare("SELECT campaignId FROM submissions WHERE workerId = ?").bind(uid).all();
  const mySubmittedCampaignIds = mySubs.map((r) => r.campaignId);

  return json({ campaigns, mySubmittedCampaignIds });
}

// A business's own campaigns, any status (unlike the worker task feed,
// which only shows active ones with capacity left).
async function getMyCampaigns(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare("SELECT * FROM campaigns WHERE businessId = ? ORDER BY createdAt DESC LIMIT 100")
    .bind(uid)
    .all();
  return json({ campaigns: results });
}

// A business viewing who's submitted to one of their own campaigns,
// with proof. workerDisplayName is joined from users at read time
// rather than snapshotted at submission time — one less place for
// stale data to hide.
async function getCampaignSubmissions(request, env, campaignId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!campaignId) return json({ message: "campaignId is required." }, 400);

  const campaign = await db.prepare("SELECT * FROM campaigns WHERE id = ?").bind(campaignId).first();
  if (!campaign) return json({ message: "Campaign not found." }, 404);
  if (campaign.businessId !== uid) return json({ message: "Not your campaign." }, 403);

  const { results } = await db
    .prepare(
      `SELECT s.*, u.displayName as workerDisplayName
       FROM submissions s LEFT JOIN users u ON u.uid = s.workerId
       WHERE s.campaignId = ? ORDER BY s.createdAt DESC LIMIT 200`
    )
    .bind(campaignId)
    .all();

  // Parse proofData JSON and attach a viewable URL for screenshots —
  // the actual bytes are served by GET /task-proofs/:id (see storage.js),
  // authorization-checked there, not exposed directly here.
  const submissions = results.map((s) => {
    let proof = null;
    try { proof = JSON.parse(s.proofData || "null"); } catch { /* leave null */ }
    return {
      ...s,
      proofData: proof,
      proofViewUrl: proof?.proofFileId ? `/task-proofs/${proof.proofFileId}` : null,
    };
  });

  return json({ campaign, submissions });
}

// A worker's own submissions, filtered by status, joined with
// task_catalogue for display fields the submission row doesn't carry.
async function getMySubmissions(request, env, status) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const validStatuses = ["needs_review", "approved", "rejected"];
  const statusFilter = validStatuses.includes(status) ? status : "needs_review";

  const { results } = await db
    .prepare(
      `SELECT s.*, t.name as taskName, t.category as taskCategory
       FROM submissions s LEFT JOIN task_catalogue t ON t.id = s.taskTypeId
       WHERE s.workerId = ? AND s.status = ?
       ORDER BY s.createdAt DESC LIMIT 50`
    )
    .bind(uid, statusFilter)
    .all();

  return json({ submissions: results });
}

async function getMyNotifications(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { results } = await db
    .prepare("SELECT * FROM notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 50")
    .bind(uid)
    .all();
  const unreadRow = await db.prepare("SELECT COUNT(*) as cnt FROM notifications WHERE userId = ? AND read = 0").bind(uid).first();

  return json({ notifications: results, unreadCount: unreadRow?.cnt ?? 0 });
}

async function markNotificationsRead(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { notificationId } = await request.json().catch(() => ({}));
  if (notificationId) {
    await db.prepare("UPDATE notifications SET read = 1 WHERE id = ? AND userId = ?").bind(notificationId, uid).run();
  } else {
    await db.prepare("UPDATE notifications SET read = 1 WHERE userId = ? AND read = 0").bind(uid).run();
  }
  return json({ success: true });
}

// A worker's referral history — who they referred, and how much
// commission each has generated so far. Joined with users for a
// display name rather than trusting anything snapshotted at signup
// time, same reasoning as getCampaignSubmissions.
async function getMyReferrals(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { results } = await db
    .prepare(
      `SELECT r.*, u.displayName as referredDisplayName, u.email as referredEmail
       FROM referrals r LEFT JOIN users u ON u.uid = r.referredId
       WHERE r.referrerId = ? ORDER BY r.createdAt DESC LIMIT 100`
    )
    .bind(uid)
    .all();

  return json({ referrals: results });
}

  return {
  getMyWallet,
  getMyWalletTransactions,
  getMyWithdrawals,
  getMyBusinessWallet,
  getMyBusinessProfile,
  getMyBusinessTransactions,
  getMyWorkerProfile,
  getTaskCatalogue,
  getActiveCampaigns,
  getMyCampaigns,
  getCampaignSubmissions,
  getMySubmissions,
  getMyReferrals,
  getMyNotifications,
  markNotificationsRead,
};
})();


// FROM: disputes.js
const disputes = (function() {
/**
 * Qapela — Disputes (Cloudflare Workers + D1)
 * -----------------------------------------------------------
 * New functionality — the original Firebase code had a "disputes"
 * collection referenced in Firestore rules and this page's client-side
 * logic, but no Cloud Function ever wrote to it (same situation as the
 * affiliate marketplace originally was). This is a straightforward
 * from-scratch build: a worker who was rejected can raise a dispute,
 * which sits as 'open' until an admin resolves it. No automatic
 * re-payout happens here — resolving a dispute in the worker's favor
 * is a manual admin action (see resolveDispute), same caution as every
 * other money-adjacent decision in this codebase.
 *
 * Routes (mounted in worker.js):
 *   POST /disputes              { relatedId, reason }  — worker raises one
 *   GET  /disputes/mine         — which submissions this worker has already disputed
 *   GET  /admin/disputes        — admin queue of open disputes
 *   POST /admin/disputes/:id/resolve   { resolution, approve }
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
async function isAdmin(db, uid) {
  const row = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  return !!row;
}

async function createDispute(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { relatedId, reason } = await request.json();
  const cleanReason = typeof reason === "string" ? reason.trim() : "";
  if (!relatedId || !cleanReason) {
    return json({ success: false, message: "relatedId and a reason are required." }, 400);
  }

  // A worker can only dispute their own rejected submission — not an
  // arbitrary id, and not something that hasn't actually been rejected.
  const submission = await db.prepare("SELECT * FROM submissions WHERE id = ?").bind(relatedId).first();
  if (!submission) return json({ success: false, message: "Submission not found." }, 404);
  if (submission.workerId !== uid) return json({ success: false, message: "Not your submission." }, 403);
  if (submission.status !== "rejected") return json({ success: false, message: "Only rejected submissions can be disputed." });

  const existing = await db.prepare("SELECT id FROM disputes WHERE raisedBy = ? AND relatedId = ?").bind(uid, relatedId).first();
  if (existing) return json({ success: true, alreadyExists: true });

  const disputeId = crypto.randomUUID();
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO disputes (id, raisedBy, relatedId, reason, status, resolution, createdAt)
       VALUES (?, ?, ?, ?, 'open', NULL, ?)`
    )
    .bind(disputeId, uid, relatedId, cleanReason, now)
    .run();

  return json({ success: true, disputeId });
}

async function getMyDisputes(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB.prepare("SELECT * FROM disputes WHERE raisedBy = ? ORDER BY createdAt DESC").bind(uid).all();
  return json({ disputes: results, disputedSubmissionIds: results.map((d) => d.relatedId) });
}

async function listOpenDisputes(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const { results } = await db
    .prepare(
      `SELECT d.*, u.displayName as raisedByName
       FROM disputes d LEFT JOIN users u ON u.uid = d.raisedBy
       WHERE d.status = 'open' ORDER BY d.createdAt ASC LIMIT 50`
    )
    .all();
  return json({ disputes: results });
}

// Resolving a dispute never auto-pays anyone — an admin who decides a
// rejected submission should actually be paid uses the normal
// finance.js reviewSubmission approve path separately. This endpoint
// only records the decision and closes the dispute.
async function resolveDispute(request, env, disputeId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);
  if (!disputeId) return json({ success: false, message: "disputeId is required." });

  const dispute = await db.prepare("SELECT * FROM disputes WHERE id = ?").bind(disputeId).first();
  if (!dispute) return json({ success: false, message: "Dispute not found." });
  if (dispute.status !== "open") return json({ success: false, message: "This dispute has already been resolved." });

  const { resolution } = await request.json();
  await db
    .prepare("UPDATE disputes SET status = 'resolved', resolution = ? WHERE id = ? AND status = 'open'")
    .bind(typeof resolution === "string" ? resolution.trim() : null, disputeId)
    .run();

  return json({ success: true });
}

  return { createDispute, getMyDisputes, listOpenDisputes, resolveDispute };
})();


// FROM: catalogue.js
const catalogue = (function() {
/**
 * Qapela — Task Catalogue Management (Cloudflare Workers + D1)
 * -----------------------------------------------------------------
 * Admin-only CRUD for task_catalogue — the task types businesses pick
 * from when creating a campaign (see finance.js createCampaign) and
 * that the worker task feed displays (see reads.js getActiveCampaigns).
 * Until now there was NO way to create a task type at all — the table
 * has sat empty since it was first created; nothing in the whole
 * campaign/task system can work without at least one row existing here.
 *
 * Routes (mounted in worker.js):
 *   GET  /admin/task-catalogue          — list all (any status)
 *   POST /admin/task-catalogue          — create
 *   POST /admin/task-catalogue/:id      — update
 *   POST /admin/task-catalogue/:id/toggle  — active/inactive
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
async function isAdmin(db, uid) {
  const row = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  return !!row;
}

function validateTaskFields(d) {
  const name = typeof d.name === "string" ? d.name.trim() : "";
  const category = typeof d.category === "string" ? d.category.trim() : "";
  const workerReward = Math.floor(Number(d.workerReward));
  const businessPrice = Math.floor(Number(d.businessPrice));

  if (!name) return { error: "Task name is required." };
  if (!category) return { error: "Category is required." };
  if (!workerReward || workerReward <= 0) return { error: "Enter a valid worker reward." };
  if (!businessPrice || businessPrice <= 0) return { error: "Enter a valid business price." };
  if (workerReward !== Math.floor(businessPrice * 0.7)) {
    return { error: "Worker reward must be exactly 70% of the business price — this is a fixed platform rule, not adjustable per task." };
  }

  return {
    name,
    category,
    workerReward,
    businessPrice,
    minCampaignSize: Math.max(1, Math.floor(Number(d.minCampaignSize)) || 1),
    verificationMethod: typeof d.verificationMethod === "string" ? d.verificationMethod.trim() : "screenshot",
    aiVerifiable: d.aiVerifiable === "yes" ? "yes" : "no",
    difficulty: typeof d.difficulty === "string" ? d.difficulty.trim() : null,
    estMinutes: d.estMinutes != null ? Math.floor(Number(d.estMinutes)) || null : null,
    minUserLevel: Math.max(1, Math.floor(Number(d.minUserLevel)) || 1),
    dailyLimitPerWorker: d.dailyLimitPerWorker != null ? Math.floor(Number(d.dailyLimitPerWorker)) || null : null,
    fraudRiskTier: typeof d.fraudRiskTier === "string" ? d.fraudRiskTier.trim() : null,
    effortTier: typeof d.effortTier === "string" ? d.effortTier.trim() : null,
  };
}

async function listTaskCatalogue(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const { results } = await db.prepare("SELECT * FROM task_catalogue ORDER BY category, name").all();
  return json({ tasks: results });
}

async function createTask(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const body = await request.json();
  const parsed = validateTaskFields(body);
  if (parsed.error) return json({ success: false, message: parsed.error }, 400);

  const id = crypto.randomUUID();
  await db
    .prepare(
      `INSERT INTO task_catalogue (id, name, category, active, minCampaignSize, workerReward, businessPrice, verificationMethod, aiVerifiable, difficulty, estMinutes, minUserLevel, dailyLimitPerWorker, fraudRiskTier, effortTier)
       VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      id,
      parsed.name,
      parsed.category,
      parsed.minCampaignSize,
      parsed.workerReward,
      parsed.businessPrice,
      parsed.verificationMethod,
      parsed.aiVerifiable,
      parsed.difficulty,
      parsed.estMinutes,
      parsed.minUserLevel,
      parsed.dailyLimitPerWorker,
      parsed.fraudRiskTier,
      parsed.effortTier
    )
    .run();

  return json({ success: true, taskId: id });
}

async function updateTask(request, env, taskId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);
  if (!taskId) return json({ success: false, message: "taskId is required." }, 400);

  const existing = await db.prepare("SELECT id FROM task_catalogue WHERE id = ?").bind(taskId).first();
  if (!existing) return json({ success: false, message: "Task not found." }, 404);

  const body = await request.json();
  const parsed = validateTaskFields(body);
  if (parsed.error) return json({ success: false, message: parsed.error }, 400);

  await db
    .prepare(
      `UPDATE task_catalogue SET name=?, category=?, minCampaignSize=?, workerReward=?, businessPrice=?, verificationMethod=?, aiVerifiable=?, difficulty=?, estMinutes=?, minUserLevel=?, dailyLimitPerWorker=?, fraudRiskTier=?, effortTier=? WHERE id=?`
    )
    .bind(
      parsed.name,
      parsed.category,
      parsed.minCampaignSize,
      parsed.workerReward,
      parsed.businessPrice,
      parsed.verificationMethod,
      parsed.aiVerifiable,
      parsed.difficulty,
      parsed.estMinutes,
      parsed.minUserLevel,
      parsed.dailyLimitPerWorker,
      parsed.fraudRiskTier,
      parsed.effortTier,
      taskId
    )
    .run();

  return json({ success: true });
}

async function toggleTask(request, env, taskId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);
  if (!taskId) return json({ success: false, message: "taskId is required." }, 400);

  const task = await db.prepare("SELECT active FROM task_catalogue WHERE id = ?").bind(taskId).first();
  if (!task) return json({ success: false, message: "Task not found." }, 404);

  await db.prepare("UPDATE task_catalogue SET active = ? WHERE id = ?").bind(task.active ? 0 : 1, taskId).run();
  return json({ success: true, active: !task.active });
}

  return { listTaskCatalogue, createTask, updateTask, toggleTask };
})();


// FROM: adminOverview.js
const adminOverview = (function() {
/**
 * Qapela — Admin Platform Oversight (Cloudflare Workers + D1)
 * -----------------------------------------------------------------
 * Everything an admin needs to see or moderate across the WHOLE
 * platform, not just their own account — as opposed to reads.js
 * (a user's own data) or admin.js (settings/wallet totals).
 *
 * KYC note: there is no document-upload flow anywhere in this system
 * — kycStatus is a plain flag an admin sets after verifying someone
 * by whatever means they actually use (a call, an external form,
 * etc.). This just gives admin a place to record and view that
 * decision, not a verification pipeline.
 *
 * Fraud note: nothing in this codebase automatically writes to
 * fraud_events — there's no fraud-detection engine. This gives admin
 * a place to manually log a concern against a user and review the
 * list; it's a record-keeping tool, not a detector.
 *
 * Routes (mounted in worker.js):
 *   GET  /admin/users                       — list all users
 *   POST /admin/users/:uid/status           — set active/suspended/banned
 *   GET  /admin/verification                — worker profiles + kycStatus
 *   POST /admin/verification/:uid           — set kycStatus
 *   GET  /admin/fraud-events                — list
 *   POST /admin/fraud-events                — log one manually
 *   GET  /admin/businesses                  — list + wallet balances
 *   GET  /admin/campaigns                   — list ALL campaigns, any business
 *   GET  /admin/referrals                   — list ALL referrals platform-wide
 *   GET  /admin/affiliate-sales             — list ALL affiliate sales platform-wide
 *   GET  /admin/reports                     — aggregate counts + revenue summary
 *   GET  /admin/dashboard                   — overview: counts + pending-review items
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
async function isAdmin(db, uid) {
  const row = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  return !!row;
}
async function requireAdmin(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return { error: json({ message: "Sign in required." }, 401) };
  if (!(await isAdmin(env.DB, uid))) return { error: json({ message: "Admin access required." }, 403) };
  return { uid };
}

// ---------------------------------------------------------------------
async function listUsers(request, env) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;

  const { results } = await env.DB
    .prepare(
      `SELECT uid, displayName, email, phone, roleWorker, roleBusiness, accountActivated, status, referralCode, createdAt
       FROM users ORDER BY createdAt DESC LIMIT 200`
    )
    .all();
  return json({ users: results });
}

async function setUserStatus(request, env, targetUid) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;
  if (!targetUid) return json({ success: false, message: "uid is required." }, 400);

  const { status } = await request.json();
  if (!["active", "suspended", "banned"].includes(status)) {
    return json({ success: false, message: "status must be active, suspended, or banned." }, 400);
  }

  await env.DB.prepare("UPDATE users SET status = ? WHERE uid = ?").bind(status, targetUid).run();
  return json({ success: true, status });
}

// ---------------------------------------------------------------------
async function listVerification(request, env) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;

  const { results } = await env.DB
    .prepare(
      `SELECT w.uid, w.kycStatus, w.level, w.tasksCompleted, u.displayName, u.email, u.createdAt
       FROM worker_profiles w LEFT JOIN users u ON u.uid = w.uid
       ORDER BY CASE w.kycStatus WHEN 'pending' THEN 0 ELSE 1 END, u.createdAt DESC LIMIT 200`
    )
    .all();
  return json({ profiles: results });
}

async function setKycStatus(request, env, targetUid) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;
  if (!targetUid) return json({ success: false, message: "uid is required." }, 400);

  const { kycStatus } = await request.json();
  if (!["none", "pending", "verified", "rejected"].includes(kycStatus)) {
    return json({ success: false, message: "Invalid kycStatus." }, 400);
  }

  await env.DB
    .prepare(
      `INSERT INTO worker_profiles (uid, kycStatus) VALUES (?, ?)
       ON CONFLICT(uid) DO UPDATE SET kycStatus = ?`
    )
    .bind(targetUid, kycStatus, kycStatus)
    .run();
  return json({ success: true, kycStatus });
}

// ---------------------------------------------------------------------
async function listFraudEvents(request, env) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;

  const { results } = await env.DB
    .prepare(
      `SELECT f.*, u.displayName FROM fraud_events f LEFT JOIN users u ON u.uid = f.userId
       ORDER BY f.createdAt DESC LIMIT 200`
    )
    .all();
  return json({ events: results });
}

async function logFraudEvent(request, env) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;

  const { userId, type, details } = await request.json();
  if (!userId || !type) return json({ success: false, message: "userId and type are required." }, 400);

  await env.DB
    .prepare("INSERT INTO fraud_events (id, userId, type, details, createdAt) VALUES (?, ?, ?, ?, ?)")
    .bind(crypto.randomUUID(), userId, String(type).trim(), details ? JSON.stringify(details) : null, new Date().toISOString())
    .run();
  return json({ success: true });
}

// ---------------------------------------------------------------------
async function listBusinesses(request, env) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;

  const { results } = await env.DB
    .prepare(
      `SELECT b.uid, b.name, b.createdAt, u.email, u.status, bw.availableBalance, bw.reservedFunds
       FROM businesses b LEFT JOIN users u ON u.uid = b.uid LEFT JOIN business_wallets bw ON bw.uid = b.uid
       ORDER BY b.createdAt DESC LIMIT 200`
    )
    .all();
  return json({ businesses: results });
}

async function listAllCampaigns(request, env) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;

  const { results } = await env.DB
    .prepare(
      `SELECT c.*, b.name as businessName FROM campaigns c LEFT JOIN businesses b ON b.uid = c.businessId
       ORDER BY c.createdAt DESC LIMIT 200`
    )
    .all();
  return json({ campaigns: results });
}

async function listAllReferrals(request, env) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;

  const { results } = await env.DB
    .prepare(
      `SELECT r.*, ru.displayName as referrerName, du.displayName as referredName
       FROM referrals r LEFT JOIN users ru ON ru.uid = r.referrerId LEFT JOIN users du ON du.uid = r.referredId
       ORDER BY r.createdAt DESC LIMIT 200`
    )
    .all();
  return json({ referrals: results });
}

async function listAllAffiliateSales(request, env) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;

  const { results } = await env.DB
    .prepare(
      `SELECT s.*, al.title as listingTitle FROM affiliate_sales s LEFT JOIN affiliate_listings al ON al.id = s.listingId
       ORDER BY s.createdAt DESC LIMIT 200`
    )
    .all();
  return json({ sales: results });
}

// ---------------------------------------------------------------------
async function getReports(request, env) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;
  const db = env.DB;

  const [users, businesses, campaigns, submissions, withdrawals, revenue] = await Promise.all([
    db.prepare("SELECT COUNT(*) as cnt FROM users").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM businesses").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM campaigns").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM submissions").first(),
    db.prepare("SELECT COUNT(*) as cnt, COALESCE(SUM(amount),0) as total FROM withdrawals WHERE status = 'completed'").first(),
    db.prepare("SELECT type, COUNT(*) as count, COALESCE(SUM(amount),0) as total FROM platform_revenue GROUP BY type").all(),
  ]);

  return json({
    userCount: users?.cnt ?? 0,
    businessCount: businesses?.cnt ?? 0,
    campaignCount: campaigns?.cnt ?? 0,
    submissionCount: submissions?.cnt ?? 0,
    withdrawalsCompleted: withdrawals?.cnt ?? 0,
    withdrawalsTotal: withdrawals?.total ?? 0,
    revenueByType: revenue.results,
  });
}

async function getDashboard(request, env) {
  const gate = await requireAdmin(request, env);
  if (gate.error) return gate.error;
  const db = env.DB;

  const [users, activeCampaigns, needsReview, openDisputes, otpPending, kycPending] = await Promise.all([
    db.prepare("SELECT COUNT(*) as cnt FROM users").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM campaigns WHERE status = 'active'").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM submissions WHERE status = 'needs_review'").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM disputes WHERE status = 'open'").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM withdrawals WHERE status = 'processing' AND paystackStatus = 'otp'").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM worker_profiles WHERE kycStatus = 'pending'").first(),
  ]);

  return json({
    userCount: users?.cnt ?? 0,
    activeCampaigns: activeCampaigns?.cnt ?? 0,
    needsReviewSubmissions: needsReview?.cnt ?? 0,
    openDisputes: openDisputes?.cnt ?? 0,
    otpPendingTransfers: otpPending?.cnt ?? 0,
    kycPending: kycPending?.cnt ?? 0,
    payoutCover: await withdrawal.getPayoutCover(env),
  });
}

  return {
  listUsers,
  setUserStatus,
  listVerification,
  setKycStatus,
  listFraudEvents,
  logFraudEvent,
  listBusinesses,
  listAllCampaigns,
  listAllReferrals,
  listAllAffiliateSales,
  getReports,
  getDashboard,
};
})();


// FROM: worker.js
/**
 * Qapela — Cloudflare Worker entry point
 * -----------------------------------------
 * Binds: DB (D1 database "capella-db")
 * Secrets: PAYSTACK_SECRET_KEY, AUTH_SECRET (wrangler secret put ...)
 *
 * This file is just a router. Each feature area lives in its own module
 * under src/ (withdrawal.js, finance.js, activation.js, task.js,
 * topup.js, otp.js, music.js, storage.js, cleanup.js, auth.js).
 */


function withCORS(response, renewedToken) {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", "*"); // tighten to your real domain before launch
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-mime-type");
  headers.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  // Silent session renewal (see auth.js maybeRenewToken) — present on
  // almost every response once a token is within 7 days of expiring.
  // Client should overwrite its stored token with this value if present.
  if (renewedToken) headers.set("X-Renewed-Token", renewedToken);
  return new Response(response.body, { status: response.status, headers });
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return withCORS(new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);
    const { pathname } = url;
    // Computed once per request so every route below can attach it to
    // its response without each individual handler needing to know
    // about renewal at all.
    const renewedToken = await auth.maybeRenewToken(request, env);

    try {
      // ---- auth ----
      if (pathname === "/auth/register" && request.method === "POST") {
        return withCORS(await auth.register(request, env), renewedToken);
      }
      if (pathname === "/auth/login" && request.method === "POST") {
        return withCORS(await auth.login(request, env), renewedToken);
      }
      if (pathname === "/auth/password-reset/request" && request.method === "POST") {
        return withCORS(await auth.requestPasswordReset(request, env), renewedToken);
      }
      if (pathname === "/auth/password-reset/confirm" && request.method === "POST") {
        return withCORS(await auth.confirmPasswordReset(request, env), renewedToken);
      }
      if (pathname === "/auth/me" && request.method === "GET") {
        return withCORS(await auth.getMe(request, env), renewedToken);
      }
      if (pathname === "/public/settings" && request.method === "GET") {
        return withCORS(await admin.getPublicSettings(request, env), renewedToken);
      }
      if (pathname === "/account/roles" && request.method === "POST") {
        return withCORS(await auth.addRole(request, env), renewedToken);
      }
      if (pathname === "/account/profile" && request.method === "POST") {
        return withCORS(await auth.updateProfile(request, env), renewedToken);
      }
      if (pathname === "/account/contact" && request.method === "POST") {
        return withCORS(await auth.changeContact(request, env), renewedToken);
      }
      if (pathname === "/account/password" && request.method === "POST") {
        return withCORS(await auth.changePassword(request, env), renewedToken);
      }
      if (pathname === "/account/delete-check" && request.method === "GET") {
        return withCORS(await auth.deleteCheck(request, env), renewedToken);
      }
      if (pathname === "/account/delete" && request.method === "POST") {
        return withCORS(await auth.deleteAccount(request, env), renewedToken);
      }
      if (pathname === "/account/business-profile" && request.method === "POST") {
        return withCORS(await auth.updateBusinessProfile(request, env), renewedToken);
      }

      // ---- "my data" reads ----
      if (pathname === "/wallet/mine" && request.method === "GET") {
        return withCORS(await reads.getMyWallet(request, env), renewedToken);
      }
      if (pathname === "/wallet/transactions" && request.method === "GET") {
        return withCORS(await reads.getMyWalletTransactions(request, env), renewedToken);
      }
      if (pathname === "/withdrawals/mine" && request.method === "GET") {
        return withCORS(await reads.getMyWithdrawals(request, env), renewedToken);
      }
      if (pathname === "/wallet/business/mine" && request.method === "GET") {
        return withCORS(await reads.getMyBusinessWallet(request, env), renewedToken);
      }
      if (pathname === "/business-profile/mine" && request.method === "GET") {
        return withCORS(await reads.getMyBusinessProfile(request, env), renewedToken);
      }
      if (pathname === "/wallet/business/transactions" && request.method === "GET") {
        return withCORS(await reads.getMyBusinessTransactions(request, env), renewedToken);
      }
      if (pathname === "/worker-profile/mine" && request.method === "GET") {
        return withCORS(await reads.getMyWorkerProfile(request, env), renewedToken);
      }
      if (pathname === "/task-catalogue" && request.method === "GET") {
        return withCORS(await reads.getTaskCatalogue(request, env), renewedToken);
      }
      if (pathname === "/campaigns/active" && request.method === "GET") {
        return withCORS(await reads.getActiveCampaigns(request, env), renewedToken);
      }
      if (pathname === "/campaigns/mine" && request.method === "GET") {
        return withCORS(await reads.getMyCampaigns(request, env), renewedToken);
      }
      const campaignSubsMatch = pathname.match(/^\/campaigns\/([^/]+)\/submissions$/);
      if (campaignSubsMatch && request.method === "GET") {
        return withCORS(await reads.getCampaignSubmissions(request, env, campaignSubsMatch[1]), renewedToken);
      }
      if (pathname === "/notifications/mine" && request.method === "GET") {
        return withCORS(await reads.getMyNotifications(request, env), renewedToken);
      }
      if (pathname === "/notifications/mark-read" && request.method === "POST") {
        return withCORS(await reads.markNotificationsRead(request, env), renewedToken);
      }
      if (pathname === "/referrals/mine" && request.method === "GET") {
        return withCORS(await reads.getMyReferrals(request, env), renewedToken);
      }
      const mySubsMatch = pathname.match(/^\/submissions\/mine$/);
      if (mySubsMatch && request.method === "GET") {
        return withCORS(await reads.getMySubmissions(request, env, url.searchParams.get("status")), renewedToken);
      }

      // ---- disputes ----
      if (pathname === "/disputes" && request.method === "POST") {
        return withCORS(await disputes.createDispute(request, env), renewedToken);
      }
      if (pathname === "/disputes/mine" && request.method === "GET") {
        return withCORS(await disputes.getMyDisputes(request, env), renewedToken);
      }
      if (pathname === "/admin/disputes" && request.method === "GET") {
        return withCORS(await disputes.listOpenDisputes(request, env), renewedToken);
      }
      const resolveDisputeMatch = pathname.match(/^\/admin\/disputes\/([^/]+)\/resolve$/);
      if (resolveDisputeMatch && request.method === "POST") {
        return withCORS(await disputes.resolveDispute(request, env, resolveDisputeMatch[1]), renewedToken);
      }

      // ---- withdrawals ----
      if (pathname === "/banks" && request.method === "GET") {
        return withCORS(await withdrawal.listBanks(request, env), renewedToken);
      }
      if (pathname === "/banks/resolve" && request.method === "POST") {
        return withCORS(await withdrawal.resolveBankAccount(request, env), renewedToken);
      }
      if (pathname === "/business/refunds" && request.method === "GET") {
        return withCORS(await withdrawal.getMyBusinessRefunds(request, env), renewedToken);
      }
      if (pathname === "/business/refund" && request.method === "POST") {
        return withCORS(await withdrawal.requestBusinessRefund(request, env), renewedToken);
      }
      if (pathname === "/withdrawals" && request.method === "POST") {
        return withCORS(await withdrawal.requestWithdrawal(request, env), renewedToken);
      }
      if (pathname === "/admin/revenue" && request.method === "GET") {
        return withCORS(await withdrawal.getAdminRevenue(request, env), renewedToken);
      }
      if (pathname === "/admin/revenue/withdraw" && request.method === "POST") {
        return withCORS(await withdrawal.requestRevenueWithdrawal(request, env), renewedToken);
      }
      if (pathname === "/webhooks/paystack-transfer" && request.method === "POST") {
        // no CORS needed — Paystack calls this server-to-server
        return await withdrawal.transferWebhook(request, env);
      }

      // ---- finance / campaigns ----
      if (pathname === "/campaigns" && request.method === "POST") {
        return withCORS(await finance.createCampaign(request, env), renewedToken);
      }
      const cancelMatch = pathname.match(/^\/campaigns\/([^/]+)\/cancel$/);
      if (cancelMatch && request.method === "POST") {
        return withCORS(await finance.cancelCampaign(request, env, cancelMatch[1]), renewedToken);
      }
      const approveMatch = pathname.match(/^\/admin\/submissions\/([^/]+)\/approve$/);
      if (approveMatch && request.method === "POST") {
        return withCORS(await finance.reviewSubmission(request, env, approveMatch[1], true), renewedToken);
      }
      const rejectMatch = pathname.match(/^\/admin\/submissions\/([^/]+)\/reject$/);
      if (rejectMatch && request.method === "POST") {
        return withCORS(await finance.reviewSubmission(request, env, rejectMatch[1], false), renewedToken);
      }

      // ---- activation ----
      if (pathname === "/activations/verify" && request.method === "POST") {
        return withCORS(await activation.verifyActivationPayment(request, env), renewedToken);
      }

      // ---- task submission + auto-verification ----
      if (pathname === "/submissions" && request.method === "POST") {
        return withCORS(await task.createSubmission(request, env), renewedToken);
      }

      // ---- wallet top-up ----
      if (pathname === "/wallet/topup" && request.method === "POST") {
        return withCORS(await topup.topUpBusinessWallet(request, env), renewedToken);
      }

      // ---- music marketplace ----
      if (pathname === "/musicians/songs" && request.method === "POST") {
        return withCORS(await music.createSongListing(request, env), renewedToken);
      }
      if (pathname === "/musicians/profile" && request.method === "POST") {
        return withCORS(await music.setArtistProfile(request, env), renewedToken);
      }
      if (pathname === "/musicians/profile/mine" && request.method === "GET") {
        return withCORS(await music.getMyArtistProfile(request, env), renewedToken);
      }
      if (pathname === "/musicians/songs/mine" && request.method === "GET") {
        return withCORS(await music.getMySongs(request, env), renewedToken);
      }
      const removeSongMatch = pathname.match(/^\/musicians\/songs\/([^/]+)\/remove$/);
      if (removeSongMatch && request.method === "POST") {
        return withCORS(await music.removeSongListing(request, env, removeSongMatch[1]), renewedToken);
      }
      if (pathname === "/music/songs" && request.method === "GET") {
        return withCORS(await music.listActiveSongs(request, env), renewedToken);
      }
      if (pathname === "/music/library" && request.method === "GET") {
        return withCORS(await music.getMyPurchasedSongs(request, env), renewedToken);
      }
      if (pathname === "/music/purchase" && request.method === "POST") {
        return withCORS(await music.purchaseSong(request, env), renewedToken);
      }

      // ---- file storage (D1 BLOBs — see storage.js) ----
      if (pathname === "/task-proofs" && request.method === "POST") {
        return withCORS(await storage.uploadTaskProof(request, env), renewedToken);
      }
      const taskProofViewMatch = pathname.match(/^\/task-proofs\/([^/]+)$/);
      if (taskProofViewMatch && request.method === "GET") {
        return withCORS(await storage.streamTaskProof(request, env, taskProofViewMatch[1]), renewedToken);
      }
      const songUploadMatch = pathname.match(/^\/musicians\/songs\/([^/]+)\/file$/);
      if (songUploadMatch && request.method === "POST") {
        return withCORS(await storage.uploadSongFile(request, env, songUploadMatch[1]), renewedToken);
      }
      const songStreamMatch = pathname.match(/^\/music\/file\/([^/]+)$/);
      if (songStreamMatch && request.method === "GET") {
        // no withCORS wrapper needed for the JSON error paths inside this
        // function either, but audio tags fetch cross-origin too, so keep it
        return withCORS(await storage.streamSongFile(request, env, songStreamMatch[1]), renewedToken);
      }

      // ---- affiliate marketplace ----
      if (pathname === "/affiliate/listings" && request.method === "POST") {
        return withCORS(await affiliate.createListing(request, env), renewedToken);
      }
      if (pathname === "/affiliate/listings" && request.method === "GET") {
        return withCORS(await affiliate.listActiveListings(request, env), renewedToken);
      }
      if (pathname === "/affiliate/listings/mine/sales" && request.method === "GET") {
        return withCORS(await affiliate.myListingSales(request, env), renewedToken);
      }
      if (pathname === "/affiliate/listings/mine" && request.method === "GET") {
        return withCORS(await affiliate.listMyListings(request, env), renewedToken);
      }
      const deleteListingMatch = pathname.match(/^\/affiliate\/listings\/([^/]+)$/);
      if (deleteListingMatch && request.method === "DELETE") {
        return withCORS(await affiliate.deleteListing(request, env, deleteListingMatch[1]), renewedToken);
      }
      if (pathname === "/affiliate/links" && request.method === "POST") {
        return withCORS(await affiliate.createLink(request, env), renewedToken);
      }
      if (pathname === "/affiliate/links/mine" && request.method === "GET") {
        return withCORS(await affiliate.myLinks(request, env), renewedToken);
      }
      if (pathname === "/affiliate/links/mine/sales" && request.method === "GET") {
        return withCORS(await affiliate.myLinkSales(request, env), renewedToken);
      }
      const checkoutMatch = pathname.match(/^\/affiliate\/checkout\/([^/]+)$/);
      if (checkoutMatch && request.method === "GET") {
        // Customer-facing, no auth required — they may not be a Qapela user.
        return withCORS(await affiliate.checkoutPreview(request, env, checkoutMatch[1]), renewedToken);
      }
      if (pathname === "/affiliate/purchase" && request.method === "POST") {
        return withCORS(await affiliate.purchase(request, env), renewedToken);
      }

      // ---- admin settings ----
      if (pathname === "/admin/settings" && request.method === "GET") {
        return withCORS(await admin.getSettings(request, env), renewedToken);
      }
      if (pathname === "/admin/settings" && request.method === "POST") {
        return withCORS(await admin.updateSettings(request, env), renewedToken);
      }
      if (pathname === "/admin/wallet" && request.method === "GET") {
        return withCORS(await admin.getWallet(request, env), renewedToken);
      }

      // ---- admin: task catalogue ----
      if (pathname === "/admin/task-catalogue" && request.method === "GET") {
        return withCORS(await catalogue.listTaskCatalogue(request, env), renewedToken);
      }
      if (pathname === "/admin/task-catalogue" && request.method === "POST") {
        return withCORS(await catalogue.createTask(request, env), renewedToken);
      }
      const updateTaskMatch = pathname.match(/^\/admin\/task-catalogue\/([^/]+)$/);
      if (updateTaskMatch && request.method === "POST") {
        return withCORS(await catalogue.updateTask(request, env, updateTaskMatch[1]), renewedToken);
      }
      const toggleTaskMatch = pathname.match(/^\/admin\/task-catalogue\/([^/]+)\/toggle$/);
      if (toggleTaskMatch && request.method === "POST") {
        return withCORS(await catalogue.toggleTask(request, env, toggleTaskMatch[1]), renewedToken);
      }

      // ---- admin: platform-wide oversight ----
      if (pathname === "/admin/users" && request.method === "GET") {
        return withCORS(await adminOverview.listUsers(request, env), renewedToken);
      }
      const userStatusMatch = pathname.match(/^\/admin\/users\/([^/]+)\/status$/);
      if (userStatusMatch && request.method === "POST") {
        return withCORS(await adminOverview.setUserStatus(request, env, userStatusMatch[1]), renewedToken);
      }
      if (pathname === "/admin/verification" && request.method === "GET") {
        return withCORS(await adminOverview.listVerification(request, env), renewedToken);
      }
      const kycMatch = pathname.match(/^\/admin\/verification\/([^/]+)$/);
      if (kycMatch && request.method === "POST") {
        return withCORS(await adminOverview.setKycStatus(request, env, kycMatch[1]), renewedToken);
      }
      if (pathname === "/admin/fraud-events" && request.method === "GET") {
        return withCORS(await adminOverview.listFraudEvents(request, env), renewedToken);
      }
      if (pathname === "/admin/fraud-events" && request.method === "POST") {
        return withCORS(await adminOverview.logFraudEvent(request, env), renewedToken);
      }
      if (pathname === "/admin/businesses" && request.method === "GET") {
        return withCORS(await adminOverview.listBusinesses(request, env), renewedToken);
      }
      if (pathname === "/admin/campaigns" && request.method === "GET") {
        return withCORS(await adminOverview.listAllCampaigns(request, env), renewedToken);
      }
      if (pathname === "/admin/referrals" && request.method === "GET") {
        return withCORS(await adminOverview.listAllReferrals(request, env), renewedToken);
      }
      if (pathname === "/admin/affiliate-sales" && request.method === "GET") {
        return withCORS(await adminOverview.listAllAffiliateSales(request, env), renewedToken);
      }
      if (pathname === "/admin/reports" && request.method === "GET") {
        return withCORS(await adminOverview.getReports(request, env), renewedToken);
      }
      if (pathname === "/admin/dashboard" && request.method === "GET") {
        return withCORS(await adminOverview.getDashboard(request, env), renewedToken);
      }

      return withCORS(new Response(JSON.stringify({ message: "Not found" }), { status: 404 }), renewedToken);
    } catch (err) {
      return withCORS(
        new Response(JSON.stringify({ message: "Internal error", detail: err.message }), { status: 500 }),
        renewedToken
      );
    }
  },

  // Cloudflare Cron Trigger entry point — configured via [triggers].crons
  // in wrangler.toml. Replaces Firebase's onSchedule('every 1 hours').
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanup.deleteExpiredTaskProofs(env));
    ctx.waitUntil(cleanup.expireReleasedSongs(env));
    ctx.waitUntil(withdrawal.reconcileWithdrawals(env));
  },
};
