# Qapela — GitHub Pages Upload

Upload everything in this folder (22 `.html` files + the `assets/` folder)
to the root of your `EjitechX/qapela-worker` repo. This is everything
users actually see and use — worker, business, musician, onboarding, legal
pages, the entry point (`index.html`).

**Admin pages are separate** — see the other zip.

## Before it works

1. **Paystack public key** — placeholder in `qapela-activation.html`,
   `qapela-business.html`, `qapela-checkout.html`,
   `qapela-music-marketplace.html`. Replace `pk_test_xxxx...` in all four.
2. **Resend API key** — needed for password reset emails. Set as
   `RESEND_API_KEY` in Cloudflare (see the admin/backend package).
3. **Legal page emails** — already set to `qapela.zrofeet@gmail.com` in
   `qapela-privacy-policy.html` and `qapela-terms-of-use.html`.
4. **Logo files** — `assets/qapela-logo.png`, `qapela-logo-icon.png` and
   `qapela-wordmark.png` replace the old `qapela-logo*.png`. Delete the old
   ones from the repo. The admin pages load the icon from the same `assets/`
   folder, so upload `assets/` before (or with) the admin pages.

## How deployment works

Qapela has two parts that deploy separately. Both are driven by GitHub.

| Part | What it is | Where it lives | How it goes live |
|---|---|---|---|
| **Site** | The `.html` pages + `assets/` (worker, business, admin, legal…) | Repo root of `EjitechX/qapela-worker` | **GitHub Pages** publishes it automatically on every push to `main`. Live at `ejitechx.github.io/qapela-worker/` |
| **API** | `worker.js` — signup, login, wallets, payments, emails | Same repo | **Cloudflare Workers Builds** watches the repo; every push to `main` builds and deploys it to the Worker `capella-api-5c6c` |

The pages call the API at `https://capella-api-5c6c.drthankgod08.workers.dev` (the `API_BASE` line in each page).
That URL is internal — users never see it. The Worker's name can't be renamed in Cloudflare, so it keeps this name.

**The Worker is wired to Cloudflare, not to GitHub, for its settings.** These live in the Cloudflare dashboard and survive every deploy:

- D1 database `capella-db`, bound as `DB`
- Secrets: `PAYSTACK_SECRET_KEY`, `AUTH_SECRET`, `RESEND_API_KEY`
- Optional variable: `EMAIL_FROM`
- Cron trigger: `0 * * * *`

### Updating the site (pages, logos)

1. Add/replace files in the repo root (keep the `assets/` folder).
2. Commit to `main`. GitHub Pages republishes within a minute or two.
3. Hard-refresh the browser if you still see the old version.

### Updating the API (`worker.js`)

1. Replace `worker.js` in the repo with the new file and commit to `main`.
2. Cloudflare picks up the push, builds, and deploys. Watch it under **Workers & Pages → capella-api-5c6c → Deployments**.
3. Secrets and the D1 binding are kept — you do not re-enter them.

One push can contain both site and API changes; each part deploys on its own.

### If "Latest build failed" shows in Cloudflare

Most common cause: the GitHub account or repo was renamed, which breaks the link.
Go to the Worker → **Settings → Builds**, disconnect the repository, and reconnect it as `EjitechX/qapela-worker`
(production branch `main`). Then push again or press **Retry build**.

### Things to keep in sync

- `SITE_BASE` near the top of the password-reset section in `worker.js` must match the real Pages address
  (`https://ejitechx.github.io/qapela-worker/`). It builds the reset-link and email-logo URLs. Change only that line if the username or repo name changes.
- Reset emails: no domain needed with **Brevo**. Add the secret `BREVO_API_KEY` and verify `qapela.zrofeet@gmail.com` as a sender in Brevo (Senders, Domains & Dedicated IPs → Senders). Mail shows as "Qapela". `worker.js` uses Brevo when that key exists, otherwise Resend (`RESEND_API_KEY`, which only delivers to your own address until a domain is verified).
- Old referral codes: new accounts get `QAP-` codes. The database had no `CAP-` codes when checked (Oct 2026).

## Hosting on Netlify instead (or as well)

- **Main site:** drag this folder (or connect the repo; no build command, publish directory = repo root) to a Netlify site. It works as is.
  If the main site moves to Netlify, change `SITE_BASE` in `worker.js` to the Netlify address (keep the trailing `/`) so reset links and the email logo point there.
- **Admin panel:** use the separate `qapela-admin-netlify` package as its own Netlify site. It has its own sign-in page (`index.html`) and its own `assets/`.
- The Worker itself still deploys through GitHub as described above; Netlify only hosts the pages.

## Payments and withdrawals

- **Payments in:** activation fees, wallet top-ups, music and affiliate purchases are all paid online. The Worker re-checks every payment with the payment provider (right amount, success, and made by the same signed-in account) before crediting anything, and each payment reference can only be used once.
- **Withdrawals out:** fully automatic, no admin approval. Safeguards, all enforced on the server:
  - the bank account name is looked up by the server, never taken from the browser;
  - the money is taken from the balance and the withdrawal is recorded in one atomic step, only if the available balance covers it, so a balance can't go negative or be spent twice;
  - one withdrawal at a time per user; minimum, per-withdrawal (₦200,000) and daily (₦500,000, 5 attempts) limits, set in `WITHDRAWAL_LIMITS` near the top of `worker.js`;
  - failed or reversed transfers refund exactly once, even if the provider sends the same event twice;
  - if a payout can't be confirmed either way, the money stays held and the hourly job settles it, so a transfer that actually went out is never refunded;
  - every withdrawal and refund appears in the user's wallet history.
- **One-time setup in Cloudflare/Paystack:**
  1. Worker variable `PAYSTACK_PUBLIC_KEY` = your public key (`pk_live_…`). The pages read it from the API, so it is no longer pasted into any page.
  2. Paystack dashboard: turn OFF the manual confirmation (OTP) for transfers, otherwise every payout is refused and refunded.
  3. Paystack dashboard: set the webhook URL to `https://capella-api-5c6c.drthankgod08.workers.dev/webhooks/paystack-transfer`.
  4. Keep enough balance in the Paystack account to cover payouts.

## Account settings (self-service)

`qapela-account.html`, linked from the worker profile, business profile and musician pages, lets every user:
- change their name, email and phone (current password required for email/phone);
- change their password (current password required);
- delete their own account (password + typing DELETE). Deletion is blocked until the wallet is empty, no withdrawal is in progress, nothing is awaiting review, there is no open dispute, and no affiliate payout is pending, so nobody loses money or escapes an obligation. It removes personal details, signs the user out everywhere immediately, and keeps payment records without personal details.

## Business refund to bank

`qapela-business-refund.html` (button "Refund to bank" on the business dashboard) lets a business send its unused wallet balance back to its own bank account. It uses the same protections as worker withdrawals (server-resolved account name, atomic debit, one at a time, exactly-once refund on failure, hourly settlement of unconfirmed payouts) plus:
- money added by card in the last 24 hours can't be refunded yet (`holdHours` in `BUSINESS_REFUND_LIMITS` near the top of `worker.js`);
- limits: ₦1,000,000 per refund, ₦2,000,000 and 3 attempts per day;
- only the available balance is refundable, never money already used or reserved for campaigns.

It needs the `business_refunds` table (already created in the live database) and a `settleToken` column on `withdrawals` (already added).

## Keeping payouts covered (no manual settlement needed)

Payouts (withdrawals, refunds, affiliate payments) are sent from the Paystack balance. The admin dashboard now shows the **payment account balance**, **what is owed to users** and the **surplus**. Rules of thumb:
- Only move money out to your own bank when the surplus is positive, and never more than the surplus.
- If it shows a shortfall, top up the Paystack balance (dashboard → Transfers/Balance).
- The Worker checks the balance before taking money from a wallet, so a low balance gives users a "temporarily unavailable" message instead of a failed payout, and it leaves an alert in the admin fraud/alerts list once a day while the balance is below what is owed.

## Revenue (admin)

The admin **Revenue** page (`qapela-admin-finance.html`) shows what Qapela earns, split by source — activation fees, task service margin, music sales fees, affiliate fees, and the reserve set aside from task payouts — each with its own Withdraw button, plus the total of all streams with a **Withdraw all revenue** button.
- Every withdrawal goes to the bank account chosen on that page; the account name is looked up by the server.
- A withdrawal can never exceed what that stream has actually earned and not yet withdrawn, and never exceeds the cash that sits above what is owed to users.
- One revenue withdrawal at a time; failures put the money back exactly once; unconfirmed ones are settled by the hourly check.
- Needs the `revenue_withdrawals` and `revenue_withdrawal_items` tables (already created in the live database).
- The old "reserve withdrawal" form and endpoint were removed; the reserve is now one of the streams.
