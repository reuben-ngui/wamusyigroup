# Merry-Go-Round Number Selector (v2)

Static website (Vercel) + Supabase (database, auth, realtime).

## Files
index.html (members) · admin/index.html (administrator) · config.js · style.css · vercel.json · schema.sql

## Setup
1. Supabase > Authentication > Sign In / Providers: turn OFF "Allow new users to sign up".
2. Supabase > SQL Editor: paste all of schema.sql and Run. (Replaces earlier test tables.)
3. Supabase > Authentication > Users > Add user: your admin email + password, tick Auto Confirm.
   The FIRST user created becomes the one and only administrator (enforced by the database).
4. Supabase > Authentication > URL Configuration: set Site URL to your Vercel address and add
   https://YOUR-SITE.vercel.app/admin/ to Redirect URLs (needed for "Forgot password").
5. config.js already holds your public Supabase URL and publishable key. Push to GitHub; Vercel redeploys.
6. Open /admin/login, log in, Registration Settings > create the 4 invitation codes, send each link privately.

## Tests (run before sharing)
- Four test invitations: each gets a different number, the 5th attempt is refused.
- Same invitation twice or after refresh: same number, never a new one.
- Two phones tapping at once: never a duplicate number.
- Number cards on a second device turn "Taken" without refreshing.
- /admin/login rejects any other account; Reset needs the admin password; old rounds appear in Previous Rounds.
