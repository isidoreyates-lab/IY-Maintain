# IY Maintain — Backup & Restore Update

## What changed
- Restore System Backup is now functional for the IY Maintain JSON backup format.
- Restore is restricted to the `company_admin` role.
- The restore checks the backup company ID when available and blocks cross-company restores.
- A two-step confirmation is required before replacement.
- User accounts, passwords, Supabase Auth IDs and memberships are not replaced by the restore.
- Company records are restored into the currently authenticated company workspace.
- The backup download now records the company ID and company name for safer future restores.

## Deployment
Replace the production `index.html` with this file and deploy it to GitHub Pages.

No RLS policies need to be disabled.
