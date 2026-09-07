IY Maintain V24.13 — Users & Roles Management

Changes:
- Users & Roles supports inviting new users from the workspace.
- Added Remove action for users other than the signed-in administrator.
- Removing a user deletes their company membership, immediately removing workspace access while preserving their Supabase Auth account for possible future re-invitation.
- Self-removal is blocked.
- User management remains company-scoped through Supabase RLS.
- System version updated to V24.13.
