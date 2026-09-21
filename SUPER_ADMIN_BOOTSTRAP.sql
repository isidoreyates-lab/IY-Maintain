-- ============================================================
-- IY Maintain — SUPER ADMIN LOGIN BOOTSTRAP
-- ============================================================
-- Purpose:
--   Authorize one Supabase Auth account as a global Super Admin.
--
-- IMPORTANT:
--   1. Run IY-Maintain-V7.00-Super-Admin-Platform-Control-Center.sql first.
--   2. The Auth account must already exist in Supabase Authentication.
--   3. Replace the email below.
--   4. If the account already belongs to an active company, the script
--      will use that company automatically. For a brand-new Auth account,
--      replace REPLACE_WITH_COMPANY_ID with an existing company UUID.
--   5. This does NOT create/change the Auth password. Passwords remain
--      managed by Supabase Authentication.
-- ============================================================

BEGIN;

DO $$
DECLARE
    v_email text := lower(trim('REPLACE_WITH_SUPER_ADMIN_EMAIL'));
    v_company_id uuid := NULL;
    v_company_override text := trim('REPLACE_WITH_COMPANY_ID');
    v_user_id uuid;
    v_full_name text;
BEGIN
    IF v_email = 'replace_with_super_admin_email' OR v_email = '' THEN
        RAISE EXCEPTION 'Replace REPLACE_WITH_SUPER_ADMIN_EMAIL with the real Supabase Auth email before running this script.';
    END IF;

    SELECT u.id,
           COALESCE(
             NULLIF(trim(u.raw_user_meta_data->>'full_name'),''),
             split_part(COALESCE(u.email,''),'@',1)
           )
      INTO v_user_id, v_full_name
    FROM auth.users u
    WHERE lower(u.email) = v_email
    ORDER BY u.created_at ASC
    LIMIT 1;

    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'No Supabase Auth user exists for %.', v_email;
    END IF;

    SELECT m.company_id
      INTO v_company_id
    FROM public.memberships m
    WHERE m.user_id = v_user_id
      AND m.is_active = true
    ORDER BY m.created_at ASC
    LIMIT 1;

    IF v_company_id IS NULL THEN
        IF v_company_override = '' OR lower(v_company_override) = 'replace_with_company_id' THEN
            RAISE EXCEPTION 'No active company membership found for %. Replace REPLACE_WITH_COMPANY_ID with an existing company UUID.', v_email;
        END IF;

        BEGIN
            v_company_id := v_company_override::uuid;
        EXCEPTION WHEN invalid_text_representation THEN
            RAISE EXCEPTION 'REPLACE_WITH_COMPANY_ID must be a valid company UUID.';
        END;

        IF NOT EXISTS (SELECT 1 FROM public.companies c WHERE c.id = v_company_id) THEN
            RAISE EXCEPTION 'Company % does not exist.', v_company_id;
        END IF;
    END IF;

    INSERT INTO public.memberships(
        company_id,user_id,full_name,email,role,site_id,department_id,department,is_active
    )
    VALUES(
        v_company_id,v_user_id,v_full_name,v_email,'super_admin',NULL,NULL,NULL,true
    )
    ON CONFLICT (company_id, user_id)
    DO UPDATE SET
        full_name=EXCLUDED.full_name,
        email=EXCLUDED.email,
        role='super_admin',
        site_id=NULL,
        department_id=NULL,
        department=NULL,
        is_active=true;

    RAISE NOTICE 'Super Admin authorization granted to % (user %, company %).', v_email, v_user_id, v_company_id;
END $$;

COMMIT;

SELECT
    m.id,
    m.user_id,
    m.company_id,
    m.full_name,
    m.email,
    m.role,
    m.is_active
FROM public.memberships m
WHERE lower(m.role) = 'super_admin'
ORDER BY m.created_at DESC;

SELECT to_regprocedure('public.super_admin_is_authorized()') AS authorization_function;
