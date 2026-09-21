-- ============================================================
-- IY Maintain — SUPER ADMIN LOGIN BOOTSTRAP
-- ============================================================
-- Run IY-Maintain-V7.00-Super-Admin-Platform-Control-Center.sql first.
-- The Auth account must already exist in Supabase Authentication.
-- Replace the email below with the account that should be the
-- IY Maintain platform administrator.
-- ============================================================

BEGIN;

DO $$
DECLARE
    v_email text := lower(trim('REPLACE_WITH_SUPER_ADMIN_EMAIL'));
    v_user_id uuid;
    v_company_id uuid;
    v_full_name text;
BEGIN
    IF v_email = 'replace_with_super_admin_email' OR v_email = '' THEN
        RAISE EXCEPTION 'Replace REPLACE_WITH_SUPER_ADMIN_EMAIL with the real Supabase Auth email before running this script.';
    END IF;

    SELECT u.id,
           COALESCE(NULLIF(trim(u.raw_user_meta_data->>'full_name'),''), split_part(COALESCE(u.email,''),'@',1))
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
        RAISE EXCEPTION 'The Auth account % does not have an active company membership. Create the account and attach it to the intended company first.', v_email;
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

    RAISE NOTICE 'Super Admin authorization granted to % (user %).', v_email, v_user_id;
END $$;

COMMIT;

SELECT id,user_id,company_id,full_name,email,role,is_active
FROM public.memberships
WHERE lower(role)='super_admin'
ORDER BY created_at DESC;

SELECT to_regprocedure('public.super_admin_is_authorized()') AS authorization_function;
