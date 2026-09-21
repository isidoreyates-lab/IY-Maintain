-- ============================================================
-- IY Maintain V7.00 — SUPER ADMIN PLATFORM CONTROL CENTER
-- ============================================================
-- Purpose:
--   Create a GLOBAL Super Admin backend layer without changing
--   existing customer-facing RLS policies or V24.81 maintenance,
--   approval, reporting, subscription, or billing workflows.
--
-- Security model:
--   Every function independently verifies that auth.uid() belongs
--   to at least one active membership whose role is super_admin.
--   Functions are SECURITY DEFINER with an empty search_path.
--   They provide controlled cross-company reads and administration.
--
-- Notes:
--   - Stripe remains the source of truth for Stripe-billed payment
--     state. This migration does NOT fabricate Stripe subscription
--     status or cancel/reactivate Stripe subscriptions.
--   - Company creation can optionally attach an EXISTING auth user
--     as the initial Company Administrator by email. Creating a new
--     auth account/invitation remains an Edge Function concern.
--   - Existing customer RLS policies are intentionally untouched.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 1. Global Super Admin authorization helper
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.super_admin_is_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.memberships m
        WHERE m.user_id = (SELECT auth.uid())
          AND m.is_active = true
          AND lower(m.role) = 'super_admin'
    );
$$;

REVOKE ALL ON FUNCTION public.super_admin_is_authorized() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_is_authorized() TO authenticated;

-- ------------------------------------------------------------
-- 2. Platform-wide dashboard snapshot
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.super_admin_platform_snapshot()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid := (SELECT auth.uid());
    v_result jsonb;
BEGIN
    IF v_user IS NULL OR NOT public.super_admin_is_authorized() THEN
        RAISE EXCEPTION 'Super Admin access is required.';
    END IF;

    SELECT jsonb_build_object(
        'generated_at', now(),
        'metrics', jsonb_build_object(
            'total_companies', (SELECT count(*) FROM public.companies),
            'active_companies', (
                SELECT count(*)
                FROM public.companies c
                JOIN LATERAL (
                    SELECT s.status
                    FROM public.subscriptions s
                    WHERE s.company_id=c.id
                    ORDER BY (CASE WHEN s.status IN ('trialing','active','past_due','suspended') THEN 0 ELSE 1 END), s.created_at DESC
                    LIMIT 1
                ) current_sub ON true
                WHERE current_sub.status='active'
            ),
            'trial_companies', (
                SELECT count(*)
                FROM public.companies c
                JOIN LATERAL (
                    SELECT s.status
                    FROM public.subscriptions s
                    WHERE s.company_id=c.id
                    ORDER BY (CASE WHEN s.status IN ('trialing','active','past_due','suspended') THEN 0 ELSE 1 END), s.created_at DESC
                    LIMIT 1
                ) current_sub ON true
                WHERE current_sub.status='trialing'
            ),
            'past_due_companies', (
                SELECT count(*)
                FROM public.companies c
                JOIN LATERAL (
                    SELECT s.status
                    FROM public.subscriptions s
                    WHERE s.company_id=c.id
                    ORDER BY (CASE WHEN s.status IN ('trialing','active','past_due','suspended') THEN 0 ELSE 1 END), s.created_at DESC
                    LIMIT 1
                ) current_sub ON true
                WHERE current_sub.status='past_due'
            ),
            'suspended_companies', (
                SELECT count(*)
                FROM public.companies c
                JOIN LATERAL (
                    SELECT s.status
                    FROM public.subscriptions s
                    WHERE s.company_id=c.id
                    ORDER BY (CASE WHEN s.status IN ('trialing','active','past_due','suspended') THEN 0 ELSE 1 END), s.created_at DESC
                    LIMIT 1
                ) current_sub ON true
                WHERE current_sub.status='suspended'
            ),
            'expired_or_canceled_companies', (
                SELECT count(*)
                FROM public.companies c
                WHERE NOT EXISTS (
                    SELECT 1 FROM public.subscriptions s
                    WHERE s.company_id = c.id
                      AND s.status IN ('trialing','active','past_due','suspended')
                )
            ),
            'active_users', (SELECT count(*) FROM public.memberships WHERE is_active = true),
            'total_memberships', (SELECT count(*) FROM public.memberships),
            'sites', (SELECT count(*) FROM public.sites WHERE is_active = true),
            'departments', (SELECT count(*) FROM public.departments WHERE is_active = true),
            'machines', (SELECT count(*) FROM public.machines),
            'parts', (SELECT count(*) FROM public.parts),
            'inventory_records', (SELECT count(*) FROM public.inventory),
            'maintenance_records', (SELECT count(*) FROM public.maintenance_records),
            'open_approvals', (SELECT count(*) FROM public.report_approval_requests WHERE status = 'pending'),
            'failed_payments', (SELECT count(*) FROM public.subscriptions WHERE stripe_last_payment_failed_at IS NOT NULL),
            'failed_webhooks', (SELECT count(*) FROM public.stripe_webhook_events WHERE status = 'failed')
        ),
        'recent_activity', COALESCE((
            SELECT jsonb_agg(to_jsonb(a) ORDER BY a.created_at DESC)
            FROM (
                SELECT
                    al.id,
                    al.company_id,
                    (SELECT c.name FROM public.companies c WHERE c.id = al.company_id) AS company_name,
                    al.user_id,
                    (SELECT m.full_name FROM public.memberships m
                     WHERE m.user_id = al.user_id AND m.company_id = al.company_id
                     ORDER BY m.created_at DESC LIMIT 1) AS actor_name,
                    al.action,
                    al.module,
                    al.details,
                    al.created_at
                FROM public.audit_logs al
                ORDER BY al.created_at DESC
                LIMIT 30
            ) a
        ), '[]'::jsonb),
        'failed_webhook_events', COALESCE((
            SELECT jsonb_agg(to_jsonb(w) ORDER BY w.received_at DESC)
            FROM (
                SELECT
                    swe.id,
                    swe.stripe_event_id,
                    swe.event_type,
                    swe.status,
                    swe.last_error,
                    swe.received_at,
                    swe.processed_at,
                    (swe.payload->'data'->'object'->>'id') AS stripe_object_id,
                    (swe.payload->'data'->'object'->>'customer') AS stripe_customer_id
                FROM public.stripe_webhook_events swe
                WHERE swe.status = 'failed'
                ORDER BY swe.received_at DESC
                LIMIT 20
            ) w
        ), '[]'::jsonb),
        'recent_billing', COALESCE((
            SELECT jsonb_agg(to_jsonb(b) ORDER BY b.created_at DESC)
            FROM (
                SELECT
                    bcs.id,
                    bcs.company_id,
                    (SELECT c.name FROM public.companies c WHERE c.id = bcs.company_id) AS company_name,
                    bcs.subscription_id,
                    bcs.plan_id,
                    (SELECT p.code FROM public.subscription_plans p WHERE p.id = bcs.plan_id) AS plan_code,
                    bcs.billing_interval,
                    bcs.currency,
                    bcs.amount,
                    bcs.status,
                    bcs.provider_checkout_id,
                    bcs.provider_reference,
                    bcs.created_at,
                    bcs.updated_at
                FROM public.billing_checkout_sessions bcs
                ORDER BY bcs.created_at DESC
                LIMIT 20
            ) b
        ), '[]'::jsonb)
    ) INTO v_result;

    RETURN v_result;
END;
$$;

REVOKE ALL ON FUNCTION public.super_admin_platform_snapshot() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_platform_snapshot() TO authenticated;

-- ------------------------------------------------------------
-- 3. Global company directory
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.super_admin_list_companies(
    p_search text DEFAULT NULL,
    p_status text DEFAULT NULL,
    p_plan_code text DEFAULT NULL,
    p_limit integer DEFAULT 100,
    p_offset integer DEFAULT 0
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid := (SELECT auth.uid());
    v_limit integer := LEAST(GREATEST(COALESCE(p_limit,100),1),500);
    v_offset integer := GREATEST(COALESCE(p_offset,0),0);
    v_result jsonb;
BEGIN
    IF v_user IS NULL OR NOT public.super_admin_is_authorized() THEN
        RAISE EXCEPTION 'Super Admin access is required.';
    END IF;

    SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.created_at DESC), '[]'::jsonb)
    INTO v_result
    FROM (
        SELECT
            c.id,
            c.name,
            c.address,
            c.telephone,
            c.email,
            c.website,
            c.created_at,
            c.updated_at,
            cs.logo_path,
            sub.id AS subscription_id,
            sub.status AS subscription_status,
            sub.billing_interval,
            sub.current_period_start,
            sub.current_period_end,
            sub.cancel_at_period_end,
            sub.canceled_at,
            sub.stripe_customer_id,
            sub.stripe_subscription_id,
            p.id AS plan_id,
            p.code AS plan_code,
            p.name AS plan_name,
            p.max_sites,
            p.max_departments,
            p.max_employees,
            p.max_machines,
            p.max_parts,
            p.max_suppliers,
            (SELECT count(*) FROM public.memberships m WHERE m.company_id = c.id AND m.is_active = true) AS users_count,
            (SELECT count(*) FROM public.sites s WHERE s.company_id = c.id AND s.is_active = true) AS sites_count,
            (SELECT count(*) FROM public.departments d WHERE d.company_id = c.id AND d.is_active = true) AS departments_count,
            (SELECT count(*) FROM public.machines m WHERE m.company_id = c.id) AS machines_count,
            (SELECT count(*) FROM public.parts pt WHERE pt.company_id = c.id) AS parts_count,
            (SELECT max(al.created_at) FROM public.audit_logs al WHERE al.company_id = c.id) AS last_activity_at
        FROM public.companies c
        LEFT JOIN public.company_settings cs ON cs.company_id = c.id
        LEFT JOIN LATERAL (
            SELECT s.*
            FROM public.subscriptions s
            WHERE s.company_id = c.id
            ORDER BY (CASE WHEN s.status IN ('trialing','active','past_due','suspended') THEN 0 ELSE 1 END), s.created_at DESC
            LIMIT 1
        ) sub ON true
        LEFT JOIN public.subscription_plans p ON p.id = sub.plan_id
        WHERE (
            nullif(btrim(p_search), '') IS NULL
            OR c.name ILIKE '%' || btrim(p_search) || '%'
            OR COALESCE(c.email,'') ILIKE '%' || btrim(p_search) || '%'
            OR c.id::text ILIKE '%' || btrim(p_search) || '%'
        )
        AND (
            nullif(btrim(p_status), '') IS NULL
            OR lower(COALESCE(sub.status,'')) = lower(btrim(p_status))
        )
        AND (
            nullif(btrim(p_plan_code), '') IS NULL
            OR upper(COALESCE(p.code,'')) = upper(btrim(p_plan_code))
        )
        ORDER BY c.created_at DESC
        OFFSET v_offset
        LIMIT v_limit
    ) x;

    RETURN v_result;
END;
$$;

REVOKE ALL ON FUNCTION public.super_admin_list_companies(text,text,text,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_list_companies(text,text,text,integer,integer) TO authenticated;

-- ------------------------------------------------------------
-- 4. Complete company detail
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.super_admin_company_detail(p_company_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid := (SELECT auth.uid());
    v_company_exists boolean;
    v_result jsonb;
BEGIN
    IF v_user IS NULL OR NOT public.super_admin_is_authorized() THEN
        RAISE EXCEPTION 'Super Admin access is required.';
    END IF;

    SELECT EXISTS (SELECT 1 FROM public.companies c WHERE c.id = p_company_id)
    INTO v_company_exists;

    IF NOT v_company_exists THEN
        RAISE EXCEPTION 'Company not found.';
    END IF;

    SELECT jsonb_build_object(
        'company', (
            SELECT to_jsonb(c)
            FROM public.companies c
            WHERE c.id = p_company_id
        ),
        'settings', (
            SELECT to_jsonb(cs)
            FROM public.company_settings cs
            WHERE cs.company_id = p_company_id
        ),
        'subscription', (
            SELECT to_jsonb(s)
            FROM public.subscriptions s
            WHERE s.company_id = p_company_id
            ORDER BY (CASE WHEN s.status IN ('trialing','active','past_due','suspended') THEN 0 ELSE 1 END), s.created_at DESC
            LIMIT 1
        ),
        'plan', (
            SELECT to_jsonb(p)
            FROM public.subscription_plans p
            WHERE p.id = (
                SELECT s.plan_id FROM public.subscriptions s
                WHERE s.company_id = p_company_id
                ORDER BY (CASE WHEN s.status IN ('trialing','active','past_due','suspended') THEN 0 ELSE 1 END), s.created_at DESC
                LIMIT 1
            )
        ),
        'metrics', jsonb_build_object(
            'users', (SELECT count(*) FROM public.memberships m WHERE m.company_id = p_company_id AND m.is_active=true),
            'sites', (SELECT count(*) FROM public.sites s WHERE s.company_id = p_company_id AND s.is_active=true),
            'departments', (SELECT count(*) FROM public.departments d WHERE d.company_id = p_company_id AND d.is_active=true),
            'machines', (SELECT count(*) FROM public.machines m WHERE m.company_id = p_company_id),
            'parts', (SELECT count(*) FROM public.parts pt WHERE pt.company_id = p_company_id),
            'inventory', (SELECT count(*) FROM public.inventory i WHERE i.company_id = p_company_id),
            'maintenance', (SELECT count(*) FROM public.maintenance_records mr WHERE mr.company_id = p_company_id),
            'open_approvals', (SELECT count(*) FROM public.report_approval_requests r WHERE r.company_id = p_company_id AND r.status='pending')
        ),
        'users', COALESCE((
            SELECT jsonb_agg(to_jsonb(m) ORDER BY m.created_at ASC)
            FROM (
                SELECT id,user_id,user_code,full_name,email,role,department,site_id,department_id,is_active,last_login_at,invited_at,created_at
                FROM public.memberships
                WHERE company_id = p_company_id
                ORDER BY created_at ASC
            ) m
        ), '[]'::jsonb),
        'sites', COALESCE((
            SELECT jsonb_agg(to_jsonb(s) ORDER BY s.created_at ASC)
            FROM public.sites s
            WHERE s.company_id = p_company_id
        ), '[]'::jsonb),
        'departments', COALESCE((
            SELECT jsonb_agg(to_jsonb(d) ORDER BY d.created_at ASC)
            FROM public.departments d
            WHERE d.company_id = p_company_id
        ), '[]'::jsonb),
        'recent_billing', COALESCE((
            SELECT jsonb_agg(to_jsonb(b) ORDER BY b.created_at DESC)
            FROM (
                SELECT id,subscription_id,plan_id,billing_interval,currency,amount,status,provider_checkout_id,provider_reference,checkout_url,expires_at,created_at,updated_at
                FROM public.billing_checkout_sessions
                WHERE company_id = p_company_id
                ORDER BY created_at DESC
                LIMIT 25
            ) b
        ), '[]'::jsonb),
        'recent_activity', COALESCE((
            SELECT jsonb_agg(to_jsonb(a) ORDER BY a.created_at DESC)
            FROM (
                SELECT
                    al.id,
                    al.user_id,
                    (SELECT m.full_name FROM public.memberships m WHERE m.user_id=al.user_id AND m.company_id=al.company_id ORDER BY m.created_at DESC LIMIT 1) AS actor_name,
                    al.action,
                    al.module,
                    al.details,
                    al.created_at
                FROM public.audit_logs al
                WHERE al.company_id = p_company_id
                ORDER BY al.created_at DESC
                LIMIT 50
            ) a
        ), '[]'::jsonb)
    ) INTO v_result;

    RETURN v_result;
END;
$$;

REVOKE ALL ON FUNCTION public.super_admin_company_detail(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_company_detail(uuid) TO authenticated;

-- ------------------------------------------------------------
-- 5. Update company information
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.super_admin_update_company(
    p_company_id uuid,
    p_name text,
    p_address text DEFAULT NULL,
    p_telephone text DEFAULT NULL,
    p_email text DEFAULT NULL,
    p_website text DEFAULT NULL,
    p_reason text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid := (SELECT auth.uid());
    v_before jsonb;
    v_after jsonb;
BEGIN
    IF v_user IS NULL OR NOT public.super_admin_is_authorized() THEN
        RAISE EXCEPTION 'Super Admin access is required.';
    END IF;

    IF p_company_id IS NULL OR NOT EXISTS (SELECT 1 FROM public.companies c WHERE c.id=p_company_id) THEN
        RAISE EXCEPTION 'Company not found.';
    END IF;

    IF nullif(btrim(p_name), '') IS NULL THEN
        RAISE EXCEPTION 'Company name is required.';
    END IF;

    SELECT jsonb_build_object(
        'name', c.name,
        'address', c.address,
        'telephone', c.telephone,
        'email', c.email,
        'website', c.website
    )
    INTO v_before
    FROM public.companies c
    WHERE c.id=p_company_id;

    UPDATE public.companies
    SET
        name = btrim(p_name),
        address = NULLIF(btrim(COALESCE(p_address,'')),''),
        telephone = NULLIF(btrim(COALESCE(p_telephone,'')),''),
        email = NULLIF(btrim(COALESCE(p_email,'')),''),
        website = NULLIF(btrim(COALESCE(p_website,'')),''),
        updated_at = now()
    WHERE id = p_company_id;

    SELECT jsonb_build_object(
        'name', c.name,
        'address', c.address,
        'telephone', c.telephone,
        'email', c.email,
        'website', c.website
    )
    INTO v_after
    FROM public.companies c
    WHERE c.id=p_company_id;

    INSERT INTO public.audit_logs(company_id,user_id,action,module,details)
    VALUES(
        p_company_id,
        v_user,
        'Super Admin updated company',
        'super_admin',
        jsonb_build_object(
            'reason', NULLIF(btrim(COALESCE(p_reason,'')),''),
            'before', v_before,
            'after', v_after
        )::text
    );

    RETURN jsonb_build_object('success',true,'company',v_after);
END;
$$;

REVOKE ALL ON FUNCTION public.super_admin_update_company(uuid,text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_update_company(uuid,text,text,text,text,text,text) TO authenticated;

-- ------------------------------------------------------------
-- 6. Manual company creation
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.super_admin_create_company(
    p_name text,
    p_address text DEFAULT NULL,
    p_telephone text DEFAULT NULL,
    p_email text DEFAULT NULL,
    p_website text DEFAULT NULL,
    p_plan_code text DEFAULT 'BASIC',
    p_billing_interval text DEFAULT 'monthly',
    p_initial_admin_email text DEFAULT NULL,
    p_initial_site_name text DEFAULT NULL,
    p_initial_site_code text DEFAULT NULL,
    p_initial_site_address text DEFAULT NULL,
    p_initial_department_name text DEFAULT NULL,
    p_initial_department_code text DEFAULT NULL,
    p_reason text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid := (SELECT auth.uid());
    v_company uuid;
    v_plan_id uuid;
    v_trial_days integer;
    v_admin_user_id uuid;
    v_site_id uuid;
    v_department_id uuid;
    v_subscription_id uuid;
    v_interval text := CASE WHEN lower(btrim(COALESCE(p_billing_interval,'')))='annual' THEN 'annual' ELSE 'monthly' END;
BEGIN
    IF v_user IS NULL OR NOT public.super_admin_is_authorized() THEN
        RAISE EXCEPTION 'Super Admin access is required.';
    END IF;

    IF nullif(btrim(p_name),'') IS NULL THEN
        RAISE EXCEPTION 'Company name is required.';
    END IF;

    SELECT id,trial_days
    INTO v_plan_id,v_trial_days
    FROM public.subscription_plans
    WHERE upper(code)=upper(btrim(COALESCE(p_plan_code,'BASIC')))
      AND is_active=true
    ORDER BY display_order,created_at
    LIMIT 1;

    IF v_plan_id IS NULL THEN
        RAISE EXCEPTION 'The selected plan is not active or does not exist.';
    END IF;

    INSERT INTO public.companies(name,address,telephone,email,website)
    VALUES(
        btrim(p_name),
        NULLIF(btrim(COALESCE(p_address,'')),''),
        NULLIF(btrim(COALESCE(p_telephone,'')),''),
        NULLIF(btrim(COALESCE(p_email,'')),''),
        NULLIF(btrim(COALESCE(p_website,'')),'' )
    )
    RETURNING id INTO v_company;

    INSERT INTO public.company_settings(company_id)
    VALUES(v_company)
    ON CONFLICT(company_id) DO NOTHING;

    -- New manually created companies begin on the configured trial period.
    INSERT INTO public.subscriptions(
        company_id,
        plan_id,
        status,
        billing_interval,
        trial_started_at,
        trial_ends_at,
        started_at,
        current_period_start,
        current_period_end,
        cancel_at_period_end
    )
    VALUES(
        v_company,
        v_plan_id,
        'trialing',
        v_interval,
        now(),
        now() + make_interval(days => COALESCE(v_trial_days,14)),
        now(),
        now(),
        CASE WHEN v_interval='annual' THEN now() + interval '1 year' ELSE now() + interval '1 month' END,
        false
    )
    RETURNING id INTO v_subscription_id;

    -- Optional initial site.
    IF nullif(btrim(COALESCE(p_initial_site_name,'')),'') IS NOT NULL THEN
        INSERT INTO public.sites(company_id,name,code,address,is_active)
        VALUES(
            v_company,
            btrim(p_initial_site_name),
            NULLIF(btrim(COALESCE(p_initial_site_code,'')),''),
            NULLIF(btrim(COALESCE(p_initial_site_address,'')),''),
            true
        )
        RETURNING id INTO v_site_id;
    END IF;

    -- Optional initial department. A site is required for a department.
    IF nullif(btrim(COALESCE(p_initial_department_name,'')),'') IS NOT NULL THEN
        IF v_site_id IS NULL THEN
            RAISE EXCEPTION 'An initial site is required when creating an initial department.';
        END IF;
        INSERT INTO public.departments(company_id,site_id,name,code,is_active)
        VALUES(
            v_company,
            v_site_id,
            btrim(p_initial_department_name),
            NULLIF(btrim(COALESCE(p_initial_department_code,'')),''),
            true
        )
        RETURNING id INTO v_department_id;
    END IF;

    -- Optional attachment of an already registered auth account.
    IF nullif(btrim(COALESCE(p_initial_admin_email,'')),'') IS NOT NULL THEN
        SELECT id
        INTO v_admin_user_id
        FROM auth.users
        WHERE lower(email)=lower(btrim(p_initial_admin_email))
        ORDER BY created_at ASC
        LIMIT 1;

        IF v_admin_user_id IS NOT NULL THEN
            INSERT INTO public.memberships(
                company_id,user_id,full_name,email,role,site_id,department_id,is_active
            )
            SELECT
                v_company,
                v_admin_user_id,
                COALESCE(NULLIF(btrim(COALESCE((u.raw_user_meta_data->>'full_name'),'')),''),btrim(COALESCE(u.email,'User'))),
                u.email,
                'company_admin',
                NULL,
                NULL,
                true
            FROM auth.users u
            WHERE u.id=v_admin_user_id
            ON CONFLICT DO NOTHING;
        END IF;
    END IF;

    INSERT INTO public.audit_logs(company_id,user_id,action,module,details)
    VALUES(
        v_company,
        v_user,
        'Super Admin created company',
        'super_admin',
        jsonb_build_object(
            'reason',NULLIF(btrim(COALESCE(p_reason,'')),''),
            'plan_code',upper(btrim(COALESCE(p_plan_code,'BASIC'))),
            'billing_interval',v_interval,
            'initial_admin_email',NULLIF(btrim(COALESCE(p_initial_admin_email,'')),''),
            'admin_account_found',v_admin_user_id IS NOT NULL,
            'initial_site_id',v_site_id,
            'initial_department_id',v_department_id
        )::text
    );

    RETURN jsonb_build_object(
        'success',true,
        'company_id',v_company,
        'subscription_id',v_subscription_id,
        'site_id',v_site_id,
        'department_id',v_department_id,
        'admin_user_id',v_admin_user_id,
        'admin_account_found',v_admin_user_id IS NOT NULL
    );
END;
$$;

REVOKE ALL ON FUNCTION public.super_admin_create_company(text,text,text,text,text,text,text,text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_create_company(text,text,text,text,text,text,text,text,text,text,text,text,text) TO authenticated;

-- ------------------------------------------------------------
-- 7. Global users directory
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.super_admin_list_users(
    p_search text DEFAULT NULL,
    p_limit integer DEFAULT 200,
    p_offset integer DEFAULT 0
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid := (SELECT auth.uid());
    v_result jsonb;
BEGIN
    IF v_user IS NULL OR NOT public.super_admin_is_authorized() THEN
        RAISE EXCEPTION 'Super Admin access is required.';
    END IF;

    SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.last_seen_at DESC NULLS LAST), '[]'::jsonb)
    INTO v_result
    FROM (
        SELECT
            au.id AS user_id,
            au.email,
            COALESCE(
                (SELECT m.full_name FROM public.memberships m WHERE m.user_id=au.id ORDER BY m.created_at DESC LIMIT 1),
                au.raw_user_meta_data->>'full_name'
            ) AS full_name,
            (SELECT max(m.last_login_at) FROM public.memberships m WHERE m.user_id=au.id) AS last_seen_at,
            (SELECT count(*) FROM public.memberships m WHERE m.user_id=au.id AND m.is_active=true) AS active_memberships,
            (SELECT count(DISTINCT m.company_id) FROM public.memberships m WHERE m.user_id=au.id) AS company_count,
            COALESCE((
                SELECT jsonb_agg(jsonb_build_object(
                    'membership_id',m.id,
                    'company_id',m.company_id,
                    'company_name',(SELECT c.name FROM public.companies c WHERE c.id=m.company_id),
                    'role',m.role,
                    'site_id',m.site_id,
                    'department_id',m.department_id,
                    'is_active',m.is_active
                ) ORDER BY m.created_at ASC)
                FROM public.memberships m
                WHERE m.user_id=au.id
            ),'[]'::jsonb) AS memberships
        FROM auth.users au
        WHERE EXISTS (SELECT 1 FROM public.memberships m0 WHERE m0.user_id=au.id)
          AND (
            nullif(btrim(p_search),'') IS NULL
            OR COALESCE(au.email,'') ILIKE '%'||btrim(p_search)||'%'
            OR COALESCE(au.raw_user_meta_data->>'full_name','') ILIKE '%'||btrim(p_search)||'%'
            OR au.id::text ILIKE '%'||btrim(p_search)||'%'
            OR EXISTS (
                SELECT 1 FROM public.memberships ms
                WHERE ms.user_id=au.id
                  AND (COALESCE(ms.full_name,'') ILIKE '%'||btrim(p_search)||'%' OR COALESCE(ms.user_code,'') ILIKE '%'||btrim(p_search)||'%')
            )
          )
        ORDER BY last_seen_at DESC NULLS LAST, au.created_at DESC
        OFFSET GREATEST(COALESCE(p_offset,0),0)
        LIMIT LEAST(GREATEST(COALESCE(p_limit,200),1),500)
    ) x;

    RETURN v_result;
END;
$$;

REVOKE ALL ON FUNCTION public.super_admin_list_users(text,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_list_users(text,integer,integer) TO authenticated;

-- ------------------------------------------------------------
-- 8. Update an existing company membership/user assignment
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.super_admin_update_membership(
    p_membership_id uuid,
    p_full_name text,
    p_role text,
    p_site_id uuid DEFAULT NULL,
    p_department_id uuid DEFAULT NULL,
    p_is_active boolean DEFAULT true,
    p_reason text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid := (SELECT auth.uid());
    v_company_id uuid;
    v_before jsonb;
    v_after jsonb;
    v_role text := lower(btrim(COALESCE(p_role,'')));
BEGIN
    IF v_user IS NULL OR NOT public.super_admin_is_authorized() THEN
        RAISE EXCEPTION 'Super Admin access is required.';
    END IF;

    SELECT m.company_id INTO v_company_id
    FROM public.memberships m
    WHERE m.id=p_membership_id;

    IF v_company_id IS NULL THEN
        RAISE EXCEPTION 'Membership not found.';
    END IF;

    IF EXISTS (
        SELECT 1 FROM public.memberships m
        WHERE m.id=p_membership_id AND lower(m.role)='super_admin' AND v_role<>'super_admin'
    ) THEN
        RAISE EXCEPTION 'A Super Admin membership cannot be demoted from this screen.';
    END IF;

    IF v_role NOT IN ('company_admin','manager','site_supervisor','department_supervisor','team_lead','parts_coordinator','technician','viewer','super_admin') THEN
        RAISE EXCEPTION 'Invalid application role.';
    END IF;

    IF v_role='super_admin' THEN
        RAISE EXCEPTION 'Super Admin role changes require the dedicated Super Admin security workflow.';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public.memberships m
        WHERE m.id=p_membership_id AND m.company_id=v_company_id
    ) THEN
        RAISE EXCEPTION 'Membership not found.';
    END IF;

    IF p_site_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM public.sites s WHERE s.id=p_site_id AND s.company_id=v_company_id AND s.is_active=true
    ) THEN
        RAISE EXCEPTION 'The selected site does not belong to this company.';
    END IF;

    IF p_department_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM public.departments d
        WHERE d.id=p_department_id AND d.company_id=v_company_id AND d.is_active=true
          AND (p_site_id IS NULL OR d.site_id=p_site_id)
    ) THEN
        RAISE EXCEPTION 'The selected department does not belong to the selected site/company.';
    END IF;

    SELECT jsonb_build_object('full_name',m.full_name,'role',m.role,'site_id',m.site_id,'department_id',m.department_id,'is_active',m.is_active)
    INTO v_before
    FROM public.memberships m WHERE m.id=p_membership_id;

    UPDATE public.memberships m
    SET
        full_name = COALESCE(NULLIF(btrim(COALESCE(p_full_name,'')),''),m.full_name),
        role = v_role,
        site_id = CASE WHEN v_role IN ('company_admin','manager') THEN NULL ELSE p_site_id END,
        department_id = CASE WHEN v_role IN ('company_admin','manager','site_supervisor') THEN NULL ELSE p_department_id END,
        department = CASE
            WHEN v_role IN ('company_admin','manager','site_supervisor') THEN NULL
            WHEN p_department_id IS NULL THEN NULL
            ELSE (SELECT d.name FROM public.departments d WHERE d.id=p_department_id)
        END,
        is_active = COALESCE(p_is_active,true)
    WHERE m.id=p_membership_id;

    SELECT jsonb_build_object('full_name',m.full_name,'role',m.role,'site_id',m.site_id,'department_id',m.department_id,'is_active',m.is_active)
    INTO v_after
    FROM public.memberships m WHERE m.id=p_membership_id;

    INSERT INTO public.audit_logs(company_id,user_id,action,module,details)
    VALUES(
        v_company_id,v_user,'Super Admin updated membership','super_admin',
        jsonb_build_object('membership_id',p_membership_id,'reason',NULLIF(btrim(COALESCE(p_reason,'')),''),'before',v_before,'after',v_after)::text
    );

    RETURN jsonb_build_object('success',true,'membership',v_after);
END;
$$;

REVOKE ALL ON FUNCTION public.super_admin_update_membership(uuid,text,text,uuid,uuid,boolean,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_update_membership(uuid,text,text,uuid,uuid,boolean,text) TO authenticated;

-- ------------------------------------------------------------
-- 9. Recent global audit activity
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.super_admin_recent_activity(p_limit integer DEFAULT 200)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.created_at DESC),'[]'::jsonb)
    FROM (
        SELECT
            al.id,
            al.company_id,
            (SELECT c.name FROM public.companies c WHERE c.id=al.company_id) AS company_name,
            al.user_id,
            (SELECT m.full_name FROM public.memberships m WHERE m.user_id=al.user_id AND m.company_id=al.company_id ORDER BY m.created_at DESC LIMIT 1) AS actor_name,
            al.action,
            al.module,
            al.details,
            al.created_at
        FROM public.audit_logs al
        WHERE public.super_admin_is_authorized()
        ORDER BY al.created_at DESC
        LIMIT LEAST(GREATEST(COALESCE(p_limit,200),1),1000)
    ) x;
$$;

REVOKE ALL ON FUNCTION public.super_admin_recent_activity(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_recent_activity(integer) TO authenticated;

-- ------------------------------------------------------------
-- 10. Global site administration
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.super_admin_create_site(
    p_company_id uuid,
    p_name text,
    p_code text DEFAULT NULL,
    p_address text DEFAULT NULL,
    p_reason text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid := (SELECT auth.uid());
    v_site_id uuid;
    v_status text;
    v_max_sites integer;
    v_count bigint;
BEGIN
    IF v_user IS NULL OR NOT public.super_admin_is_authorized() THEN
        RAISE EXCEPTION 'Super Admin access is required.';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.companies c WHERE c.id=p_company_id) THEN
        RAISE EXCEPTION 'Company not found.';
    END IF;
    IF nullif(btrim(COALESCE(p_name,'')),'') IS NULL THEN
        RAISE EXCEPTION 'Site name is required.';
    END IF;

    SELECT s.status,p.max_sites INTO v_status,v_max_sites
    FROM public.subscriptions s
    JOIN public.subscription_plans p ON p.id=s.plan_id
    WHERE s.company_id=p_company_id
      AND s.status IN ('trialing','active','past_due','suspended')
    ORDER BY s.created_at DESC LIMIT 1;

    IF v_status IS NULL THEN
        RAISE EXCEPTION 'No current subscription was found for this company.';
    END IF;
    IF v_status='suspended' THEN
        RAISE EXCEPTION 'This subscription is suspended.';
    END IF;

    SELECT count(*) INTO v_count FROM public.sites WHERE company_id=p_company_id AND is_active=true;
    IF v_count >= v_max_sites THEN
        RAISE EXCEPTION 'Site limit reached. The current plan allows % active site(s).',v_max_sites;
    END IF;

    INSERT INTO public.sites(company_id,name,code,address,is_active)
    VALUES(p_company_id,btrim(p_name),NULLIF(btrim(COALESCE(p_code,'')),''),NULLIF(btrim(COALESCE(p_address,'')),''),true)
    RETURNING id INTO v_site_id;

    INSERT INTO public.audit_logs(company_id,user_id,action,module,details)
    VALUES(p_company_id,v_user,'Super Admin created site','super_admin',jsonb_build_object('site_id',v_site_id,'reason',NULLIF(btrim(COALESCE(p_reason,'')),''))::text);

    RETURN jsonb_build_object('success',true,'site_id',v_site_id,'company_id',p_company_id);
END;
$$;


CREATE OR REPLACE FUNCTION public.super_admin_update_site(
    p_site_id uuid,
    p_name text,
    p_code text DEFAULT NULL,
    p_address text DEFAULT NULL,
    p_is_active boolean DEFAULT true,
    p_reason text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid := (SELECT auth.uid());
    v_company_id uuid;
    v_before jsonb;
    v_after jsonb;
BEGIN
    IF v_user IS NULL OR NOT public.super_admin_is_authorized() THEN
        RAISE EXCEPTION 'Super Admin access is required.';
    END IF;
    SELECT company_id INTO v_company_id FROM public.sites WHERE id=p_site_id;
    IF v_company_id IS NULL THEN RAISE EXCEPTION 'Site not found.'; END IF;
    IF nullif(btrim(COALESCE(p_name,'')),'') IS NULL THEN RAISE EXCEPTION 'Site name is required.'; END IF;
    SELECT jsonb_build_object('name',name,'code',code,'address',address,'is_active',is_active) INTO v_before FROM public.sites WHERE id=p_site_id;
    UPDATE public.sites
    SET name=btrim(p_name), code=NULLIF(btrim(COALESCE(p_code,'')),''), address=NULLIF(btrim(COALESCE(p_address,'')),''), is_active=COALESCE(p_is_active,true)
    WHERE id=p_site_id;
    SELECT jsonb_build_object('name',name,'code',code,'address',address,'is_active',is_active) INTO v_after FROM public.sites WHERE id=p_site_id;

    INSERT INTO public.audit_logs(company_id,user_id,action,module,details)
    VALUES(v_company_id,v_user,'Super Admin updated site','super_admin',jsonb_build_object('site_id',p_site_id,'reason',NULLIF(btrim(COALESCE(p_reason,'')),''),'before',v_before,'after',v_after)::text);
    RETURN jsonb_build_object('success',true,'site',v_after);
END;
$$;

REVOKE ALL ON FUNCTION public.super_admin_create_site(uuid,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_create_site(uuid,text,text,text,text) TO authenticated;
REVOKE ALL ON FUNCTION public.super_admin_update_site(uuid,text,text,text,boolean,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_update_site(uuid,text,text,text,boolean,text) TO authenticated;

-- ------------------------------------------------------------
-- 11. Global department administration
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.super_admin_create_department(
    p_company_id uuid,
    p_site_id uuid,
    p_name text,
    p_code text DEFAULT NULL,
    p_reason text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid := (SELECT auth.uid());
    v_department_id uuid;
    v_status text;
    v_max_departments integer;
    v_count bigint;
BEGIN
    IF v_user IS NULL OR NOT public.super_admin_is_authorized() THEN
        RAISE EXCEPTION 'Super Admin access is required.';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.companies c WHERE c.id=p_company_id) THEN RAISE EXCEPTION 'Company not found.'; END IF;
    IF NOT EXISTS (SELECT 1 FROM public.sites s WHERE s.id=p_site_id AND s.company_id=p_company_id AND s.is_active=true) THEN RAISE EXCEPTION 'The selected site does not belong to this company or is inactive.'; END IF;
    IF nullif(btrim(COALESCE(p_name,'')),'') IS NULL THEN RAISE EXCEPTION 'Department name is required.'; END IF;

    SELECT s.status,p.max_departments INTO v_status,v_max_departments
    FROM public.subscriptions s JOIN public.subscription_plans p ON p.id=s.plan_id
    WHERE s.company_id=p_company_id AND s.status IN ('trialing','active','past_due','suspended')
    ORDER BY s.created_at DESC LIMIT 1;
    IF v_status IS NULL THEN RAISE EXCEPTION 'No current subscription was found for this company.'; END IF;
    IF v_status='suspended' THEN RAISE EXCEPTION 'This subscription is suspended.'; END IF;

    SELECT count(*) INTO v_count FROM public.departments WHERE company_id=p_company_id AND is_active=true;
    IF v_count >= v_max_departments THEN RAISE EXCEPTION 'Department limit reached. The current plan allows % active department(s).',v_max_departments; END IF;

    INSERT INTO public.departments(company_id,site_id,name,code,is_active)
    VALUES(p_company_id,p_site_id,btrim(p_name),NULLIF(btrim(COALESCE(p_code,'')),''),true)
    RETURNING id INTO v_department_id;

    INSERT INTO public.audit_logs(company_id,user_id,action,module,details)
    VALUES(p_company_id,v_user,'Super Admin created department','super_admin',jsonb_build_object('department_id',v_department_id,'site_id',p_site_id,'reason',NULLIF(btrim(COALESCE(p_reason,'')),''))::text);
    RETURN jsonb_build_object('success',true,'department_id',v_department_id,'company_id',p_company_id,'site_id',p_site_id);
END;
$$;

CREATE OR REPLACE FUNCTION public.super_admin_update_department(
    p_department_id uuid,
    p_site_id uuid,
    p_name text,
    p_code text DEFAULT NULL,
    p_is_active boolean DEFAULT true,
    p_reason text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid := (SELECT auth.uid());
    v_company_id uuid;
    v_before jsonb;
    v_after jsonb;
BEGIN
    IF v_user IS NULL OR NOT public.super_admin_is_authorized() THEN RAISE EXCEPTION 'Super Admin access is required.'; END IF;
    SELECT company_id INTO v_company_id FROM public.departments WHERE id=p_department_id;
    IF v_company_id IS NULL THEN RAISE EXCEPTION 'Department not found.'; END IF;
    IF NOT EXISTS (SELECT 1 FROM public.sites s WHERE s.id=p_site_id AND s.company_id=v_company_id) THEN RAISE EXCEPTION 'The selected site does not belong to this company.'; END IF;
    IF nullif(btrim(COALESCE(p_name,'')),'') IS NULL THEN RAISE EXCEPTION 'Department name is required.'; END IF;

    SELECT jsonb_build_object('site_id',site_id,'name',name,'code',code,'is_active',is_active) INTO v_before FROM public.departments WHERE id=p_department_id;
    UPDATE public.departments
    SET site_id=p_site_id,name=btrim(p_name),code=NULLIF(btrim(COALESCE(p_code,'')),''),is_active=COALESCE(p_is_active,true)
    WHERE id=p_department_id;
    SELECT jsonb_build_object('site_id',site_id,'name',name,'code',code,'is_active',is_active) INTO v_after FROM public.departments WHERE id=p_department_id;

    INSERT INTO public.audit_logs(company_id,user_id,action,module,details)
    VALUES(v_company_id,v_user,'Super Admin updated department','super_admin',jsonb_build_object('department_id',p_department_id,'reason',NULLIF(btrim(COALESCE(p_reason,'')),''),'before',v_before,'after',v_after)::text);
    RETURN jsonb_build_object('success',true,'department',v_after);
END;
$$;

REVOKE ALL ON FUNCTION public.super_admin_create_department(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_create_department(uuid,uuid,text,text,text) TO authenticated;
REVOKE ALL ON FUNCTION public.super_admin_update_department(uuid,uuid,text,text,boolean,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.super_admin_update_department(uuid,uuid,text,text,boolean,text) TO authenticated;

-- ------------------------------------------------------------
-- Verification — global admin functions
-- ------------------------------------------------------------
SELECT proname, pg_get_function_identity_arguments(p.oid) AS arguments
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname='public' AND proname LIKE 'super_admin_%'
ORDER BY proname;

COMMIT;