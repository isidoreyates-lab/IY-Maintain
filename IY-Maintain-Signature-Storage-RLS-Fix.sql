-- IY Maintain — User Signature Storage RLS Fix
-- Purpose: allow an authenticated user to create/replace/view/delete ONLY
-- their own signature under:
--   user-signatures/<company_id>/<auth_user_id>.png
--
-- This does NOT disable RLS and does not change report approval logic.

BEGIN;

DROP POLICY IF EXISTS "iy_signature_insert_own" ON storage.objects;
DROP POLICY IF EXISTS "iy_signature_select_own" ON storage.objects;
DROP POLICY IF EXISTS "iy_signature_update_own" ON storage.objects;
DROP POLICY IF EXISTS "iy_signature_delete_own" ON storage.objects;

CREATE POLICY "iy_signature_insert_own"
ON storage.objects
FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'user-signatures'
  AND (storage.foldername(name))[1] <> ''
  AND (storage.foldername(name))[2] = (SELECT auth.uid()::text)
  AND EXISTS (
    SELECT 1
    FROM public.memberships m
    WHERE m.user_id = (SELECT auth.uid())
      AND m.company_id::text = (storage.foldername(name))[1]
      AND m.is_active = true
  )
);

CREATE POLICY "iy_signature_select_own"
ON storage.objects
FOR SELECT
TO authenticated
USING (
  bucket_id = 'user-signatures'
  AND (storage.foldername(name))[2] = (SELECT auth.uid()::text)
  AND EXISTS (
    SELECT 1
    FROM public.memberships m
    WHERE m.user_id = (SELECT auth.uid())
      AND m.company_id::text = (storage.foldername(name))[1]
      AND m.is_active = true
  )
);

CREATE POLICY "iy_signature_update_own"
ON storage.objects
FOR UPDATE
TO authenticated
USING (
  bucket_id = 'user-signatures'
  AND (storage.foldername(name))[2] = (SELECT auth.uid()::text)
  AND EXISTS (
    SELECT 1
    FROM public.memberships m
    WHERE m.user_id = (SELECT auth.uid())
      AND m.company_id::text = (storage.foldername(name))[1]
      AND m.is_active = true
  )
)
WITH CHECK (
  bucket_id = 'user-signatures'
  AND (storage.foldername(name))[2] = (SELECT auth.uid()::text)
  AND EXISTS (
    SELECT 1
    FROM public.memberships m
    WHERE m.user_id = (SELECT auth.uid())
      AND m.company_id::text = (storage.foldername(name))[1]
      AND m.is_active = true
  )
);

CREATE POLICY "iy_signature_delete_own"
ON storage.objects
FOR DELETE
TO authenticated
USING (
  bucket_id = 'user-signatures'
  AND (storage.foldername(name))[2] = (SELECT auth.uid()::text)
  AND EXISTS (
    SELECT 1
    FROM public.memberships m
    WHERE m.user_id = (SELECT auth.uid())
      AND m.company_id::text = (storage.foldername(name))[1]
      AND m.is_active = true
  )
);

COMMIT;

-- Verification:
SELECT policyname, cmd
FROM pg_policies
WHERE schemaname = 'storage'
  AND tablename = 'objects'
  AND policyname LIKE 'iy_signature_%'
ORDER BY policyname;
