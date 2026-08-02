CREATE OR REPLACE FUNCTION claims.adjust_claims(p_ids bigint[])
RETURNS SETOF bigint
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
AS $$
DECLARE
    v_id bigint;
    v_count integer;
BEGIN
    ASSERT array_length(p_ids, 1) IS NOT NULL, 'ids required';
    SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
    LOCK TABLE claims.claim IN SHARE ROW EXCLUSIVE MODE;
    FOREACH v_id IN ARRAY p_ids LOOP
        INSERT INTO claims.claim(claim_id, status)
        VALUES (v_id, 'ADJUSTED')
        ON CONFLICT (claim_id) DO UPDATE SET status = EXCLUDED.status;
        RETURN NEXT v_id;
    END LOOP;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    EXECUTE 'SELECT count(*) FROM claims.claim WHERE status = $1' INTO v_count USING 'ADJUSTED';
    RETURN;
EXCEPTION
    WHEN unique_violation THEN
        RAISE WARNING 'duplicate claim';
        RETURN;
END;
$$;
