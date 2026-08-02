CREATE OR REPLACE PROCEDURE claims.process_claim(
    IN p_claim_id bigint,
    IN p_amount numeric,
    INOUT p_decision text DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_score numeric := 0;
    v_count integer := 0;
    r record;
BEGIN
    IF p_claim_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'claim id required';
    ELSIF p_amount > 100000 THEN
        p_decision := 'REVIEW';
    ELSE
        SELECT count(*) INTO STRICT v_count FROM claims.claim_item WHERE claim_id = p_claim_id;
        v_score := p_amount + v_count;
        CASE
            WHEN v_score > 50000 THEN p_decision := 'MANUAL_REVIEW';
            ELSE p_decision := 'APPROVED';
        END CASE;
    END IF;

    FOR r IN SELECT amount FROM claims.claim_item WHERE claim_id = p_claim_id LOOP
        v_score := v_score + r.amount;
    END LOOP;

    UPDATE claims.claim SET status = p_decision WHERE claim_id = p_claim_id;
    INSERT INTO claims.claim_audit(claim_id, decision) VALUES (p_claim_id, p_decision);
    EXECUTE 'UPDATE claims.claim_summary SET touched = true WHERE claim_id = $1' USING p_claim_id;
    COMMIT;
EXCEPTION
    WHEN no_data_found THEN
        p_decision := 'NOT_FOUND';
    WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS p_decision = MESSAGE_TEXT;
        RAISE;
END;
$$;
