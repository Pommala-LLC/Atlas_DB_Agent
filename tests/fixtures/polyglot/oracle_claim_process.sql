CREATE OR REPLACE PROCEDURE claims.process_claim (
    p_claim_id IN NUMBER,
    p_amount IN NUMBER,
    p_decision OUT VARCHAR2,
    p_total OUT NUMBER
) AUTHID DEFINER AS
    v_score NUMBER := 0;
    v_count NUMBER := 0;
    CURSOR c_items IS SELECT amount FROM claim_item WHERE claim_id = p_claim_id;
    e_invalid EXCEPTION;
BEGIN
    IF p_claim_id IS NULL THEN
        RAISE e_invalid;
    ELSIF p_amount > 100000 THEN
        p_decision := 'REVIEW';
    ELSE
        SELECT COUNT(*) INTO v_count FROM claim_item WHERE claim_id = p_claim_id;
        v_score := p_amount + v_count;
        IF v_score > 50000 THEN
            p_decision := 'MANUAL_REVIEW';
        ELSE
            p_decision := 'APPROVED';
        END IF;
    END IF;

    FOR r IN c_items LOOP
        p_total := NVL(p_total, 0) + r.amount;
    END LOOP;

    UPDATE claim SET status = p_decision WHERE claim_id = p_claim_id;
    INSERT INTO claim_audit(claim_id, decision) VALUES (p_claim_id, p_decision);
    EXECUTE IMMEDIATE 'UPDATE claim_summary SET touched = 1 WHERE claim_id = :1' USING p_claim_id;
    COMMIT;
EXCEPTION
    WHEN e_invalid THEN
        p_decision := 'ERROR';
        ROLLBACK;
    WHEN OTHERS THEN
        p_decision := 'ERROR';
        RAISE;
END;
/
