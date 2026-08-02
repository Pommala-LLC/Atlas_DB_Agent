CREATE OR REPLACE PROCEDURE claims.bulk_adjust(
    p_limit IN NUMBER,
    p_status OUT VARCHAR2
) AUTHID CURRENT_USER AS
    PRAGMA AUTONOMOUS_TRANSACTION;
    e_bulk EXCEPTION;
    PRAGMA EXCEPTION_INIT(e_bulk, -24381);
    TYPE id_list IS TABLE OF NUMBER;
    v_ids id_list;
    v_count NUMBER;
BEGIN
    LOCK TABLE claim IN SHARE ROW EXCLUSIVE MODE;
    SELECT claim_id BULK COLLECT INTO v_ids FROM claim WHERE status = 'PENDING' FETCH FIRST p_limit ROWS ONLY;
    FORALL i IN INDICES OF v_ids SAVE EXCEPTIONS
        UPDATE claim SET status = 'ADJUSTED' WHERE claim_id = v_ids(i) RETURNING claim_id INTO v_count;
    <<after_bulk>>
    IF SQL%ROWCOUNT = 0 THEN
        GOTO no_rows;
    END IF;
    p_status := 'DONE';
    COMMIT;
    RETURN;
    <<no_rows>>
    p_status := 'EMPTY';
    ROLLBACK;
EXCEPTION
    WHEN e_bulk THEN
        p_status := 'PARTIAL';
        ROLLBACK;
END;
/
