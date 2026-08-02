DELIMITER $$
CREATE PROCEDURE claims.adjust_claims(IN p_limit INT, OUT p_status VARCHAR(40))
SQL SECURITY INVOKER
MODIFIES SQL DATA
BEGIN
    DECLARE v_done BOOLEAN DEFAULT FALSE;
    DECLARE v_id BIGINT;
    DECLARE no_rows CONDITION FOR SQLSTATE '02000';
    DECLARE c CURSOR FOR SELECT claim_id FROM claims.claim WHERE status = 'PENDING';
    DECLARE CONTINUE HANDLER FOR no_rows SET v_done = TRUE;
    SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
    START TRANSACTION;
    OPEN c;
    read_loop: REPEAT
        FETCH c INTO v_id;
        IF NOT v_done THEN
            INSERT INTO claims.claim_audit(claim_id, decision)
            VALUES (v_id, 'ADJUSTED')
            ON DUPLICATE KEY UPDATE decision = VALUES(decision);
        END IF;
    UNTIL v_done END REPEAT;
    CLOSE c;
    GET DIAGNOSTICS @rows = ROW_COUNT;
    LOCK TABLES claims.claim WRITE;
    UPDATE claims.claim SET status = 'ADJUSTED' WHERE status = 'PENDING' LIMIT p_limit;
    COMMIT;
    SELECT claim_id, status FROM claims.claim WHERE status = 'ADJUSTED';
END$$
DELIMITER ;
