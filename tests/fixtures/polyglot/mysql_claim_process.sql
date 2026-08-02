DELIMITER $$
CREATE PROCEDURE claims.process_claim(
    IN p_claim_id BIGINT,
    IN p_amount DECIMAL(18,2),
    OUT p_decision VARCHAR(40)
)
SQL SECURITY DEFINER
BEGIN
    DECLARE v_score DECIMAL(18,2) DEFAULT 0;
    DECLARE v_count INT DEFAULT 0;
    DECLARE done BOOLEAN DEFAULT FALSE;
    DECLARE c_items CURSOR FOR SELECT amount FROM claims.claim_item WHERE claim_id = p_claim_id;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        SET p_decision = 'ERROR';
        ROLLBACK;
        RESIGNAL;
    END;

    IF p_claim_id IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'claim id required';
    ELSEIF p_amount > 100000 THEN
        SET p_decision = 'REVIEW';
    ELSE
        SELECT COUNT(*) INTO v_count FROM claims.claim_item WHERE claim_id = p_claim_id;
        SET v_score = p_amount + v_count;
        IF v_score > 50000 THEN
            SET p_decision = 'MANUAL_REVIEW';
        ELSE
            SET p_decision = 'APPROVED';
        END IF;
    END IF;

    OPEN c_items;
    item_loop: LOOP
        FETCH c_items INTO v_score;
        IF done THEN
            LEAVE item_loop;
        END IF;
        SET v_score = v_score + 1;
    END LOOP;
    CLOSE c_items;

    START TRANSACTION;
    UPDATE claims.claim SET status = p_decision WHERE claim_id = p_claim_id;
    INSERT INTO claims.claim_audit(claim_id, decision) VALUES (p_claim_id, p_decision);
    SET @sql_text = 'UPDATE claims.claim_summary SET touched = 1 WHERE claim_id = ?';
    PREPARE stmt FROM @sql_text;
    EXECUTE stmt USING p_claim_id;
    DEALLOCATE PREPARE stmt;
    COMMIT;
    SELECT claim_id, status FROM claims.claim WHERE claim_id = p_claim_id;
END$$
DELIMITER ;
