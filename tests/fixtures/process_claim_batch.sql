CREATE PROCEDURE CLAIMS.PROCESS_CLAIM_BATCH (
    IN  P_BATCH_ID          BIGINT,
    IN  P_PROCESS_DATE      DATE,
    IN  P_MAX_ITEMS         INTEGER,
    OUT P_PROCESSED_COUNT   INTEGER,
    OUT P_ERROR_CODE        CHAR(5)
)
LANGUAGE SQL
MODIFIES SQL DATA
P_CLAIM_BATCH: BEGIN
    -- -----------------------------------------------------------------
    -- Complex stored procedure for testing the DB2 Behavior Extractor
    -- -----------------------------------------------------------------
    DECLARE V_CURRENT_TS       TIMESTAMP DEFAULT CURRENT TIMESTAMP;
    DECLARE V_ITEM_COUNT       INTEGER DEFAULT 0;
    DECLARE V_TOTAL_AMOUNT     DECIMAL(15,2) DEFAULT 0.00;
    DECLARE V_HIGH_RISK_COUNT  INTEGER DEFAULT 0;
    DECLARE V_BATCH_STATUS     VARCHAR(20) DEFAULT 'PROCESSING';
    DECLARE V_SQL              VARCHAR(4000);
    DECLARE V_CLAIM_ID         BIGINT;
    DECLARE V_AMOUNT           DECIMAL(12,2);
    DECLARE V_STATUS           VARCHAR(20);
    DECLARE V_RISK_SCORE       INTEGER;
    DECLARE V_PREV_AMOUNT      DECIMAL(12,2) DEFAULT NULL;

    -- Cursor for claims in the batch
    DECLARE C_CLAIM_CURSOR CURSOR WITH HOLD FOR
        SELECT CB.CLAIM_ID,
               C.AMOUNT,
               C.STATUS,
               COALESCE(R.RISK_SCORE, 0) AS RISK_SCORE
        FROM CLAIM_BATCH_ITEM CB
        INNER JOIN CLAIM C
            ON CB.CLAIM_ID = C.CLAIM_ID
        LEFT JOIN CLAIM_RISK_SCORE R
            ON C.CLAIM_ID = R.CLAIM_ID
            AND R.EFFECTIVE_TS <= V_CURRENT_TS
            AND R.EXPIRY_TS > V_CURRENT_TS
        WHERE CB.BATCH_ID = P_BATCH_ID
          AND CB.PROCESSED_IND = 'N'
        ORDER BY CB.SEQUENCE_NUMBER
        FETCH FIRST P_MAX_ITEMS ROWS ONLY;

    -- Handler for NOT FOUND on cursor
    DECLARE CONTINUE HANDLER FOR NOT FOUND
        SET V_BATCH_STATUS = 'COMPLETED';

    -- Handler for SQL errors (logging only)
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        SET P_ERROR_CODE = '99999';
        -- Dynamic insert into error log
        SET V_SQL = 'INSERT INTO ERROR_LOG VALUES ('
                    || 'DEFAULT, ''PROCESS_CLAIM_BATCH'', '''
                    || SQLSTATE || ''', '''
                    || SQLERRM || ''', '
                    || 'CURRENT TIMESTAMP)';
        EXECUTE IMMEDIATE V_SQL;
        RESIGNAL;
    END;

    -- -----------------------------------------------------------------
    -- Dynamic SQL: Determine if parallel processing is active
    -- -----------------------------------------------------------------
    DECLARE V_PARALLEL_ENABLED CHAR(1) DEFAULT 'N';

    SET V_SQL =
        'SELECT VALUE INTO ? FROM SYSTEM_CONFIG WHERE KEY = ''PARALLEL_CLAIM_PROCESSING''';
    PREPARE S1 FROM V_SQL;
    EXECUTE S1 INTO V_PARALLEL_ENABLED;

    -- -----------------------------------------------------------------
    -- Main processing loop
    -- -----------------------------------------------------------------
    OPEN C_CLAIM_CURSOR;

    PROCESS_LOOP: LOOP
        FETCH C_CLAIM_CURSOR INTO V_CLAIM_ID, V_AMOUNT, V_STATUS, V_RISK_SCORE;

        -- Exit loop if batch completed
        IF V_BATCH_STATUS = 'COMPLETED' THEN
            LEAVE PROCESS_LOOP;
        END IF;

        -- Business rule: Skip claims that are not in pending or under-review
        IF V_STATUS NOT IN ('PENDING', 'UNDER_REVIEW') THEN
            ITERATE PROCESS_LOOP;
        END IF;

        -- Risk evaluation with window function context
        WITH CLAIM_HISTORY AS (
            SELECT CLAIM_ID,
                   AMOUNT,
                   LAG(AMOUNT) OVER (PARTITION BY CUSTOMER_ID
                                     ORDER BY CREATED_TS) AS PREV_AMOUNT
            FROM CLAIM
            WHERE CLAIM_ID = V_CLAIM_ID
        )
        SELECT PREV_AMOUNT INTO V_PREV_AMOUNT
        FROM CLAIM_HISTORY;

        -- Decision logic
        IF V_RISK_SCORE >= 900 THEN
            -- High risk: direct escalation
            SET P_ERROR_CODE = NULL;
            UPDATE CLAIM
               SET STATUS = 'ESCALATED',
                   REVIEW_REQUIRED = 'Y',
                   UPDATED_TS = V_CURRENT_TS
             WHERE CLAIM_ID = V_CLAIM_ID;

            SET V_HIGH_RISK_COUNT = V_HIGH_RISK_COUNT + 1;

        ELSEIF V_AMOUNT > 50000 AND V_RISK_SCORE >= 700 THEN
            -- Medium-high: manual review
            CALL CLAIMS.REQUEST_MANUAL_REVIEW(V_CLAIM_ID, 'LARGE_AMOUNT_RISK');

        ELSEIF V_AMOUNT > 10000 AND V_PREV_AMOUNT IS NOT NULL
               AND V_AMOUNT > (V_PREV_AMOUNT * 1.5) THEN
            -- Amount spike detected
            SET V_SQL = 'UPDATE CLAIM SET STATUS = ''REVIEW'', '
                        || 'REVIEW_REASON = ''AMOUNT_SPIKE'' '
                        || 'WHERE CLAIM_ID = ' || V_CLAIM_ID;
            EXECUTE IMMEDIATE V_SQL;

        ELSE
            -- Normal processing
            MERGE INTO CUSTOMER_CLAIM_SUMMARY AS T
            USING (
                SELECT CUSTOMER_ID,
                       COUNT(*) AS OPEN_COUNT,
                       SUM(AMOUNT) AS TOTAL_OPEN
                FROM CLAIM
                WHERE CUSTOMER_ID = (SELECT CUSTOMER_ID FROM CLAIM WHERE CLAIM_ID = V_CLAIM_ID)
                  AND STATUS IN ('PENDING', 'UNDER_REVIEW')
                GROUP BY CUSTOMER_ID
            ) AS S
            ON T.CUSTOMER_ID = S.CUSTOMER_ID
            WHEN MATCHED THEN
                UPDATE SET OPEN_CLAIM_COUNT = S.OPEN_COUNT,
                           TOTAL_OPEN_AMOUNT = S.TOTAL_OPEN,
                           UPDATED_TS = V_CURRENT_TS
            WHEN NOT MATCHED THEN
                INSERT (CUSTOMER_ID, OPEN_CLAIM_COUNT, TOTAL_OPEN_AMOUNT, UPDATED_TS)
                VALUES (S.CUSTOMER_ID, S.OPEN_COUNT, S.TOTAL_OPEN, V_CURRENT_TS);

            -- Update batch item as processed
            UPDATE CLAIM_BATCH_ITEM
               SET PROCESSED_IND = 'Y',
                   PROCESSED_TS = V_CURRENT_TS
             WHERE BATCH_ID = P_BATCH_ID
               AND CLAIM_ID = V_CLAIM_ID;

            SET V_ITEM_COUNT = V_ITEM_COUNT + 1;
        END IF;

        -- Threshold check
        IF V_ITEM_COUNT >= P_MAX_ITEMS THEN
            SET V_BATCH_STATUS = 'THRESHOLD_REACHED';
            LEAVE PROCESS_LOOP;
        END IF;

    END LOOP PROCESS_LOOP;

    CLOSE C_CLAIM_CURSOR;

    -- -----------------------------------------------------------------
    -- Final aggregation
    -- -----------------------------------------------------------------
    SELECT COUNT(*),
           COALESCE(SUM(C.AMOUNT), 0)
    INTO V_ITEM_COUNT, V_TOTAL_AMOUNT
    FROM CLAIM C
    WHERE C.CLAIM_ID IN (
        SELECT CB.CLAIM_ID
        FROM CLAIM_BATCH_ITEM CB
        WHERE CB.BATCH_ID = P_BATCH_ID
          AND CB.PROCESSED_IND = 'Y'
    )
    HAVING COUNT(*) > 0;   -- If HAVING fails, NOT FOUND handler sets batch status

    -- Set output parameters
    SET P_PROCESSED_COUNT = V_ITEM_COUNT;
    IF V_HIGH_RISK_COUNT > (V_ITEM_COUNT * 0.3) THEN
        SET P_ERROR_CODE = 'WARN1';  -- Warning: high risk ratio
    ELSE
        SET P_ERROR_CODE = NULL;
    END IF;

    -- Update batch header
    UPDATE CLAIM_BATCH
       SET STATUS = V_BATCH_STATUS,
           PROCESSED_COUNT = V_ITEM_COUNT,
           END_TS = V_CURRENT_TS
     WHERE BATCH_ID = P_BATCH_ID;

END P_CLAIM_BATCH
