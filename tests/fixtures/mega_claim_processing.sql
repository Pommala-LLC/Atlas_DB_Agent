CREATE PROCEDURE CLAIMS.MEGA_CLAIM_PROCESSING (
    IN  P_CLAIM_ID            BIGINT,
    IN  P_TENANT_ID           CHAR(8),
    IN  P_PROCESS_DATE        DATE,
    OUT P_FINAL_STATUS        VARCHAR(30),
    OUT P_RISK_SCORE          DECIMAL(7,3),
    OUT P_APPROVAL_CHAIN      VARCHAR(500),
    OUT P_AUDIT_REF           BIGINT
)
LANGUAGE SQL
MODIFIES SQL DATA
P_MEGA_PROCESS: BEGIN
    DECLARE V_CURRENT_TS         TIMESTAMP DEFAULT CURRENT TIMESTAMP;
    DECLARE V_CUSTOMER_ID        BIGINT;
    DECLARE V_CLAIM_AMOUNT       DECIMAL(15,2);
    DECLARE V_CLAIM_TYPE         VARCHAR(20);
    DECLARE V_CUSTOMER_TIER      VARCHAR(10);
    DECLARE V_LIFETIME_CLAIMS    INTEGER;
    DECLARE V_AVG_CLAIM_AMOUNT   DECIMAL(15,2);
    DECLARE V_MAX_SELF_AMOUNT    DECIMAL(15,2);
    DECLARE V_PEER_AVG_AMOUNT    DECIMAL(15,2);
    DECLARE V_RISK_WEIGHT        DECIMAL(5,2);
    DECLARE V_FRAUD_FLAG         CHAR(1);
    DECLARE V_SCORE              DECIMAL(10,4);
    DECLARE V_ESCALATION_NOTE    VARCHAR(200);
    DECLARE V_APPROVAL_DEPTH     INTEGER;
    DECLARE V_MANAGER_ID         BIGINT;
    DECLARE V_DYNAMIC_SQL        VARCHAR(4000);
    DECLARE V_DYNAMIC_TABLE      VARCHAR(128);
    DECLARE V_RULE_THRESHOLD     DECIMAL(15,2);
    DECLARE V_RULE_ACTION        VARCHAR(30);
    DECLARE V_CURSOR_ROW_COUNT   INTEGER DEFAULT 0;

    -- Handler for unexpected SQL errors
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        SET P_FINAL_STATUS = 'ERROR';
        SET P_RISK_SCORE = -1;
        SET P_APPROVAL_CHAIN = '';
        SET P_AUDIT_REF = -1;
        INSERT INTO ERROR_LOG (CLAIM_ID, TENANT_ID, SQLSTATE, SQLERRM, TS)
        VALUES (P_CLAIM_ID, P_TENANT_ID, SQLSTATE, SQLERRM, V_CURRENT_TS);
    END;

    -- -----------------------------------------------------------------
    -- 1. Fetch claim + customer with multiple scalar subqueries
    -- -----------------------------------------------------------------
    SELECT C.CLAIM_AMOUNT,
           C.CLAIM_TYPE,
           C.CUSTOMER_ID,
           CU.CUSTOMER_TIER,
           (SELECT 'Y' FROM FRAUD_WATCHLIST FW
            WHERE FW.CUSTOMER_ID = CU.CUSTOMER_ID
              AND FW.ACTIVE_IND = 'Y'
            FETCH FIRST 1 ROW ONLY) AS FRAUD,
           (SELECT COUNT(*) FROM CLAIM_DOCUMENT DOC
            WHERE DOC.CLAIM_ID = C.CLAIM_ID
              AND DOC.TENANT_ID = C.TENANT_ID
              AND DOC.STATUS = 'VERIFIED')
    INTO V_CLAIM_AMOUNT, V_CLAIM_TYPE, V_CUSTOMER_ID, V_CUSTOMER_TIER,
         V_FRAUD_FLAG, V_DOC_COUNT
    FROM CLAIM C
    INNER JOIN CUSTOMER CU
        ON C.CUSTOMER_ID = CU.CUSTOMER_ID
       AND C.TENANT_ID  = CU.TENANT_ID
    WHERE C.CLAIM_ID = P_CLAIM_ID
      AND C.TENANT_ID = P_TENANT_ID
      AND C.DELETED_IND = 'N';

    -- -----------------------------------------------------------------
    -- 2. Self‑join with window function to find max previous amount
    --    and a LAG‑based spike indicator in a single CTE
    -- -----------------------------------------------------------------
    WITH CLAIM_HISTORY AS (
        SELECT CLAIM_ID,
               CLAIM_AMOUNT,
               CLAIM_TYPE,
               CREATED_TS,
               LAG(CLAIM_AMOUNT) OVER (PARTITION BY CUSTOMER_ID
                                      ORDER BY CREATED_TS) AS PREV_AMOUNT
        FROM CLAIM
        WHERE CUSTOMER_ID = V_CUSTOMER_ID
          AND TENANT_ID   = P_TENANT_ID
          AND DELETED_IND = 'N'
          AND STATUS IN ('APPROVED','PAID')
    ),
    SPIKE_CHECK AS (
        SELECT MAX(CLAIM_AMOUNT) AS MAX_SELF,
               MAX(CASE WHEN CLAIM_AMOUNT > PREV_AMOUNT * 1.5 THEN 1 ELSE 0 END) AS SPIKE_FLAG
        FROM CLAIM_HISTORY
        WHERE CLAIM_ID <> P_CLAIM_ID
    )
    SELECT MAX_SELF,
           COALESCE(SPIKE_FLAG, 0)
    INTO V_MAX_SELF_AMOUNT, V_SPIKE_FLAG
    FROM SPIKE_CHECK;

    -- -----------------------------------------------------------------
    -- 3. Aggregate with correlated subquery in HAVING
    -- -----------------------------------------------------------------
    SELECT COUNT(*),
           AVG(CL.CLAIM_AMOUNT)
    INTO V_LIFETIME_CLAIMS, V_AVG_CLAIM_AMOUNT
    FROM CLAIM CL
    WHERE CL.CUSTOMER_ID = V_CUSTOMER_ID
      AND CL.TENANT_ID   = P_TENANT_ID
      AND CL.STATUS      IN ('APPROVED','PAID')
      AND CL.DELETED_IND = 'N'
      AND EXISTS (
          SELECT 1 FROM CLAIM_STATUS_HISTORY SH
          WHERE SH.CLAIM_ID = CL.CLAIM_ID
            AND SH.STATUS = 'APPROVED'
            AND SH.CREATED_TS >= V_CURRENT_TS - 2 YEARS
      )
    HAVING COUNT(*) > 0; -- HAVING + NOT FOUND possibility

    -- -----------------------------------------------------------------
    -- 4. Peer comparison using derived table and multi‑level subqueries
    -- -----------------------------------------------------------------
    SELECT AVG(PEER_AMT)
    INTO V_PEER_AVG_AMOUNT
    FROM (
        SELECT PEER.CLAIM_AMOUNT AS PEER_AMT
        FROM CLAIM PEER
        INNER JOIN CUSTOMER PCU
            ON PEER.CUSTOMER_ID = PCU.CUSTOMER_ID
           AND PEER.TENANT_ID   = PCU.TENANT_ID
        WHERE PEER.CLAIM_TYPE   = V_CLAIM_TYPE
          AND PCU.CUSTOMER_TIER = V_CUSTOMER_TIER
          AND PEER.STATUS       IN ('APPROVED','PAID')
          AND PEER.DELETED_IND  = 'N'
          AND PEER.CLAIM_ID    <> P_CLAIM_ID
          AND PEER.TENANT_ID   <> 'EXCLUDED'
          AND PEER.CLAIM_AMOUNT > (
              SELECT AVG(CLAIM_AMOUNT)
              FROM CLAIM
              WHERE CUSTOMER_ID = V_CUSTOMER_ID
                AND TENANT_ID   = P_TENANT_ID
          )
        FETCH FIRST 50 ROWS ONLY
    ) AS PEER_DERIVED;

    -- -----------------------------------------------------------------
    -- 5. Recursive CTE for approval hierarchy
    -- -----------------------------------------------------------------
    WITH APPROVAL_CHAIN (EMP_ID, LVL, APPROVAL_LIMIT, CHAIN_TEXT) AS (
        -- Anchor: direct manager of customer's rep
        SELECT M.MANAGER_ID, 1, M.APPROVAL_LIMIT,
               CAST(M.MANAGER_NAME AS VARCHAR(500))
        FROM CUSTOMER_ACCOUNT_REP R
        JOIN EMPLOYEE M
            ON R.REP_EMP_ID = M.EMP_ID
        WHERE R.CUSTOMER_ID = V_CUSTOMER_ID
          AND R.TENANT_ID   = P_TENANT_ID
          AND R.ACTIVE_IND  = 'Y'

        UNION ALL

        -- Recursive: manager's manager
        SELECT M2.MANAGER_ID, A.LVL + 1, M2.APPROVAL_LIMIT,
               A.CHAIN_TEXT || ' -> ' || M2.MANAGER_NAME
        FROM APPROVAL_CHAIN A
        JOIN EMPLOYEE M2
            ON A.EMP_ID = M2.EMP_ID
        WHERE A.LVL < 10
          AND M2.APPROVAL_LIMIT IS NOT NULL
    ),
    CHAIN_AGG AS (
        SELECT EMP_ID, LVL, APPROVAL_LIMIT, CHAIN_TEXT,
               ROW_NUMBER() OVER (ORDER BY LVL ASC) AS RN
        FROM APPROVAL_CHAIN
        WHERE APPROVAL_LIMIT >= V_CLAIM_AMOUNT
    )
    SELECT EMP_ID, LVL, CHAIN_TEXT
    INTO V_MANAGER_ID, V_APPROVAL_DEPTH, V_APPROVAL_CHAIN
    FROM CHAIN_AGG
    WHERE RN = 1;

    -- -----------------------------------------------------------------
    -- 6. Dynamic SQL to fetch tenant‑specific rule
    -- -----------------------------------------------------------------
    SET V_DYNAMIC_TABLE = 'CLAIM_RULES_' || P_TENANT_ID;
    SET V_DYNAMIC_SQL =
        'SELECT THRESHOLD_AMOUNT, ACTION FROM ' || V_DYNAMIC_TABLE ||
        ' WHERE CLAIM_TYPE = ? AND CUSTOMER_TIER = ? ' ||
        '   AND VALID_FROM <= ? AND VALID_TO > ? ' ||
        'ORDER BY PRIORITY DESC FETCH FIRST 1 ROW ONLY';
    PREPARE S1 FROM V_DYNAMIC_SQL;
    EXECUTE S1 INTO V_RULE_THRESHOLD, V_RULE_ACTION
        USING V_CLAIM_TYPE, V_CUSTOMER_TIER,
              V_CURRENT_TS, V_CURRENT_TS;

    -- -----------------------------------------------------------------
    -- 7. MERGE statement to update/insert customer summary
    -- -----------------------------------------------------------------
    MERGE INTO CUSTOMER_CLAIM_SUMMARY AS T
    USING (
        SELECT CUSTOMER_ID,
               COUNT(*) AS OPEN_COUNT,
               SUM(CLAIM_AMOUNT) AS TOTAL_OPEN
        FROM CLAIM
        WHERE CUSTOMER_ID = V_CUSTOMER_ID
          AND TENANT_ID   = P_TENANT_ID
          AND STATUS IN ('SUBMITTED','PENDING_REVIEW')
          AND DELETED_IND = 'N'
        GROUP BY CUSTOMER_ID
    ) AS S
    ON T.CUSTOMER_ID = S.CUSTOMER_ID
       AND T.TENANT_ID = P_TENANT_ID
    WHEN MATCHED THEN
        UPDATE SET OPEN_CLAIM_COUNT = S.OPEN_COUNT,
                   TOTAL_OPEN_AMOUNT = S.TOTAL_OPEN,
                   UPDATED_TS = V_CURRENT_TS
    WHEN NOT MATCHED THEN
        INSERT (CUSTOMER_ID, TENANT_ID, OPEN_CLAIM_COUNT,
                TOTAL_OPEN_AMOUNT, UPDATED_TS)
        VALUES (S.CUSTOMER_ID, P_TENANT_ID, S.OPEN_COUNT,
                S.TOTAL_OPEN, V_CURRENT_TS);

    -- -----------------------------------------------------------------
    -- 8. Complex scoring combining all gathered data
    -- -----------------------------------------------------------------
    SET V_SCORE =
        (V_CLAIM_AMOUNT / NULLIF(V_PEER_AVG_AMOUNT, 0)) * 40.0
      + (V_LIFETIME_CLAIMS * 0.5)
      + (CASE WHEN V_MAX_SELF_AMOUNT > 0
              THEN V_CLAIM_AMOUNT / V_MAX_SELF_AMOUNT * 30.0
              ELSE 0 END)
      + (CASE WHEN V_SPIKE_FLAG = 1 THEN 20.0 ELSE 0 END)
      + (CASE WHEN V_FRAUD_FLAG = 'Y' THEN 50.0 ELSE 0 END);

    -- Apply dynamic rule adjustment
    IF V_RULE_THRESHOLD IS NOT NULL AND V_CLAIM_AMOUNT > V_RULE_THRESHOLD THEN
        SET V_SCORE = V_SCORE + 15.0;
    END IF;

    SET P_RISK_SCORE = DECIMAL(ROUND(V_SCORE, 3), 7, 3);

    -- -----------------------------------------------------------------
    -- 9. Decision logic with multiple branches and a cursor loop
    -- -----------------------------------------------------------------
    IF V_FRAUD_FLAG = 'Y' THEN
        SET P_FINAL_STATUS = 'REJECTED_FRAUD';
    ELSEIF P_RISK_SCORE > 90.0 AND V_APPROVAL_DEPTH IS NULL THEN
        SET P_FINAL_STATUS = 'REJECTED_NO_APPROVAL';
    ELSEIF P_RISK_SCORE > 75.0 THEN
        SET P_FINAL_STATUS = 'MANUAL_REVIEW';
    ELSE
        SET P_FINAL_STATUS = 'APPROVED';
    END IF;

    -- If status is MANUAL_REVIEW, enrich via cursor over related claims
    IF P_FINAL_STATUS = 'MANUAL_REVIEW' THEN
        BEGIN
            DECLARE V_REL_CLAIM_ID    BIGINT;
            DECLARE V_REL_AMOUNT      DECIMAL(15,2);
            DECLARE V_DONE            INTEGER DEFAULT 0;
            DECLARE C_REL CURSOR FOR
                SELECT CLAIM_ID, CLAIM_AMOUNT
                FROM CLAIM
                WHERE CUSTOMER_ID = V_CUSTOMER_ID
                  AND TENANT_ID   = P_TENANT_ID
                  AND CLAIM_ID   <> P_CLAIM_ID
                  AND STATUS IN ('PENDING_REVIEW','UNDER_INVESTIGATION')
                  AND DELETED_IND = 'N'
                ORDER BY CREATED_TS DESC
                FETCH FIRST 5 ROWS ONLY;
            DECLARE CONTINUE HANDLER FOR NOT FOUND
                SET V_DONE = 1;

            OPEN C_REL;
            FETCH_LOOP: LOOP
                FETCH C_REL INTO V_REL_CLAIM_ID, V_REL_AMOUNT;
                IF V_DONE = 1 THEN
                    LEAVE FETCH_LOOP;
                END IF;

                -- Subquery inside loop: check if related claim has a high‑risk flag
                IF EXISTS (
                    SELECT 1 FROM CLAIM_RISK_FLAG RF
                    WHERE RF.CLAIM_ID = V_REL_CLAIM_ID
                      AND RF.TENANT_ID = P_TENANT_ID
                      AND RF.RISK_LEVEL = 'HIGH'
                ) THEN
                    SET P_FINAL_STATUS = 'MANUAL_REVIEW_ESCALATED';
                    -- Insert audit record
                    INSERT INTO CLAIM_AUDIT (CLAIM_ID, TENANT_ID, NOTE, TS)
                    VALUES (P_CLAIM_ID, P_TENANT_ID,
                            'Related claim ' || CHAR(V_REL_CLAIM_ID) || ' high risk',
                            V_CURRENT_TS);
                END IF;

                SET V_CURSOR_ROW_COUNT = V_CURSOR_ROW_COUNT + 1;
            END LOOP;
            CLOSE C_REL;
        END;
    END IF;

    -- -----------------------------------------------------------------
    -- 10. Final update and audit generation
    -- -----------------------------------------------------------------
    IF P_FINAL_STATUS IN ('APPROVED','MANUAL_REVIEW','MANUAL_REVIEW_ESCALATED') THEN
        UPDATE CLAIM
           SET STATUS = P_FINAL_STATUS,
               RISK_SCORE = P_RISK_SCORE,
               UPDATED_TS = V_CURRENT_TS
         WHERE CLAIM_ID = P_CLAIM_ID
           AND TENANT_ID = P_TENANT_ID;
    ELSE
        -- Rejected or error: log to rejection audit
        INSERT INTO CLAIM_REJECTION_AUDIT (CLAIM_ID, TENANT_ID, STATUS, SCORE, TS)
        VALUES (P_CLAIM_ID, P_TENANT_ID, P_FINAL_STATUS, P_RISK_SCORE, V_CURRENT_TS);
    END IF;

    -- Generate an audit reference from a sequence
    SET P_AUDIT_REF = NEXT VALUE FOR AUDIT_SEQ;

END P_MEGA_PROCESS