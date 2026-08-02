CREATE OR REPLACE PROCEDURE claims.validate_claim(p_id IN NUMBER, p_ok OUT NUMBER) AS
BEGIN
  IF p_id IS NULL THEN p_ok := 0; ELSE p_ok := 1; END IF;
END validate_claim;
/
CREATE OR REPLACE FUNCTION claims.claim_score(p_amount IN NUMBER) RETURN NUMBER AS
BEGIN
  IF p_amount > 1000 THEN RETURN 100; ELSE RETURN 10; END IF;
END claim_score;
/
