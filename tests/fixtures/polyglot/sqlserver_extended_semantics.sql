CREATE OR ALTER PROCEDURE claims.AdjustClaims
    @Limit int,
    @Status nvarchar(40) OUTPUT
WITH EXECUTE AS OWNER, RECOMPILE
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
    CREATE TABLE #changed (ClaimId bigint NOT NULL PRIMARY KEY);
    DECLARE c CURSOR LOCAL FAST_FORWARD FOR SELECT ClaimId FROM claims.Claim WHERE Status = N'PENDING';
    BEGIN TRY
        BEGIN TRANSACTION;
        SAVE TRANSACTION before_update;
        UPDATE TOP (@Limit) claims.Claim
           SET Status = N'ADJUSTED'
           OUTPUT inserted.ClaimId INTO #changed(ClaimId)
         WHERE Status = N'PENDING';
        IF @@ROWCOUNT = 0 GOTO no_rows;
        SET @Status = N'DONE';
        COMMIT TRANSACTION;
        GOTO finish;
no_rows:
        SET @Status = N'EMPTY';
        ROLLBACK TRANSACTION before_update;
finish:
        SELECT ClaimId FROM #changed;
    END TRY
    BEGIN CATCH
        IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
        PRINT ERROR_MESSAGE();
        RAISERROR('Adjustment failed', 16, 1);
    END CATCH
END;
GO
