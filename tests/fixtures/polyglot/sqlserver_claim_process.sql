CREATE OR ALTER PROCEDURE claims.ProcessClaim
    @ClaimId BIGINT,
    @Amount DECIMAL(18,2),
    @Decision NVARCHAR(40) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @Score DECIMAL(18,2) = 0;
    BEGIN TRY
        IF @ClaimId IS NULL
        BEGIN
            THROW 50001, 'Claim id required', 1;
        END
        ELSE IF @Amount > 100000
        BEGIN
            SET @Decision = N'REVIEW';
        END
        ELSE
        BEGIN
            SELECT @Score = @Amount + COUNT(*) FROM claims.ClaimItem WHERE ClaimId = @ClaimId;
            WHILE @Score > 50000
            BEGIN
                SET @Score = @Score - 10000;
                IF @Score < 60000 BREAK;
            END
            SET @Decision = CASE WHEN @Score > 25000 THEN N'MANUAL_REVIEW' ELSE N'APPROVED' END;
        END

        BEGIN TRANSACTION;
        UPDATE claims.Claim SET Status = @Decision WHERE ClaimId = @ClaimId;
        INSERT INTO claims.ClaimAudit(ClaimId, Decision) VALUES (@ClaimId, @Decision);
        EXEC sys.sp_executesql N'UPDATE claims.ClaimSummary SET Touched = 1 WHERE ClaimId = @p', N'@p bigint', @ClaimId;
        COMMIT TRANSACTION;
        SELECT ClaimId, Status FROM claims.Claim WHERE ClaimId = @ClaimId;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        SET @Decision = N'ERROR';
        THROW;
    END CATCH
END;
GO
