import { test, expect } from '@playwright/test';

test.describe('Risk Factor Review and Validation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate risk factor review dashboard displays data correctly', async ({ page }) => {
    // Step 1: Login as Risk Analyst and navigate to review dashboard
    await page.fill('[data-testid="username-input"]', 'risk.analyst@company.com');
    await page.fill('[data-testid="password-input"]', 'RiskAnalyst123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and navigate to dashboard
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="main-menu"]');
    await page.click('text=Risk Factor Review');
    
    // Expected Result: Dashboard displays all captured risk factors
    await expect(page.locator('[data-testid="risk-factor-review-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="risk-factors-table"]')).toBeVisible();
    const riskFactorRows = page.locator('[data-testid="risk-factor-row"]');
    await expect(riskFactorRows).toHaveCount(await riskFactorRows.count());
    expect(await riskFactorRows.count()).toBeGreaterThan(0);
    
    // Step 2: Identify missing or inconsistent data
    // Expected Result: System highlights issues clearly
    const highlightedIssues = page.locator('[data-testid="risk-factor-issue"]');
    await expect(highlightedIssues.first()).toBeVisible();
    await expect(highlightedIssues.first()).toHaveClass(/.*highlighted.*|.*warning.*|.*error.*/);
    
    // Verify issue indicators are present
    const missingDataIndicator = page.locator('[data-testid="missing-data-indicator"]');
    const inconsistentDataIndicator = page.locator('[data-testid="inconsistent-data-indicator"]');
    const issueCount = await missingDataIndicator.count() + await inconsistentDataIndicator.count();
    expect(issueCount).toBeGreaterThan(0);
    
    // Step 3: Request corrections with comments
    await highlightedIssues.first().click();
    await page.click('[data-testid="request-corrections-button"]');
    
    // Enter correction request comments
    await page.fill('[data-testid="correction-comments-field"]', 'Missing employment history data. Please provide complete employment records for the past 5 years.');
    await page.click('[data-testid="submit-correction-request-button"]');
    
    // Expected Result: Correction request submitted and status updated
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Correction request submitted successfully');
    
    // Verify status update
    const statusBadge = page.locator('[data-testid="risk-factor-status"]').first();
    await expect(statusBadge).toContainText('Correction Requested');
  });

  test('Verify access control restricts non-analyst users', async ({ page, request }) => {
    // Step 1: Login as non-Risk Analyst user
    await page.fill('[data-testid="username-input"]', 'regular.user@company.com');
    await page.fill('[data-testid="password-input"]', 'RegularUser123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Expected Result: Access to review dashboard is denied
    // Attempt to navigate via menu
    await page.click('[data-testid="main-menu"]');
    const riskReviewMenuItem = page.locator('text=Risk Factor Review');
    await expect(riskReviewMenuItem).not.toBeVisible();
    
    // Attempt direct URL access
    await page.goto('/risk-factor-review');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page).toHaveURL(/.*unauthorized|.*access-denied/);
    
    // Step 2: Attempt to access review APIs
    // Expected Result: Access denied with appropriate error
    const apiResponse = await request.get('/api/applicants/riskfactors/review', {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });
    
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Access denied');
    expect(responseBody.message).toMatch(/unauthorized|forbidden|access denied/i);
  });

  test('Test approval of risk factor data', async ({ page }) => {
    // Step 1: Login as Risk Analyst and review risk data
    await page.fill('[data-testid="username-input"]', 'risk.analyst@company.com');
    await page.fill('[data-testid="password-input"]', 'RiskAnalyst123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="main-menu"]');
    await page.click('text=Risk Factor Review');
    
    // Expected Result: Data displayed for review
    await expect(page.locator('[data-testid="risk-factor-review-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="risk-factors-table"]')).toBeVisible();
    
    // Select a complete and valid risk factor record
    const validRiskFactorRow = page.locator('[data-testid="risk-factor-row"]').filter({
      has: page.locator('[data-testid="risk-factor-complete-indicator"]')
    }).first();
    
    await expect(validRiskFactorRow).toBeVisible();
    await validRiskFactorRow.click();
    
    // Review all risk factor details
    await expect(page.locator('[data-testid="risk-factor-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="applicant-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="employment-history"]')).toBeVisible();
    await expect(page.locator('[data-testid="financial-data"]')).toBeVisible();
    await expect(page.locator('[data-testid="credit-score"]')).toBeVisible();
    
    // Verify completeness indicators
    const completenessIndicator = page.locator('[data-testid="completeness-indicator"]');
    await expect(completenessIndicator).toContainText('100%');
    
    // Step 2: Approve risk data
    await page.click('[data-testid="approve-button"]');
    
    // Confirm approval if confirmation dialog appears
    const confirmDialog = page.locator('[data-testid="confirm-approval-dialog"]');
    if (await confirmDialog.isVisible()) {
      await page.click('[data-testid="confirm-approve-button"]');
    }
    
    // Expected Result: Status updated to approved and confirmation shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Risk data approved successfully');
    
    // Verify status update
    const statusBadge = page.locator('[data-testid="risk-factor-status"]');
    await expect(statusBadge).toContainText('Approved');
    await expect(statusBadge).toHaveClass(/.*approved.*|.*success.*/);
    
    // Verify approval timestamp is displayed
    const approvalTimestamp = page.locator('[data-testid="approval-timestamp"]');
    await expect(approvalTimestamp).toBeVisible();
    expect(await approvalTimestamp.textContent()).toMatch(/\d{1,2}\/\d{1,2}\/\d{4}/);
  });
});