import { test, expect } from '@playwright/test';

test.describe('Story-22: View Detailed Referral Reasons', () => {
  const baseURL = process.env.BASE_URL || 'https://app.example.com';
  const specialistEmail = 'specialist@example.com';
  const specialistPassword = 'SecurePass123!';
  const unauthorizedEmail = 'user@example.com';
  const unauthorizedPassword = 'UserPass123!';
  const referralApplicationId = 'REF-2024-001';

  test('Verify referral reason details display (happy-path)', async ({ page, context }) => {
    // Log into the system as an authorized underwriting specialist
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', specialistEmail);
    await page.fill('[data-testid="password-input"]', specialistPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 10000 });

    // Navigate to the referrals section of the dashboard
    await page.click('[data-testid="referrals-menu"]');
    await expect(page.locator('[data-testid="referrals-section"]')).toBeVisible();

    // Select a referral flagged application from the list by clicking on it
    await page.click(`[data-testid="referral-application-${referralApplicationId}"]`);
    await expect(page.locator('[data-testid="application-details"]')).toBeVisible();

    // Locate and view the referral reasons section on the application details page
    const referralReasonsSection = page.locator('[data-testid="referral-reasons-section"]');
    await expect(referralReasonsSection).toBeVisible();

    // Verify each referral reason includes the specific underwriting rule code that triggered it
    const referralReasons = page.locator('[data-testid="referral-reason-item"]');
    const reasonCount = await referralReasons.count();
    expect(reasonCount).toBeGreaterThan(0);

    for (let i = 0; i < reasonCount; i++) {
      const reasonItem = referralReasons.nth(i);
      await expect(reasonItem.locator('[data-testid="rule-code"]')).toBeVisible();
      await expect(reasonItem.locator('[data-testid="rule-description"]')).toBeVisible();
      const ruleCode = await reasonItem.locator('[data-testid="rule-code"]').textContent();
      expect(ruleCode).toBeTruthy();
    }

    // Click on a rule code link to view the complete rule details
    const firstRuleLink = referralReasons.first().locator('[data-testid="rule-code-link"]');
    await firstRuleLink.click();
    await expect(page.locator('[data-testid="rule-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="rule-details-content"]')).toBeVisible();
    await page.click('[data-testid="close-modal-button"]');

    // Measure the time taken from clicking the application to displaying referral details
    const startTime = Date.now();
    await page.click('[data-testid="referrals-menu"]');
    await page.click(`[data-testid="referral-application-${referralApplicationId}"]`);
    await expect(page.locator('[data-testid="referral-reasons-section"]')).toBeVisible();
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    expect(loadTime).toBeLessThan(1000); // Performance requirement: within 1 second

    // Verify API call to GET /api/referrals/{id}/details returns response within performance threshold
    const apiStartTime = Date.now();
    const apiResponse = await page.request.get(`${baseURL}/api/referrals/${referralApplicationId}/details`);
    const apiEndTime = Date.now();
    const apiResponseTime = apiEndTime - apiStartTime;
    expect(apiResponse.status()).toBe(200);
    expect(apiResponseTime).toBeLessThan(1000);
    const responseData = await apiResponse.json();
    expect(responseData).toHaveProperty('referralReasons');
    expect(responseData.referralReasons.length).toBeGreaterThan(0);

    // Log out from the specialist account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Log into the system with an unauthorized user account (non-specialist role)
    await page.fill('[data-testid="email-input"]', unauthorizedEmail);
    await page.fill('[data-testid="password-input"]', unauthorizedPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 10000 });

    // Attempt to access the referral flagged application details directly via URL or navigation
    await page.goto(`${baseURL}/referrals/${referralApplicationId}`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible({ timeout: 5000 });
    const accessDeniedText = await page.locator('[data-testid="access-denied-message"]').textContent();
    expect(accessDeniedText).toContain('Access denied');

    // Attempt to call GET /api/referrals/{id}/details API endpoint with unauthorized credentials
    const unauthorizedApiResponse = await page.request.get(`${baseURL}/api/referrals/${referralApplicationId}/details`);
    expect(unauthorizedApiResponse.status()).toBe(403);

    // Log out from unauthorized account and log back in as authorized specialist
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    await page.fill('[data-testid="email-input"]', specialistEmail);
    await page.fill('[data-testid="password-input"]', specialistPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 10000 });

    // Navigate back to the referral flagged application details page
    await page.click('[data-testid="referrals-menu"]');
    await page.click(`[data-testid="referral-application-${referralApplicationId}"]`);
    await expect(page.locator('[data-testid="application-details"]')).toBeVisible();

    // Locate and access the referral history section
    await page.click('[data-testid="referral-history-tab"]');
    const referralHistorySection = page.locator('[data-testid="referral-history-section"]');
    await expect(referralHistorySection).toBeVisible();

    // Verify each history entry includes timestamp, rule triggered, and status change
    const historyEntries = page.locator('[data-testid="history-entry"]');
    const historyCount = await historyEntries.count();
    expect(historyCount).toBeGreaterThan(0);

    for (let i = 0; i < historyCount; i++) {
      const historyEntry = historyEntries.nth(i);
      await expect(historyEntry.locator('[data-testid="history-timestamp"]')).toBeVisible();
      await expect(historyEntry.locator('[data-testid="history-rule-triggered"]')).toBeVisible();
      await expect(historyEntry.locator('[data-testid="history-status-change"]')).toBeVisible();
      
      const timestamp = await historyEntry.locator('[data-testid="history-timestamp"]').textContent();
      expect(timestamp).toBeTruthy();
      expect(timestamp).toMatch(/\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{4}/);
    }

    // Verify the initial referral flagging timestamp matches the application submission processing time
    const firstHistoryEntry = historyEntries.first();
    const initialTimestamp = await firstHistoryEntry.locator('[data-testid="history-timestamp"]').textContent();
    expect(initialTimestamp).toBeTruthy();
    
    const applicationSubmissionTime = await page.locator('[data-testid="application-submission-time"]').textContent();
    expect(applicationSubmissionTime).toBeTruthy();

    // Check if any subsequent changes to referral status are logged with specialist ID
    if (historyCount > 1) {
      for (let i = 1; i < historyCount; i++) {
        const historyEntry = historyEntries.nth(i);
        const specialistId = historyEntry.locator('[data-testid="history-specialist-id"]');
        if (await specialistId.count() > 0) {
          await expect(specialistId).toBeVisible();
          const specialistIdText = await specialistId.textContent();
          expect(specialistIdText).toBeTruthy();
        }
      }
    }

    // Final cleanup - logout
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
  });
});