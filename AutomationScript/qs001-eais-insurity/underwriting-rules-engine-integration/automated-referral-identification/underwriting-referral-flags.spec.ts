import { test, expect } from '@playwright/test';

test.describe('Underwriting Referral Flags - Story 21', () => {
  const submitterCredentials = {
    username: 'application.submitter@test.com',
    password: 'TestPass123!'
  };

  const specialistCredentials = {
    username: 'underwriting.specialist@test.com',
    password: 'SpecialistPass123!'
  };

  const referralApplicationData = {
    applicantName: 'John Doe',
    occupation: 'Offshore Oil Rig Worker',
    coverageAmount: '2500000',
    medicalHistory: 'Adverse medical history - diabetes',
    dateOfBirth: '01/15/1980',
    email: 'john.doe@test.com',
    phone: '555-0123'
  };

  test('Validate automatic referral flagging on application submission', async ({ page }) => {
    // Step 1: Log into the application submission portal with valid credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', submitterCredentials.username);
    await page.fill('[data-testid="password-input"]', submitterCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Fill out application form with data that meets referral criteria
    await page.goto('/application/new');
    await page.fill('[data-testid="applicant-name"]', referralApplicationData.applicantName);
    await page.fill('[data-testid="occupation"]', referralApplicationData.occupation);
    await page.fill('[data-testid="coverage-amount"]', referralApplicationData.coverageAmount);
    await page.fill('[data-testid="medical-history"]', referralApplicationData.medicalHistory);
    await page.fill('[data-testid="date-of-birth"]', referralApplicationData.dateOfBirth);
    await page.fill('[data-testid="email"]', referralApplicationData.email);
    await page.fill('[data-testid="phone"]', referralApplicationData.phone);

    // Step 3: Submit the application by clicking the Submit button
    const submissionTime = Date.now();
    const responsePromise = page.waitForResponse(response => 
      response.url().includes('/api/underwriting/evaluate') && response.status() === 200
    );
    await page.click('[data-testid="submit-application-button"]');
    
    // Step 4: Verify system sends application data to underwriting rules engine
    const response = await responsePromise;
    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('referralFlag');
    expect(responseBody.referralFlag).toBe(true);
    
    // Capture application ID from response or confirmation page
    await expect(page.locator('[data-testid="application-submitted-message"]')).toBeVisible();
    const applicationId = await page.locator('[data-testid="application-id"]').textContent();
    expect(applicationId).toBeTruthy();

    // Step 5: Log out and log into the underwriting specialist dashboard
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', specialistCredentials.username);
    await page.fill('[data-testid="password-input"]', specialistCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*specialist.*dashboard/);

    // Step 6: Navigate to the referrals section or filter applications by referral status
    await page.click('[data-testid="referrals-tab"]');
    await page.selectOption('[data-testid="status-filter"]', 'referral');
    
    // Step 7: Verify application is displayed with referral flag
    const referralRow = page.locator(`[data-testid="application-row-${applicationId?.trim()}"]`);
    await expect(referralRow).toBeVisible();
    await expect(referralRow.locator('[data-testid="referral-flag-icon"]')).toBeVisible();
    await expect(referralRow.locator('[data-testid="referral-status"]')).toHaveText(/Referral|Flagged/);

    // Step 8: Access the referral log and verify timestamp
    await referralRow.click();
    await page.click('[data-testid="view-referral-log"]');
    
    const logEntry = page.locator('[data-testid="referral-log-entry"]').first();
    await expect(logEntry).toBeVisible();
    
    const logTimestamp = await logEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    
    // Verify referral decision is recorded
    await expect(logEntry.locator('[data-testid="referral-decision"]')).toHaveText(/Referral Required|Flagged/);
    await expect(logEntry.locator('[data-testid="referral-reason"]')).toBeVisible();
    
    // Verify timestamp is within 2 seconds of submission time
    const logTime = new Date(logTimestamp!).getTime();
    const timeDifference = Math.abs(logTime - submissionTime);
    expect(timeDifference).toBeLessThanOrEqual(2000);
  });

  test('Verify notification alert for new referrals', async ({ page }) => {
    // Step 1: Ensure underwriting specialist is logged into the system
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', specialistCredentials.username);
    await page.fill('[data-testid="password-input"]', specialistCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*specialist.*dashboard/);
    
    // Verify notification preferences are configured
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="notification-settings"]');
    await expect(page.locator('[data-testid="referral-notifications-toggle"]')).toBeChecked();
    await page.goto('/specialist/dashboard');

    // Step 2: Submit a new application with data that triggers referral criteria
    // Open new tab/context for submission
    const submissionPage = await page.context().newPage();
    await submissionPage.goto('/login');
    await submissionPage.fill('[data-testid="username-input"]', submitterCredentials.username);
    await submissionPage.fill('[data-testid="password-input"]', submitterCredentials.password);
    await submissionPage.click('[data-testid="login-button"]');
    
    await submissionPage.goto('/application/new');
    await submissionPage.fill('[data-testid="applicant-name"]', 'Jane Smith');
    await submissionPage.fill('[data-testid="occupation"]', 'Commercial Pilot');
    await submissionPage.fill('[data-testid="coverage-amount"]', '3000000');
    await submissionPage.fill('[data-testid="medical-history"]', 'Recent cardiac evaluation');
    await submissionPage.fill('[data-testid="date-of-birth"]', '05/20/1975');
    await submissionPage.fill('[data-testid="email"]', 'jane.smith@test.com');
    await submissionPage.fill('[data-testid="phone"]', '555-0456');
    
    await submissionPage.click('[data-testid="submit-application-button"]');
    await expect(submissionPage.locator('[data-testid="application-submitted-message"]')).toBeVisible();
    const applicationId = await submissionPage.locator('[data-testid="application-id"]').textContent();
    await submissionPage.close();

    // Step 3: Check notification delivery mechanism
    await page.waitForTimeout(1000); // Allow notification to propagate
    await page.reload();
    
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible();
    const notificationCount = await notificationBadge.textContent();
    expect(parseInt(notificationCount!)).toBeGreaterThan(0);
    
    // Step 4: Verify notification content
    await page.click('[data-testid="notification-bell"]');
    const notificationPanel = page.locator('[data-testid="notification-panel"]');
    await expect(notificationPanel).toBeVisible();
    
    const latestNotification = notificationPanel.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toBeVisible();
    await expect(latestNotification).toContainText(applicationId?.trim() || '');
    await expect(latestNotification.locator('[data-testid="notification-reason"]')).toBeVisible();
    await expect(latestNotification.locator('[data-testid="notification-timestamp"]')).toBeVisible();

    // Step 5: Log into underwriting specialist dashboard (already logged in)
    await page.click('[data-testid="referrals-tab"]');
    
    // Step 6: Locate the referral flagged application in the dashboard
    const referralRow = page.locator(`[data-testid="application-row-${applicationId?.trim()}"]`);
    await expect(referralRow).toBeVisible();
    await expect(referralRow.locator('[data-testid="referral-flag-icon"]')).toBeVisible();
    
    // Step 7: Click on the referral flagged application to view details
    await referralRow.click();
    await expect(page.locator('[data-testid="application-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="referral-status-badge"]')).toHaveText(/Referral|Flagged/);
    
    // Step 8: Clear the referral flag
    await page.click('[data-testid="clear-referral-button"]');
    
    // Step 9: Confirm the clearance action
    const confirmDialog = page.locator('[data-testid="confirm-clear-dialog"]');
    await expect(confirmDialog).toBeVisible();
    await page.click('[data-testid="confirm-clear-yes-button"]');
    
    // Verify flag status is updated
    await expect(page.locator('[data-testid="referral-cleared-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="referral-status-badge"]')).toHaveText(/Cleared|Processed/);
    
    // Step 10: Verify notification is cleared or marked as resolved
    await page.click('[data-testid="notification-bell"]');
    const clearedNotification = notificationPanel.locator(`[data-testid="notification-item"][data-application-id="${applicationId?.trim()}"]`);
    await expect(clearedNotification.locator('[data-testid="notification-status"]')).toHaveText(/Resolved|Cleared/);
    
    // Step 11: Refresh the dashboard and verify application no longer in active referrals
    await page.click('[data-testid="referrals-tab"]');
    await page.selectOption('[data-testid="status-filter"]', 'referral');
    await page.reload();
    
    const activeReferralRow = page.locator(`[data-testid="application-row-${applicationId?.trim()}"]`);
    await expect(activeReferralRow).not.toBeVisible();
  });
});