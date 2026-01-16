import { test, expect } from '@playwright/test';

test.describe('Story-28: Underwriting Specialist Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Login as underwriting specialist
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'specialist@underwriting.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify notification delivery for referral updates (happy-path)', async ({ page }) => {
    // Navigate to the referrals list
    await page.click('[data-testid="referrals-menu"]');
    await expect(page).toHaveURL(/.*referrals/);
    await page.waitForSelector('[data-testid="referrals-list"]');

    // Select an existing referral assigned to the current specialist
    const referralRow = page.locator('[data-testid="referral-row"]').first();
    await expect(referralRow).toBeVisible();
    const referralId = await referralRow.getAttribute('data-referral-id');
    await referralRow.click();

    // Note the current referral status and timestamp before making changes
    await page.waitForSelector('[data-testid="referral-details"]');
    const currentStatus = await page.locator('[data-testid="referral-status"]').textContent();
    const currentTimestamp = await page.locator('[data-testid="referral-timestamp"]').textContent();
    expect(currentStatus).toBeTruthy();
    expect(currentTimestamp).toBeTruthy();

    // Update the referral status to a different state
    await page.click('[data-testid="edit-referral-button"]');
    await page.waitForSelector('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-dropdown"]');
    
    // Select 'Under Investigation' status
    await page.click('[data-testid="status-option-under-investigation"]');
    await page.click('[data-testid="save-referral-button"]');

    // Verify that a notification is generated immediately after the status update
    await page.waitForSelector('[data-testid="notification-indicator"]', { timeout: 2000 });
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible();
    const notificationCount = await notificationBadge.textContent();
    expect(parseInt(notificationCount || '0')).toBeGreaterThan(0);

    // Check the system notification panel or bell icon in the application header
    await page.click('[data-testid="notification-bell-icon"]');
    await page.waitForSelector('[data-testid="notification-panel"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();

    // Verify the notification content includes relevant details about the referral update
    const latestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toBeVisible();
    const notificationText = await latestNotification.textContent();
    expect(notificationText).toContain('referral');
    expect(notificationText).toContain('Under Investigation');
    expect(notificationText?.toLowerCase()).toMatch(/update|changed|modified/);

    // Check the specialist's email inbox for the notification email
    // Note: This would typically require email API integration or test email service
    // For automation purposes, we verify the email notification was triggered
    await page.goto('/settings/notifications');
    await page.waitForSelector('[data-testid="notification-history"]');
    const emailNotificationLog = page.locator('[data-testid="email-notification-log"]').first();
    await expect(emailNotificationLog).toBeVisible();
    const emailStatus = await emailNotificationLog.locator('[data-testid="email-status"]').textContent();
    expect(emailStatus).toContain('Sent');

    // Click on the notification in the system notification panel
    await page.click('[data-testid="notification-bell-icon"]');
    await page.waitForSelector('[data-testid="notification-panel"]');
    const notificationToClick = page.locator('[data-testid="notification-item"]').first();
    await notificationToClick.click();

    // Verify the notification is visible and actionable by checking available actions
    await page.waitForSelector('[data-testid="notification-detail-view"]');
    await expect(page.locator('[data-testid="notification-detail-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledge-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledge-button"]')).toBeEnabled();

    // Click the 'Acknowledge' button on the notification
    await page.click('[data-testid="acknowledge-button"]');
    await page.waitForTimeout(500);

    // Verify notification status updates to acknowledged
    const acknowledgedStatus = page.locator('[data-testid="notification-status"]');
    await expect(acknowledgedStatus).toHaveText(/acknowledged/i);

    // Navigate to the notification history section from the user profile or settings menu
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="notification-history-link"]');
    await expect(page).toHaveURL(/.*notifications.*history/);
    await page.waitForSelector('[data-testid="notification-history-table"]');

    // Search for the acknowledged notification using the referral ID or date filter
    await page.fill('[data-testid="notification-search-input"]', referralId || '');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(500);

    // Verify the notification history shows the complete audit trail
    const historyRow = page.locator('[data-testid="notification-history-row"]').first();
    await expect(historyRow).toBeVisible();
    
    const historyReferralId = await historyRow.locator('[data-testid="history-referral-id"]').textContent();
    expect(historyReferralId).toContain(referralId || '');
    
    const historyStatus = await historyRow.locator('[data-testid="history-status"]').textContent();
    expect(historyStatus).toContain('Acknowledged');
    
    const historyTimestamp = await historyRow.locator('[data-testid="history-timestamp"]').textContent();
    expect(historyTimestamp).toBeTruthy();
    
    const historyDetails = await historyRow.locator('[data-testid="history-details"]').textContent();
    expect(historyDetails).toContain('Under Investigation');
  });

  test('Verify notification delivery for referral updates - basic flow', async ({ page }) => {
    // Navigate to referrals and update status
    await page.goto('/referrals');
    await page.waitForSelector('[data-testid="referrals-list"]');
    
    const referral = page.locator('[data-testid="referral-row"]').first();
    await referral.click();
    
    // Action: Update referral status
    await page.click('[data-testid="edit-referral-button"]');
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-approved"]');
    await page.click('[data-testid="save-referral-button"]');
    
    // Expected Result: Notification is generated and sent
    await page.waitForSelector('[data-testid="notification-indicator"]', { timeout: 2000 });
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();
    
    // Action: Specialist receives notification
    await page.click('[data-testid="notification-bell-icon"]');
    await page.waitForSelector('[data-testid="notification-panel"]');
    
    // Expected Result: Notification is visible and actionable
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    await expect(page.locator('[data-testid="acknowledge-button"]')).toBeVisible();
    
    // Action: Specialist acknowledges notification
    await page.click('[data-testid="acknowledge-button"]');
    
    // Expected Result: Notification status updates to acknowledged
    await expect(page.locator('[data-testid="notification-status"]')).toHaveText(/acknowledged/i);
  });
});