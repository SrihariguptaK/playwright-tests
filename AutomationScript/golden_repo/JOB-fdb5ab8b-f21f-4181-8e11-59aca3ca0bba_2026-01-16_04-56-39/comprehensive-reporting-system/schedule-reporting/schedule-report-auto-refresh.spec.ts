import { test, expect } from '@playwright/test';

test.describe('Schedule Report Auto-Refresh - Story 9', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate automatic schedule report refresh after schedule changes', async ({ page }) => {
    // Step 1: Navigate to the schedule reports section from the main dashboard
    await page.click('[data-testid="schedule-reports-nav"]');
    await expect(page.locator('[data-testid="schedule-reports-page"]')).toBeVisible();

    // Step 2: Select and open a specific schedule report to view
    await page.click('[data-testid="schedule-report-item"]');
    await expect(page.locator('[data-testid="schedule-report-detail"]')).toBeVisible();

    // Step 3: Note the current data values in the report
    const initialEmployeeName = await page.locator('[data-testid="employee-name-cell"]').first().textContent();
    const initialShiftTime = await page.locator('[data-testid="shift-time-cell"]').first().textContent();
    const initialTimestamp = await page.locator('[data-testid="report-timestamp"]').textContent();

    // Step 4: Navigate to the scheduling module while keeping the report accessible
    await page.click('[data-testid="scheduling-module-nav"]');
    await expect(page.locator('[data-testid="scheduling-page"]')).toBeVisible();

    // Step 5: Make a schedule change (reassign an employee to a different shift)
    await page.click('[data-testid="schedule-entry-edit-button"]');
    await expect(page.locator('[data-testid="schedule-edit-modal"]')).toBeVisible();
    
    await page.selectOption('[data-testid="shift-select"]', 'Evening Shift');
    await page.fill('[data-testid="shift-time-input"]', '18:00');

    // Step 6: Save the schedule changes in the system
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Changes saved successfully');

    // Step 7: Return to the schedule report view immediately after saving changes
    await page.click('[data-testid="schedule-reports-nav"]');
    await page.click('[data-testid="schedule-report-item"]');
    await expect(page.locator('[data-testid="schedule-report-detail"]')).toBeVisible();

    // Step 8: Monitor the report for automatic refresh, waiting up to 5 minutes
    const startTime = Date.now();
    let refreshDetected = false;
    let refreshTime = 0;

    // Poll for report refresh by checking timestamp change
    while (Date.now() - startTime < 5 * 60 * 1000) {
      await page.waitForTimeout(10000); // Check every 10 seconds
      const currentTimestamp = await page.locator('[data-testid="report-timestamp"]').textContent();
      
      if (currentTimestamp !== initialTimestamp) {
        refreshDetected = true;
        refreshTime = (Date.now() - startTime) / 1000;
        break;
      }
    }

    // Step 9: Verify the report now displays the updated schedule data
    expect(refreshDetected).toBeTruthy();
    expect(refreshTime).toBeLessThanOrEqual(300); // Within 5 minutes

    const updatedShiftTime = await page.locator('[data-testid="shift-time-cell"]').first().textContent();
    expect(updatedShiftTime).not.toBe(initialShiftTime);
    expect(updatedShiftTime).toContain('18:00');

    // Step 10: Check the report timestamp or last updated indicator
    const finalTimestamp = await page.locator('[data-testid="report-timestamp"]').textContent();
    expect(finalTimestamp).not.toBe(initialTimestamp);
    await expect(page.locator('[data-testid="report-last-updated"]')).toBeVisible();
  });

  test('Verify user notification of report refresh completion', async ({ page }) => {
    // Step 1: Navigate to the schedule reports section and open a specific schedule report
    await page.click('[data-testid="schedule-reports-nav"]');
    await expect(page.locator('[data-testid="schedule-reports-page"]')).toBeVisible();
    await page.click('[data-testid="schedule-report-item"]');
    await expect(page.locator('[data-testid="schedule-report-detail"]')).toBeVisible();

    // Step 2: Navigate to the scheduling module to make changes
    await page.click('[data-testid="scheduling-module-nav"]');
    await expect(page.locator('[data-testid="scheduling-page"]')).toBeVisible();

    // Step 3: Trigger a schedule change by modifying an existing schedule entry
    await page.click('[data-testid="schedule-entry-edit-button"]');
    await expect(page.locator('[data-testid="schedule-edit-modal"]')).toBeVisible();
    
    await page.selectOption('[data-testid="employee-select"]', 'John Smith');
    await page.fill('[data-testid="shift-time-input"]', '14:00');

    // Step 4: Save the schedule changes to trigger the report refresh process
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 5: Monitor the notification area for refresh status updates
    const notificationBell = page.locator('[data-testid="notification-bell"]');
    await expect(notificationBell).toBeVisible();

    // Step 6: Wait for the automatic report refresh process to complete (up to 5 minutes)
    let notificationReceived = false;
    const startTime = Date.now();

    while (Date.now() - startTime < 5 * 60 * 1000) {
      await page.waitForTimeout(10000); // Check every 10 seconds
      
      const notificationBadge = page.locator('[data-testid="notification-badge"]');
      const badgeCount = await notificationBadge.textContent().catch(() => '0');
      
      if (parseInt(badgeCount) > 0) {
        notificationReceived = true;
        break;
      }
    }

    // Step 7: Check for a completion notification in the notification area
    expect(notificationReceived).toBeTruthy();
    await page.click('[data-testid="notification-bell"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();

    const refreshNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'refresh' });
    await expect(refreshNotification).toBeVisible();
    await expect(refreshNotification).toContainText('completion');

    // Step 8: Click on the notification to verify it links back to the refreshed report
    await refreshNotification.click();
    await expect(page.locator('[data-testid="schedule-report-detail"]')).toBeVisible();
    await expect(page).toHaveURL(/.*schedule-reports/);

    // Step 9: Verify the refreshed report contains the schedule changes made in step 3
    const updatedEmployeeName = await page.locator('[data-testid="employee-name-cell"]').filter({ hasText: 'John Smith' }).first();
    await expect(updatedEmployeeName).toBeVisible();
    
    const updatedShiftTime = await page.locator('[data-testid="shift-time-cell"]').filter({ hasText: '14:00' }).first();
    await expect(updatedShiftTime).toBeVisible();

    // Step 10: Check notification history or log to confirm the notification was recorded
    await page.click('[data-testid="notification-bell"]');
    await page.click('[data-testid="notification-history-link"]');
    await expect(page.locator('[data-testid="notification-history-page"]')).toBeVisible();
    
    const historyEntry = page.locator('[data-testid="notification-history-item"]').filter({ hasText: 'report refresh' });
    await expect(historyEntry).toBeVisible();
    await expect(historyEntry).toContainText('completion');
  });
});