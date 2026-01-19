import { test, expect } from '@playwright/test';

test.describe('Supervisor Acknowledge Attendance Anomaly Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Login as supervisor
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'supervisor@company.com');
    await page.fill('[data-testid="password-input"]', 'SupervisorPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate supervisor acknowledgment of attendance anomaly (happy-path)', async ({ page }) => {
    // Navigate to the notifications section in the application
    await page.click('[data-testid="notifications-menu"]');
    await expect(page.locator('[data-testid="notifications-section"]')).toBeVisible();

    // Locate the unacknowledged attendance anomaly notification in the list
    const unacknowledgedNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Attendance Anomaly' }).filter({ has: page.locator('[data-testid="status-unacknowledged"]') }).first();
    await expect(unacknowledgedNotification).toBeVisible();

    // Click on the notification to view full details
    await unacknowledgedNotification.click();
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();

    // Locate and click the 'Acknowledge' button
    const acknowledgeButton = page.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeButton).toBeVisible();
    await acknowledgeButton.click();

    // Enter optional comment: 'Spoke with employee - medical emergency, documentation to follow'
    await page.fill('[data-testid="acknowledgment-comment"]', 'Spoke with employee - medical emergency, documentation to follow');

    // Click 'Submit' or 'Confirm' button to complete acknowledgment
    await page.click('[data-testid="submit-acknowledgment-button"]');

    // Verify notification status updated in the notifications list
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();
    await page.click('[data-testid="close-notification-details"]');
    
    const acknowledgedNotification = page.locator('[data-testid="notification-item"]').filter({ has: page.locator('[data-testid="status-acknowledged"]') }).first();
    await expect(acknowledgedNotification).toBeVisible();

    // Navigate to system audit logs or acknowledgment history section
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-logs-section"]')).toBeVisible();

    // Search for the recently acknowledged notification in audit logs
    await page.fill('[data-testid="audit-search-input"]', 'Attendance Anomaly');
    await page.click('[data-testid="audit-search-button"]');

    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();

    // Verify timestamp accuracy in acknowledgment record
    const timestamp = await auditLogEntry.locator('[data-testid="audit-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    const timestampDate = new Date(timestamp!);
    const now = new Date();
    const timeDifference = Math.abs(now.getTime() - timestampDate.getTime());
    expect(timeDifference).toBeLessThan(60000); // Within 1 minute

    // Verify comment is correctly stored in the log
    await auditLogEntry.click();
    await expect(page.locator('[data-testid="audit-comment"]')).toHaveText('Spoke with employee - medical emergency, documentation to follow');
  });

  test('Ensure acknowledgment processing performance (boundary)', async ({ page }) => {
    // Open the attendance anomaly notification requiring acknowledgment
    await page.click('[data-testid="notifications-menu"]');
    const notification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Attendance Anomaly' }).filter({ has: page.locator('[data-testid="status-unacknowledged"]') }).first();
    await notification.click();

    // Click the 'Acknowledge' button and start timer
    const startTime = Date.now();
    await page.click('[data-testid="acknowledge-button"]');

    // Enter optional comment: 'Performance test acknowledgment'
    await page.fill('[data-testid="acknowledgment-comment"]', 'Performance test acknowledgment');

    // Click 'Submit' button and measure response time until confirmation appears
    await page.click('[data-testid="submit-acknowledgment-button"]');
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();
    const endTime = Date.now();

    // Record the exact processing time from submission to confirmation
    const processingTime = endTime - startTime;
    console.log(`Acknowledgment processing time: ${processingTime}ms`);

    // Verify acknowledgment processed within 2 seconds
    expect(processingTime).toBeLessThan(2000);

    // Navigate to system audit logs immediately after acknowledgment
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-logs-section"]')).toBeVisible();

    // Search for the acknowledgment entry just created
    await page.fill('[data-testid="audit-search-input"]', 'Performance test acknowledgment');
    await page.click('[data-testid="audit-search-button"]');

    // Verify all acknowledgment details in the log entry
    const auditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditEntry).toBeVisible();
    await auditEntry.click();
    await expect(page.locator('[data-testid="audit-comment"]')).toHaveText('Performance test acknowledgment');
    await expect(page.locator('[data-testid="audit-user"]')).toContainText('supervisor@company.com');

    // Check system performance metrics or logs for processing time
    const loggedTimestamp = await page.locator('[data-testid="audit-timestamp"]').textContent();
    expect(loggedTimestamp).toBeTruthy();
  });

  test('Verify system handles missing acknowledgment gracefully (error-case)', async ({ page }) => {
    // Open an unacknowledged attendance anomaly notification
    await page.click('[data-testid="notifications-menu"]');
    const notification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Attendance Anomaly' }).filter({ has: page.locator('[data-testid="status-unacknowledged"]') }).first();
    await notification.click();

    // Click the 'Acknowledge' button to open acknowledgment form
    await page.click('[data-testid="acknowledge-button"]');
    await expect(page.locator('[data-testid="acknowledgment-form"]')).toBeVisible();

    // Leave all required fields empty (if any exist beyond the acknowledge action itself)
    // Simulate a scenario where required fields exist
    const requiredField = page.locator('[data-testid="required-acknowledgment-field"]');
    if (await requiredField.isVisible()) {
      await requiredField.clear();
    }

    // Attempt to submit the acknowledgment without completing required fields
    await page.click('[data-testid="submit-acknowledgment-button"]');

    // Verify error messages are clear and user-friendly
    const errorMessage = page.locator('[data-testid="validation-error-message"]');
    await expect(errorMessage).toBeVisible();
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText!.length).toBeGreaterThan(0);

    // Verify form submission is blocked
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="acknowledgment-form"]')).toBeVisible();

    // Check that no partial data was saved to the database
    await page.click('[data-testid="cancel-acknowledgment-button"]');
    await page.click('[data-testid="audit-logs-menu"]');
    await page.fill('[data-testid="audit-search-input"]', 'Resubmitting after validation');
    await page.click('[data-testid="audit-search-button"]');
    const noResults = page.locator('[data-testid="no-audit-results"]');
    await expect(noResults).toBeVisible();

    // Navigate back to notification
    await page.click('[data-testid="notifications-menu"]');
    await notification.click();
    await page.click('[data-testid="acknowledge-button"]');

    // Fill in all required fields with valid data
    if (await requiredField.isVisible()) {
      await requiredField.fill('Required field data');
    }

    // Add optional comment: 'Resubmitting after validation correction'
    await page.fill('[data-testid="acknowledgment-comment"]', 'Resubmitting after validation correction');

    // Click 'Submit' button to resubmit acknowledgment
    await page.click('[data-testid="submit-acknowledgment-button"]');

    // Verify success confirmation message is displayed
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();
    const successText = await page.locator('[data-testid="acknowledgment-success-message"]').textContent();
    expect(successText).toContain('success');

    // Check audit logs for acknowledgment entry
    await page.click('[data-testid="audit-logs-menu"]');
    await page.fill('[data-testid="audit-search-input"]', 'Resubmitting after validation correction');
    await page.click('[data-testid="audit-search-button"]');
    const auditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditEntry).toBeVisible();

    // Verify notification status updated to 'Acknowledged'
    await page.click('[data-testid="notifications-menu"]');
    const acknowledgedNotification = page.locator('[data-testid="notification-item"]').filter({ has: page.locator('[data-testid="status-acknowledged"]') });
    await expect(acknowledgedNotification.first()).toBeVisible();
  });
});