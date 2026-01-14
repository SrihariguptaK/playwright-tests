import { test, expect } from '@playwright/test';

test.describe('Unexcused Absence Notifications - Story 16', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate detection and notification of unexcused absences (happy-path)', async ({ page }) => {
    // Step 1: Simulate employee absence by ensuring no check-in record exists
    await page.goto('/admin/attendance');
    const employeeId = 'EMP001';
    const currentDate = new Date().toISOString().split('T')[0];
    
    // Verify no check-in record exists for the employee
    await page.fill('[data-testid="employee-search-input"]', employeeId);
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="attendance-record"]')).toHaveCount(0);
    
    // Verify no leave approval is present
    await page.goto('/admin/leave-requests');
    await page.fill('[data-testid="employee-search-input"]', employeeId);
    await page.fill('[data-testid="date-filter-input"]', currentDate);
    await page.click('[data-testid="filter-button"]');
    await expect(page.locator('[data-testid="approved-leave-record"]')).toHaveCount(0);
    
    // Expected Result: System detects unexcused absence
    await page.goto('/admin/unexcused-absences');
    await page.waitForTimeout(2000); // Allow system to process
    await expect(page.locator(`[data-testid="unexcused-absence-${employeeId}"]`)).toBeVisible();
    
    // Step 2: Wait for system to process absence detection (within 30 minutes)
    // Check manager's email inbox for notification
    await page.goto('/notifications/email');
    await page.waitForSelector('[data-testid="notification-list"]', { timeout: 30000 });
    const emailNotification = page.locator('[data-testid="email-notification"]').filter({ hasText: employeeId });
    await expect(emailNotification).toBeVisible();
    await expect(emailNotification).toContainText('Unexcused Absence');
    
    // Check manager's SMS notifications
    await page.goto('/notifications/sms');
    const smsNotification = page.locator('[data-testid="sms-notification"]').filter({ hasText: employeeId });
    await expect(smsNotification).toBeVisible();
    
    // Step 3: Navigate to Notifications Dashboard
    await page.goto('/notifications/dashboard');
    await expect(page.locator('[data-testid="notifications-dashboard"]')).toBeVisible();
    
    // Step 4: Click on the notification to view full details
    const dashboardNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: employeeId });
    await expect(dashboardNotification).toBeVisible();
    await dashboardNotification.click();
    
    // Expected Result: Manager receives notification with correct details
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-id"]')).toContainText(employeeId);
    await expect(page.locator('[data-testid="absence-date"]')).toContainText(currentDate);
    await expect(page.locator('[data-testid="absence-type"]')).toContainText('Unexcused');
    
    // Step 5: Click 'Acknowledge' button to acknowledge the notification
    await page.click('[data-testid="acknowledge-button"]');
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();
    
    // Step 6: Navigate to Notification History/Logs section
    await page.goto('/notifications/history');
    await expect(page.locator('[data-testid="notification-history"]')).toBeVisible();
    
    // Expected Result: Acknowledgment logged successfully
    const acknowledgedNotification = page.locator('[data-testid="history-item"]').filter({ hasText: employeeId });
    await expect(acknowledgedNotification).toBeVisible();
    await expect(acknowledgedNotification.locator('[data-testid="status"]')).toContainText('Acknowledged');
    await expect(acknowledgedNotification.locator('[data-testid="acknowledged-by"]')).toContainText('manager@company.com');
  });

  test('Verify notification preference configuration (happy-path)', async ({ page }) => {
    // Step 1: Navigate to Notification Preferences or Settings section
    await page.goto('/settings/notifications');
    await expect(page.locator('[data-testid="notification-preferences"]')).toBeVisible();
    
    // Step 2: Review current notification delivery preferences
    const emailCheckbox = page.locator('[data-testid="email-notification-checkbox"]');
    const smsCheckbox = page.locator('[data-testid="sms-notification-checkbox"]');
    const dashboardCheckbox = page.locator('[data-testid="dashboard-notification-checkbox"]');
    
    await expect(emailCheckbox).toBeVisible();
    await expect(smsCheckbox).toBeVisible();
    await expect(dashboardCheckbox).toBeVisible();
    
    // Step 3: Update notification delivery preferences
    // Disable SMS notifications and keep email and dashboard enabled
    if (await smsCheckbox.isChecked()) {
      await smsCheckbox.uncheck();
    }
    if (!(await emailCheckbox.isChecked())) {
      await emailCheckbox.check();
    }
    if (!(await dashboardCheckbox.isChecked())) {
      await dashboardCheckbox.check();
    }
    
    // Step 4: Configure notification timing preference
    await page.selectOption('[data-testid="notification-timing-select"]', 'immediate');
    
    // Step 5: Click 'Save' or 'Update Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();
    
    // Expected Result: Preferences saved and applied
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toContainText('Preferences saved successfully');
    
    // Step 6: Refresh the page or navigate away and return to verify persistence
    await page.goto('/dashboard');
    await page.goto('/settings/notifications');
    
    // Verify preferences persisted
    await expect(emailCheckbox).toBeChecked();
    await expect(smsCheckbox).not.toBeChecked();
    await expect(dashboardCheckbox).toBeChecked();
    await expect(page.locator('[data-testid="notification-timing-select"]')).toHaveValue('immediate');
    
    // Step 7: Trigger a test unexcused absence notification to verify preferences are applied
    await page.goto('/admin/test-notifications');
    await page.click('[data-testid="trigger-test-notification-button"]');
    await expect(page.locator('[data-testid="test-notification-sent-message"]')).toBeVisible();
    
    // Verify notification sent via email and dashboard only (not SMS)
    await page.goto('/notifications/dashboard');
    await expect(page.locator('[data-testid="notification-item"]').first()).toBeVisible({ timeout: 35000 });
    
    await page.goto('/notifications/email');
    await expect(page.locator('[data-testid="email-notification"]').first()).toBeVisible();
    
    // Verify no SMS notification was sent
    await page.goto('/notifications/sms');
    const recentSmsCount = await page.locator('[data-testid="sms-notification"]').count();
    // Should be 0 or same as before since SMS is disabled
    await expect(page.locator('[data-testid="no-sms-notifications-message"]')).toBeVisible();
  });
});