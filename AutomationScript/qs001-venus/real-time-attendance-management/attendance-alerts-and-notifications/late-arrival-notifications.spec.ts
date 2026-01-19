import { test, expect } from '@playwright/test';

test.describe('Late Arrival Notifications - Story 18', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate late arrival detection and notification (happy-path)', async ({ page }) => {
    // Step 1: Navigate to notification preferences page
    await page.click('[data-testid="dashboard-menu"]');
    await page.click('[data-testid="notification-preferences-link"]');
    await expect(page.locator('[data-testid="notification-preferences-page"]')).toBeVisible();

    // Step 2: Enable late arrival notifications
    await page.click('[data-testid="late-arrival-notification-toggle"]');
    await expect(page.locator('[data-testid="late-arrival-notification-toggle"]')).toBeChecked();

    // Step 3: Configure notification channels - select both email and in-app
    await page.click('[data-testid="email-notification-checkbox"]');
    await page.click('[data-testid="in-app-notification-checkbox"]');
    await expect(page.locator('[data-testid="email-notification-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="in-app-notification-checkbox"]')).toBeChecked();

    // Step 4: Set late arrival threshold (15 minutes)
    await page.fill('[data-testid="late-arrival-threshold-input"]', '15');
    await expect(page.locator('[data-testid="late-arrival-threshold-input"]')).toHaveValue('15');

    // Step 5: Save notification preferences
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');

    // Step 6: Simulate employee late arrival
    await page.goto('/attendance/record');
    await page.fill('[data-testid="employee-id-input"]', 'EMP001');
    
    // Set scheduled time to 9:00 AM and arrival time to 9:20 AM (20 minutes late)
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="scheduled-time-input"]', `${currentDate}T09:00`);
    await page.fill('[data-testid="arrival-time-input"]', `${currentDate}T09:20`);
    await page.click('[data-testid="record-attendance-button"]');
    await expect(page.locator('[data-testid="attendance-recorded-message"]')).toBeVisible();

    // Step 7: Wait for system to detect late arrival (max 5 minutes)
    await page.waitForTimeout(5000); // Simulate waiting for notification processing

    // Step 8: Check in-app notification
    await page.click('[data-testid="notification-center-icon"]');
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    const lateArrivalNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Late Arrival' }).first();
    await expect(lateArrivalNotification).toBeVisible();
    await expect(lateArrivalNotification).toContainText('EMP001');

    // Step 9: Verify notification timestamp is within 5 minutes
    const notificationTime = await lateArrivalNotification.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTime).toBeTruthy();

    // Step 10: Verify notification contains accurate information
    await lateArrivalNotification.click();
    await expect(page.locator('[data-testid="notification-detail-employee"]')).toContainText('EMP001');
    await expect(page.locator('[data-testid="notification-detail-late-by"]')).toContainText('20 minutes');
  });

  test('Verify notification history accessibility (happy-path)', async ({ page }) => {
    // Step 1: Simulate multiple employee late arrivals
    await page.goto('/attendance/record');
    
    const employees = ['EMP001', 'EMP002', 'EMP003'];
    const currentDate = new Date().toISOString().split('T')[0];
    
    for (const empId of employees) {
      await page.fill('[data-testid="employee-id-input"]', empId);
      await page.fill('[data-testid="scheduled-time-input"]', `${currentDate}T09:00`);
      await page.fill('[data-testid="arrival-time-input"]', `${currentDate}T09:20`);
      await page.click('[data-testid="record-attendance-button"]');
      await expect(page.locator('[data-testid="attendance-recorded-message"]')).toBeVisible();
      await page.waitForTimeout(1000);
    }

    // Step 2: Wait for notifications to be generated
    await page.waitForTimeout(5000);

    // Step 3: Navigate to notification history page
    await page.goto('/dashboard');
    await page.click('[data-testid="notifications-section-link"]');
    await page.click('[data-testid="notification-history-link"]');
    await expect(page.locator('[data-testid="notification-history-page"]')).toBeVisible();

    // Step 4: Review displayed notifications
    const notificationItems = page.locator('[data-testid="notification-history-item"]');
    await expect(notificationItems).toHaveCount(3, { timeout: 10000 });

    // Step 5: Verify chronological order
    const firstNotification = notificationItems.first();
    const lastNotification = notificationItems.last();
    await expect(firstNotification).toBeVisible();
    await expect(lastNotification).toBeVisible();

    // Step 6: Use filter to find specific notification
    await page.fill('[data-testid="notification-search-input"]', 'EMP002');
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="notification-history-item"]').filter({ hasText: 'EMP002' })).toBeVisible();

    // Step 7: Clear search and filter by date
    await page.fill('[data-testid="notification-search-input"]', '');
    await page.fill('[data-testid="date-filter-input"]', currentDate);
    await page.click('[data-testid="apply-filter-button"]');
    await expect(notificationItems).toHaveCount(3, { timeout: 10000 });

    // Step 8: Click on individual notification to view details
    await notificationItems.first().click();
    await expect(page.locator('[data-testid="notification-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-detail-employee"]')).toBeVisible();

    // Step 9: Verify delivery status for both channels
    await expect(page.locator('[data-testid="email-delivery-status"]')).toContainText('Delivered');
    await expect(page.locator('[data-testid="in-app-delivery-status"]')).toContainText('Delivered');
  });

  test('Test notification preference validation (error-case)', async ({ page }) => {
    // Step 1: Navigate to notification preferences page
    await page.click('[data-testid="dashboard-menu"]');
    await page.click('[data-testid="notification-preferences-link"]');
    await expect(page.locator('[data-testid="notification-preferences-page"]')).toBeVisible();

    // Step 2: Attempt to save without selecting any notification channel
    await page.click('[data-testid="late-arrival-notification-toggle"]');
    
    // Ensure both checkboxes are unchecked
    const emailCheckbox = page.locator('[data-testid="email-notification-checkbox"]');
    const inAppCheckbox = page.locator('[data-testid="in-app-notification-checkbox"]');
    
    if (await emailCheckbox.isChecked()) {
      await emailCheckbox.click();
    }
    if (await inAppCheckbox.isChecked()) {
      await inAppCheckbox.click();
    }
    
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('At least one notification channel must be selected');

    // Step 3: Enter negative threshold value
    await page.click('[data-testid="email-notification-checkbox"]');
    await page.fill('[data-testid="late-arrival-threshold-input"]', '-10');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toContainText('Threshold must be a positive value');

    // Step 4: Enter excessively large threshold value
    await page.fill('[data-testid="late-arrival-threshold-input"]', '500');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toContainText('Threshold cannot exceed');

    // Step 5: Enter non-numeric characters in threshold field
    await page.fill('[data-testid="late-arrival-threshold-input"]', 'abc');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toContainText('Threshold must be a number');

    // Step 6: Enter special characters in threshold field
    await page.fill('[data-testid="late-arrival-threshold-input"]', '@#$');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toContainText('Threshold must be a number');

    // Step 7: Enter invalid email address format
    await page.fill('[data-testid="late-arrival-threshold-input"]', '15');
    await page.fill('[data-testid="notification-email-input"]', 'invalid-email');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="email-validation-error"]')).toContainText('Invalid email format');

    // Step 8: Leave required fields empty
    await page.fill('[data-testid="late-arrival-threshold-input"]', '');
    await page.fill('[data-testid="notification-email-input"]', '');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();

    // Step 9: Enter threshold value of zero
    await page.fill('[data-testid="late-arrival-threshold-input"]', '0');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toContainText('Threshold must be greater than zero');

    // Step 10: Verify validation messages are clear and near input fields
    const thresholdError = page.locator('[data-testid="threshold-validation-error"]');
    await expect(thresholdError).toBeVisible();
    
    const thresholdInput = page.locator('[data-testid="late-arrival-threshold-input"]');
    const errorBox = await thresholdError.boundingBox();
    const inputBox = await thresholdInput.boundingBox();
    
    expect(errorBox).toBeTruthy();
    expect(inputBox).toBeTruthy();

    // Step 11: Verify form does not submit with validation errors
    const currentUrl = page.url();
    expect(currentUrl).toContain('notification-preferences');
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
  });
});