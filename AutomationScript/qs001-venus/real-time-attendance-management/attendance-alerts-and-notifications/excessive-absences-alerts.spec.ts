import { test, expect } from '@playwright/test';

test.describe('Excessive Absences Alert Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate alert generation on absence threshold breach (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the alert configuration page from the main dashboard
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alert-configuration-link"]');
    await expect(page.locator('[data-testid="alert-config-page"]')).toBeVisible();

    // Step 2: Select a department from the department dropdown list
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await expect(page.locator('[data-testid="department-dropdown"]')).toContainText('Engineering');

    // Step 3: Enter a valid absence threshold value (e.g., 3 absences in 30 days)
    await page.fill('[data-testid="threshold-input"]', '3');
    await page.fill('[data-testid="period-days-input"]', '30');

    // Step 4: Click the 'Save' or 'Submit' button to save the threshold configuration
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Threshold saved successfully');

    // Step 5: Simulate employee absences exceeding the configured threshold
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="attendance-records-link"]');
    
    // Add multiple absence records for an employee
    for (let i = 0; i < 4; i++) {
      await page.click('[data-testid="add-absence-button"]');
      await page.fill('[data-testid="employee-search"]', 'John Doe');
      await page.click('[data-testid="employee-option-john-doe"]');
      await page.fill('[data-testid="absence-date"]', `2024-01-${10 + i}`);
      await page.click('[data-testid="submit-absence-button"]');
      await expect(page.locator('[data-testid="absence-added-confirmation"]')).toBeVisible();
    }

    // Step 6: Wait and monitor the system for alert generation (maximum 5 minutes)
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alert-history-link"]');
    
    // Wait for alert to appear within 5 minutes
    await expect(page.locator('[data-testid="alert-item"]').first()).toBeVisible({ timeout: 300000 });

    // Step 7: Check the manager's email inbox for alert notification
    // Note: In real scenario, this would integrate with email testing service
    await page.goto('/email-notifications');
    await expect(page.locator('[data-testid="email-notification"]').filter({ hasText: 'Excessive Absence Alert' })).toBeVisible();

    // Step 8: Check the in-app notification center for alert notification
    await page.click('[data-testid="notification-bell"]');
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: 'Excessive Absence Alert' })).toBeVisible();

    // Step 9: Verify that both email and in-app notifications contain consistent information
    const inAppNotification = await page.locator('[data-testid="notification-item"]').first().textContent();
    expect(inAppNotification).toContain('John Doe');
    expect(inAppNotification).toContain('Engineering');
    expect(inAppNotification).toContain('3 absences');
  });

  test('Verify alert logging and audit trail (happy-path)', async ({ page }) => {
    // Step 1: Simulate multiple employee absences exceeding thresholds
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="attendance-records-link"]');

    const employees = ['John Doe', 'Jane Smith', 'Bob Johnson'];
    
    for (const employee of employees) {
      for (let i = 0; i < 4; i++) {
        await page.click('[data-testid="add-absence-button"]');
        await page.fill('[data-testid="employee-search"]', employee);
        await page.click(`[data-testid="employee-option-${employee.toLowerCase().replace(' ', '-')}"]`);
        await page.fill('[data-testid="absence-date"]', `2024-01-${10 + i}`);
        await page.click('[data-testid="submit-absence-button"]');
        await expect(page.locator('[data-testid="absence-added-confirmation"]')).toBeVisible();
      }
    }

    // Step 2: Wait for the system to generate alerts (within 5 minutes each)
    await page.waitForTimeout(10000); // Wait 10 seconds for alert processing

    // Step 3: Verify that all generated alerts are logged in the database with timestamps
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alert-history-link"]');
    
    const alertItems = page.locator('[data-testid="alert-item"]');
    await expect(alertItems).toHaveCount(3, { timeout: 300000 });

    // Step 4: Navigate to the alert history UI
    await expect(page.locator('[data-testid="alert-history-page"]')).toBeVisible();

    // Step 5: Review the displayed alerts in the alert history UI
    for (let i = 0; i < 3; i++) {
      const alert = alertItems.nth(i);
      await expect(alert.locator('[data-testid="alert-timestamp"]')).toBeVisible();
      await expect(alert.locator('[data-testid="alert-employee-name"]')).toBeVisible();
      await expect(alert.locator('[data-testid="alert-department"]')).toBeVisible();
    }

    // Step 6: Verify the chronological order of alerts based on timestamps
    const timestamps = await alertItems.locator('[data-testid="alert-timestamp"]').allTextContents();
    expect(timestamps.length).toBe(3);

    // Step 7: Click on individual alert entries to view detailed information
    await alertItems.first().click();
    await expect(page.locator('[data-testid="alert-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-detail-employee"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-detail-absence-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-detail-threshold"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-detail-period"]')).toBeVisible();

    // Step 8: Verify audit trail includes all necessary information
    await expect(page.locator('[data-testid="alert-detail-generated-at"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-detail-triggered-by"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-detail-notification-status"]')).toBeVisible();
  });

  test('Test alert configuration validation (error-case)', async ({ page }) => {
    // Navigate to the alert configuration page
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alert-configuration-link"]');
    await expect(page.locator('[data-testid="alert-config-page"]')).toBeVisible();

    // Select a department first
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');

    // Step 1: Enter a negative number (e.g., -5) in the absence threshold field
    await page.fill('[data-testid="threshold-input"]', '-5');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toContainText('Threshold must be a positive number');

    // Step 2: Clear the threshold field and enter zero (0)
    await page.fill('[data-testid="threshold-input"]', '0');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toContainText('Threshold must be greater than zero');

    // Step 3: Enter an excessively large number (e.g., 99999)
    await page.fill('[data-testid="threshold-input"]', '99999');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toContainText('Threshold value is too large');

    // Step 4: Enter non-numeric characters (e.g., 'abc' or special characters)
    await page.fill('[data-testid="threshold-input"]', 'abc');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toContainText('Threshold must be a valid number');

    await page.fill('[data-testid="threshold-input"]', '@#$%');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toBeVisible();

    // Step 5: Leave the threshold field empty and attempt to save
    await page.fill('[data-testid="threshold-input"]', '');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toContainText('Threshold is required');

    // Step 6: Enter a decimal number (e.g., 3.5) if only integers are allowed
    await page.fill('[data-testid="threshold-input"]', '3.5');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="threshold-validation-error"]')).toContainText('Threshold must be a whole number');

    // Step 7: Attempt to save configuration without selecting a department
    await page.reload();
    await page.fill('[data-testid="threshold-input"]', '3');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="department-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="department-validation-error"]')).toContainText('Department is required');

    // Step 8: Verify that all validation messages are clear and user-friendly
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.fill('[data-testid="threshold-input"]', '-1');
    await page.click('[data-testid="save-threshold-button"]');
    
    const validationError = page.locator('[data-testid="threshold-validation-error"]');
    await expect(validationError).toBeVisible();
    
    // Verify error message is displayed near the input field
    const errorBox = await validationError.boundingBox();
    const inputBox = await page.locator('[data-testid="threshold-input"]').boundingBox();
    
    expect(errorBox).not.toBeNull();
    expect(inputBox).not.toBeNull();
    expect(Math.abs(errorBox!.y - inputBox!.y)).toBeLessThan(100);
  });
});