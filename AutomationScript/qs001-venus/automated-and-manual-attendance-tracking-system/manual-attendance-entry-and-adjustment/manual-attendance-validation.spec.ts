import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Input Validation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to HR dashboard and then to manual attendance entry section
    await page.goto('/hr-dashboard');
    await page.click('[data-testid="manual-attendance-link"]');
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();
  });

  test('Validate mandatory field enforcement - error case', async ({ page }) => {
    // Step 1: Navigate to the manual attendance entry section from the HR dashboard
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();
    
    // Step 2: Leave Employee ID field empty and attempt to submit the form
    await page.click('[data-testid="submit-attendance-btn"]');
    await expect(page.locator('[data-testid="employee-id-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-id-error"]')).toContainText('Employee ID is required');
    
    // Step 3: Enter valid Employee ID, leave Date field empty, and attempt to submit the form
    await page.fill('[data-testid="employee-id-input"]', 'EMP001');
    await page.click('[data-testid="submit-attendance-btn"]');
    await expect(page.locator('[data-testid="date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-error"]')).toContainText('Date is required');
    
    // Step 4: Enter valid Employee ID and Date, leave Time field empty, and attempt to submit the form
    await page.fill('[data-testid="employee-id-input"]', 'EMP001');
    await page.fill('[data-testid="date-input"]', '15/06/2023');
    await page.click('[data-testid="submit-attendance-btn"]');
    await expect(page.locator('[data-testid="time-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-error"]')).toContainText('Time is required');
    
    // Step 5: Fill all mandatory fields (Employee ID, Date, Time) with valid data and click Submit button
    await page.fill('[data-testid="employee-id-input"]', 'EMP001');
    await page.fill('[data-testid="date-input"]', '15/06/2023');
    await page.fill('[data-testid="time-input"]', '09:00');
    await page.click('[data-testid="submit-attendance-btn"]');
    
    // Verify successful submission
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance entry submitted successfully');
  });

  test('Verify real-time validation feedback - happy path', async ({ page }) => {
    // Step 1: Click on the Date field and enter an invalid date format
    await page.click('[data-testid="date-input"]');
    await page.fill('[data-testid="date-input"]', '32/13/2023');
    
    // Wait for real-time validation feedback (within 1 second)
    await expect(page.locator('[data-testid="date-error"]')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="date-error"]')).toContainText('Invalid date format');
    
    // Try another invalid format
    await page.fill('[data-testid="date-input"]', 'abc123');
    await expect(page.locator('[data-testid="date-error"]')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="date-error"]')).toContainText('Invalid date format');
    
    // Step 2: Clear the Date field and enter a valid date format
    await page.fill('[data-testid="date-input"]', '');
    await page.fill('[data-testid="date-input"]', '15/06/2023');
    
    // Verify error message disappears
    await expect(page.locator('[data-testid="date-error"]')).not.toBeVisible({ timeout: 1000 });
    
    // Step 3: Click on the Time field and enter an invalid time format
    await page.click('[data-testid="time-input"]');
    await page.fill('[data-testid="time-input"]', '25:70');
    
    // Wait for real-time validation feedback
    await expect(page.locator('[data-testid="time-error"]')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="time-error"]')).toContainText('Invalid time format');
    
    // Try another invalid format
    await page.fill('[data-testid="time-input"]', 'invalid');
    await expect(page.locator('[data-testid="time-error"]')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="time-error"]')).toContainText('Invalid time format');
    
    // Step 4: Clear the Time field and enter a valid time format
    await page.fill('[data-testid="time-input"]', '');
    await page.fill('[data-testid="time-input"]', '09:30');
    
    // Verify error message disappears
    await expect(page.locator('[data-testid="time-error"]')).not.toBeVisible({ timeout: 1000 });
  });

  test('Ensure duplicate entry prevention - error case', async ({ page }) => {
    // Step 1: Open the manual attendance entry form
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();
    
    // Step 2: Enter Employee ID that matches an existing record
    await page.fill('[data-testid="employee-id-input"]', 'EMP001');
    
    // Step 3: Enter Date that matches the existing record
    await page.fill('[data-testid="date-input"]', '15/06/2023');
    
    // Step 4: Enter Time that matches the existing record
    await page.fill('[data-testid="time-input"]', '09:00');
    
    // Step 5: Click Submit button to attempt submission of the duplicate attendance entry
    await page.click('[data-testid="submit-attendance-btn"]');
    
    // Verify duplicate entry error is displayed
    await expect(page.locator('[data-testid="duplicate-error"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="duplicate-error"]')).toContainText('Duplicate attendance entry');
    
    // Verify form is not submitted
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Step 6: Modify the Time field to a different value and click Submit button
    await page.fill('[data-testid="time-input"]', '10:00');
    await page.click('[data-testid="submit-attendance-btn"]');
    
    // Verify successful submission with modified time
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance entry submitted successfully');
    
    // Verify duplicate error is no longer displayed
    await expect(page.locator('[data-testid="duplicate-error"]')).not.toBeVisible();
  });
});