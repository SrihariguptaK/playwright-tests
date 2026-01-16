import { test, expect } from '@playwright/test';

test.describe('Edit Manual Attendance Records - Story 4', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Edit manual attendance record successfully', async ({ page }) => {
    // Step 1: Login as authorized HR officer
    await page.fill('[data-testid="username-input"]', 'hr.officer@company.com');
    await page.fill('[data-testid="password-input"]', 'HRPassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to manual attendance edit page
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForSelector('[data-testid="manual-attendance-link"]');
    await page.click('[data-testid="manual-attendance-link"]');
    await expect(page).toHaveURL(/.*manual-attendance/);
    await expect(page.locator('[data-testid="manual-attendance-page"]')).toBeVisible();

    // Step 2: Search and select a manual attendance record
    await page.fill('[data-testid="search-employee-input"]', 'John Doe');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="attendance-record-row"]');
    
    // Expected Result: Record details displayed for editing
    const recordRow = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(recordRow).toBeVisible();
    await recordRow.locator('[data-testid="edit-record-button"]').click();
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name-display"]')).toContainText('John Doe');

    // Step 3: Modify date and time fields with valid data
    const currentDate = page.locator('[data-testid="attendance-date-input"]');
    await currentDate.clear();
    await currentDate.fill('2024-01-15');
    
    const timeIn = page.locator('[data-testid="time-in-input"]');
    await timeIn.clear();
    await timeIn.fill('09:00');
    
    const timeOut = page.locator('[data-testid="time-out-input"]');
    await timeOut.clear();
    await timeOut.fill('17:30');
    
    // Expected Result: Input accepted without errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(currentDate).toHaveValue('2024-01-15');
    await expect(timeIn).toHaveValue('09:00');
    await expect(timeOut).toHaveValue('17:30');

    // Step 4: Submit changes
    await page.click('[data-testid="save-changes-button"]');
    
    // Expected Result: Record updated and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record updated successfully');
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).not.toBeVisible();
    
    // Verify the updated record appears in the list
    await page.fill('[data-testid="search-employee-input"]', 'John Doe');
    await page.click('[data-testid="search-button"]');
    const updatedRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(updatedRecord.locator('[data-testid="date-cell"]')).toContainText('2024-01-15');
    await expect(updatedRecord.locator('[data-testid="time-in-cell"]')).toContainText('09:00');
    await expect(updatedRecord.locator('[data-testid="time-out-cell"]')).toContainText('17:30');
  });

  test('Prevent duplicate attendance record on edit', async ({ page }) => {
    // Login as authorized HR officer
    await page.fill('[data-testid="username-input"]', 'hr.officer@company.com');
    await page.fill('[data-testid="password-input"]', 'HRPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to manual attendance page
    await page.click('[data-testid="manual-attendance-link"]');
    await expect(page).toHaveURL(/.*manual-attendance/);
    
    // Search and select a manual attendance record
    await page.fill('[data-testid="search-employee-input"]', 'Jane Smith');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="attendance-record-row"]');
    const recordRow = page.locator('[data-testid="attendance-record-row"]').first();
    await recordRow.locator('[data-testid="edit-record-button"]').click();
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();

    // Step 1: Attempt to edit manual record to match existing biometric entry
    const dateInput = page.locator('[data-testid="attendance-date-input"]');
    await dateInput.clear();
    await dateInput.fill('2024-01-10');
    
    const timeInInput = page.locator('[data-testid="time-in-input"]');
    await timeInInput.clear();
    await timeInInput.fill('08:30');
    
    const timeOutInput = page.locator('[data-testid="time-out-input"]');
    await timeOutInput.clear();
    await timeOutInput.fill('17:00');
    
    await page.click('[data-testid="save-changes-button"]');
    
    // Expected Result: System displays error preventing duplicate
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/duplicate|already exists|biometric/i);
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();

    // Step 2: Change to unique time and resubmit
    await timeInInput.clear();
    await timeInInput.fill('09:15');
    
    await timeOutInput.clear();
    await timeOutInput.fill('18:00');
    
    await page.click('[data-testid="save-changes-button"]');
    
    // Expected Result: System accepts and saves changes
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record updated successfully');
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Verify the updated record with unique time
    await page.fill('[data-testid="search-employee-input"]', 'Jane Smith');
    await page.click('[data-testid="search-button"]');
    const updatedRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(updatedRecord.locator('[data-testid="date-cell"]')).toContainText('2024-01-10');
    await expect(updatedRecord.locator('[data-testid="time-in-cell"]')).toContainText('09:15');
    await expect(updatedRecord.locator('[data-testid="time-out-cell"]')).toContainText('18:00');
  });
});