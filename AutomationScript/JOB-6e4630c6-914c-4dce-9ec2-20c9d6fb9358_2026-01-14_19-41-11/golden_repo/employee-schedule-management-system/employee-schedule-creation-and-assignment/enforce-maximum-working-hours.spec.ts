import { test, expect } from '@playwright/test';

test.describe('Story-7: Enforce Maximum Working Hours Per Employee', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/schedule');
    // Assume user is already authenticated as Scheduling Manager
  });

  test('Block schedule saving when max hours exceeded - daily limit violation', async ({ page }) => {
    // Navigate to the schedule assignment page
    await page.goto('/schedule/assignment');
    
    // Select an employee (EMP002) who has existing shifts for the current week
    await page.click('[data-testid="employee-selector"]');
    await page.click('[data-testid="employee-option-EMP002"]');
    
    // Wait for employee schedule to load
    await page.waitForSelector('[data-testid="employee-schedule-view"]');
    
    // Assign a new shift that would exceed the maximum daily hours (10-hour shift when max is 8 hours per day)
    await page.click('[data-testid="add-shift-button"]');
    await page.fill('[data-testid="shift-start-time"]', '08:00');
    await page.fill('[data-testid="shift-end-time"]', '18:00');
    await page.selectOption('[data-testid="shift-date"]', { label: 'Today' });
    
    // Click assign shift button
    await page.click('[data-testid="assign-shift-button"]');
    
    // Expected Result: Validation error displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('exceeds maximum daily hours');
    
    // Attempt to save schedule
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Save blocked until hours reduced
    await expect(page.locator('[data-testid="save-blocked-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-blocked-message"]')).toContainText('Cannot save schedule');
    await expect(page.locator('[data-testid="save-schedule-button"]')).toBeDisabled();
  });

  test('Block schedule saving when max hours exceeded - weekly limit violation', async ({ page }) => {
    // Navigate to the schedule assignment page
    await page.goto('/schedule/assignment');
    
    // Select an employee (EMP002) who has existing shifts for the current week
    await page.click('[data-testid="employee-selector"]');
    await page.click('[data-testid="employee-option-EMP002"]');
    
    // Wait for employee schedule to load
    await page.waitForSelector('[data-testid="employee-schedule-view"]');
    
    // Verify current weekly hours (should show 35 hours already assigned)
    await expect(page.locator('[data-testid="weekly-hours-total"]')).toContainText('35');
    
    // Assign shifts that would exceed maximum weekly hours (add 8 more hours when max is 40 hours per week)
    await page.click('[data-testid="add-shift-button"]');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.selectOption('[data-testid="shift-date"]', { label: 'Friday' });
    
    // Click assign shift button
    await page.click('[data-testid="assign-shift-button"]');
    
    // Expected Result: Validation error displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('exceeds maximum weekly hours');
    
    // Attempt to save schedule
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Save blocked until hours reduced
    await expect(page.locator('[data-testid="save-blocked-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-schedule-button"]')).toBeDisabled();
  });

  test('Save schedule within max hours successfully', async ({ page }) => {
    // Navigate to the schedule assignment page
    await page.goto('/schedule/assignment');
    
    // Select an employee (EMP003) to assign shifts
    await page.click('[data-testid="employee-selector"]');
    await page.click('[data-testid="employee-option-EMP003"]');
    
    // Wait for employee schedule to load
    await page.waitForSelector('[data-testid="employee-schedule-view"]');
    
    // Assign shifts that are within the allowed daily and weekly limits (7-hour shift on a day with no existing shifts)
    await page.click('[data-testid="add-shift-button"]');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '16:00');
    await page.selectOption('[data-testid="shift-date"]', { label: 'Monday' });
    
    // Click assign shift button
    await page.click('[data-testid="assign-shift-button"]');
    
    // Expected Result: No validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Review the hours summary display to confirm compliance
    await page.click('[data-testid="hours-summary-button"]');
    await expect(page.locator('[data-testid="daily-hours-display"]')).toContainText('7');
    await expect(page.locator('[data-testid="weekly-hours-display"]')).toBeVisible();
    
    // Verify hours are within limits
    const weeklyHours = await page.locator('[data-testid="weekly-hours-total"]').textContent();
    const weeklyHoursNumber = parseInt(weeklyHours || '0');
    expect(weeklyHoursNumber).toBeLessThanOrEqual(40);
    
    // Click the Save button to save the schedule
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Schedule saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule saved successfully');
    
    // Verify the saved schedule by navigating to the employee's schedule view
    await page.goto('/schedule/employee/EMP003');
    await expect(page.locator('[data-testid="employee-schedule-view"]')).toBeVisible();
    
    // Verify the shift appears in the schedule
    await expect(page.locator('[data-testid="shift-entry"]').filter({ hasText: 'Monday' })).toBeVisible();
    await expect(page.locator('[data-testid="shift-entry"]').filter({ hasText: '09:00' })).toBeVisible();
    
    // Navigate to hours summary report to verify
    await page.goto('/schedule/hours-summary');
    await page.fill('[data-testid="employee-search"]', 'EMP003');
    await page.click('[data-testid="search-button"]');
    
    // Verify the hours are reflected in the summary report
    await expect(page.locator('[data-testid="employee-hours-row"]').filter({ hasText: 'EMP003' })).toBeVisible();
    await expect(page.locator('[data-testid="employee-hours-row"]').filter({ hasText: 'EMP003' })).toContainText('7');
  });
});