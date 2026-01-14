import { test, expect } from '@playwright/test';

test.describe('Schedule Conflict Validation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to schedule management page before each test
    await page.goto('/schedule-management');
    // Wait for page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate detection of overlapping shifts', async ({ page }) => {
    // Step 1: Select an employee from the employee list
    await page.click('[data-testid="employee-list"]');
    await page.click('[data-testid="employee-option-1"]');
    
    // Step 2: Assign a shift to the selected employee for a specific time (Monday 9:00 AM - 5:00 PM)
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-day-select"]', 'Monday');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    
    // Step 3: Click Save button to save the shift
    await page.click('[data-testid="save-shift-button"]');
    
    // Expected Result: Shift is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift saved successfully');
    
    // Step 4: Attempt to assign another overlapping shift to the same employee (Monday 3:00 PM - 11:00 PM)
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-day-select"]', 'Monday');
    await page.fill('[data-testid="shift-start-time"]', '15:00');
    await page.fill('[data-testid="shift-end-time"]', '23:00');
    
    // Expected Result: System alerts conflict and blocks save
    await page.click('[data-testid="save-shift-button"]');
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('conflict');
    
    // Verify save button is disabled or schedule is not saved
    const saveButton = page.locator('[data-testid="save-shift-button"]');
    const isDisabled = await saveButton.isDisabled();
    if (!isDisabled) {
      // If button is not disabled, verify that the conflicting shift was not saved
      await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    }
    
    // Step 5: Resolve conflict by adjusting shift times to non-overlapping hours (Monday 6:00 PM - 11:00 PM)
    await page.fill('[data-testid="shift-start-time"]', '18:00');
    await page.fill('[data-testid="shift-end-time"]', '23:00');
    
    // Step 6: Click Save button to save the adjusted shift
    await page.click('[data-testid="save-shift-button"]');
    
    // Expected Result: System allows save after validation passes
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift saved successfully');
    
    // Verify no conflict alert is present
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
  });

  test('Verify conflict alert displays detailed information', async ({ page }) => {
    // Step 1: Select the employee who already has a shift assigned for Tuesday 8:00 AM - 4:00 PM
    await page.click('[data-testid="employee-list"]');
    await page.click('[data-testid="employee-option-2"]');
    
    // Assign initial shift for Tuesday 8:00 AM - 4:00 PM
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-day-select"]', 'Tuesday');
    await page.fill('[data-testid="shift-start-time"]', '08:00');
    await page.fill('[data-testid="shift-end-time"]', '16:00');
    await page.click('[data-testid="save-shift-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 2: Attempt to assign an overlapping shift to the same employee (Tuesday 2:00 PM - 10:00 PM)
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-day-select"]', 'Tuesday');
    await page.fill('[data-testid="shift-start-time"]', '14:00');
    await page.fill('[data-testid="shift-end-time"]', '22:00');
    await page.click('[data-testid="save-shift-button"]');
    
    // Expected Result: Conflict alert is displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    // Step 3: Review the conflict alert details
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    
    // Expected Result: Alert shows conflicting shift times and employee name
    await expect(conflictAlert).toContainText('Tuesday');
    await expect(conflictAlert.locator('[data-testid="conflict-shift-times"]')).toBeVisible();
    await expect(conflictAlert.locator('[data-testid="conflict-employee-name"]')).toBeVisible();
    
    // Verify alert contains time information
    const alertText = await conflictAlert.textContent();
    expect(alertText).toMatch(/08:00|8:00/);
    expect(alertText).toMatch(/16:00|4:00/);
    
    // Step 4: Verify that the alert provides clear guidance on resolving the conflict
    await expect(conflictAlert.locator('[data-testid="conflict-resolution-guidance"]')).toBeVisible();
    await expect(conflictAlert.locator('[data-testid="conflict-resolution-guidance"]')).toContainText(/resolve|adjust|change/);
    
    // Step 5: Click Dismiss or Close button on the conflict alert
    await page.click('[data-testid="dismiss-alert-button"]');
    
    // Expected Result: Alert closes
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    
    // Step 6: Adjust the schedule to resolve the conflict by changing the shift time to non-overlapping hours (Tuesday 5:00 PM - 10:00 PM)
    await page.fill('[data-testid="shift-start-time"]', '17:00');
    await page.fill('[data-testid="shift-end-time"]', '22:00');
    
    // Step 7: Click Save button to save the adjusted schedule
    await page.click('[data-testid="save-shift-button"]');
    
    // Expected Result: Schedule can be saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift saved successfully');
    
    // Verify no conflict alert is present after successful save
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
  });
});