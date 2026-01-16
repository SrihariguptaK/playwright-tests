import { test, expect } from '@playwright/test';

test.describe('Scheduling Conflict Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to schedule management interface before each test
    await page.goto('/schedule-management');
    await expect(page).toHaveTitle(/Schedule Management/);
  });

  test('Detect overlapping shift conflicts during scheduling', async ({ page }) => {
    // Select an employee from the employee list
    await page.click('[data-testid="employee-list"]');
    await page.click('[data-testid="employee-item"]:has-text("John Doe")');
    
    // Assign first shift (Monday 9:00 AM - 5:00 PM)
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-day-select"]', 'Monday');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.click('[data-testid="confirm-shift-button"]');
    
    // Assign second overlapping shift (Monday 3:00 PM - 11:00 PM)
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-day-select"]', 'Monday');
    await page.fill('[data-testid="shift-start-time"]', '15:00');
    await page.fill('[data-testid="shift-end-time"]', '23:00');
    await page.click('[data-testid="confirm-shift-button"]');
    
    // Expected Result: Conflict alert is displayed immediately
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('overlapping shift');
    
    // Review the conflict alert message
    const alertMessage = await page.locator('[data-testid="conflict-alert-message"]').textContent();
    expect(alertMessage).toBeTruthy();
    
    // Attempt to save the schedule with unresolved conflict
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Save is blocked until conflict is resolved
    await expect(page.locator('[data-testid="save-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-error-message"]')).toContainText('resolve conflicts');
    await expect(page.locator('[data-testid="schedule-saved-confirmation"]')).not.toBeVisible();
  });

  test('Enforce minimum rest period between shifts', async ({ page }) => {
    // Select an employee from the employee list
    await page.click('[data-testid="employee-list"]');
    await page.click('[data-testid="employee-item"]:has-text("Jane Smith")');
    
    // Assign first shift (Monday 9:00 AM - 5:00 PM)
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-day-select"]', 'Monday');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.click('[data-testid="confirm-shift-button"]');
    
    // Assign second shift violating rest period (Monday 9:00 PM - Tuesday 5:00 AM, only 4 hours rest)
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-day-select"]', 'Monday');
    await page.fill('[data-testid="shift-start-time"]', '21:00');
    await page.selectOption('[data-testid="shift-end-day-select"]', 'Tuesday');
    await page.fill('[data-testid="shift-end-time"]', '05:00');
    await page.click('[data-testid="confirm-shift-button"]');
    
    // Expected Result: Alert is displayed indicating rest period violation
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('rest period');
    
    // Review the rest period violation alert
    const restPeriodAlert = await page.locator('[data-testid="conflict-alert-message"]').textContent();
    expect(restPeriodAlert).toContain('minimum rest period');
    
    // Adjust the second shift to comply with rest period policy (Tuesday 1:00 AM - 9:00 AM, providing 8 hours rest)
    await page.click('[data-testid="edit-shift-button"]:last-of-type');
    await page.selectOption('[data-testid="shift-day-select"]', 'Tuesday');
    await page.fill('[data-testid="shift-start-time"]', '01:00');
    await page.fill('[data-testid="shift-end-time"]', '09:00');
    await page.click('[data-testid="confirm-shift-button"]');
    
    // Expected Result: Alert disappears and save is allowed
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    
    // Attempt to save the schedule
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-saved-confirmation"]')).toBeVisible();
  });

  test('Revalidate conflicts after schedule adjustments', async ({ page }) => {
    // Navigate to schedule with existing conflicts
    await page.click('[data-testid="employee-list"]');
    await page.click('[data-testid="employee-item"]:has-text("Mike Johnson")');
    
    // Create initial conflicting shifts
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-day-select"]', 'Wednesday');
    await page.fill('[data-testid="shift-start-time"]', '10:00');
    await page.fill('[data-testid="shift-end-time"]', '18:00');
    await page.click('[data-testid="confirm-shift-button"]');
    
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-day-select"]', 'Wednesday');
    await page.fill('[data-testid="shift-start-time"]', '16:00');
    await page.fill('[data-testid="shift-end-time"]', '22:00');
    await page.click('[data-testid="confirm-shift-button"]');
    
    // View the schedule with existing conflicts
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    // Select one of the conflicting shifts for editing
    await page.click('[data-testid="edit-shift-button"]').first();
    
    // Modify the shift time to resolve the conflict (change end time to eliminate overlap)
    await page.fill('[data-testid="shift-end-time"]', '15:00');
    await page.click('[data-testid="confirm-shift-button"]');
    
    // Expected Result: System rechecks conflicts in real-time
    await page.waitForTimeout(500); // Allow real-time validation
    
    // Verify that no conflict alerts are displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    
    // Make an additional minor adjustment to another shift (non-conflicting change)
    await page.click('[data-testid="edit-shift-button"]').last();
    await page.fill('[data-testid="shift-start-time"]', '16:30');
    await page.click('[data-testid="confirm-shift-button"]');
    
    // Verify no new conflicts appear
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    
    // Save the schedule after resolving all conflicts
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Schedule saves successfully
    await expect(page.locator('[data-testid="schedule-saved-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-saved-confirmation"]')).toContainText('successfully');
    
    // Verify the saved schedule
    const savedSchedule = await page.locator('[data-testid="schedule-summary"]').textContent();
    expect(savedSchedule).toBeTruthy();
  });
});