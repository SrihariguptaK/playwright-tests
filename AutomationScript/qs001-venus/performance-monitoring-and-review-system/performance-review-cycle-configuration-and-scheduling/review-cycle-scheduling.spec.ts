import { test, expect } from '@playwright/test';

test.describe('Review Cycle Scheduling - Story 17', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const reviewCycleSchedulingURL = `${baseURL}/review-cycles/scheduling`;

  test.beforeEach(async ({ page }) => {
    // Login as Performance Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'performance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful review cycle scheduling (happy-path)', async ({ page }) => {
    // Step 1: Navigate to Review Cycle Scheduling page
    await page.goto(reviewCycleSchedulingURL);
    await expect(page.locator('[data-testid="review-cycle-scheduling-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-selector"]')).toBeVisible();

    // Step 2: Select a review cycle template from the available templates
    await page.click('[data-testid="template-selector"]');
    await page.click('[data-testid="template-option-q1-2024"]', { timeout: 5000 });
    const selectedTemplate = await page.locator('[data-testid="template-selector"]').textContent();
    expect(selectedTemplate).toContain('Q1 2024 Performance Review');

    // Step 3: Click on 'Select Employees/Groups' button or field
    await page.click('[data-testid="select-employees-groups-button"]');
    await expect(page.locator('[data-testid="employees-groups-modal"]')).toBeVisible();

    // Step 4: Select multiple employees or groups from the list
    await page.click('[data-testid="employee-group-engineering-team"]');
    await page.click('[data-testid="employee-john-doe"]');
    await page.click('[data-testid="employee-jane-smith"]');
    
    // Verify selections are checked
    await expect(page.locator('[data-testid="employee-group-engineering-team"]')).toBeChecked();
    await expect(page.locator('[data-testid="employee-john-doe"]')).toBeChecked();
    await expect(page.locator('[data-testid="employee-jane-smith"]')).toBeChecked();
    
    // Confirm selections
    await page.click('[data-testid="confirm-selection-button"]');
    await expect(page.locator('[data-testid="employees-groups-modal"]')).not.toBeVisible();

    // Step 5: Enter valid start date in the start date field
    await page.fill('[data-testid="start-date-input"]', '2024-04-01');
    const startDateValue = await page.inputValue('[data-testid="start-date-input"]');
    expect(startDateValue).toBe('2024-04-01');

    // Step 6: Enter valid end date in the end date field that is after start date
    await page.fill('[data-testid="end-date-input"]', '2024-04-30');
    const endDateValue = await page.inputValue('[data-testid="end-date-input"]');
    expect(endDateValue).toBe('2024-04-30');

    // Step 7: Review the scheduling summary
    await expect(page.locator('[data-testid="scheduling-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="summary-template"]')).toContainText('Q1 2024 Performance Review');
    await expect(page.locator('[data-testid="summary-assignees"]')).toContainText('Engineering Team');
    await expect(page.locator('[data-testid="summary-date-range"]')).toContainText('2024-04-01');
    await expect(page.locator('[data-testid="summary-date-range"]')).toContainText('2024-04-30');

    // Step 8: Click 'Submit' button to save the schedule
    const startTime = Date.now();
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Step 9: Verify confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule created successfully');
    
    // Verify API response time is under 2 seconds
    const responseTime = Date.now() - startTime;
    expect(responseTime).toBeLessThan(2000);

    // Step 10: Verify the newly created schedule appears in the list of scheduled review cycles
    await expect(page.locator('[data-testid="scheduled-cycles-list"]')).toBeVisible();
    const scheduleRow = page.locator('[data-testid="schedule-row"]').filter({ hasText: 'Q1 2024 Performance Review' });
    await expect(scheduleRow).toBeVisible();
    await expect(scheduleRow).toContainText('2024-04-01');
    await expect(scheduleRow).toContainText('2024-04-30');
    await expect(scheduleRow.locator('[data-testid="schedule-status"]')).toContainText('Active');
  });

  test('Reject scheduling with conflicting dates (error-case)', async ({ page }) => {
    // Step 1: Navigate to Review Cycle Scheduling page
    await page.goto(reviewCycleSchedulingURL);
    await expect(page.locator('[data-testid="review-cycle-scheduling-page"]')).toBeVisible();

    // Step 2: Select a review cycle template from available templates
    await page.click('[data-testid="template-selector"]');
    await page.click('[data-testid="template-option-q2-2024"]');
    const selectedTemplate = await page.locator('[data-testid="template-selector"]').textContent();
    expect(selectedTemplate).toContain('Q2 2024');

    // Step 3: Select the same employees or groups that have an existing schedule
    await page.click('[data-testid="select-employees-groups-button"]');
    await expect(page.locator('[data-testid="employees-groups-modal"]')).toBeVisible();
    await page.click('[data-testid="employee-group-engineering-team"]');
    await expect(page.locator('[data-testid="employee-group-engineering-team"]')).toBeChecked();
    await page.click('[data-testid="confirm-selection-button"]');

    // Step 4: Enter start date that overlaps with existing schedule
    await page.fill('[data-testid="start-date-input"]', '2024-04-15');
    
    // Step 5: Enter end date that extends beyond existing schedule
    await page.fill('[data-testid="end-date-input"]', '2024-05-15');

    // Step 6: Click 'Submit' button to attempt scheduling
    await page.click('[data-testid="submit-schedule-button"]');

    // Step 7: Verify validation error is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="error-message"]')).toContainText('scheduling conflict');
    
    // Step 8: Review the conflict details displayed by the system
    await expect(page.locator('[data-testid="conflict-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('Engineering Team');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('2024-04-01');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('2024-04-30');

    // Step 9: Adjust start date to non-conflicting date after existing schedule ends
    await page.fill('[data-testid="start-date-input"]', '2024-05-01');
    const adjustedStartDate = await page.inputValue('[data-testid="start-date-input"]');
    expect(adjustedStartDate).toBe('2024-05-01');

    // Step 10: Adjust end date to valid date after new start date
    await page.fill('[data-testid="end-date-input"]', '2024-05-31');
    const adjustedEndDate = await page.inputValue('[data-testid="end-date-input"]');
    expect(adjustedEndDate).toBe('2024-05-31');

    // Step 11: Click 'Submit' button again with corrected dates
    await page.click('[data-testid="submit-schedule-button"]');

    // Step 12: Verify the newly created schedule appears in the list without conflicts
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule created successfully');
    
    // Verify no error messages are displayed
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Verify schedule appears in the list
    await expect(page.locator('[data-testid="scheduled-cycles-list"]')).toBeVisible();
    const scheduleRow = page.locator('[data-testid="schedule-row"]').filter({ hasText: 'Q2 2024' });
    await expect(scheduleRow).toBeVisible();
    await expect(scheduleRow).toContainText('2024-05-01');
    await expect(scheduleRow).toContainText('2024-05-31');
    await expect(scheduleRow.locator('[data-testid="schedule-status"]')).toContainText('Active');
  });
});