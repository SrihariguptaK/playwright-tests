import { test, expect } from '@playwright/test';

test.describe('Shift Template Data Validation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to shift template creation page before each test
    await page.goto('/shift-templates/create');
    await expect(page).toHaveURL(/.*shift-templates\/create/);
  });

  test('Validate time format and logical order', async ({ page }) => {
    // Step 1: Enter invalid time format in start time field
    await page.fill('[data-testid="start-time-input"]', '25:00');
    await page.blur('[data-testid="start-time-input"]');
    
    // Expected Result: Inline error message displayed
    await expect(page.locator('[data-testid="start-time-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="start-time-error"]')).toContainText(/invalid.*time.*format/i);
    
    // Try another invalid format
    await page.fill('[data-testid="start-time-input"]', 'abc');
    await page.blur('[data-testid="start-time-input"]');
    await expect(page.locator('[data-testid="start-time-error"]')).toBeVisible();
    
    // Try yet another invalid format
    await page.fill('[data-testid="start-time-input"]', '13:75');
    await page.blur('[data-testid="start-time-input"]');
    await expect(page.locator('[data-testid="start-time-error"]')).toBeVisible();
    
    // Step 2: Clear and enter valid start time
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.blur('[data-testid="start-time-input"]');
    
    // Expected Result: No error for start time
    await expect(page.locator('[data-testid="start-time-error"]')).not.toBeVisible();
    
    // Step 3: Enter end time earlier than start time
    await page.fill('[data-testid="end-time-input"]', '08:00');
    await page.blur('[data-testid="end-time-input"]');
    
    // Step 4: Attempt to submit the form with invalid end time
    await page.click('[data-testid="submit-shift-template-btn"]');
    
    // Expected Result: Validation error prevents submission
    await expect(page.locator('[data-testid="end-time-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="end-time-error"]')).toContainText(/end time.*after.*start time/i);
    
    // Verify form was not submitted (still on creation page)
    await expect(page).toHaveURL(/.*shift-templates\/create/);
    
    // Step 5: Correct the end time to valid time after start time
    await page.fill('[data-testid="end-time-input"]', '17:00');
    await page.blur('[data-testid="end-time-input"]');
    
    // Step 6: Complete all remaining required fields with valid data
    await page.fill('[data-testid="shift-name-input"]', 'Morning Shift');
    await page.fill('[data-testid="shift-description-input"]', 'Standard morning shift');
    
    // Submit the form
    await page.click('[data-testid="submit-shift-template-btn"]');
    
    // Expected Result: No validation errors, form accepted
    await expect(page.locator('[data-testid="end-time-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="start-time-error"]')).not.toBeVisible();
    
    // Verify successful submission (redirected or success message shown)
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/successfully created/i);
  });

  test('Prevent overlapping shift templates', async ({ page }) => {
    // Prerequisite: Assume an existing shift template exists (08:00-16:00)
    // This would typically be set up in test data or beforeEach hook
    
    // Step 1: Enter shift template name
    await page.fill('[data-testid="shift-name-input"]', 'Mid-Day Shift');
    
    // Step 2: Attempt to create shift template with overlapping times
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '18:00');
    await page.blur('[data-testid="end-time-input"]');
    
    // Complete other required fields
    await page.fill('[data-testid="shift-description-input"]', 'Mid-day shift overlapping existing');
    
    // Step 3: Attempt to submit the form with overlapping times
    await page.click('[data-testid="submit-shift-template-btn"]');
    
    // Expected Result: Error message displayed and submission blocked
    await expect(page.locator('[data-testid="overlap-error"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="overlap-error"]')).toContainText(/overlap/i);
    
    // Verify form was not submitted (still on creation page)
    await expect(page).toHaveURL(/.*shift-templates\/create/);
    
    // Step 4: Adjust the start time to a non-overlapping value
    await page.fill('[data-testid="start-time-input"]', '16:00');
    await page.fill('[data-testid="end-time-input"]', '23:00');
    await page.blur('[data-testid="end-time-input"]');
    
    // Step 5: Complete all remaining required fields and submit the form
    await page.fill('[data-testid="shift-name-input"]', 'Evening Shift');
    await page.fill('[data-testid="shift-description-input"]', 'Evening shift non-overlapping');
    
    await page.click('[data-testid="submit-shift-template-btn"]');
    
    // Expected Result: Form accepts submission
    await expect(page.locator('[data-testid="overlap-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    
    // Step 6: Verify the newly created shift template appears in the list
    await page.goto('/shift-templates');
    await expect(page).toHaveURL(/.*shift-templates/);
    
    // Verify the shift template appears in the list
    const shiftTemplateRow = page.locator('[data-testid="shift-template-row"]', { hasText: 'Evening Shift' });
    await expect(shiftTemplateRow).toBeVisible();
    await expect(shiftTemplateRow).toContainText('16:00');
    await expect(shiftTemplateRow).toContainText('23:00');
  });
});