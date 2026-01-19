import { test, expect } from '@playwright/test';

test.describe('Review Cycle Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to Review Cycle Configuration page before each test
    await page.goto('/review-cycles/configuration');
    await expect(page).toHaveURL(/.*review-cycles\/configuration/);
  });

  test('Validate successful creation of review cycle', async ({ page }) => {
    // Step 1: Navigate to Review Cycle Configuration page
    await expect(page.locator('[data-testid="review-cycles-list"]')).toBeVisible();
    await expect(page.locator('h1, h2').filter({ hasText: /Review Cycle Configuration/i })).toBeVisible();

    // Step 2: Click 'Add Review Cycle' and fill in valid details
    await page.click('[data-testid="add-review-cycle-button"]');
    await expect(page.locator('[data-testid="review-cycle-form"]')).toBeVisible();

    // Enter valid cycle name
    await page.fill('[data-testid="cycle-name-input"]', 'Q1 2024 Performance Review');

    // Select frequency from dropdown
    await page.click('[data-testid="frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-quarterly"]');

    // Enter valid duration value
    await page.fill('[data-testid="duration-input"]', '30');

    // Configure notification settings
    await page.click('[data-testid="notification-schedule-dropdown"]');
    await page.click('[data-testid="notification-option-7-days-before"]');
    await page.click('[data-testid="notification-schedule-dropdown"]');
    await page.click('[data-testid="notification-option-1-day-before-end"]');

    // Assign review cycle to users or groups
    await page.click('[data-testid="assign-users-dropdown"]');
    await page.click('[data-testid="user-group-option-engineering"]');

    // Verify form accepts inputs without errors
    await expect(page.locator('[data-testid="form-error"]')).not.toBeVisible();

    // Step 3: Submit the form
    await page.click('[data-testid="submit-review-cycle-button"]');

    // Verify review cycle is created and confirmation is shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/Review cycle created successfully/i);

    // Verify the newly created review cycle appears in the list
    await expect(page.locator('[data-testid="review-cycles-list"]')).toContainText('Q1 2024 Performance Review');
    await expect(page.locator('[data-testid="cycle-item-Q1-2024-Performance-Review"]')).toBeVisible();
  });

  test('Reject review cycle creation with invalid frequency', async ({ page }) => {
    // Step 1: Open Add Review Cycle form
    await page.click('[data-testid="add-review-cycle-button"]');
    await expect(page.locator('[data-testid="review-cycle-form"]')).toBeVisible();

    // Enter valid cycle name
    await page.fill('[data-testid="cycle-name-input"]', 'Invalid Frequency Test');

    // Step 2: Enter invalid frequency value (zero)
    await page.fill('[data-testid="frequency-input"]', '0');

    // Verify validation error is displayed
    await page.blur('[data-testid="frequency-input"]');
    await expect(page.locator('[data-testid="frequency-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="frequency-error"]')).toContainText(/Frequency must be greater than zero/i);

    // Step 3: Attempt to submit form
    await page.click('[data-testid="submit-review-cycle-button"]');

    // Verify submission is blocked
    await expect(page.locator('[data-testid="review-cycle-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Clear frequency field and enter negative value
    await page.fill('[data-testid="frequency-input"]', '-5');
    await page.blur('[data-testid="frequency-input"]');

    // Verify validation error is displayed for negative value
    await expect(page.locator('[data-testid="frequency-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="frequency-error"]')).toContainText(/Frequency must be a positive number/i);

    // Attempt to submit form again
    await page.click('[data-testid="submit-review-cycle-button"]');

    // Verify submission is still blocked
    await expect(page.locator('[data-testid="review-cycle-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Correct the frequency field with valid value
    await page.fill('[data-testid="frequency-input"]', '90');
    await page.blur('[data-testid="frequency-input"]');

    // Verify validation error is cleared
    await expect(page.locator('[data-testid="frequency-error"]')).not.toBeVisible();

    // Complete remaining required fields
    await page.fill('[data-testid="duration-input"]', '30');
    await page.click('[data-testid="notification-schedule-dropdown"]');
    await page.click('[data-testid="notification-option-7-days-before"]');
    await page.click('[data-testid="assign-users-dropdown"]');
    await page.click('[data-testid="user-group-option-sales"]');

    // Submit the corrected form
    await page.click('[data-testid="submit-review-cycle-button"]');

    // Verify successful submission
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/Review cycle created successfully/i);
  });
});