import { test, expect } from '@playwright/test';

test.describe('Schedule Change Draft Functionality', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Schedule Coordinator
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'schedule.coordinator@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate saving and retrieving schedule change drafts (happy-path)', async ({ page }) => {
    // Navigate to schedule change request form page
    await page.goto(`${BASE_URL}/schedule-change-request`);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Enter partial data: schedule ID 'SCH-67890' in the schedule field
    await page.fill('[data-testid="schedule-id-input"]', 'SCH-67890');
    await expect(page.locator('[data-testid="schedule-id-input"]')).toHaveValue('SCH-67890');

    // Enter date '2024-03-20' in the date field
    await page.fill('[data-testid="date-input"]', '2024-03-20');
    await expect(page.locator('[data-testid="date-input"]')).toHaveValue('2024-03-20');

    // Leave time and reason fields empty intentionally
    const timeField = page.locator('[data-testid="time-input"]');
    const reasonField = page.locator('[data-testid="reason-input"]');
    await expect(timeField).toHaveValue('');
    await expect(reasonField).toHaveValue('');

    // Click the 'Save Draft' button
    await page.click('[data-testid="save-draft-button"]');

    // Verify draft is saved and confirmation is shown
    await expect(page.locator('[data-testid="draft-saved-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="draft-saved-confirmation"]')).toContainText('Draft saved successfully');

    // Note the draft ID or timestamp and navigate away from the form page
    const draftId = await page.locator('[data-testid="draft-id"]').textContent();
    await page.goto(`${BASE_URL}/dashboard`);

    // Navigate to 'My Drafts' or 'Saved Drafts' section
    await page.click('[data-testid="my-drafts-link"]');
    await expect(page).toHaveURL(/.*drafts/);

    // Click on the saved draft to open it
    await page.click(`[data-testid="draft-item-${draftId}"]`);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Verify schedule ID field contains 'SCH-67890'
    await expect(page.locator('[data-testid="schedule-id-input"]')).toHaveValue('SCH-67890');

    // Verify date field contains '2024-03-20'
    await expect(page.locator('[data-testid="date-input"]')).toHaveValue('2024-03-20');

    // Verify time and reason fields are empty as originally saved
    await expect(page.locator('[data-testid="time-input"]')).toHaveValue('');
    await expect(page.locator('[data-testid="reason-input"]')).toHaveValue('');

    // Verify 'Save Draft' and 'Submit' buttons are available for further actions
    await expect(page.locator('[data-testid="save-draft-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="submit-button"]')).toBeVisible();
  });

  test('Verify validation is bypassed on draft save (edge-case)', async ({ page }) => {
    // Navigate to schedule change request form page
    await page.goto(`${BASE_URL}/schedule-change-request`);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Enter only schedule ID 'SCH-11111' leaving all other mandatory fields empty
    await page.fill('[data-testid="schedule-id-input"]', 'SCH-11111');
    await expect(page.locator('[data-testid="schedule-id-input"]')).toHaveValue('SCH-11111');

    // Click the 'Save Draft' button without filling date, time, or reason
    await page.click('[data-testid="save-draft-button"]');

    // Verify no error messages are displayed for missing mandatory fields
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="field-error"]')).not.toBeVisible();

    // Verify draft is saved by checking the drafts list
    await expect(page.locator('[data-testid="draft-saved-confirmation"]')).toBeVisible();
    const draftId = await page.locator('[data-testid="draft-id"]').textContent();

    // Navigate to drafts list
    await page.click('[data-testid="my-drafts-link"]');
    await expect(page.locator(`[data-testid="draft-item-${draftId}"]`)).toBeVisible();

    // Retrieve the saved draft by clicking on it from the drafts list
    await page.click(`[data-testid="draft-item-${draftId}"]`);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-id-input"]')).toHaveValue('SCH-11111');

    // Without adding any additional data, click the 'Submit' button
    await page.click('[data-testid="submit-button"]');

    // Observe validation error messages for missing mandatory fields
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-field-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-field-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-field-error"]')).toBeVisible();

    // Verify a summary error message appears at the top of the form
    await expect(page.locator('[data-testid="form-error-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-error-summary"]')).toContainText('Please fill in all required fields');

    // Verify the Submit button action is prevented
    await expect(page).toHaveURL(/.*schedule-change-request/);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
  });

  test('Ensure auto-save triggers every 2 minutes (happy-path)', async ({ page }) => {
    // Navigate to schedule change request form page and note the current time
    await page.goto(`${BASE_URL}/schedule-change-request`);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    const startTime = Date.now();

    // Enter schedule ID 'SCH-99999' in the schedule field
    await page.fill('[data-testid="schedule-id-input"]', 'SCH-99999');
    await expect(page.locator('[data-testid="schedule-id-input"]')).toHaveValue('SCH-99999');

    // Enter date '2024-04-10' in the date field
    await page.fill('[data-testid="date-input"]', '2024-04-10');
    await expect(page.locator('[data-testid="date-input"]')).toHaveValue('2024-04-10');

    // Wait for 2 minutes without any user interaction (do not click any buttons)
    await page.waitForTimeout(120000);

    // Observe for auto-save indicator or notification
    await expect(page.locator('[data-testid="auto-save-indicator"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="auto-save-indicator"]')).toContainText('Auto-saved');

    // Enter time '02:30 PM' in the time field after auto-save
    await page.fill('[data-testid="time-input"]', '02:30 PM');
    await expect(page.locator('[data-testid="time-input"]')).toHaveValue('02:30 PM');

    // Wait for another 2 minutes without clicking any buttons
    await page.waitForTimeout(120000);

    // Observe for second auto-save indicator or notification
    await expect(page.locator('[data-testid="auto-save-indicator"]')).toBeVisible({ timeout: 5000 });
    const autoSaveText = await page.locator('[data-testid="auto-save-indicator"]').textContent();
    expect(autoSaveText).toContain('Auto-saved');

    // Navigate away from the form without manually saving
    await page.goto(`${BASE_URL}/dashboard`);

    // Navigate to 'My Drafts' section
    await page.click('[data-testid="my-drafts-link"]');
    await expect(page).toHaveURL(/.*drafts/);

    // Open the auto-saved draft
    const draftItems = page.locator('[data-testid^="draft-item-"]');
    await expect(draftItems.first()).toBeVisible();
    await draftItems.first().click();

    // Verify draft data contains the latest entered information including time field
    await expect(page.locator('[data-testid="schedule-id-input"]')).toHaveValue('SCH-99999');
    await expect(page.locator('[data-testid="date-input"]')).toHaveValue('2024-04-10');
    await expect(page.locator('[data-testid="time-input"]')).toHaveValue('02:30 PM');
  });
});