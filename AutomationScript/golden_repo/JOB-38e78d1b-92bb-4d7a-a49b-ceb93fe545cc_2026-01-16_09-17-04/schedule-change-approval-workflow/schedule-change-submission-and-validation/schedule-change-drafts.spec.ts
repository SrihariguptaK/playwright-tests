import { test, expect } from '@playwright/test';

test.describe('Schedule Change Draft Functionality', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as Schedule Coordinator
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'schedule.coordinator@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate saving and retrieving schedule change drafts (happy-path)', async ({ page }) => {
    // Step 1: Navigate to schedule change request form page
    await page.goto(`${baseURL}/schedule-change-request`);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 2: Enter partial data: schedule change date as '01/20/2025'
    await page.fill('[data-testid="schedule-change-date"]', '01/20/2025');
    await expect(page.locator('[data-testid="schedule-change-date"]')).toHaveValue('01/20/2025');

    // Step 3: Enter partial data: schedule change time as '02:00 PM'
    await page.fill('[data-testid="schedule-change-time"]', '02:00 PM');
    await expect(page.locator('[data-testid="schedule-change-time"]')).toHaveValue('02:00 PM');

    // Step 4: Leave the reason field empty (mandatory field intentionally left blank)
    const reasonField = page.locator('[data-testid="schedule-change-reason"]');
    await expect(reasonField).toBeEmpty();

    // Step 5: Click the Save Draft button
    await page.click('[data-testid="save-draft-button"]');
    
    // Verify draft is saved and confirmation is shown
    await expect(page.locator('[data-testid="draft-saved-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="draft-saved-confirmation"]')).toContainText('Draft saved successfully');

    // Step 6: Navigate away from the form page to dashboard or another page
    await page.goto(`${baseURL}/dashboard`);
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 7: Navigate back to schedule change request form or access 'My Drafts' section
    await page.click('[data-testid="my-drafts-link"]');
    await expect(page.locator('[data-testid="drafts-list"]')).toBeVisible();

    // Step 8: Click on the saved draft to retrieve and edit it
    await page.click('[data-testid="draft-item"]:first-child');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 9: Verify the date field contains the previously entered value '01/20/2025'
    await expect(page.locator('[data-testid="schedule-change-date"]')).toHaveValue('01/20/2025');

    // Step 10: Verify the time field contains the previously entered value '02:00 PM'
    await expect(page.locator('[data-testid="schedule-change-time"]')).toHaveValue('02:00 PM');

    // Step 11: Verify the reason field is empty as it was not filled during draft save
    await expect(page.locator('[data-testid="schedule-change-reason"]')).toBeEmpty();
  });

  test('Verify validation is bypassed on draft save (edge-case)', async ({ page }) => {
    // Step 1: Navigate to schedule change request form page
    await page.goto(`${baseURL}/schedule-change-request`);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 2: Leave all mandatory fields empty (date, time, reason)
    await expect(page.locator('[data-testid="schedule-change-date"]')).toBeEmpty();
    await expect(page.locator('[data-testid="schedule-change-time"]')).toBeEmpty();
    await expect(page.locator('[data-testid="schedule-change-reason"]')).toBeEmpty();

    // Step 3: Click the Save Draft button without filling any mandatory fields
    await page.click('[data-testid="save-draft-button"]');

    // Step 4: Verify confirmation message is displayed (no validation errors)
    await expect(page.locator('[data-testid="draft-saved-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 5: Retrieve the saved draft from 'My Drafts' section
    await page.click('[data-testid="my-drafts-link"]');
    await expect(page.locator('[data-testid="drafts-list"]')).toBeVisible();
    await page.click('[data-testid="draft-item"]:first-child');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 6: Without filling any mandatory fields, click the Submit button
    await page.click('[data-testid="submit-button"]');

    // Step 7: Verify validation error messages are displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-validation-error"]')).toBeVisible();

    // Step 8: Fill in only the date field with '02/10/2025' and attempt to submit again
    await page.fill('[data-testid="schedule-change-date"]', '02/10/2025');
    await page.click('[data-testid="submit-button"]');
    
    // Verify validation errors still present for time and reason
    await expect(page.locator('[data-testid="time-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-validation-error"]')).toBeVisible();

    // Step 9: Click Save Draft button with only date field filled
    await page.click('[data-testid="save-draft-button"]');
    
    // Verify draft is saved without validation errors
    await expect(page.locator('[data-testid="draft-saved-confirmation"]')).toBeVisible();
  });

  test('Ensure auto-save triggers every 2 minutes (happy-path)', async ({ page }) => {
    // Step 1: Navigate to schedule change request form page and note the current time
    await page.goto(`${baseURL}/schedule-change-request`);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    const startTime = Date.now();

    // Step 2: Enter schedule change date as '03/15/2025'
    await page.fill('[data-testid="schedule-change-date"]', '03/15/2025');
    await expect(page.locator('[data-testid="schedule-change-date"]')).toHaveValue('03/15/2025');

    // Step 3: Wait for 2 minutes without any user interaction (do not click Save Draft or Submit)
    await page.waitForTimeout(120000); // 2 minutes = 120000 milliseconds

    // Step 4: Observe for auto-save notification or indicator on the screen
    await expect(page.locator('[data-testid="auto-save-indicator"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="auto-save-indicator"]')).toContainText(/auto.*saved/i);

    // Step 5: Enter additional data: schedule change time as '03:30 PM'
    await page.fill('[data-testid="schedule-change-time"]', '03:30 PM');
    await expect(page.locator('[data-testid="schedule-change-time"]')).toHaveValue('03:30 PM');

    // Step 6: Wait for another 2 minutes without any user interaction
    await page.waitForTimeout(120000); // Another 2 minutes

    // Step 7: Observe for second auto-save notification
    await expect(page.locator('[data-testid="auto-save-indicator"]')).toBeVisible({ timeout: 5000 });

    // Step 8: Navigate away from the form without manually saving
    await page.goto(`${baseURL}/dashboard`);
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 9: Return to the form or access 'My Drafts' section
    await page.click('[data-testid="my-drafts-link"]');
    await expect(page.locator('[data-testid="drafts-list"]')).toBeVisible();

    // Step 10: Open the auto-saved draft and verify the data
    await page.click('[data-testid="draft-item"]:first-child');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Verify the date field contains '03/15/2025'
    await expect(page.locator('[data-testid="schedule-change-date"]')).toHaveValue('03/15/2025');

    // Verify the time field contains '03:30 PM'
    await expect(page.locator('[data-testid="schedule-change-time"]')).toHaveValue('03:30 PM');

    // Step 11: Check the draft timestamp in the database or UI
    const draftTimestamp = await page.locator('[data-testid="draft-timestamp"]').textContent();
    expect(draftTimestamp).toBeTruthy();
    
    // Verify draft was saved within the expected timeframe
    const draftTime = new Date(draftTimestamp || '').getTime();
    const timeDifference = draftTime - startTime;
    expect(timeDifference).toBeGreaterThanOrEqual(120000); // At least 2 minutes after start
  });
});