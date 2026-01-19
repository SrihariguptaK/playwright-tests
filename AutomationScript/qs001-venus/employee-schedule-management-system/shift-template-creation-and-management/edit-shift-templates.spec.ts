import { test, expect } from '@playwright/test';

test.describe('Edit Shift Templates - Story 2', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as HR Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful shift template edit with versioning (happy-path)', async ({ page }) => {
    // Step 1: Navigate to shift template list page
    await page.click('text=Shift Templates');
    await page.click('text=View Templates');
    await expect(page.locator('[data-testid="shift-templates-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-item"]')).toHaveCount(await page.locator('[data-testid="template-item"]').count());

    // Step 2: Locate and select a specific shift template
    const morningShiftTemplate = page.locator('[data-testid="template-item"]').filter({ hasText: 'Morning Shift - Standard' });
    await expect(morningShiftTemplate).toBeVisible();
    await morningShiftTemplate.locator('[data-testid="edit-button"]').click();
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();

    // Step 3: Modify the start time
    const startTimeInput = page.locator('[data-testid="start-time-input"]');
    await expect(startTimeInput).toBeVisible();
    await expect(startTimeInput).toHaveValue('09:00');
    await startTimeInput.clear();
    await startTimeInput.fill('08:30');
    await expect(startTimeInput).toHaveValue('08:30');

    // Step 4: Modify the end time
    const endTimeInput = page.locator('[data-testid="end-time-input"]');
    await expect(endTimeInput).toBeVisible();
    await expect(endTimeInput).toHaveValue('17:00');
    await endTimeInput.clear();
    await endTimeInput.fill('17:30');
    await expect(endTimeInput).toHaveValue('17:30');

    // Step 5: Save the modifications
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template updated successfully');
    await expect(page.locator('[data-testid="version-indicator"]')).toContainText('Version 2');

    // Step 6: View version history
    await page.click('[data-testid="view-history-button"]');
    await expect(page.locator('[data-testid="version-history-modal"]')).toBeVisible();
    const versionHistoryItems = page.locator('[data-testid="version-history-item"]');
    await expect(versionHistoryItems).toHaveCount(2);
    await expect(versionHistoryItems.first()).toContainText('Version 2');
    await expect(versionHistoryItems.first()).toContainText('08:30');
    await expect(versionHistoryItems.first()).toContainText('17:30');
    await expect(versionHistoryItems.last()).toContainText('Version 1');
    await expect(versionHistoryItems.last()).toContainText('09:00');
    await expect(versionHistoryItems.last()).toContainText('17:00');
  });

  test('Prevent editing of templates assigned to active schedules (error-case)', async ({ page }) => {
    // Step 1: Navigate to shift template list page
    await page.click('text=Shift Templates');
    await page.click('text=View Templates');
    await expect(page.locator('[data-testid="shift-templates-list"]')).toBeVisible();

    // Step 2: Select a template assigned to active schedules
    const activeTemplate = page.locator('[data-testid="template-item"]').filter({ has: page.locator('[data-testid="active-schedule-badge"]') }).first();
    await expect(activeTemplate).toBeVisible();
    await activeTemplate.locator('[data-testid="edit-button"]').click();

    // Step 3: Verify warning message is displayed
    await expect(page.locator('[data-testid="warning-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="warning-message"]')).toContainText('This template is assigned to active schedules and cannot be edited');

    // Step 4: Verify input fields are disabled
    await expect(page.locator('[data-testid="start-time-input"]')).toBeDisabled();
    await expect(page.locator('[data-testid="end-time-input"]')).toBeDisabled();
    await expect(page.locator('[data-testid="break-start-input"]')).toBeDisabled();
    await expect(page.locator('[data-testid="break-end-input"]')).toBeDisabled();

    // Step 5: Verify Save button is disabled or hidden
    const saveButton = page.locator('[data-testid="save-changes-button"]');
    const isDisabled = await saveButton.isDisabled().catch(() => false);
    const isHidden = await saveButton.isHidden().catch(() => false);
    expect(isDisabled || isHidden).toBeTruthy();

    // Step 6: Check if system provides information about active schedules
    await expect(page.locator('[data-testid="active-schedules-info"]')).toBeVisible();
    await expect(page.locator('[data-testid="active-schedule-link"]')).toHaveCount(await page.locator('[data-testid="active-schedule-link"]').count());
  });

  test('Reject edits with invalid shift parameters (error-case)', async ({ page }) => {
    // Step 1: Navigate to shift template list and select a template
    await page.click('text=Shift Templates');
    await page.click('text=View Templates');
    await expect(page.locator('[data-testid="shift-templates-list"]')).toBeVisible();
    
    const editableTemplate = page.locator('[data-testid="template-item"]').filter({ hasNot: page.locator('[data-testid="active-schedule-badge"]') }).first();
    await editableTemplate.locator('[data-testid="edit-button"]').click();
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();

    // Step 2: Create invalid time range (end time before start time)
    await page.locator('[data-testid="start-time-input"]').clear();
    await page.locator('[data-testid="start-time-input"]').fill('18:00');
    await page.locator('[data-testid="end-time-input"]').clear();
    await page.locator('[data-testid="end-time-input"]').fill('14:00');

    // Step 3: Verify validation error is displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('End time must be after start time');

    // Step 4: Attempt to save without correcting the error
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();

    // Step 5: Correct the end time to valid value
    await page.locator('[data-testid="end-time-input"]').clear();
    await page.locator('[data-testid="end-time-input"]').fill('22:00');
    await expect(page.locator('[data-testid="validation-error"]').filter({ hasText: 'End time must be after start time' })).not.toBeVisible();

    // Step 6: Test break period outside shift duration
    await page.locator('[data-testid="break-start-input"]').clear();
    await page.locator('[data-testid="break-start-input"]').fill('23:00');
    await page.locator('[data-testid="break-end-input"]').clear();
    await page.locator('[data-testid="break-end-input"]').fill('00:00');

    // Step 7: Verify validation error for invalid break period
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Break period must be within shift duration');

    // Step 8: Attempt to save with break validation error
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Step 9: Correct break times to valid values
    await page.locator('[data-testid="break-start-input"]').clear();
    await page.locator('[data-testid="break-start-input"]').fill('20:00');
    await page.locator('[data-testid="break-end-input"]').clear();
    await page.locator('[data-testid="break-end-input"]').fill('20:30');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 10: Save with valid data
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template updated successfully');
  });
});