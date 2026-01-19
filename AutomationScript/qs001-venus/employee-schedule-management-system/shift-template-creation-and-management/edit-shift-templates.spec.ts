import { test, expect } from '@playwright/test';

test.describe('Edit Shift Templates', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduling Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Edit shift template successfully with valid data', async ({ page }) => {
    // Step 1: Navigate to shift template list
    await page.click('text=Shift Templates');
    await page.click('text=View All Templates');
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-item"]')).toHaveCount(await page.locator('[data-testid="template-item"]').count());

    // Step 2: Select a template and open edit form
    const morningShiftTemplate = page.locator('[data-testid="template-item"]').filter({ hasText: 'Morning Shift' });
    await expect(morningShiftTemplate).toBeVisible();
    await morningShiftTemplate.click();
    await page.click('[data-testid="edit-template-button"]');
    
    // Verify edit form is populated with current template data
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-name-input"]')).toHaveValue('Morning Shift');
    await expect(page.locator('[data-testid="end-time-input"]')).toHaveValue('04:00 PM');

    // Step 3: Modify shift times and submit
    await page.fill('[data-testid="end-time-input"]', '05:00 PM');
    await page.fill('[data-testid="break-start-input"]', '12:30 PM');
    await page.fill('[data-testid="break-end-input"]', '01:00 PM');
    await page.click('[data-testid="save-changes-button"]');

    // Verify template is saved as new version and confirmation shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template saved as new version');
    await expect(page.locator('[data-testid="version-indicator"]')).toContainText('Version');
  });

  test('Prevent editing of templates assigned to active schedules', async ({ page }) => {
    // Step 1: Navigate to shift template management page
    await page.click('text=Shift Templates');
    await page.click('text=View All Templates');
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();

    // Locate the Evening Shift template that is assigned to active schedules
    const eveningShiftTemplate = page.locator('[data-testid="template-item"]').filter({ hasText: 'Evening Shift' });
    await expect(eveningShiftTemplate).toBeVisible();
    
    // Step 2: Attempt to edit the Evening Shift template
    await eveningShiftTemplate.click();
    await page.click('[data-testid="edit-template-button"]');

    // Verify system displays error and blocks editing
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot edit template assigned to active schedules');
    await expect(page.locator('[data-testid="edit-template-form"]')).not.toBeVisible();
  });

  test('Reject invalid time updates during edit', async ({ page }) => {
    // Step 1: Navigate to shift template list, select Afternoon Shift template, and open edit form
    await page.click('text=Shift Templates');
    await page.click('text=View All Templates');
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    
    const afternoonShiftTemplate = page.locator('[data-testid="template-item"]').filter({ hasText: 'Afternoon Shift' });
    await expect(afternoonShiftTemplate).toBeVisible();
    await afternoonShiftTemplate.click();
    await page.click('[data-testid="edit-template-button"]');
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();

    // Step 2: Enter invalid shift times (start time after end time)
    await page.fill('[data-testid="start-time-input"]', '09:00 PM');
    // End time remains at 08:00 PM (unchanged)
    await expect(page.locator('[data-testid="end-time-input"]')).toHaveValue('08:00 PM');

    // Verify validation errors are displayed
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Start time must be before end time');

    // Step 3: Attempt to save changes - verify save is blocked
    const saveButton = page.locator('[data-testid="save-changes-button"]');
    await expect(saveButton).toBeDisabled();
    
    // Verify form is still visible with errors
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
  });
});