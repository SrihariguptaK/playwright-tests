import { test, expect } from '@playwright/test';

test.describe('Edit Shift Templates - Story 2', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduling Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Edit shift template with valid data successfully', async ({ page }) => {
    // Step 1: Navigate to shift template list
    await page.click('[data-testid="navigation-menu"]');
    await page.click('[data-testid="shift-templates-link"]');
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    
    // Verify list is displayed
    await expect(page.locator('[data-testid="shift-template-table"]')).toBeVisible();
    const templateRows = page.locator('[data-testid="template-row"]');
    await expect(templateRows).toHaveCountGreaterThan(0);

    // Step 2: Select a template and edit start/end times
    const firstTemplate = templateRows.first();
    const originalStartTime = await firstTemplate.locator('[data-testid="start-time"]').textContent();
    await firstTemplate.locator('[data-testid="edit-button"]').click();
    
    // Verify edit form is displayed
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-title"]')).toContainText('Edit Shift Template');
    
    // Modify start and end times with valid values
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.fill('[data-testid="end-time-input"]', '17:00');
    await page.fill('[data-testid="break-duration-input"]', '30');

    // Step 3: Submit changes
    await page.click('[data-testid="submit-button"]');
    
    // Verify update is confirmed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift template updated successfully');
    
    // Verify audit log was created
    await page.click('[data-testid="view-audit-log"]');
    await expect(page.locator('[data-testid="audit-log-modal"]')).toBeVisible();
    const latestAuditEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(latestAuditEntry).toContainText('Modified');
    await expect(latestAuditEntry).toContainText('09:00');
    await expect(latestAuditEntry).toContainText('17:00');
  });

  test('Prevent editing shift template with overlapping times', async ({ page }) => {
    // Step 1: Navigate to shift template list and select template to edit
    await page.click('[data-testid="navigation-menu"]');
    await page.click('[data-testid="shift-templates-link"]');
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    
    const templateRows = page.locator('[data-testid="template-row"]');
    const secondTemplate = templateRows.nth(1);
    await secondTemplate.locator('[data-testid="edit-button"]').click();
    
    // Verify edit form is displayed
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();

    // Step 2: Enter times overlapping another template
    // Assuming first template has times 09:00-17:00, we'll create overlap
    await page.fill('[data-testid="start-time-input"]', '08:00');
    await page.fill('[data-testid="end-time-input"]', '16:00');
    
    // Trigger validation by moving focus
    await page.click('[data-testid="break-duration-input"]');
    
    // Verify validation error is displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('overlapping');
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('shift times');

    // Step 3: Attempt to save changes
    await page.click('[data-testid="submit-button"]');
    
    // Verify save is blocked
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    
    // Verify no success message appears
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Verify submit button remains disabled or error persists
    const submitButton = page.locator('[data-testid="submit-button"]');
    const isDisabled = await submitButton.isDisabled();
    if (!isDisabled) {
      // If button is not disabled, error should still be visible
      await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    }
    
    // Verify form remains open until corrected
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-title"]')).toContainText('Edit Shift Template');
  });
});