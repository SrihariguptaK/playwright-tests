import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request - Draft and Submission', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto(baseURL);
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate saving and editing draft schedule change requests', async ({ page }) => {
    // Step 1: Navigate to schedule change request form
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-request-button"]');
    
    // Expected Result: Form is displayed with all fields
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-schedule-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="proposed-schedule-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-input"]')).toBeVisible();
    
    // Step 2: Enter partial data and save as draft
    await page.fill('[data-testid="employee-name-input"]', 'John Doe');
    await page.fill('[data-testid="effective-date-input"]', '2024-02-15');
    await page.click('[data-testid="save-draft-button"]');
    
    // Expected Result: Draft is saved successfully with confirmation
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Draft saved successfully');
    
    // Get the draft ID from the URL or confirmation message
    const draftId = await page.locator('[data-testid="draft-id"]').textContent();
    
    // Navigate away from the form
    await page.click('[data-testid="dashboard-link"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 3: Retrieve and edit saved draft
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="drafts-list-link"]');
    await page.click(`[data-testid="draft-item-${draftId}"]`);
    
    // Expected Result: Draft data is loaded and editable
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name-input"]')).toHaveValue('John Doe');
    await expect(page.locator('[data-testid="effective-date-input"]')).toHaveValue('2024-02-15');
    
    // Modify existing data and add additional information
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday 9AM-5PM');
    await page.fill('[data-testid="proposed-schedule-input"]', 'Tuesday-Saturday 10AM-6PM');
    await page.click('[data-testid="save-draft-button"]');
    
    // Verify draft saved again
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Draft saved successfully');
  });

  test('Validate submission with all mandatory fields completed', async ({ page }) => {
    // Step 1: Navigate to schedule change request form or open an existing draft
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-request-button"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Complete all mandatory fields
    await page.fill('[data-testid="employee-name-input"]', 'Jane Smith');
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday 8AM-4PM');
    await page.fill('[data-testid="proposed-schedule-input"]', 'Monday-Friday 9AM-5PM');
    await page.fill('[data-testid="reason-input"]', 'Childcare responsibilities require later start time');
    await page.fill('[data-testid="effective-date-input"]', '2024-03-01');
    
    // Expected Result: No validation errors displayed
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('.error-message')).toHaveCount(0);
    
    // Step 2: Submit the schedule change request
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Request is submitted with status 'Pending Approval' and confirmation shown
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Request submitted successfully');
    
    // Verify the request status
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="submitted-requests-link"]');
    
    // Check for the submitted request in the list
    await expect(page.locator(`[data-testid="request-${requestId}"]`)).toBeVisible();
    await expect(page.locator(`[data-testid="request-${requestId}-status"]`)).toContainText('Pending Approval');
    
    // Verify request details
    await page.click(`[data-testid="request-${requestId}"]`);
    await expect(page.locator('[data-testid="employee-name-display"]')).toContainText('Jane Smith');
    await expect(page.locator('[data-testid="status-display"]')).toContainText('Pending Approval');
  });

  test('Validate submission blocked with missing mandatory fields', async ({ page }) => {
    // Step 1: Navigate to schedule change request form
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-request-button"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Fill in some fields but intentionally leave mandatory fields empty
    await page.fill('[data-testid="employee-name-input"]', 'Bob Johnson');
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday 7AM-3PM');
    await page.fill('[data-testid="proposed-schedule-input"]', 'Tuesday-Saturday 8AM-4PM');
    await page.fill('[data-testid="effective-date-input"]', '2024-03-15');
    // Intentionally leave 'Reason' field blank
    
    // Step 2: Click Submit button
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Validation error messages are displayed
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toContainText('Reason is required');
    
    // Verify the request status has not changed (still in draft or not created)
    await expect(page.locator('[data-testid="status-display"]')).not.toContainText('Pending Approval');
    
    // Verify error messages remain visible
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    
    // Attempt to navigate away from the form
    await page.click('[data-testid="dashboard-link"]');
    
    // Verify unsaved changes warning (if implemented)
    const dialogPromise = page.waitForEvent('dialog', { timeout: 2000 }).catch(() => null);
    const dialog = await dialogPromise;
    if (dialog) {
      expect(dialog.message()).toContain('unsaved changes');
      await dialog.dismiss();
    }
    
    // Return to form and fill in the previously empty mandatory field
    if (await page.url().includes('dashboard')) {
      await page.click('[data-testid="schedule-change-menu"]');
      await page.click('[data-testid="drafts-list-link"]');
      await page.click('[data-testid="draft-item-latest"]');
    }
    
    // Fill in the Reason field
    await page.fill('[data-testid="reason-input"]', 'Personal schedule adjustment needed');
    
    // Click Submit button again
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Submission is successful
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Request submitted successfully');
    
    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
  });
});