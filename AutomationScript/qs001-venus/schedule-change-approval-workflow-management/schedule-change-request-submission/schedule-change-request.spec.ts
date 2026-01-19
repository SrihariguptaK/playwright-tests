import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Schedule Change Request Submission', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs into the scheduling system
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful schedule change request submission with valid data', async ({ page }) => {
    // Action: Navigate to schedule change request page
    await page.click('[data-testid="schedule-change-link"]');
    
    // Expected Result: Schedule change request form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Schedule Change Request');
    
    // Action: Enter valid date, time, reason, and attach a document
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const formattedDate = tomorrow.toISOString().split('T')[0];
    
    await page.fill('[data-testid="date-field"]', formattedDate);
    await page.fill('[data-testid="time-field"]', '09:00');
    await page.fill('[data-testid="reason-field"]', 'Medical appointment');
    
    // Attach a valid document
    const filePath = path.join(__dirname, 'fixtures', 'test-document.pdf');
    await page.setInputFiles('[data-testid="attachment-input"]', filePath);
    
    // Expected Result: All inputs accept data without validation errors
    await expect(page.locator('[data-testid="date-field"]')).toHaveValue(formattedDate);
    await expect(page.locator('[data-testid="time-field"]')).toHaveValue('09:00');
    await expect(page.locator('[data-testid="reason-field"]')).toHaveValue('Medical appointment');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Action: Submit the schedule change request
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Request is saved and confirmation message is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Schedule change request submitted successfully');
    
    // Verify API call was made
    const response = await page.waitForResponse(response => 
      response.url().includes('/api/schedule-change-requests') && response.status() === 200
    );
    expect(response.ok()).toBeTruthy();
  });

  test('Verify rejection of submission with missing mandatory fields', async ({ page }) => {
    // Action: Navigate to schedule change request page
    await page.click('[data-testid="schedule-change-link"]');
    
    // Expected Result: Schedule change request form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Action: Leave mandatory fields empty
    await page.click('[data-testid="date-field"]');
    await page.click('[data-testid="time-field"]');
    await page.click('[data-testid="reason-field"]');
    await page.click('h1'); // Click outside to trigger validation
    
    // Expected Result: Real-time validation highlights missing fields
    await expect(page.locator('[data-testid="date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    
    // Action: Attempt to submit the form
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Submission is blocked and error messages are displayed
    await expect(page.locator('[data-testid="date-error"]')).toContainText('Date is required');
    await expect(page.locator('[data-testid="time-error"]')).toContainText('Time is required');
    await expect(page.locator('[data-testid="reason-error"]')).toContainText('Reason is required');
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
    
    // Verify submit button is disabled or form is not submitted
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Fill in only the date field and attempt to submit again
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const formattedDate = tomorrow.toISOString().split('T')[0];
    await page.fill('[data-testid="date-field"]', formattedDate);
    await page.click('[data-testid="submit-button"]');
    
    // Verify time and reason errors still present
    await expect(page.locator('[data-testid="time-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
  });

  test('Test file attachment size validation', async ({ page }) => {
    // Navigate to schedule change request page and locate the file attachment section
    await page.click('[data-testid="schedule-change-link"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-section"]')).toBeVisible();
    
    // Action: Attach a file larger than 5MB
    const largeFilePath = path.join(__dirname, 'fixtures', 'large-file-6mb.pdf');
    await page.setInputFiles('[data-testid="attachment-input"]', largeFilePath);
    
    // Expected Result: Validation error message is displayed preventing attachment
    await expect(page.locator('[data-testid="attachment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText('File size must not exceed 5MB');
    
    // Verify that the attachment field remains empty after the error
    const fileInputValue = await page.locator('[data-testid="attachment-input"]').inputValue();
    expect(fileInputValue).toBe('');
    await expect(page.locator('[data-testid="attached-file-name"]')).not.toBeVisible();
    
    // Action: Attach a file smaller than 5MB
    const validFilePath = path.join(__dirname, 'fixtures', 'valid-file-3mb.pdf');
    await page.setInputFiles('[data-testid="attachment-input"]', validFilePath);
    
    // Expected Result: File is accepted without errors
    await expect(page.locator('[data-testid="attachment-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="attached-file-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="attached-file-name"]')).toContainText('valid-file-3mb.pdf');
    
    // Fill in all mandatory fields (date, time, reason) with valid data
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const formattedDate = tomorrow.toISOString().split('T')[0];
    
    await page.fill('[data-testid="date-field"]', formattedDate);
    await page.fill('[data-testid="time-field"]', '09:00');
    await page.fill('[data-testid="reason-field"]', 'Medical appointment');
    
    // Action: Submit the form with the valid attachment
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Submission succeeds with confirmation
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Schedule change request submitted successfully');
    
    // Verify API call was successful
    const response = await page.waitForResponse(response => 
      response.url().includes('/api/schedule-change-requests') && response.status() === 200
    );
    expect(response.ok()).toBeTruthy();
  });
});