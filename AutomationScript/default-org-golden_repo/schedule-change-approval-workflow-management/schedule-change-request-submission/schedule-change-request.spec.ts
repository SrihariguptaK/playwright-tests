import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Schedule Change Request Submission', () => {
  test.beforeEach(async ({ page }) => {
    // Log into the system using valid scheduler credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful schedule change request submission (happy-path)', async ({ page }) => {
    // Navigate to the schedule change request form from the main menu
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-change-request-link"]');
    
    // Expected Result: Form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-id-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="change-date-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="description-input"]')).toBeVisible();
    
    // Enter valid data in the schedule ID field
    await page.fill('[data-testid="schedule-id-input"]', 'SCH-2024-001');
    
    // Select a valid future date in the change date field
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="change-date-input"]', formattedDate);
    
    // Enter a valid reason for the schedule change
    await page.fill('[data-testid="reason-input"]', 'Operational requirement');
    
    // Enter detailed description of the schedule change
    await page.fill('[data-testid="description-input"]', 'Schedule change required due to operational needs and resource availability adjustments');
    
    // Click on the attachment button and select a valid document file
    const fileInput = page.locator('[data-testid="attachment-input"]');
    const filePath = path.join(__dirname, 'test-files', 'valid-document.pdf');
    await fileInput.setInputFiles(filePath);
    
    // Expected Result: All inputs accept data without validation errors
    await expect(page.locator('[data-testid="schedule-id-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="change-date-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="description-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="attachment-name"]')).toContainText('valid-document.pdf');
    
    // Click the Submit button
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Request is saved, workflow initiated, and confirmation message displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('successfully submitted');
    
    // Verify request ID is displayed
    const requestIdElement = page.locator('[data-testid="request-id"]');
    await expect(requestIdElement).toBeVisible();
    const requestIdText = await requestIdElement.textContent();
    expect(requestIdText).toMatch(/[A-Z0-9-]+/);
  });

  test('Verify rejection of submission with missing mandatory fields (error-case)', async ({ page }) => {
    // Navigate to the schedule change request form
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-change-request-link"]');
    
    // Expected Result: Form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Leave the schedule ID field empty and trigger validation
    await page.click('[data-testid="schedule-id-input"]');
    await page.click('[data-testid="change-date-input"]');
    
    // Expected Result: Real-time validation highlights missing fields
    await expect(page.locator('[data-testid="schedule-id-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-id-error"]')).toContainText(/required|mandatory/i);
    
    // Leave the change date field empty and trigger validation
    await page.click('[data-testid="reason-input"]');
    await expect(page.locator('[data-testid="change-date-error"]')).toBeVisible();
    
    // Leave the reason field empty and trigger validation
    await page.click('[data-testid="description-input"]');
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    
    // Scroll through the form to verify all validation messages are displayed
    await page.evaluate(() => window.scrollTo(0, 0));
    await expect(page.locator('[data-testid="schedule-id-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="change-date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    
    // Click the Submit button without filling any mandatory fields
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Submission blocked and error messages displayed
    await expect(page.locator('[data-testid="form-error-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-error-summary"]')).toContainText(/complete all required fields|mandatory fields/i);
    
    // Verify that no request ID is generated
    await expect(page.locator('[data-testid="request-id"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
    
    // Verify form remains on the same page
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
  });

  test('Test attachment size validation (boundary)', async ({ page }) => {
    // Navigate to the schedule change request form
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-change-request-link"]');
    
    // Fill in all mandatory fields with valid data
    await page.fill('[data-testid="schedule-id-input"]', 'SCH-2024-002');
    
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 10);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="change-date-input"]', formattedDate);
    
    await page.fill('[data-testid="reason-input"]', 'Resource reallocation');
    await page.fill('[data-testid="description-input"]', 'Schedule adjustment needed for resource optimization and efficiency improvements');
    
    // Attempt to attach a file larger than 10MB
    const fileInput = page.locator('[data-testid="attachment-input"]');
    const largeFilePath = path.join(__dirname, 'test-files', 'large-document-12mb.pdf');
    await fileInput.setInputFiles(largeFilePath);
    
    // Expected Result: System displays error message preventing attachment
    await expect(page.locator('[data-testid="attachment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText(/10MB|size limit|too large/i);
    
    // Verify that the large file is not attached to the form
    await expect(page.locator('[data-testid="attachment-name"]')).not.toContainText('large-document-12mb.pdf');
    
    // Select and attach a valid file within the size limit
    const validFilePath = path.join(__dirname, 'test-files', 'valid-document-5mb.pdf');
    await fileInput.setInputFiles(validFilePath);
    
    // Expected Result: Attachment accepted without errors
    await expect(page.locator('[data-testid="attachment-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="attachment-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-name"]')).toContainText('valid-document-5mb.pdf');
    
    // Click the Submit button
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Submission succeeds with attachment
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('successfully submitted');
    await expect(page.locator('[data-testid="request-id"]')).toBeVisible();
  });
});