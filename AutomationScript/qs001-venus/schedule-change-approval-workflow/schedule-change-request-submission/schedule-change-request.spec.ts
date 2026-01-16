import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Schedule Change Request Submission', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Employee logs into the scheduling system
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful schedule change request submission with valid input', async ({ page }) => {
    // Action: Navigate to schedule change request page
    await page.goto(`${baseURL}/schedule-change-request`);
    
    // Expected Result: Form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="file-attachment-button"]')).toBeVisible();
    
    // Action: Enter valid date, time, reason, and attach a valid file
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowFormatted = tomorrow.toISOString().split('T')[0];
    
    await page.fill('[data-testid="date-field"]', tomorrowFormatted);
    await page.fill('[data-testid="time-field"]', '09:00');
    await page.fill('[data-testid="reason-field"]', 'Medical appointment');
    
    // Attach a valid file (assuming test file exists)
    const filePath = path.join(__dirname, 'test-files', 'test-document.pdf');
    await page.setInputFiles('[data-testid="file-attachment-input"]', filePath);
    
    // Expected Result: All inputs accept data without validation errors
    await expect(page.locator('[data-testid="date-field"]')).toHaveValue(tomorrowFormatted);
    await expect(page.locator('[data-testid="time-field"]')).toHaveValue('09:00');
    await expect(page.locator('[data-testid="reason-field"]')).toHaveValue('Medical appointment');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Action: Submit the form
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Request is saved, confirmation message displayed, and request logged
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('successfully submitted');
    
    // Verify request is logged in submission history
    await page.goto(`${baseURL}/submission-history`);
    await expect(page.locator('[data-testid="submission-list"]')).toContainText('Medical appointment');
  });

  test('Verify rejection of submission with missing mandatory fields', async ({ page }) => {
    // Action: Navigate to schedule change request page
    await page.goto(`${baseURL}/schedule-change-request`);
    
    // Expected Result: Form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Action: Leave mandatory fields empty
    // Leave Date field empty and click outside
    await page.click('[data-testid="date-field"]');
    await page.click('[data-testid="time-field"]');
    
    // Expected Result: Real-time validation highlights missing fields
    await expect(page.locator('[data-testid="date-error"]')).toBeVisible();
    
    // Leave Time field empty and click outside
    await page.click('[data-testid="time-field"]');
    await page.click('[data-testid="reason-field"]');
    await expect(page.locator('[data-testid="time-error"]')).toBeVisible();
    
    // Leave Reason field empty and click outside
    await page.click('[data-testid="reason-field"]');
    await page.click('[data-testid="date-field"]');
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    
    // Action: Attempt to submit the form
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Submission blocked with descriptive error messages
    await expect(page.locator('[data-testid="date-error"]')).toContainText('Date is required');
    await expect(page.locator('[data-testid="time-error"]')).toContainText('Time is required');
    await expect(page.locator('[data-testid="reason-error"]')).toContainText('Reason is required');
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
    
    // Verify no data is saved - check submission history remains empty
    await page.goto(`${baseURL}/submission-history`);
    const submissionCount = await page.locator('[data-testid="submission-item"]').count();
    const initialCount = submissionCount;
    
    // Fill in only the Date field and attempt to submit again
    await page.goto(`${baseURL}/schedule-change-request`);
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowFormatted = tomorrow.toISOString().split('T')[0];
    await page.fill('[data-testid="date-field"]', tomorrowFormatted);
    await page.click('[data-testid="submit-button"]');
    
    // Verify submission still blocked due to missing Time and Reason
    await expect(page.locator('[data-testid="time-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
  });

  test('Ensure draft save functionality works correctly', async ({ page }) => {
    // Action: Navigate to schedule change request page
    await page.goto(`${baseURL}/schedule-change-request`);
    
    // Expected Result: Form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Action: Fill partial data in the schedule change request form
    const nextWeek = new Date();
    nextWeek.setDate(nextWeek.getDate() + 7);
    const nextWeekFormatted = nextWeek.toISOString().split('T')[0];
    
    await page.fill('[data-testid="date-field"]', nextWeekFormatted);
    await page.fill('[data-testid="time-field"]', '14:00');
    // Leave Reason field empty (partial data entry)
    
    // Expected Result: Partial data accepted without errors
    await expect(page.locator('[data-testid="date-field"]')).toHaveValue(nextWeekFormatted);
    await expect(page.locator('[data-testid="time-field"]')).toHaveValue('14:00');
    
    // Action: Click 'Save Draft' button
    await page.click('[data-testid="save-draft-button"]');
    
    // Expected Result: Draft is saved and user receives confirmation notification
    await expect(page.locator('[data-testid="draft-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="draft-confirmation-message"]')).toContainText('Draft saved successfully');
    
    // Verify draft timestamp is displayed
    await expect(page.locator('[data-testid="draft-timestamp"]')).toBeVisible();
    
    // Action: Navigate away from the schedule change request page
    await page.goto(`${baseURL}/dashboard`);
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Action: Return to the schedule change request page
    await page.goto(`${baseURL}/schedule-change-request`);
    
    // Expected Result: Previously saved draft data is loaded correctly
    await expect(page.locator('[data-testid="date-field"]')).toHaveValue(nextWeekFormatted);
    await expect(page.locator('[data-testid="time-field"]')).toHaveValue('14:00');
    await expect(page.locator('[data-testid="reason-field"]')).toHaveValue('');
    
    // Verify draft indicator is present
    await expect(page.locator('[data-testid="draft-indicator"]')).toBeVisible();
  });
});