import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Schedule Change Request Submission', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SCHEDULER_EMAIL = 'scheduler@example.com';
  const SCHEDULER_PASSWORD = 'SchedulerPass123!';
  const NON_SCHEDULER_EMAIL = 'user@example.com';
  const NON_SCHEDULER_PASSWORD = 'UserPass123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful schedule change request submission with valid data', async ({ page }) => {
    // Login as scheduler
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Action: Scheduler navigates to schedule change request page
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-request-button"]');
    
    // Expected Result: Schedule change request form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Schedule Change Request');
    
    // Action: Scheduler fills all mandatory fields with valid data
    await page.fill('[data-testid="employee-name-input"]', 'John Smith');
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday 9AM-5PM');
    await page.fill('[data-testid="proposed-schedule-input"]', 'Tuesday-Saturday 10AM-6PM');
    
    // Fill effective date (future date)
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 14);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="effective-date-input"]', formattedDate);
    
    await page.fill('[data-testid="reason-input"]', 'Employee requested schedule change for personal commitments');
    
    // Upload attachment (less than 10MB)
    const filePath = path.join(__dirname, 'fixtures', 'test-document.pdf');
    await page.setInputFiles('[data-testid="attachment-upload"]', filePath);
    
    // Expected Result: All inputs accept data without validation errors
    await expect(page.locator('[data-testid="employee-name-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="current-schedule-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="proposed-schedule-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="effective-date-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="attachment-name"]')).toContainText('test-document.pdf');
    
    // Action: Scheduler submits the form
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Submission succeeds and confirmation message is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');
    await expect(page.locator('[data-testid="confirmation-number"]')).toBeVisible();
    
    // Verify request entered approval workflow
    await expect(page.locator('[data-testid="workflow-status"]')).toContainText('Pending Approval');
  });

  test('Verify rejection of submission with missing mandatory fields', async ({ page }) => {
    // Login as scheduler
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Action: Scheduler navigates to schedule change request page
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-request-button"]');
    
    // Expected Result: Schedule change request form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Action: Scheduler fills some fields but leaves mandatory fields empty
    await page.fill('[data-testid="employee-name-input"]', 'Jane Doe');
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday 8AM-4PM');
    await page.fill('[data-testid="proposed-schedule-input"]', 'Monday-Friday 9AM-5PM');
    
    // Intentionally leave effective date and reason for change empty
    // Expected Result: Real-time validation highlights missing fields
    await page.click('[data-testid="employee-name-input"]'); // Trigger blur event
    await page.click('[data-testid="effective-date-input"]');
    await page.click('[data-testid="reason-input"]');
    await page.click('[data-testid="employee-name-input"]'); // Click away to trigger validation
    
    // Verify validation errors appear for empty mandatory fields
    await expect(page.locator('[data-testid="effective-date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-error"]')).toContainText('Effective date is required');
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toContainText('Reason for change is required');
    
    // Action: Scheduler attempts to submit the form
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Submission is blocked and error messages are displayed
    await expect(page.locator('[data-testid="form-error-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-error-summary"]')).toContainText('Please correct the errors before submitting');
    
    // Verify submit button is disabled or form remains on same page
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Verify error count
    const errorMessages = page.locator('[class*="error-message"]:visible');
    await expect(errorMessages).toHaveCount(2);
  });

  test('Ensure unauthorized users cannot access submission form', async ({ page }) => {
    // Action: User without scheduler role attempts to login
    await page.fill('[data-testid="email-input"]', NON_SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', NON_SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Action: User attempts to access schedule change request page by navigating to URL
    await page.goto(`${BASE_URL}/schedule-change-request/new`);
    
    // Expected Result: Access is denied with appropriate error message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this page');
    
    // Verify user is redirected or form is not displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).not.toBeVisible();
    
    // Alternative: Try accessing via menu option if visible
    const scheduleChangeMenu = page.locator('[data-testid="schedule-change-menu"]');
    if (await scheduleChangeMenu.isVisible()) {
      await scheduleChangeMenu.click();
      const newRequestButton = page.locator('[data-testid="new-request-button"]');
      await expect(newRequestButton).not.toBeVisible();
    }
    
    // Verify HTTP status or error page
    const pageTitle = await page.title();
    expect(pageTitle).toMatch(/Access Denied|Unauthorized|403/);
  });
});