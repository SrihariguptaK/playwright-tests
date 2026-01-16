import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Submission', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    
    // Login with scheduler credentials
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'SchedulerPass123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Validate successful schedule change request submission', async ({ page }) => {
    // Action: Scheduler navigates to schedule change request page
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-change-request"]');
    
    // Expected Result: Submission form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="change-request-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="change-type-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="description-field"]')).toBeVisible();
    
    // Action: Scheduler fills all required fields and attaches a valid document
    await page.selectOption('[data-testid="change-type-field"]', 'shift-modification');
    
    // Set effective date to future date
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="effective-date-field"]', formattedDate);
    
    await page.fill('[data-testid="reason-field"]', 'Employee availability change required');
    await page.fill('[data-testid="description-field"]', 'Need to modify shift schedule due to multiple employee requests for time off during holiday period');
    
    // Attach valid document
    const fileInput = page.locator('[data-testid="attach-document-button"]');
    await fileInput.setInputFiles({
      name: 'schedule_change_justification.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('Mock PDF content for testing')
    });
    
    // Expected Result: Form accepts input without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="attachment-preview"]')).toBeVisible();
    
    // Action: Scheduler submits the request
    await page.click('[data-testid="submit-request-button"]');
    
    // Expected Result: System confirms submission with unique request ID
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    const requestIdElement = page.locator('[data-testid="request-id"]');
    await expect(requestIdElement).toBeVisible();
    const requestId = await requestIdElement.textContent();
    expect(requestId).toMatch(/^REQ-\d+$/);
    
    // Navigate to My Requests dashboard
    await page.click('[data-testid="my-requests-link"]');
    await expect(page.locator('[data-testid="requests-dashboard"]')).toBeVisible();
    await expect(page.locator(`[data-testid="request-${requestId}"]`)).toBeVisible();
  });

  test('Verify rejection of submission with missing mandatory fields', async ({ page }) => {
    // Action: Scheduler navigates to submission form
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-change-request"]');
    
    // Expected Result: Form is displayed
    await expect(page.locator('[data-testid="change-request-form"]')).toBeVisible();
    
    // Action: Scheduler leaves mandatory fields empty
    // Click on next field to trigger validation
    await page.click('[data-testid="change-type-field"]');
    await page.click('[data-testid="effective-date-field"]');
    
    // Expected Result: Real-time validation highlights missing fields
    await expect(page.locator('[data-testid="change-type-error"]')).toBeVisible();
    
    await page.click('[data-testid="reason-field"]');
    await expect(page.locator('[data-testid="effective-date-error"]')).toBeVisible();
    
    await page.click('[data-testid="description-field"]');
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    
    // Action: Scheduler attempts to submit the form
    await page.click('[data-testid="submit-request-button"]');
    
    // Expected Result: Submission blocked with inline error messages
    await expect(page.locator('[data-testid="form-error-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-error-summary"]')).toContainText('Please correct the following errors');
    
    await expect(page.locator('[data-testid="change-type-error"]')).toContainText('Change Type is required');
    await expect(page.locator('[data-testid="effective-date-error"]')).toContainText('Effective Date is required');
    await expect(page.locator('[data-testid="reason-error"]')).toContainText('Reason for Change is required');
    await expect(page.locator('[data-testid="description-error"]')).toContainText('Description is required');
    
    // Verify form is still on the same page (not submitted)
    await expect(page.locator('[data-testid="change-request-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
    
    // Fill only Change Type and attempt to submit again
    await page.selectOption('[data-testid="change-type-field"]', 'shift-modification');
    await page.click('[data-testid="submit-request-button"]');
    
    // Verify page focus moves to first field with error
    const firstErrorField = page.locator('[data-testid="effective-date-field"]');
    await expect(firstErrorField).toBeFocused();
    await expect(page.locator('[data-testid="effective-date-error"]')).toBeVisible();
  });

  test('Test attachment upload and validation', async ({ page }) => {
    // Navigate to the schedule change request submission form
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-change-request"]');
    await expect(page.locator('[data-testid="change-request-form"]')).toBeVisible();
    
    // Fill in all mandatory fields with valid data
    await page.selectOption('[data-testid="change-type-field"]', 'shift-modification');
    
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 10);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="effective-date-field"]', formattedDate);
    
    await page.fill('[data-testid="reason-field"]', 'Operational efficiency improvement needed');
    await page.fill('[data-testid="description-field"]', 'Adjusting shift patterns to better align with peak operational hours and employee preferences');
    
    // Action: Scheduler selects a supported document file for upload
    const fileInput = page.locator('[data-testid="attach-document-button"]');
    await fileInput.setInputFiles({
      name: 'schedule_change_justification.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('Mock PDF content representing a 2MB file for testing purposes')
    });
    
    // Expected Result: Attachment preview is displayed
    await expect(page.locator('[data-testid="attachment-preview"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-name"]')).toContainText('schedule_change_justification.pdf');
    await expect(page.locator('[data-testid="upload-progress"]')).toHaveAttribute('aria-valuenow', '100');
    
    // Action: Scheduler submits the request with attachment
    await page.click('[data-testid="submit-request-button"]');
    
    // Expected Result: Attachment is stored and linked to the request
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    const requestIdElement = page.locator('[data-testid="request-id"]');
    const requestId = await requestIdElement.textContent();
    
    // Navigate to My Requests dashboard
    await page.click('[data-testid="my-requests-link"]');
    await expect(page.locator('[data-testid="requests-dashboard"]')).toBeVisible();
    
    // Locate and click on the newly submitted request
    await page.click(`[data-testid="request-${requestId}"]`);
    
    // Action: Scheduler views request details
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    
    // Scroll to attachments section
    await page.locator('[data-testid="attachments-section"]').scrollIntoViewIfNeeded();
    await expect(page.locator('[data-testid="attachments-section"]')).toBeVisible();
    
    // Expected Result: Attachment is accessible and downloadable
    const attachmentLink = page.locator('[data-testid="attachment-link"]');
    await expect(attachmentLink).toBeVisible();
    await expect(attachmentLink).toContainText('schedule_change_justification.pdf');
    
    // Verify download functionality
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="download-attachment-button"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe('schedule_change_justification.pdf');
  });
});