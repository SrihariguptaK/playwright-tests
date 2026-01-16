import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Submission', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SCHEDULE_CHANGE_PAGE = `${BASE_URL}/schedule-change-submission`;

  test.beforeEach(async ({ page }) => {
    // Navigate to schedule change submission page before each test
    await page.goto(SCHEDULE_CHANGE_PAGE);
  });

  test('Validate successful schedule change submission with valid data', async ({ page }) => {
    // Step 1: Navigate to schedule change submission page
    await expect(page).toHaveURL(SCHEDULE_CHANGE_PAGE);
    
    // Verify submission form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-upload"]')).toBeVisible();

    // Step 2: Enter valid schedule change details
    // Enter valid schedule change date (future date in format MM/DD/YYYY)
    await page.locator('[data-testid="date-field"]').fill('12/15/2024');
    
    // Enter valid schedule change time (in format HH:MM AM/PM)
    await page.locator('[data-testid="time-field"]').fill('10:00 AM');
    
    // Enter valid reason for schedule change (minimum 10 characters)
    await page.locator('[data-testid="reason-field"]').fill('Equipment maintenance required for safety compliance');
    
    // Upload attachment (PDF, 5MB)
    const fileInput = page.locator('[data-testid="attachment-upload"]');
    await fileInput.setInputFiles({
      name: 'maintenance-schedule.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('Mock PDF content for testing purposes')
    });
    
    // Verify all inputs accept data without validation errors
    await expect(page.locator('[data-testid="date-field-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="time-field-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="reason-field-error"]')).not.toBeVisible();

    // Step 3: Submit the schedule change request
    await page.locator('[data-testid="submit-button"]').click();
    
    // Request is accepted, confirmation with request ID is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('successfully submitted');
    
    const requestIdElement = page.locator('[data-testid="request-id"]');
    await expect(requestIdElement).toBeVisible();
    const requestId = await requestIdElement.textContent();
    expect(requestId).toBeTruthy();
    expect(requestId?.length).toBeGreaterThan(0);
  });

  test('Verify rejection of submission with missing mandatory fields', async ({ page }) => {
    // Step 1: Navigate to schedule change submission page
    await expect(page).toHaveURL(SCHEDULE_CHANGE_PAGE);
    
    // Submission form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 2: Leave mandatory fields empty and trigger real-time validation
    // Leave the date field empty
    await page.locator('[data-testid="date-field"]').click();
    
    // Leave the time field empty
    await page.locator('[data-testid="time-field"]').click();
    
    // Leave the reason field empty
    await page.locator('[data-testid="reason-field"]').click();
    
    // Click outside the mandatory fields to trigger real-time validation
    await page.locator('body').click({ position: { x: 0, y: 0 } });
    
    // Real-time validation highlights missing fields
    await expect(page.locator('[data-testid="date-field-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-field-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-field-error"]')).toBeVisible();

    // Step 3: Attempt to submit the request
    await page.locator('[data-testid="submit-button"]').click();
    
    // Submission is blocked, error messages are displayed
    await expect(page.locator('[data-testid="form-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-error-message"]')).toContainText('mandatory fields');
    
    // Verify no confirmation message is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
    
    // Fill in only the date field with valid data and attempt to submit again
    await page.locator('[data-testid="date-field"]').fill('12/20/2024');
    await page.locator('[data-testid="submit-button"]').click();
    
    // Verify submission is still blocked due to other missing fields
    await expect(page.locator('[data-testid="time-field-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-field-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
  });

  test('Ensure duplicate schedule change requests are prevented', async ({ page }) => {
    // Step 1: Submit first schedule change request
    await expect(page).toHaveURL(SCHEDULE_CHANGE_PAGE);
    
    // Enter schedule change date as '12/15/2024'
    await page.locator('[data-testid="date-field"]').fill('12/15/2024');
    
    // Enter schedule change time as '10:00 AM'
    await page.locator('[data-testid="time-field"]').fill('10:00 AM');
    
    // Enter reason as 'Equipment maintenance required'
    await page.locator('[data-testid="reason-field"]').fill('Equipment maintenance required');
    
    // Click Submit button
    await page.locator('[data-testid="submit-button"]').click();
    
    // Request is accepted
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    
    // Note the request ID
    const firstRequestId = await page.locator('[data-testid="request-id"]').textContent();
    expect(firstRequestId).toBeTruthy();

    // Step 2: Navigate back to schedule change submission page
    await page.goto(SCHEDULE_CHANGE_PAGE);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Enter the same schedule change date as '12/15/2024'
    await page.locator('[data-testid="date-field"]').fill('12/15/2024');
    
    // Enter the same schedule change time as '10:00 AM'
    await page.locator('[data-testid="time-field"]').fill('10:00 AM');
    
    // Enter reason as 'Additional maintenance work'
    await page.locator('[data-testid="reason-field"]').fill('Additional maintenance work');
    
    // Click Submit button
    await page.locator('[data-testid="submit-button"]').click();
    
    // System rejects the duplicate request with an error message
    await expect(page.locator('[data-testid="duplicate-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="duplicate-error-message"]')).toContainText('duplicate');
    
    // Verify no new confirmation message is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();

    // Step 3: Verify only one request exists in the database
    // Make API call to verify database state
    const response = await page.request.get(`${BASE_URL}/api/schedule-changes?date=12/15/2024&time=10:00 AM`);
    expect(response.ok()).toBeTruthy();
    
    const scheduleChanges = await response.json();
    expect(scheduleChanges.length).toBe(1);
    expect(scheduleChanges[0].id).toBe(firstRequestId);
    expect(scheduleChanges[0].date).toBe('12/15/2024');
    expect(scheduleChanges[0].time).toBe('10:00 AM');
  });
});