import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Submission', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SUBMISSION_PAGE = `${BASE_URL}/schedule-change/submit`;

  test.beforeEach(async ({ page }) => {
    // Navigate to schedule change submission page before each test
    await page.goto(SUBMISSION_PAGE);
  });

  test('Validate successful schedule change submission with valid data', async ({ page }) => {
    // Step 1: Verify submission form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-id-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-upload"]')).toBeVisible();

    // Step 2: Enter valid schedule change details and upload attachment
    await page.locator('[data-testid="schedule-id-field"]').fill('SCH-98765');
    await page.locator('[data-testid="date-picker"]').fill('2024-03-20');
    await page.locator('[data-testid="time-field"]').fill('14:30');
    await page.locator('[data-testid="reason-field"]').fill('Operational adjustment required for maintenance');
    
    // Upload attachment (5MB PDF file)
    const fileInput = page.locator('[data-testid="attachment-upload"]');
    await fileInput.setInputFiles({
      name: 'supporting-document.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.alloc(5 * 1024 * 1024) // 5MB file
    });

    // Verify all inputs accept data without validation errors
    await expect(page.locator('[data-testid="schedule-id-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="date-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="time-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).not.toBeVisible();

    // Step 3: Submit the schedule change request
    await page.locator('[data-testid="submit-button"]').click();

    // Verify request is accepted and confirmation with request ID is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    expect(requestId).toBeTruthy();
    expect(requestId).toMatch(/^REQ-\d+$/);
  });

  test('Verify rejection of submission with missing mandatory fields', async ({ page }) => {
    // Step 1: Verify submission form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 2: Leave mandatory fields empty and trigger validation
    // Click on schedule ID field and then tab away to trigger real-time validation
    await page.locator('[data-testid="schedule-id-field"]').click();
    await page.locator('[data-testid="date-picker"]').click();
    
    // Tab away from date field
    await page.locator('[data-testid="time-field"]').click();
    
    // Tab away from time field
    await page.locator('[data-testid="reason-field"]').click();
    
    // Tab away from reason field
    await page.keyboard.press('Tab');

    // Verify real-time validation highlights missing fields
    await expect(page.locator('[data-testid="schedule-id-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-id-error"]')).toContainText('Schedule ID is required');
    await expect(page.locator('[data-testid="date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();

    // Step 3: Attempt to submit the request
    await page.locator('[data-testid="submit-button"]').click();

    // Verify submission is blocked and error messages are displayed
    await expect(page.locator('[data-testid="form-error-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-error-summary"]')).toContainText('Please correct the errors below');
    
    // Verify form remains on submission page
    await expect(page).toHaveURL(SUBMISSION_PAGE);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Verify no confirmation message is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
  });

  test('Ensure duplicate schedule change requests are prevented', async ({ page }) => {
    const scheduleId = 'SCH-12345';
    const date = '2024-02-15';
    const time = '10:00';
    const firstReason = 'Equipment maintenance required';
    const secondReason = 'Additional changes needed';

    // Step 1: Submit first schedule change request
    await page.locator('[data-testid="schedule-id-field"]').fill(scheduleId);
    await page.locator('[data-testid="date-picker"]').fill(date);
    await page.locator('[data-testid="time-field"]').fill(time);
    await page.locator('[data-testid="reason-field"]').fill(firstReason);
    await page.locator('[data-testid="submit-button"]').click();

    // Verify first request is accepted
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    const firstRequestId = await page.locator('[data-testid="request-id"]').textContent();
    expect(firstRequestId).toBeTruthy();

    // Step 2: Navigate back to submission page
    await page.goto(SUBMISSION_PAGE);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Attempt to submit duplicate request with same schedule and time
    await page.locator('[data-testid="schedule-id-field"]').fill(scheduleId);
    await page.locator('[data-testid="date-picker"]').fill(date);
    await page.locator('[data-testid="time-field"]').fill(time);
    await page.locator('[data-testid="reason-field"]').fill(secondReason);
    await page.locator('[data-testid="submit-button"]').click();

    // Verify system rejects the duplicate request with error message
    await expect(page.locator('[data-testid="duplicate-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="duplicate-error"]')).toContainText('A schedule change request already exists for this schedule and time period');
    
    // Verify no new request ID is generated
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();

    // Step 3: Verify only one request exists in the database
    // Make API call to verify database state
    const response = await page.request.get(`${BASE_URL}/api/schedule-changes?scheduleId=${scheduleId}&date=${date}&time=${time}`);
    expect(response.ok()).toBeTruthy();
    
    const requests = await response.json();
    expect(requests).toHaveLength(1);
    expect(requests[0].scheduleId).toBe(scheduleId);
    expect(requests[0].date).toBe(date);
    expect(requests[0].time).toBe(time);
    expect(requests[0].requestId).toBe(firstRequestId);
  });
});