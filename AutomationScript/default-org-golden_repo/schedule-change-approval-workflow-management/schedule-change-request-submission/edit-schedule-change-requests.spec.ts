import { test, expect } from '@playwright/test';

test.describe('Edit Schedule Change Requests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful editing of pending schedule change request', async ({ page }) => {
    // Navigate to the list of submitted schedule change requests
    await page.goto('/schedule-change-requests');
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();

    // Identify and select a request with 'Pending' status from the list
    const pendingRequest = page.locator('[data-testid="request-row"]').filter({ hasText: 'Pending' }).first();
    await expect(pendingRequest).toBeVisible();

    // Click on the 'Edit' button for the selected pending request
    await pendingRequest.locator('[data-testid="edit-request-button"]').click();

    // Expected Result: Form is pre-filled with existing data
    await expect(page.locator('[data-testid="edit-request-form"]')).toBeVisible();
    const scheduleDate = await page.locator('[data-testid="schedule-date-input"]').inputValue();
    const reasonText = await page.locator('[data-testid="reason-input"]').inputValue();
    expect(scheduleDate).toBeTruthy();
    expect(reasonText).toBeTruthy();

    // Update one or more fields with valid data
    const newScheduleDate = '2024-12-15';
    const newReasonText = 'Updated reason for schedule change - equipment maintenance required';
    await page.fill('[data-testid="schedule-date-input"]', newScheduleDate);
    await page.fill('[data-testid="reason-input"]', newReasonText);

    // Expected Result: No validation errors displayed
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Review all updated fields to ensure accuracy
    await expect(page.locator('[data-testid="schedule-date-input"]')).toHaveValue(newScheduleDate);
    await expect(page.locator('[data-testid="reason-input"]')).toHaveValue(newReasonText);

    // Click the 'Submit' or 'Save Changes' button to submit the edited request
    await page.click('[data-testid="submit-changes-button"]');

    // Expected Result: Updates saved, version history recorded, and workflow continues
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request updated successfully');

    // Verify the request status remains 'Pending' and workflow continues
    await page.goto('/schedule-change-requests');
    const updatedRequest = page.locator('[data-testid="request-row"]').filter({ hasText: newReasonText }).first();
    await expect(updatedRequest.locator('[data-testid="request-status"]')).toContainText('Pending');

    // Check version history for the edited request
    await updatedRequest.locator('[data-testid="view-details-button"]').click();
    await page.click('[data-testid="version-history-tab"]');
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();
    const versionEntries = page.locator('[data-testid="version-entry"]');
    await expect(versionEntries).toHaveCount(2); // Original + edited version
  });

  test('Verify editing is blocked for approved requests', async ({ page }) => {
    // Navigate to the list of submitted schedule change requests
    await page.goto('/schedule-change-requests');
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();

    // Identify and select a request with 'Approved' status from the list
    const approvedRequest = page.locator('[data-testid="request-row"]').filter({ hasText: 'Approved' }).first();
    await expect(approvedRequest).toBeVisible();

    // Attempt to click on the 'Edit' button or option for the approved request
    const editButton = approvedRequest.locator('[data-testid="edit-request-button"]');
    
    // Expected Result: System prevents editing and displays appropriate message
    if (await editButton.isVisible()) {
      await expect(editButton).toBeDisabled();
    } else {
      // Edit button should not be visible for approved requests
      await expect(editButton).not.toBeVisible();
    }

    // Attempt to directly access the edit endpoint via URL manipulation
    const requestId = await approvedRequest.getAttribute('data-request-id');
    await page.goto(`/schedule-change-requests/${requestId}/edit`);

    // Verify that no edit form is displayed or error message is shown
    const errorMessage = page.locator('[data-testid="error-message"]');
    const editForm = page.locator('[data-testid="edit-request-form"]');
    
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText('Cannot edit approved request');
    await expect(editForm).not.toBeVisible();
  });

  test('Test validation errors on edit form', async ({ page }) => {
    // Navigate to the list of submitted schedule change requests
    await page.goto('/schedule-change-requests');
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();

    // Select a request with 'Pending' status and click 'Edit'
    const pendingRequest = page.locator('[data-testid="request-row"]').filter({ hasText: 'Pending' }).first();
    await pendingRequest.locator('[data-testid="edit-request-button"]').click();
    await expect(page.locator('[data-testid="edit-request-form"]')).toBeVisible();

    // Clear a required field (e.g., schedule date or reason) and leave it empty
    await page.fill('[data-testid="schedule-date-input"]', '');
    await page.fill('[data-testid="reason-input"]', '');

    // Attempt to submit the form with the empty required field
    await page.click('[data-testid="submit-changes-button"]');

    // Expected Result: Validation errors displayed preventing submission
    await expect(page.locator('[data-testid="validation-error-schedule-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-schedule-date"]')).toContainText('Schedule date is required');
    await expect(page.locator('[data-testid="validation-error-reason"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-reason"]')).toContainText('Reason is required');

    // Enter invalid data format in a date field (e.g., text instead of date format)
    await page.fill('[data-testid="schedule-date-input"]', 'invalid-date-text');
    await page.click('[data-testid="submit-changes-button"]');
    await expect(page.locator('[data-testid="validation-error-schedule-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-schedule-date"]')).toContainText('Invalid date format');

    // Enter a past date if only future dates are allowed
    const pastDate = '2020-01-01';
    await page.fill('[data-testid="schedule-date-input"]', pastDate);
    await page.click('[data-testid="submit-changes-button"]');
    await expect(page.locator('[data-testid="validation-error-schedule-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-schedule-date"]')).toContainText('Date must be in the future');

    // Enter data exceeding maximum character limit in a text field (e.g., reason field)
    const longText = 'a'.repeat(1001); // Assuming 1000 character limit
    await page.fill('[data-testid="reason-input"]', longText);
    await page.click('[data-testid="submit-changes-button"]');
    await expect(page.locator('[data-testid="validation-error-reason"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-reason"]')).toContainText('Reason exceeds maximum length');

    // Verify that multiple validation errors are displayed simultaneously
    await page.fill('[data-testid="schedule-date-input"]', 'invalid-date');
    await page.fill('[data-testid="reason-input"]', '');
    await page.click('[data-testid="submit-changes-button"]');
    const validationErrors = page.locator('[data-testid^="validation-error-"]');
    await expect(validationErrors).toHaveCount(2);

    // Correct all validation errors by entering valid data in all fields
    const futureDate = '2024-12-20';
    const validReason = 'Valid reason for schedule change with proper length';
    await page.fill('[data-testid="schedule-date-input"]', futureDate);
    await page.fill('[data-testid="reason-input"]', validReason);

    // Submit the form with all valid data
    await page.click('[data-testid="submit-changes-button"]');

    // Expected Result: Form submits successfully without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request updated successfully');
  });
});