import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Editing', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Schedule Coordinator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'schedule.coordinator@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate editing of pending schedule change request (happy-path)', async ({ page }) => {
    // Navigate to 'My Schedule Change Requests' page
    await page.goto('/my-schedule-change-requests');
    await expect(page.locator('[data-testid="schedule-requests-page"]')).toBeVisible();

    // Locate and select a pending schedule change request from the list
    const pendingRequest = page.locator('[data-testid="schedule-request-row"]').filter({ hasText: 'Pending' }).first();
    await expect(pendingRequest).toBeVisible();
    const requestId = await pendingRequest.getAttribute('data-request-id');
    await pendingRequest.click();

    // Request details are displayed with edit option
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="edit-request-button"]')).toBeEnabled();

    // Click the edit button to enter edit mode
    await page.click('[data-testid="edit-request-button"]');
    await expect(page.locator('[data-testid="edit-request-form"]')).toBeVisible();

    // Modify schedule details (e.g., change date, time, or reason)
    const originalReason = await page.inputValue('[data-testid="reason-input"]');
    const newReason = 'Updated reason for schedule change - Medical appointment';
    await page.fill('[data-testid="reason-input"]', newReason);
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-15');
    await page.fill('[data-testid="schedule-time-input"]', '14:00');

    // Click save button to submit changes
    const startTime = Date.now();
    await page.click('[data-testid="save-changes-button"]');

    // Changes are saved and submission timestamp updated
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Changes saved successfully');
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    expect(responseTime).toBeLessThan(2000); // Verify update response within 2 seconds

    // Verify submission timestamp is updated
    await expect(page.locator('[data-testid="last-updated-timestamp"]')).toBeVisible();
    const timestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();

    // Navigate to audit log section or view audit trail for the request
    await page.click('[data-testid="audit-log-tab"]');
    await expect(page.locator('[data-testid="audit-log-section"]')).toBeVisible();

    // Audit log shows user, timestamp, and changes
    const latestAuditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(latestAuditEntry).toBeVisible();
    await expect(latestAuditEntry).toContainText('schedule.coordinator@example.com');
    await expect(latestAuditEntry).toContainText('Edit');
    await expect(latestAuditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(latestAuditEntry).toContainText(newReason);
  });

  test('Verify editing is blocked for approved requests (error-case)', async ({ page }) => {
    // Navigate to 'My Schedule Change Requests' page
    await page.goto('/my-schedule-change-requests');
    await expect(page.locator('[data-testid="schedule-requests-page"]')).toBeVisible();

    // Locate and select an approved schedule change request from the list
    const approvedRequest = page.locator('[data-testid="schedule-request-row"]').filter({ hasText: 'Approved' }).first();
    await expect(approvedRequest).toBeVisible();
    const requestId = await approvedRequest.getAttribute('data-request-id');
    await approvedRequest.click();

    // Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();

    // Edit option is disabled or access denied
    const editButton = page.locator('[data-testid="edit-request-button"]');
    if (await editButton.isVisible()) {
      await expect(editButton).toBeDisabled();
    } else {
      await expect(editButton).not.toBeVisible();
    }

    // Attempt direct API call to PUT /api/schedule-change-requests/{id} for approved request
    const response = await page.request.put(`/api/schedule-change-requests/${requestId}`, {
      data: {
        reason: 'Attempting to edit approved request',
        scheduleDate: '2024-03-20',
        scheduleTime: '10:00'
      }
    });

    // Verify API returns error for approved request editing
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Cannot edit approved request');
  });

  test('Test validation prevents saving invalid edits (error-case)', async ({ page }) => {
    // Navigate to 'My Schedule Change Requests' page
    await page.goto('/my-schedule-change-requests');
    await expect(page.locator('[data-testid="schedule-requests-page"]')).toBeVisible();

    // Select a pending schedule change request and click edit
    const pendingRequest = page.locator('[data-testid="schedule-request-row"]').filter({ hasText: 'Pending' }).first();
    await expect(pendingRequest).toBeVisible();
    await pendingRequest.click();
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await page.click('[data-testid="edit-request-button"]');
    await expect(page.locator('[data-testid="edit-request-form"]')).toBeVisible();

    // Enter invalid data in one or more required fields
    // Test 1: Past date
    await page.fill('[data-testid="schedule-date-input"]', '2020-01-01');
    await page.fill('[data-testid="schedule-time-input"]', '10:00');
    await page.fill('[data-testid="reason-input"]', 'Valid reason');

    // Click save button to attempt saving invalid data
    await page.click('[data-testid="save-changes-button"]');

    // Validation errors displayed, save blocked
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('date cannot be in the past');
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Test 2: Empty required field
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-20');
    await page.fill('[data-testid="reason-input"]', '');
    await page.click('[data-testid="save-changes-button"]');

    // Validation errors displayed for empty field
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Reason is required');

    // Test 3: Invalid format
    await page.fill('[data-testid="reason-input"]', 'AB'); // Too short
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();

    // Verify that no changes were saved to the database
    await page.reload();
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    const currentReason = await page.locator('[data-testid="current-reason-display"]').textContent();
    expect(currentReason).not.toBe('AB');

    // Correct the invalid data by entering valid values in all fields
    await page.click('[data-testid="edit-request-button"]');
    await expect(page.locator('[data-testid="edit-request-form"]')).toBeVisible();
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-25');
    await page.fill('[data-testid="schedule-time-input"]', '15:30');
    await page.fill('[data-testid="reason-input"]', 'Corrected valid reason for schedule change');

    // Click save button with corrected valid data
    await page.click('[data-testid="save-changes-button"]');

    // Changes saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Changes saved successfully');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Verify audit log for the successful save
    await page.click('[data-testid="audit-log-tab"]');
    await expect(page.locator('[data-testid="audit-log-section"]')).toBeVisible();
    const latestAuditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(latestAuditEntry).toBeVisible();
    await expect(latestAuditEntry).toContainText('Edit');
    await expect(latestAuditEntry).toContainText('schedule.coordinator@example.com');
    await expect(latestAuditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(latestAuditEntry).toContainText('Corrected valid reason for schedule change');
  });
});