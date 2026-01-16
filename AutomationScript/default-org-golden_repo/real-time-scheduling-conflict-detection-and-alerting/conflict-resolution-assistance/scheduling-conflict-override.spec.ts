import { test, expect } from '@playwright/test';

test.describe('Scheduling Conflict Override', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/scheduling');
  });

  test('Allow override with valid permissions', async ({ page }) => {
    // Login with user having override permissions
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler_with_override');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*scheduling/);

    // Navigate to the appointment scheduling interface
    await page.click('[data-testid="new-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Select a resource that already has an appointment scheduled
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-1"]');

    // Attempt to create a new appointment for the same resource at an overlapping time slot
    await page.fill('[data-testid="appointment-date"]', '2024-03-15');
    await page.fill('[data-testid="appointment-start-time"]', '10:00');
    await page.fill('[data-testid="appointment-end-time"]', '11:00');
    await page.fill('[data-testid="patient-name"]', 'John Doe');
    await page.fill('[data-testid="appointment-notes"]', 'Urgent consultation');

    // Click Save or Submit to attempt saving the conflicting appointment
    await page.click('[data-testid="save-appointment-button"]');

    // Review the conflict details displayed in the warning dialog
    await expect(page.locator('[data-testid="conflict-warning-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('Resource already scheduled');

    // Click the Override button to proceed with saving the conflicting appointment
    const startTime = Date.now();
    await page.click('[data-testid="override-button"]');

    // Wait for system to complete the override processing
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 2000 });
    const endTime = Date.now();
    const processingTime = endTime - startTime;

    // Verify override processing completes within 2 seconds
    expect(processingTime).toBeLessThan(2000);

    // Verify confirmation upon successful override
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment saved successfully with override');

    // Navigate to the audit log or override log section
    await page.click('[data-testid="audit-log-menu"]');
    await page.click('[data-testid="override-log-link"]');
    await expect(page).toHaveURL(/.*audit.*override/);

    // Search for the most recent override entry using timestamp or appointment ID
    await page.fill('[data-testid="log-search-input"]', 'John Doe');
    await page.click('[data-testid="search-button"]');

    // Verify the override log entry contains all required details
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-user-id"]')).toContainText('scheduler_with_override');
    await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-conflict-details"]')).toContainText('Resource already scheduled');
    await expect(logEntry.locator('[data-testid="log-action"]')).toContainText('Override');

    // Verify both appointments are now visible in the schedule for the same resource
    await page.click('[data-testid="schedule-view-link"]');
    await page.selectOption('[data-testid="resource-filter"]', 'resource-1');
    const appointments = page.locator('[data-testid="appointment-item"]');
    await expect(appointments).toHaveCount(2);
    await expect(appointments.filter({ hasText: 'John Doe' })).toBeVisible();
  });

  test('Prevent override without permissions', async ({ page }) => {
    // Log into the system using credentials of a user without override permissions
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler_no_override');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*scheduling/);

    // Navigate to the appointment scheduling interface
    await page.click('[data-testid="new-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Select a resource that already has an appointment scheduled
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-1"]');

    // Attempt to create a new appointment for the same resource at an overlapping time slot
    await page.fill('[data-testid="appointment-date"]', '2024-03-15');
    await page.fill('[data-testid="appointment-start-time"]', '10:00');
    await page.fill('[data-testid="appointment-end-time"]', '11:00');
    await page.fill('[data-testid="patient-name"]', 'Jane Smith');
    await page.fill('[data-testid="appointment-notes"]', 'Regular checkup');

    // Fill in all required appointment details and click Save or Submit
    await page.click('[data-testid="save-appointment-button"]');

    // Verify the conflict warning dialog does not show an override option
    await expect(page.locator('[data-testid="conflict-warning-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="override-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="conflict-error-message"]')).toContainText('Cannot save conflicting appointment');

    // Attempt to save the appointment by clicking any available save or confirm button
    const confirmButton = page.locator('[data-testid="confirm-button"]');
    if (await confirmButton.isVisible()) {
      await confirmButton.click();
    }

    // System blocks save and displays error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Insufficient permissions to override conflict');

    // Close the dialog
    await page.click('[data-testid="close-dialog-button"]');

    // Verify the appointment was not saved by checking the schedule
    await page.click('[data-testid="schedule-view-link"]');
    await page.selectOption('[data-testid="resource-filter"]', 'resource-1');
    const appointments = page.locator('[data-testid="appointment-item"]');
    await expect(appointments.filter({ hasText: 'Jane Smith' })).not.toBeVisible();

    // Check the database to confirm no new appointment record was created
    // This would typically be done via API call
    const response = await page.request.get('/api/appointments?patient=Jane Smith');
    expect(response.status()).toBe(200);
    const data = await response.json();
    expect(data.appointments.length).toBe(0);

    // Verify the failed override attempt is logged in the audit trail
    await page.click('[data-testid="audit-log-menu"]');
    await page.click('[data-testid="override-log-link"]');
    await page.fill('[data-testid="log-search-input"]', 'Jane Smith');
    await page.click('[data-testid="search-button"]');

    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-action"]')).toContainText('Override Denied');
    await expect(logEntry.locator('[data-testid="log-user-id"]')).toContainText('scheduler_no_override');
    await expect(logEntry.locator('[data-testid="log-reason"]')).toContainText('Insufficient permissions');
  });
});