import { test, expect } from '@playwright/test';

test.describe('Attendance Data Synchronization Audit', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Attendance Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'attendance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate logging of synchronization events (happy-path)', async ({ page }) => {
    // Navigate to the attendance data synchronization module
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="synchronization-module"]');
    await expect(page.locator('[data-testid="sync-page-header"]')).toBeVisible();

    // Select biometric and manual attendance data sources for synchronization
    await page.click('[data-testid="biometric-data-source-checkbox"]');
    await page.click('[data-testid="manual-data-source-checkbox"]');
    await expect(page.locator('[data-testid="biometric-data-source-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="manual-data-source-checkbox"]')).toBeChecked();

    // Record timestamp before synchronization
    const syncStartTime = new Date();

    // Initiate attendance data synchronization by clicking 'Synchronize' button
    await page.click('[data-testid="synchronize-button"]');

    // Wait for synchronization process to complete
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('In Progress', { timeout: 5000 });
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: 30000 });

    // Verify that synchronization event is logged with status and timestamp in the system
    const successMessage = page.locator('[data-testid="sync-success-message"]');
    await expect(successMessage).toBeVisible();
    await expect(successMessage).toContainText('Synchronization completed successfully');

    // Navigate to synchronization audit interface from the main menu
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="sync-audit-interface"]');
    await expect(page.locator('[data-testid="audit-logs-header"]')).toBeVisible();

    // Locate the most recent synchronization event in the audit logs
    const mostRecentEvent = page.locator('[data-testid="audit-log-row"]').first();
    await expect(mostRecentEvent).toBeVisible();

    // Verify the event appears within 1 minute of synchronization completion
    const eventTimestamp = await mostRecentEvent.locator('[data-testid="event-timestamp"]').textContent();
    const eventTime = new Date(eventTimestamp || '');
    const timeDifference = (eventTime.getTime() - syncStartTime.getTime()) / 1000;
    expect(timeDifference).toBeLessThanOrEqual(60);

    // Verify event status is 'Success'
    await expect(mostRecentEvent.locator('[data-testid="event-status"]')).toContainText('Success');
  });

  test('Verify filtering and export of synchronization audit logs (happy-path)', async ({ page }) => {
    // Navigate to synchronization audit interface
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="sync-audit-interface"]');
    await expect(page.locator('[data-testid="audit-logs-header"]')).toBeVisible();

    // Verify that filter options are available (date range, status, data source)
    await expect(page.locator('[data-testid="date-range-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="data-source-filter"]')).toBeVisible();

    // Select a specific date range using the date filter (e.g., last 7 days)
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="last-7-days-option"]');

    // Select 'Success' status from the status filter dropdown
    await page.click('[data-testid="status-filter"]');
    await page.click('[data-testid="status-success-option"]');

    // Click 'Apply Filters' button
    await page.click('[data-testid="apply-filters-button"]');

    // Wait for filtered results to load
    await page.waitForTimeout(1000);

    // Verify filtered results show correct data matching filter criteria
    const filteredRows = page.locator('[data-testid="audit-log-row"]');
    const rowCount = await filteredRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Verify all visible rows have 'Success' status
    for (let i = 0; i < Math.min(rowCount, 5); i++) {
      await expect(filteredRows.nth(i).locator('[data-testid="event-status"]')).toContainText('Success');
    }

    // Change status filter to 'Failed' and apply
    await page.click('[data-testid="status-filter"]');
    await page.click('[data-testid="status-failed-option"]');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(1000);

    // Click 'Export' button and select CSV format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-csv-option"]');

    // Confirm export by clicking 'Download' button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="download-confirm-button"]');
    const download = await downloadPromise;

    // Verify CSV file downloads with correct data
    expect(download.suggestedFilename()).toContain('.csv');
    const path = await download.path();
    expect(path).toBeTruthy();

    // Verify download success message
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });

  test('Ensure alert generation for synchronization failures (error-case)', async ({ page }) => {
    // Navigate to synchronization audit interface
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="sync-audit-interface"]');
    await expect(page.locator('[data-testid="audit-logs-header"]')).toBeVisible();

    // Access synchronization test/simulation module
    await page.click('[data-testid="test-simulation-menu"]');
    await page.click('[data-testid="simulate-sync-failure"]');
    await expect(page.locator('[data-testid="simulation-panel"]')).toBeVisible();

    // Disconnect biometric data source to simulate failure
    await page.click('[data-testid="disconnect-biometric-source"]');
    await expect(page.locator('[data-testid="biometric-status"]')).toContainText('Disconnected');

    // Initiate attendance data synchronization process
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="synchronization-module"]');
    await page.click('[data-testid="biometric-data-source-checkbox"]');
    
    const syncStartTime = new Date();
    await page.click('[data-testid="synchronize-button"]');

    // Wait for synchronization process to fail due to simulated error
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('In Progress', { timeout: 5000 });
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Failed', { timeout: 30000 });

    // Verify that system generates an alert notification for the synchronization failure
    const alertNotification = page.locator('[data-testid="alert-notification"]');
    await expect(alertNotification).toBeVisible({ timeout: 10000 });
    await expect(alertNotification).toContainText('Synchronization Failed');

    // Check notification channel for alert message
    await page.click('[data-testid="notifications-icon"]');
    const notificationPanel = page.locator('[data-testid="notifications-panel"]');
    await expect(notificationPanel).toBeVisible();
    const latestNotification = notificationPanel.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toContainText('Synchronization failure');

    // Navigate to synchronization audit logs
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="sync-audit-interface"]');
    await expect(page.locator('[data-testid="audit-logs-header"]')).toBeVisible();

    // Locate the failed synchronization event in the audit logs
    const failedEvent = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'Failed' }).first();
    await expect(failedEvent).toBeVisible();

    // Verify the failure event was logged within 1 minute of occurrence
    const eventTimestamp = await failedEvent.locator('[data-testid="event-timestamp"]').textContent();
    const eventTime = new Date(eventTimestamp || '');
    const timeDifference = (eventTime.getTime() - syncStartTime.getTime()) / 1000;
    expect(timeDifference).toBeLessThanOrEqual(60);

    // Click on the failed event to view detailed error information
    await failedEvent.click();
    const eventDetails = page.locator('[data-testid="event-details-panel"]');
    await expect(eventDetails).toBeVisible();

    // Verify alert contains actionable information for troubleshooting
    await expect(eventDetails.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(eventDetails.locator('[data-testid="error-message"]')).toContainText('biometric');
    await expect(eventDetails.locator('[data-testid="troubleshooting-info"]')).toBeVisible();
    await expect(eventDetails.locator('[data-testid="error-code"]')).toBeVisible();
  });
});