import { test, expect } from '@playwright/test';

test.describe('Attendance Alerts - Manager Alert Configuration and Delivery', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate alert configuration and delivery (happy-path)', async ({ page }) => {
    // Step 1: Navigate to alert configuration settings page
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="alert-configuration-link"]');
    await expect(page.locator('[data-testid="alert-config-page-title"]')).toBeVisible();

    // Step 2: Select 'Late Arrivals' as the alert type from the available options
    await page.click('[data-testid="alert-type-dropdown"]');
    await page.click('[data-testid="alert-type-late-arrivals"]');
    await expect(page.locator('[data-testid="alert-type-dropdown"]')).toContainText('Late Arrivals');

    // Step 3: Set the threshold value for late arrivals (e.g., 15 minutes)
    await page.fill('[data-testid="threshold-value-input"]', '15');
    await expect(page.locator('[data-testid="threshold-value-input"]')).toHaveValue('15');

    // Step 4: Select 'Email' as the notification channel
    await page.click('[data-testid="notification-channel-email"]');
    await expect(page.locator('[data-testid="notification-channel-email"]')).toBeChecked();

    // Step 5: Click 'Save' button to save the alert configuration
    await page.click('[data-testid="save-alert-config-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Configuration saved successfully');

    // Step 6: Simulate a late arrival event by creating a test attendance record
    await page.goto('/test-utilities/attendance-simulator');
    await page.fill('[data-testid="employee-id-input"]', 'EMP001');
    await page.fill('[data-testid="arrival-delay-input"]', '20');
    await page.click('[data-testid="simulate-late-arrival-button"]');
    await expect(page.locator('[data-testid="simulation-success-message"]')).toContainText('Late arrival event simulated');

    // Step 7: Wait and monitor for alert delivery (maximum 5 minutes)
    await page.waitForTimeout(10000); // Wait 10 seconds for alert processing

    // Step 8: Navigate to the dashboard notification center
    await page.goto('/dashboard');
    await page.click('[data-testid="notification-center-icon"]');
    await expect(page.locator('[data-testid="notification-center-panel"]')).toBeVisible();

    // Step 9: Click on the late arrival alert in the dashboard notification center
    await page.click('[data-testid="alert-late-arrival-EMP001"]');
    await expect(page.locator('[data-testid="alert-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-detail-type"]')).toContainText('Late Arrivals');
    await expect(page.locator('[data-testid="alert-detail-employee"]')).toContainText('EMP001');

    // Step 10: Click 'Acknowledge' button on the alert
    await page.click('[data-testid="acknowledge-alert-button"]');
    await expect(page.locator('[data-testid="alert-acknowledged-message"]')).toContainText('Alert acknowledged');

    // Step 11: Refresh the dashboard notification center
    await page.click('[data-testid="close-alert-detail-modal"]');
    await page.reload();
    await page.click('[data-testid="notification-center-icon"]');
    await expect(page.locator('[data-testid="alert-late-arrival-EMP001"]')).toHaveAttribute('data-status', 'acknowledged');
  });

  test('Verify alert logging and audit trail (happy-path)', async ({ page }) => {
    // Step 1: Simulate an absence event
    await page.goto('/test-utilities/attendance-simulator');
    await page.fill('[data-testid="employee-id-input"]', 'EMP002');
    await page.click('[data-testid="attendance-status-dropdown"]');
    await page.click('[data-testid="attendance-status-absent"]');
    await page.click('[data-testid="simulate-attendance-button"]');
    await expect(page.locator('[data-testid="simulation-success-message"]')).toContainText('Absence event simulated');

    // Step 2: Simulate a late arrival event
    await page.fill('[data-testid="employee-id-input"]', 'EMP003');
    await page.click('[data-testid="attendance-status-dropdown"]');
    await page.click('[data-testid="attendance-status-late"]');
    await page.fill('[data-testid="arrival-delay-input"]', '25');
    await page.click('[data-testid="simulate-attendance-button"]');
    await expect(page.locator('[data-testid="simulation-success-message"]')).toContainText('Late arrival event simulated');

    // Step 3: Simulate a threshold breach event
    await page.fill('[data-testid="employee-id-input"]', 'EMP004');
    await page.click('[data-testid="attendance-status-dropdown"]');
    await page.click('[data-testid="attendance-status-threshold-breach"]');
    await page.fill('[data-testid="consecutive-late-count-input"]', '5');
    await page.click('[data-testid="simulate-attendance-button"]');
    await expect(page.locator('[data-testid="simulation-success-message"]')).toContainText('Threshold breach event simulated');

    // Wait for alerts to be generated
    await page.waitForTimeout(10000);

    // Step 4: Navigate to the audit logs section
    await page.goto('/dashboard');
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-logs-page-title"]')).toBeVisible();

    // Step 5: Filter audit logs to display alert generation events for the current date
    await page.click('[data-testid="filter-event-type-dropdown"]');
    await page.click('[data-testid="filter-event-type-alert-generation"]');
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="filter-date-input"]', today);
    await page.click('[data-testid="apply-filter-button"]');
    await expect(page.locator('[data-testid="audit-log-results"]')).toBeVisible();

    // Step 6: Verify each alert log entry contains required information
    const alertLogRows = page.locator('[data-testid^="audit-log-row-"]');
    const rowCount = await alertLogRows.count();
    expect(rowCount).toBeGreaterThanOrEqual(3);

    for (let i = 0; i < Math.min(rowCount, 3); i++) {
      const row = alertLogRows.nth(i);
      await expect(row.locator('[data-testid="log-alert-id"]')).not.toBeEmpty();
      await expect(row.locator('[data-testid="log-alert-type"]')).not.toBeEmpty();
      await expect(row.locator('[data-testid="log-timestamp"]')).not.toBeEmpty();
      await expect(row.locator('[data-testid="log-employee-name"]')).not.toBeEmpty();
      await expect(row.locator('[data-testid="log-threshold-value"]')).not.toBeEmpty();
      await expect(row.locator('[data-testid="log-generation-timestamp"]')).not.toBeEmpty();
    }

    // Step 7: Navigate to the dashboard notification center and view the generated alerts
    await page.goto('/dashboard');
    await page.click('[data-testid="notification-center-icon"]');
    await expect(page.locator('[data-testid="notification-center-panel"]')).toBeVisible();

    // Step 8: Select the absence alert and resolve it
    await page.click('[data-testid="alert-absence-EMP002"]');
    await expect(page.locator('[data-testid="alert-detail-modal"]')).toBeVisible();
    await page.click('[data-testid="resolve-alert-button"]');
    await page.fill('[data-testid="resolution-notes-textarea"]', 'Employee on approved leave');
    await page.click('[data-testid="confirm-resolve-button"]');
    await expect(page.locator('[data-testid="alert-resolved-message"]')).toContainText('Alert resolved');
    await page.click('[data-testid="close-alert-detail-modal"]');

    // Step 9: Select the late arrival alert and resolve it
    await page.click('[data-testid="alert-late-arrival-EMP003"]');
    await expect(page.locator('[data-testid="alert-detail-modal"]')).toBeVisible();
    await page.click('[data-testid="resolve-alert-button"]');
    await page.fill('[data-testid="resolution-notes-textarea"]', 'Discussed with employee');
    await page.click('[data-testid="confirm-resolve-button"]');
    await expect(page.locator('[data-testid="alert-resolved-message"]')).toContainText('Alert resolved');
    await page.click('[data-testid="close-alert-detail-modal"]');

    // Step 10: Select the threshold breach alert and resolve it
    await page.click('[data-testid="alert-threshold-breach-EMP004"]');
    await expect(page.locator('[data-testid="alert-detail-modal"]')).toBeVisible();
    await page.click('[data-testid="resolve-alert-button"]');
    await page.fill('[data-testid="resolution-notes-textarea"]', 'Performance improvement plan initiated');
    await page.click('[data-testid="confirm-resolve-button"]');
    await expect(page.locator('[data-testid="alert-resolved-message"]')).toContainText('Alert resolved');
    await page.click('[data-testid="close-alert-detail-modal"]');

    // Step 11: Return to the audit logs section and filter for alert resolution actions
    await page.goto('/dashboard/audit-logs');
    await page.click('[data-testid="filter-event-type-dropdown"]');
    await page.click('[data-testid="filter-event-type-alert-resolution"]');
    await page.click('[data-testid="apply-filter-button"]');
    await expect(page.locator('[data-testid="audit-log-results"]')).toBeVisible();

    const resolutionLogRows = page.locator('[data-testid^="audit-log-row-"]');
    const resolutionCount = await resolutionLogRows.count();
    expect(resolutionCount).toBeGreaterThanOrEqual(3);

    // Verify resolution actions are logged
    await expect(resolutionLogRows.first().locator('[data-testid="log-action"]')).toContainText('Alert Resolved');
    await expect(resolutionLogRows.first().locator('[data-testid="log-resolution-notes"]')).not.toBeEmpty();

    // Step 12: Review the complete audit log history for one specific alert
    await page.click('[data-testid="clear-filters-button"]');
    await page.fill('[data-testid="search-alert-id-input"]', 'EMP002');
    await page.click('[data-testid="search-button"]');
    
    const specificAlertLogs = page.locator('[data-testid^="audit-log-row-"]');
    const specificLogCount = await specificAlertLogs.count();
    expect(specificLogCount).toBeGreaterThanOrEqual(2); // Generation and resolution

    // Verify complete history from generation to resolution
    await expect(specificAlertLogs.first().locator('[data-testid="log-action"]')).toContainText('Alert Generated');
    await expect(specificAlertLogs.last().locator('[data-testid="log-action"]')).toContainText('Alert Resolved');

    // Step 13: Export audit logs to verify data completeness
    await page.click('[data-testid="export-audit-logs-button"]');
    await page.click('[data-testid="export-format-csv"]');
    await page.click('[data-testid="confirm-export-button"]');
    
    const downloadPromise = page.waitForEvent('download');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('audit-logs');
    expect(download.suggestedFilename()).toContain('.csv');
  });
});