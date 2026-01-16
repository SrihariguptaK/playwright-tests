import { test, expect } from '@playwright/test';

test.describe('Integration Health Monitoring - Story 27', () => {
  test.beforeEach(async ({ page }) => {
    // Login as administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@system.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate integration health monitoring and alerts (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the integration monitoring dashboard
    await page.click('[data-testid="admin-panel-menu"]');
    await page.click('[data-testid="integration-monitoring-option"]');
    await expect(page).toHaveURL(/.*integration-monitoring/);
    await expect(page.locator('[data-testid="integration-monitoring-dashboard"]')).toBeVisible();

    // Step 2: Verify the current status section displays real-time integration status
    const statusSection = page.locator('[data-testid="current-status-section"]');
    await expect(statusSection).toBeVisible();
    await expect(statusSection.locator('[data-testid="integration-status-indicator"]')).toContainText(/Active|Connected|Healthy/);
    await expect(statusSection.locator('[data-testid="rules-engine-status"]')).toBeVisible();
    
    // Verify status updates (wait for refresh cycle)
    const initialTimestamp = await statusSection.locator('[data-testid="last-updated-timestamp"]').textContent();
    await page.waitForTimeout(31000); // Wait for 30-second refresh cycle
    const updatedTimestamp = await statusSection.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(initialTimestamp).not.toBe(updatedTimestamp);

    // Step 3: Review the logs section on the dashboard
    const logsSection = page.locator('[data-testid="logs-section"]');
    await expect(logsSection).toBeVisible();
    await expect(logsSection.locator('[data-testid="log-entry"]').first()).toBeVisible();
    const logCount = await logsSection.locator('[data-testid="log-entry"]').count();
    expect(logCount).toBeGreaterThan(0);

    // Step 4: Check the latency metrics displayed on the dashboard
    const latencyMetrics = page.locator('[data-testid="latency-metrics-section"]');
    await expect(latencyMetrics).toBeVisible();
    await expect(latencyMetrics.locator('[data-testid="average-latency"]')).toBeVisible();
    await expect(latencyMetrics.locator('[data-testid="max-latency"]')).toBeVisible();
    const avgLatency = await latencyMetrics.locator('[data-testid="average-latency"]').textContent();
    expect(avgLatency).toMatch(/\d+\s*ms/);

    // Step 5: Simulate an integration failure
    await page.click('[data-testid="test-controls-button"]');
    await page.click('[data-testid="simulate-failure-button"]');
    await page.click('[data-testid="confirm-simulate-failure"]');
    
    // Wait for failure to be processed
    await page.waitForTimeout(2000);

    // Step 6: Verify that the error is logged in the dashboard logs section
    await expect(logsSection.locator('[data-testid="log-entry"]').first()).toContainText(/Error|Failure|Failed/);
    const errorLog = logsSection.locator('[data-testid="log-entry"][data-log-type="error"]').first();
    await expect(errorLog).toBeVisible();
    await expect(errorLog.locator('[data-testid="log-severity"]')).toContainText('Error');
    await expect(errorLog.locator('[data-testid="log-message"]')).toContainText(/integration.*failure|rules engine.*error/i);

    // Step 7: Check for alert notification delivery to administrator
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible();
    const notificationCount = await notificationBadge.textContent();
    expect(parseInt(notificationCount || '0')).toBeGreaterThan(0);
    
    await page.click('[data-testid="notification-icon"]');
    const notificationPanel = page.locator('[data-testid="notification-panel"]');
    await expect(notificationPanel).toBeVisible();
    
    const alertNotification = notificationPanel.locator('[data-testid="alert-notification"]').first();
    await expect(alertNotification).toBeVisible();
    await expect(alertNotification).toContainText(/Integration.*Failure|Rules Engine.*Error/i);
    await expect(alertNotification.locator('[data-testid="alert-severity"]')).toContainText(/Critical|High|Error/);

    // Step 8: Acknowledge the alert notification
    await alertNotification.locator('[data-testid="acknowledge-alert-button"]').click();
    await expect(alertNotification.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    
    // Close notification panel
    await page.click('[data-testid="close-notification-panel"]');

    // Step 9: Restore the integration connection to normal state
    await page.click('[data-testid="test-controls-button"]');
    await page.click('[data-testid="restore-connection-button"]');
    await page.click('[data-testid="confirm-restore-connection"]');
    
    // Wait for restoration
    await page.waitForTimeout(3000);
    
    // Verify status is restored
    await expect(statusSection.locator('[data-testid="integration-status-indicator"]')).toContainText(/Active|Connected|Healthy/);

    // Step 10: Navigate to the historical performance reports section
    await page.click('[data-testid="historical-reports-tab"]');
    const reportsSection = page.locator('[data-testid="historical-reports-section"]');
    await expect(reportsSection).toBeVisible();

    // Step 11: Select a date range covering the simulated failure period
    const currentDate = new Date();
    const startDate = new Date(currentDate.getTime() - 3600000); // 1 hour ago
    const endDate = new Date();
    
    await page.click('[data-testid="date-range-picker"]');
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="start-time-input"]', startDate.toTimeString().substring(0, 5));
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-time-input"]', endDate.toTimeString().substring(0, 5));
    await page.click('[data-testid="apply-date-range-button"]');
    
    // Generate the performance report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-loading-indicator"]')).not.toBeVisible({ timeout: 15000 });

    // Step 12: Verify the report includes the simulated failure event
    const reportContent = page.locator('[data-testid="report-content"]');
    await expect(reportContent).toBeVisible();
    
    // Check for failure event in report
    const failureEvent = reportContent.locator('[data-testid="report-event"][data-event-type="failure"]').first();
    await expect(failureEvent).toBeVisible();
    
    // Verify correct timestamp
    const eventTimestamp = await failureEvent.locator('[data-testid="event-timestamp"]').textContent();
    expect(eventTimestamp).toBeTruthy();
    const eventTime = new Date(eventTimestamp || '');
    expect(eventTime.getTime()).toBeGreaterThanOrEqual(startDate.getTime());
    expect(eventTime.getTime()).toBeLessThanOrEqual(endDate.getTime());
    
    // Verify duration is recorded
    const eventDuration = await failureEvent.locator('[data-testid="event-duration"]').textContent();
    expect(eventDuration).toMatch(/\d+\s*(ms|seconds|minutes)/);
    
    // Verify event details
    await expect(failureEvent.locator('[data-testid="event-description"]')).toContainText(/Integration.*Failure|Rules Engine.*Error/i);
    await expect(failureEvent.locator('[data-testid="event-severity"]')).toContainText(/Critical|High|Error/);
    
    // Verify report summary statistics
    const reportSummary = reportContent.locator('[data-testid="report-summary"]');
    await expect(reportSummary).toBeVisible();
    await expect(reportSummary.locator('[data-testid="total-events"]')).toBeVisible();
    await expect(reportSummary.locator('[data-testid="error-count"]')).toContainText(/[1-9]\d*/);
    await expect(reportSummary.locator('[data-testid="uptime-percentage"]')).toBeVisible();
    
    // Verify report can be exported
    await expect(page.locator('[data-testid="export-report-button"]')).toBeEnabled();
  });
});