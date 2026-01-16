import { test, expect } from '@playwright/test';

test.describe('Story-14: Configure Synchronization Job Schedules', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler_user');
    await page.fill('[data-testid="password-input"]', 'scheduler_pass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify scheduling configuration and job execution (happy-path)', async ({ page }) => {
    // Navigate to synchronization settings
    await page.click('text=Settings');
    await page.click('text=Synchronization Schedule');
    await expect(page.locator('[data-testid="sync-schedule-page"]')).toBeVisible();

    // Click Create New Schedule button
    await page.click('[data-testid="create-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-form"]')).toBeVisible();

    // Select Hourly interval from dropdown
    await page.click('[data-testid="interval-dropdown"]');
    await page.click('[data-testid="interval-option-hourly"]');
    await expect(page.locator('[data-testid="interval-dropdown"]')).toContainText('Hourly');

    // Set schedule to run every 1 hour
    await page.fill('[data-testid="interval-value-input"]', '1');
    await expect(page.locator('[data-testid="interval-value-input"]')).toHaveValue('1');

    // Enter descriptive name for the schedule
    await page.fill('[data-testid="schedule-name-input"]', 'Hourly Employee Data Sync');
    await expect(page.locator('[data-testid="schedule-name-input"]')).toHaveValue('Hourly Employee Data Sync');

    // Save the schedule configuration
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule saved successfully');

    // Note the next scheduled execution time
    const nextExecutionTime = await page.locator('[data-testid="next-execution-time"]').textContent();
    expect(nextExecutionTime).toBeTruthy();

    // Monitor job execution dashboard
    await page.click('text=Dashboard');
    await page.click('[data-testid="job-execution-dashboard"]');
    await expect(page.locator('[data-testid="dashboard-title"]')).toBeVisible();

    // Wait for scheduled job execution (simulated with shorter wait for testing)
    await page.waitForTimeout(5000);

    // Navigate to synchronization logs
    await page.click('text=Logs');
    await page.click('text=Synchronization History');
    await expect(page.locator('[data-testid="sync-logs-table"]')).toBeVisible();

    // Verify most recent job execution entry
    const mostRecentJob = page.locator('[data-testid="log-entry"]').first();
    await expect(mostRecentJob).toBeVisible();
    await expect(mostRecentJob.locator('[data-testid="job-name"]')).toContainText('Hourly Employee Data Sync');
    await expect(mostRecentJob.locator('[data-testid="job-status"]')).toContainText('successful');
    await expect(mostRecentJob.locator('[data-testid="job-timestamp"]')).toBeVisible();
  });

  test('Test manual synchronization trigger (happy-path)', async ({ page }) => {
    // Navigate to synchronization control panel
    await page.click('text=Synchronization');
    await page.click('text=Manual Sync');
    await expect(page.locator('[data-testid="manual-sync-panel"]')).toBeVisible();

    // Verify manual synchronization trigger button is visible and enabled
    const manualTriggerButton = page.locator('[data-testid="run-sync-now-button"]');
    await expect(manualTriggerButton).toBeVisible();
    await expect(manualTriggerButton).toBeEnabled();

    // Review current synchronization status
    const syncStatus = page.locator('[data-testid="sync-status-display"]');
    await expect(syncStatus).toBeVisible();
    const statusText = await syncStatus.textContent();
    expect(statusText).toBeTruthy();

    // Click manual synchronization trigger button
    await manualTriggerButton.click();
    await expect(page.locator('[data-testid="confirm-dialog"]')).toBeVisible();

    // Confirm manual synchronization
    await page.click('[data-testid="confirm-button"]');
    await expect(page.locator('[data-testid="sync-started-message"]')).toContainText('Synchronization job starts immediately');

    // Monitor job progress on dashboard
    const progressIndicator = page.locator('[data-testid="job-progress-indicator"]');
    await expect(progressIndicator).toBeVisible();

    // Wait for synchronization job to complete
    await page.waitForSelector('[data-testid="job-completed-indicator"]', { timeout: 30000 });
    await expect(page.locator('[data-testid="job-completed-indicator"]')).toBeVisible();

    // Navigate to synchronization logs
    await page.click('[data-testid="view-logs-button"]');
    await expect(page.locator('[data-testid="sync-logs-page"]')).toBeVisible();

    // Verify manually triggered job in logs
    const manualJobEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(manualJobEntry).toBeVisible();
    await expect(manualJobEntry.locator('[data-testid="job-trigger-type"]')).toContainText('Manual');
    await expect(manualJobEntry.locator('[data-testid="job-status"]')).toContainText('successful');
    await expect(manualJobEntry.locator('[data-testid="job-timestamp"]')).toBeVisible();

    // Review detailed job execution log
    await manualJobEntry.click();
    await expect(page.locator('[data-testid="job-detail-panel"]')).toBeVisible();
    const errorWarnings = page.locator('[data-testid="job-errors-warnings"]');
    const errorCount = await errorWarnings.textContent();
    expect(errorCount).toContain('0 errors');
  });

  test('Validate job retry on failure (error-case)', async ({ page }) => {
    // Navigate to test configuration panel
    await page.click('text=Settings');
    await page.click('text=Test Controls');
    await expect(page.locator('[data-testid="test-controls-panel"]')).toBeVisible();

    // Enable failure simulation mode
    const failureSimToggle = page.locator('[data-testid="simulate-job-failure-toggle"]');
    await failureSimToggle.click();
    await expect(failureSimToggle).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('[data-testid="failure-mode-enabled-message"]')).toContainText('Simulate Job Failure');

    // Navigate to synchronization control panel and trigger manual sync
    await page.click('text=Synchronization');
    await page.click('text=Manual Sync');
    await page.click('[data-testid="run-sync-now-button"]');
    await page.click('[data-testid="confirm-button"]');

    // Monitor job status on dashboard
    await expect(page.locator('[data-testid="job-status-indicator"]')).toBeVisible();
    await page.waitForSelector('[data-testid="job-failed-indicator"]', { timeout: 15000 });

    // Navigate to logs and verify failure is logged
    await page.click('text=Logs');
    await page.click('text=Synchronization History');
    const failedJobEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(failedJobEntry.locator('[data-testid="job-status"]')).toContainText('Failed');
    await expect(failedJobEntry.locator('[data-testid="job-timestamp"]')).toBeVisible();

    // Check alert notifications panel
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="alert-notification"]')).toContainText('Failure logged and alert generated');

    // Wait for first retry interval and observe first retry
    await page.click('[data-testid="sync-dashboard-link"]');
    await page.waitForTimeout(5000); // Simulated retry interval
    await expect(page.locator('[data-testid="retry-attempt-indicator"]')).toContainText('Retry 1');
    await page.waitForSelector('[data-testid="job-failed-indicator"]', { timeout: 10000 });

    // Wait for second retry interval and observe second retry
    await page.waitForTimeout(5000);
    await expect(page.locator('[data-testid="retry-attempt-indicator"]')).toContainText('Retry 2');
    await page.waitForSelector('[data-testid="job-failed-indicator"]', { timeout: 10000 });

    // Disable failure simulation before third retry
    await page.click('text=Settings');
    await page.click('text=Test Controls');
    const failureToggleOff = page.locator('[data-testid="simulate-job-failure-toggle"]');
    await failureToggleOff.click();
    await expect(failureToggleOff).toHaveAttribute('aria-checked', 'false');

    // Navigate back to dashboard for third retry
    await page.click('[data-testid="sync-dashboard-link"]');
    await page.waitForTimeout(5000);
    await expect(page.locator('[data-testid="retry-attempt-indicator"]')).toContainText('Retry 3');

    // Monitor third retry execution
    await page.waitForSelector('[data-testid="job-completed-indicator"]', { timeout: 15000 });
    await expect(page.locator('[data-testid="job-status-indicator"]')).toContainText('successful');

    // Navigate to detailed job history
    await page.click('text=Logs');
    await page.click('text=Synchronization History');
    const retryJobEntry = page.locator('[data-testid="log-entry"]').first();
    await retryJobEntry.click();

    // Review complete retry sequence
    await expect(page.locator('[data-testid="job-detail-panel"]')).toBeVisible();
    const retryHistory = page.locator('[data-testid="retry-history-section"]');
    await expect(retryHistory).toBeVisible();
    await expect(retryHistory).toContainText('Retry 1: Failed');
    await expect(retryHistory).toContainText('Retry 2: Failed');
    await expect(retryHistory).toContainText('Retry 3: Successful');

    // Verify final job status
    await page.click('[data-testid="back-to-logs-button"]');
    const finalJobStatus = page.locator('[data-testid="log-entry"]').first().locator('[data-testid="job-status"]');
    await expect(finalJobStatus).toContainText('successful');
  });
});