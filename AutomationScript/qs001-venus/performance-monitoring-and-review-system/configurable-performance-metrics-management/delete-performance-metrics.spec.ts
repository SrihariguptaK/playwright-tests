import { test, expect } from '@playwright/test';

test.describe('Delete Performance Metrics', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to Metrics Management page before each test
    await page.goto('/metrics-management');
    await expect(page).toHaveURL(/.*metrics-management/);
  });

  test('Validate successful metric deletion with confirmation', async ({ page }) => {
    // Step 1: Navigate to Metrics Management page
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="metric-item"]').first()).toBeVisible();

    // Step 2: Select a metric not linked to active review cycles and initiate deletion
    const metricNotLinked = page.locator('[data-testid="metric-item"]').filter({ hasText: 'Not Linked' }).first();
    const metricName = await metricNotLinked.locator('[data-testid="metric-name"]').textContent();
    await metricNotLinked.locator('[data-testid="delete-metric-button"]').click();

    // Verify confirmation prompt is displayed
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Are you sure you want to delete this metric?');

    // Step 3: Confirm deletion
    const startTime = Date.now();
    await page.locator('[data-testid="confirm-delete-button"]').click();

    // Verify metric is deleted
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Metric deleted successfully');

    // Verify deletion response time is under 2 seconds
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    expect(responseTime).toBeLessThan(2000);

    // Verify list is refreshed and metric is removed
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="metric-item"]').filter({ hasText: metricName || '' })).toHaveCount(0);

    // Verify deletion was logged in audit logs
    await page.goto('/audit-logs');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Metric deleted');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText(metricName || '');
    await expect(page.locator('[data-testid="audit-log-timestamp"]').first()).toBeVisible();
  });

  test('Prevent deletion of metrics linked to active review cycles', async ({ page }) => {
    // Step 1: Select a metric linked to an active review cycle
    const linkedMetric = page.locator('[data-testid="metric-item"]').filter({ hasText: 'Active Review' }).first();
    const linkedMetricName = await linkedMetric.locator('[data-testid="metric-name"]').textContent();
    
    // Verify delete option is available
    await expect(linkedMetric.locator('[data-testid="delete-metric-button"]')).toBeVisible();
    await expect(linkedMetric.locator('[data-testid="delete-metric-button"]')).toBeEnabled();

    // Step 2: Attempt to delete metric
    await linkedMetric.locator('[data-testid="delete-metric-button"]').click();

    // Verify confirmation dialog appears
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toBeVisible();
    
    // Confirm deletion attempt
    await page.locator('[data-testid="confirm-delete-button"]').click();

    // System rejects deletion and displays error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot delete metric linked to active review cycles');

    // Verify the metric still exists in the metrics list
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="metric-item"]').filter({ hasText: linkedMetricName || '' })).toHaveCount(1);

    // Check audit logs for the attempted deletion
    await page.goto('/audit-logs');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Deletion attempt failed');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText(linkedMetricName || '');
  });

  test('Validate successful metric deletion with confirmation - comprehensive flow', async ({ page }) => {
    // Navigate to Metrics Management page
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();

    // Locate a metric that is not linked to any active review cycles
    const unlinkedMetric = page.locator('[data-testid="metric-item"]').filter({ has: page.locator('[data-testid="metric-status"][data-status="unlinked"]') }).first();
    const metricName = await unlinkedMetric.locator('[data-testid="metric-name"]').textContent();
    
    // Click the delete button/icon for that metric
    await unlinkedMetric.locator('[data-testid="delete-metric-button"]').click();

    // Verify confirmation prompt appears
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toBeVisible();
    
    // Click the Confirm button in the deletion confirmation prompt
    const deletionStartTime = Date.now();
    await page.locator('[data-testid="confirm-delete-button"]').click();
    
    // Verify success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Verify the deletion response time
    const deletionEndTime = Date.now();
    expect(deletionEndTime - deletionStartTime).toBeLessThan(2000);

    // Verify the deletion was logged by checking the audit logs
    await page.goto('/audit-logs');
    const latestLog = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(latestLog).toContainText('deleted');
    await expect(latestLog).toContainText(metricName || '');
    await expect(latestLog.locator('[data-testid="audit-log-user"]')).toBeVisible();
    await expect(latestLog.locator('[data-testid="audit-log-timestamp"]')).toBeVisible();
  });

  test('Prevent deletion of metrics linked to active review cycles - comprehensive flow', async ({ page }) => {
    // Navigate to Metrics Management page
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();

    // Identify and select a metric that is linked to an active review cycle
    const linkedMetric = page.locator('[data-testid="metric-item"]').filter({ has: page.locator('[data-testid="metric-status"][data-status="linked"]') }).first();
    const linkedMetricName = await linkedMetric.locator('[data-testid="metric-name"]').textContent();
    
    // Click the delete button for the selected metric
    await linkedMetric.locator('[data-testid="delete-metric-button"]').click();

    // Verify confirmation dialog
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toBeVisible();
    
    // Click the Confirm button to attempt deletion
    await page.locator('[data-testid="confirm-delete-button"]').click();

    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot delete');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('active review cycle');

    // Verify the metric still exists in the metrics list
    await page.goto('/metrics-management');
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();
    const metricStillExists = page.locator('[data-testid="metric-item"]').filter({ hasText: linkedMetricName || '' });
    await expect(metricStillExists).toHaveCount(1);

    // Check audit logs for the attempted deletion
    await page.goto('/audit-logs');
    const attemptLog = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: linkedMetricName || '' }).first();
    await expect(attemptLog).toContainText('attempt');
    await expect(attemptLog).toContainText('failed');
  });
});