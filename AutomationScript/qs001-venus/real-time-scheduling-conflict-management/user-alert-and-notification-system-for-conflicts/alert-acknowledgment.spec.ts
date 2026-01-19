import { test, expect } from '@playwright/test';

test.describe('Alert Acknowledgment - Story 6', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling interface
    await page.goto('/scheduling');
    // Login as scheduler if needed
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="scheduling-dashboard"]')).toBeVisible();
  });

  test('Validate alert acknowledgment requirement before dismissal (happy-path)', async ({ page }) => {
    // Step 1: Scheduler views the conflict alert displayed on the scheduling interface
    await page.click('[data-testid="trigger-conflict-alert"]');
    const alert = page.locator('[data-testid="conflict-alert"]');
    await expect(alert).toBeVisible();
    await expect(page.locator('[data-testid="acknowledge-button"]')).toBeVisible();
    
    // Step 2: Scheduler attempts to dismiss or close the alert without clicking the acknowledgment button
    await page.click('[data-testid="alert-close-button"]');
    // System blocks dismissal and prompts for acknowledgment
    await expect(alert).toBeVisible();
    await expect(page.locator('[data-testid="acknowledgment-required-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledgment-required-message"]')).toContainText('Please acknowledge this alert before dismissing');
    
    // Step 3: Scheduler clicks the acknowledge button on the alert
    await page.click('[data-testid="acknowledge-button"]');
    // Alert status updates and alert can be dismissed
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    await page.click('[data-testid="alert-close-button"]');
    await expect(alert).not.toBeVisible();
  });

  test('Verify acknowledgment is logged correctly (happy-path)', async ({ page }) => {
    // Step 1: Note the current timestamp and scheduler's user ID, then click the acknowledge button
    const beforeTimestamp = new Date().toISOString();
    const userId = await page.locator('[data-testid="current-user-id"]').textContent();
    
    await page.click('[data-testid="trigger-conflict-alert"]');
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    const alertId = await page.locator('[data-testid="alert-id"]').textContent();
    await page.click('[data-testid="acknowledge-button"]');
    
    // Step 2: Access the acknowledgment logs through the system admin panel
    await page.goto('/admin/acknowledgment-logs');
    await expect(page.locator('[data-testid="acknowledgment-logs-table"]')).toBeVisible();
    
    // Retrieve acknowledgment logs and verify correct entry is present
    const logEntry = page.locator(`[data-testid="log-entry-${alertId}"]`);
    await expect(logEntry).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-user-id"]')).toContainText(userId || '');
    
    const logTimestamp = await logEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    expect(new Date(logTimestamp || '').getTime()).toBeGreaterThanOrEqual(new Date(beforeTimestamp).getTime());
    
    // Step 3: Check audit trail for acknowledgment events
    await page.goto('/admin/audit-trail');
    await page.fill('[data-testid="audit-search-input"]', alertId || '');
    await page.click('[data-testid="audit-search-button"]');
    
    const auditEntry = page.locator(`[data-testid="audit-entry-${alertId}"]`);
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry.locator('[data-testid="audit-event-type"]')).toContainText('Alert Acknowledged');
    await expect(auditEntry.locator('[data-testid="audit-user"]')).toContainText(userId || '');
    await expect(auditEntry.locator('[data-testid="audit-status"]')).toContainText('Complete');
  });

  test('Ensure acknowledgment processing completes within 1 second (boundary)', async ({ page }) => {
    // Step 1: Note the current time and click the acknowledge button
    await page.click('[data-testid="trigger-conflict-alert"]');
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    const startTime = Date.now();
    await page.click('[data-testid="acknowledge-button"]');
    
    // Wait for acknowledgment to complete
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    const endTime = Date.now();
    
    // Acknowledgment processed within 1 second
    const processingTime = endTime - startTime;
    expect(processingTime).toBeLessThanOrEqual(1000);
    
    // Step 2: Monitor and record system response times
    const performanceMetrics = await page.evaluate(() => {
      const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      return {
        responseTime: navigation.responseEnd - navigation.requestStart,
        domContentLoaded: navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart
      };
    });
    
    expect(performanceMetrics.responseTime).toBeLessThanOrEqual(1000);
    
    // Step 3: Review system logs for any errors or warnings
    await page.goto('/admin/system-logs');
    await page.fill('[data-testid="log-level-filter"]', 'ERROR');
    await page.click('[data-testid="apply-filter-button"]');
    
    const errorLogs = page.locator('[data-testid="error-log-entry"]');
    const errorCount = await errorLogs.count();
    
    // Verify no errors occurred during acknowledgment
    if (errorCount > 0) {
      const recentErrors = await errorLogs.first().locator('[data-testid="log-message"]').textContent();
      expect(recentErrors).not.toContain('acknowledgment');
    }
    
    // Verify acknowledgment completed successfully
    await page.fill('[data-testid="log-level-filter"]', 'INFO');
    await page.fill('[data-testid="log-search-input"]', 'acknowledgment');
    await page.click('[data-testid="apply-filter-button"]');
    
    const successLog = page.locator('[data-testid="info-log-entry"]').first();
    await expect(successLog).toContainText('Acknowledgment completed successfully');
  });
});