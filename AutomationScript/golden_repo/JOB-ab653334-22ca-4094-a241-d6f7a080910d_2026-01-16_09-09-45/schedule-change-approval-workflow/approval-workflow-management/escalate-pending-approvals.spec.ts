import { test, expect } from '@playwright/test';

test.describe('Escalate Pending Schedule Change Approvals', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ESCALATION_THRESHOLD_MS = 2 * 60 * 60 * 1000; // 2 hours
  const ESCALATION_PROCESSING_TIME_MS = 60 * 1000; // 1 minute

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate automatic escalation of pending approvals (happy-path)', async ({ page }) => {
    // Step 1: Log in as a regular employee
    await page.fill('[data-testid="username-input"]', 'employee.user');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to Schedule Change Request page
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-request-button"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 3: Create a new schedule change request with valid details
    await page.selectOption('[data-testid="request-type-select"]', 'Shift Swap');
    const nextMonday = new Date();
    nextMonday.setDate(nextMonday.getDate() + ((1 + 7 - nextMonday.getDay()) % 7));
    const formattedDate = nextMonday.toISOString().split('T')[0];
    await page.fill('[data-testid="request-date-input"]', formattedDate);
    await page.fill('[data-testid="request-reason-input"]', 'Personal appointment');
    await page.click('[data-testid="submit-request-button"]');

    // Step 4: Verify the request appears in the system
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request submitted successfully');
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    expect(requestId).toBeTruthy();

    // Step 5: Log out and log in as primary approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="username-input"]', 'primary.approver');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');

    // Step 6: Verify the request appears in the primary approver's pending queue
    await page.click('[data-testid="approvals-menu"]');
    await page.click('[data-testid="pending-approvals-tab"]');
    await expect(page.locator(`[data-testid="request-${requestId}"]`)).toBeVisible();
    const requestStatus = await page.locator(`[data-testid="request-${requestId}-status"]`).textContent();
    expect(requestStatus).toBe('Pending');

    // Step 7: Wait for the configured escalation threshold time (simulated)
    // In real scenario, this would wait 2 hours. For testing, we simulate by updating the request timestamp
    await page.goto(`${BASE_URL}/admin/test-helpers`);
    await page.fill('[data-testid="request-id-input"]', requestId || '');
    await page.click('[data-testid="simulate-threshold-breach-button"]');
    await expect(page.locator('[data-testid="simulation-success"]')).toBeVisible();

    // Step 8: Monitor the system for escalation processing
    await page.waitForTimeout(ESCALATION_PROCESSING_TIME_MS);

    // Step 9: Check the request status after escalation processing
    await page.goto(`${BASE_URL}/approvals/pending`);
    await page.reload();
    const escalatedStatus = await page.locator(`[data-testid="request-${requestId}-status"]`).textContent();
    expect(escalatedStatus).toBe('Escalated');

    // Step 10: Log out and log in as backup approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="username-input"]', 'backup.approver');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');

    // Step 11: Check the notification inbox
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    const escalationNotification = page.locator(`[data-testid="notification-escalation-${requestId}"]`);
    await expect(escalationNotification).toBeVisible();
    await expect(escalationNotification).toContainText('Escalated');

    // Step 12: Verify the escalated request appears in backup approver's pending queue
    await page.click('[data-testid="approvals-menu"]');
    await page.click('[data-testid="pending-approvals-tab"]');
    await expect(page.locator(`[data-testid="request-${requestId}"]`)).toBeVisible();
    const backupQueueStatus = await page.locator(`[data-testid="request-${requestId}-status"]`).textContent();
    expect(backupQueueStatus).toBe('Escalated');
  });

  test('Verify escalation logging and status tracking (happy-path)', async ({ page }) => {
    // Step 1: Log in as admin to access system logs
    await page.fill('[data-testid="username-input"]', 'admin.user');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Create or identify a schedule change request that has exceeded threshold
    await page.goto(`${BASE_URL}/admin/test-helpers`);
    await page.click('[data-testid="create-test-request-button"]');
    await page.selectOption('[data-testid="test-request-type"]', 'Shift Swap');
    await page.click('[data-testid="create-and-escalate-button"]');
    const testRequestId = await page.locator('[data-testid="created-request-id"]').textContent();
    expect(testRequestId).toBeTruthy();

    // Step 3: Allow the escalation service to process and trigger escalation
    await page.click('[data-testid="trigger-escalation-button"]');
    await expect(page.locator('[data-testid="escalation-triggered-message"]')).toBeVisible();
    await page.waitForTimeout(5000); // Wait for escalation processing

    // Step 4: Navigate to System Logs or Escalation Logs section
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="system-logs-submenu"]');
    await page.click('[data-testid="escalation-logs-tab"]');
    await expect(page.locator('[data-testid="escalation-logs-table"]')).toBeVisible();

    // Step 5: Search for the escalation log entry
    await page.fill('[data-testid="log-search-input"]', testRequestId || '');
    await page.click('[data-testid="search-logs-button"]');
    await page.waitForTimeout(2000);

    // Step 6: Verify all required details are captured in the log entry
    const logEntry = page.locator(`[data-testid="log-entry-${testRequestId}"]`);
    await expect(logEntry).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-request-id"]')).toContainText(testRequestId || '');
    await expect(logEntry.locator('[data-testid="log-action"]')).toContainText('Escalated');
    await expect(logEntry.locator('[data-testid="log-user-details"]')).toBeVisible();
    
    const timestamp = await logEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    const userDetails = await logEntry.locator('[data-testid="log-user-details"]').textContent();
    expect(userDetails).toContain('backup.approver');

    // Step 7: Navigate to Escalation Monitoring UI
    await page.click('[data-testid="dashboard-menu"]');
    await page.click('[data-testid="escalation-monitoring-link"]');
    await expect(page.locator('[data-testid="escalation-monitoring-dashboard"]')).toBeVisible();

    // Step 8: Locate the escalated request in the monitoring interface
    await page.fill('[data-testid="monitoring-search-input"]', testRequestId || '');
    await page.click('[data-testid="monitoring-search-button"]');
    const monitoringEntry = page.locator(`[data-testid="monitoring-request-${testRequestId}"]`);
    await expect(monitoringEntry).toBeVisible();

    // Step 9: Click on the escalated request to view detailed status
    await monitoringEntry.click();
    await expect(page.locator('[data-testid="escalation-details-panel"]')).toBeVisible();

    // Step 10: Verify the escalation status accuracy
    const detailsStatus = await page.locator('[data-testid="details-status"]').textContent();
    expect(detailsStatus).toBe('Escalated');
    const detailsTimestamp = await page.locator('[data-testid="details-escalation-timestamp"]').textContent();
    expect(detailsTimestamp).toBeTruthy();
    const detailsBackupApprover = await page.locator('[data-testid="details-backup-approver"]').textContent();
    expect(detailsBackupApprover).toContain('backup.approver');
    
    // Compare with system logs
    expect(detailsTimestamp).toBe(timestamp);
  });

  test('Ensure escalation processing meets performance requirements (boundary)', async ({ page }) => {
    // Step 1: Log in as admin to create multiple test requests
    await page.fill('[data-testid="username-input"]', 'admin.user');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to test helpers
    await page.goto(`${BASE_URL}/admin/test-helpers`);
    await expect(page.locator('[data-testid="bulk-operations-section"]')).toBeVisible();

    // Step 3: Create 10 schedule change requests simultaneously
    const requestIds: string[] = [];
    const submissionTimestamps: Date[] = [];
    
    await page.fill('[data-testid="bulk-request-count"]', '10');
    await page.selectOption('[data-testid="bulk-request-type"]', 'Shift Swap');
    
    // Record exact timestamp when requests are submitted
    const bulkSubmissionTime = new Date();
    await page.click('[data-testid="create-bulk-requests-button"]');
    await expect(page.locator('[data-testid="bulk-creation-success"]')).toBeVisible();
    
    // Step 4: Retrieve all created request IDs
    const requestIdElements = await page.locator('[data-testid^="bulk-request-id-"]').all();
    for (const element of requestIdElements) {
      const id = await element.textContent();
      if (id) {
        requestIds.push(id);
        submissionTimestamps.push(bulkSubmissionTime);
      }
    }
    expect(requestIds.length).toBe(10);

    // Step 5: Simulate threshold breach for all requests
    await page.click('[data-testid="bulk-simulate-threshold-button"]');
    await expect(page.locator('[data-testid="bulk-threshold-simulation-success"]')).toBeVisible();
    
    const thresholdBreachTime = new Date();

    // Step 6: Monitor the escalation service processing
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="system-monitoring-submenu"]');
    await expect(page.locator('[data-testid="escalation-service-monitor"]')).toBeVisible();
    
    // Wait for escalation processing to complete
    await page.waitForTimeout(ESCALATION_PROCESSING_TIME_MS + 10000);

    // Step 7: Measure the time taken from threshold breach to escalation completion
    const escalationCompletionTimes: number[] = [];
    
    for (const requestId of requestIds) {
      await page.goto(`${BASE_URL}/admin/escalation-logs`);
      await page.fill('[data-testid="log-search-input"]', requestId);
      await page.click('[data-testid="search-logs-button"]');
      await page.waitForTimeout(1000);
      
      const logEntry = page.locator(`[data-testid="log-entry-${requestId}"]`);
      await expect(logEntry).toBeVisible();
      
      const escalationTimestampText = await logEntry.locator('[data-testid="log-timestamp"]').textContent();
      const escalationTimestamp = new Date(escalationTimestampText || '');
      const processingTime = escalationTimestamp.getTime() - thresholdBreachTime.getTime();
      escalationCompletionTimes.push(processingTime);
    }

    // Step 8: Verify escalation status updates in the database for all 10 requests
    await page.goto(`${BASE_URL}/admin/escalation-monitoring`);
    
    for (const requestId of requestIds) {
      await page.fill('[data-testid="monitoring-search-input"]', requestId);
      await page.click('[data-testid="monitoring-search-button"]');
      await page.waitForTimeout(500);
      
      const statusElement = page.locator(`[data-testid="monitoring-request-${requestId}-status"]`);
      await expect(statusElement).toBeVisible();
      const status = await statusElement.textContent();
      expect(status).toBe('Escalated');
    }

    // Step 9: Check notification delivery logs
    await page.goto(`${BASE_URL}/admin/notification-logs`);
    await page.selectOption('[data-testid="notification-type-filter"]', 'Escalation');
    await page.click('[data-testid="apply-filter-button"]');
    
    const notificationDeliveryTimes: Date[] = [];
    
    for (const requestId of requestIds) {
      await page.fill('[data-testid="notification-search-input"]', requestId);
      await page.click('[data-testid="search-notifications-button"]');
      await page.waitForTimeout(500);
      
      const notificationEntry = page.locator(`[data-testid="notification-${requestId}"]`);
      await expect(notificationEntry).toBeVisible();
      
      const deliveryStatus = await notificationEntry.locator('[data-testid="delivery-status"]').textContent();
      expect(deliveryStatus).toBe('Delivered');
      
      const deliveryTimeText = await notificationEntry.locator('[data-testid="delivery-timestamp"]').textContent();
      notificationDeliveryTimes.push(new Date(deliveryTimeText || ''));
    }

    // Step 10: Log in as backup approvers and verify notification receipt
    const backupApprovers = ['backup.approver1', 'backup.approver2', 'backup.approver3', 
                             'backup.approver4', 'backup.approver5', 'backup.approver6',
                             'backup.approver7', 'backup.approver8', 'backup.approver9', 'backup.approver10'];
    
    for (let i = 0; i < requestIds.length; i++) {
      await page.click('[data-testid="user-menu"]');
      await page.click('[data-testid="logout-button"]');
      
      await page.fill('[data-testid="username-input"]', backupApprovers[i]);
      await page.fill('[data-testid="password-input"]', 'Password123!');
      await page.click('[data-testid="login-button"]');
      
      await page.click('[data-testid="notifications-icon"]');
      const notification = page.locator(`[data-testid="notification-escalation-${requestIds[i]}"]`);
      await expect(notification).toBeVisible();
    }

    // Step 11: Verify system performance metrics
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="username-input"]', 'admin.user');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    
    await page.goto(`${BASE_URL}/admin/system-monitoring`);
    await page.click('[data-testid="performance-metrics-tab"]');
    
    const cpuUsage = await page.locator('[data-testid="cpu-usage-metric"]').textContent();
    const memoryUsage = await page.locator('[data-testid="memory-usage-metric"]').textContent();
    const responseTime = await page.locator('[data-testid="response-time-metric"]').textContent();
    
    expect(parseFloat(cpuUsage || '0')).toBeLessThan(80);
    expect(parseFloat(memoryUsage || '0')).toBeLessThan(85);
    expect(parseFloat(responseTime || '0')).toBeLessThan(5000);

    // Step 12: Review escalation logs to confirm all processing times meet 1-minute requirement
    for (let i = 0; i < escalationCompletionTimes.length; i++) {
      const processingTimeSeconds = escalationCompletionTimes[i] / 1000;
      expect(processingTimeSeconds).toBeLessThanOrEqual(60);
    }
    
    // Verify all notifications were delivered within SLA
    for (let i = 0; i < notificationDeliveryTimes.length; i++) {
      const deliveryDelay = notificationDeliveryTimes[i].getTime() - thresholdBreachTime.getTime();
      const deliveryDelaySeconds = deliveryDelay / 1000;
      expect(deliveryDelaySeconds).toBeLessThanOrEqual(120); // 2 minutes SLA
    }
  });
});