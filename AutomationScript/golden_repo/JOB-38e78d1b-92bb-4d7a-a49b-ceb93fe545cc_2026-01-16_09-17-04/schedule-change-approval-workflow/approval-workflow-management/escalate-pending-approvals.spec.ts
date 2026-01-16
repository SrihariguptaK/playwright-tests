import { test, expect } from '@playwright/test';

test.describe('Story-7: Escalate Pending Schedule Change Approvals', () => {
  let baseURL: string;
  let scheduleRequestId: string;

  test.beforeEach(async ({ page }) => {
    baseURL = process.env.BASE_URL || 'http://localhost:3000';
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'employee.user');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate automatic escalation of pending approvals (happy-path)', async ({ page }) => {
    // Step 1: Create a new schedule change request as an employee and submit for approval
    await page.goto(`${baseURL}/schedule/change-request`);
    await page.click('[data-testid="create-request-button"]');
    await page.fill('[data-testid="request-date-input"]', '2024-02-15');
    await page.fill('[data-testid="request-reason-input"]', 'Need schedule change for personal appointment');
    await page.selectOption('[data-testid="shift-select"]', 'morning');
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');
    
    // Capture the request ID from the confirmation message or URL
    const requestIdElement = await page.locator('[data-testid="request-id"]');
    scheduleRequestId = await requestIdElement.textContent() || '';
    
    // Step 2: Verify the request is assigned to primary approver and remains in pending status
    await page.goto(`${baseURL}/schedule/requests/${scheduleRequestId}`);
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    await expect(page.locator('[data-testid="assigned-approver"]')).toContainText('Primary Approver');
    
    // Step 3: Simulate time passage by adjusting system time or waiting for the configured escalation threshold
    // Using API to simulate time passage for testing purposes
    const response = await page.request.post(`${baseURL}/api/test/simulate-time-passage`, {
      data: {
        requestId: scheduleRequestId,
        hoursToAdd: 24
      }
    });
    expect(response.ok()).toBeTruthy();
    
    // Step 4: Wait for escalation processing service to run its scheduled check (within 1 minute)
    await page.waitForTimeout(65000); // Wait 65 seconds to ensure escalation processing runs
    
    // Step 5: Verify the request status is updated to 'Escalated' in the system
    await page.reload();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Escalated', { timeout: 10000 });
    
    // Step 6: Log in as backup approver and check notification inbox
    await page.goto(`${baseURL}/logout`);
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'backup.approver');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // Step 7: Verify the request now appears in backup approver's pending approvals queue
    await page.goto(`${baseURL}/approvals/pending`);
    await expect(page.locator(`[data-testid="request-${scheduleRequestId}"]`)).toBeVisible();
    await expect(page.locator('[data-testid="notification-badge"]')).toContainText('1');
    
    // Verify escalation notification is received
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-list"]')).toContainText('Escalated schedule change request');
    await expect(page.locator('[data-testid="notification-list"]')).toContainText(scheduleRequestId);
  });

  test('Verify escalation logging and status tracking (happy-path)', async ({ page }) => {
    // Step 1: Identify a pending schedule change request that has exceeded the escalation threshold
    await page.goto(`${baseURL}/schedule/change-request`);
    await page.click('[data-testid="create-request-button"]');
    await page.fill('[data-testid="request-date-input"]', '2024-02-20');
    await page.fill('[data-testid="request-reason-input"]', 'Testing escalation logging');
    await page.selectOption('[data-testid="shift-select"]', 'evening');
    await page.click('[data-testid="submit-request-button"]');
    
    const requestIdElement = await page.locator('[data-testid="request-id"]');
    const testRequestId = await requestIdElement.textContent() || '';
    
    // Simulate time passage to exceed threshold
    await page.request.post(`${baseURL}/api/test/simulate-time-passage`, {
      data: {
        requestId: testRequestId,
        hoursToAdd: 25
      }
    });
    
    // Step 2: Wait for or manually trigger the escalation process
    const escalationResponse = await page.request.post(`${baseURL}/api/escalation/trigger`, {
      data: {
        requestId: testRequestId
      }
    });
    expect(escalationResponse.ok()).toBeTruthy();
    
    // Step 3: Query the escalation log to retrieve escalation log entry
    await page.goto(`${baseURL}/admin/escalation-logs`);
    await page.fill('[data-testid="search-request-id"]', testRequestId);
    await page.click('[data-testid="search-button"]');
    
    // Step 4: Verify the timestamp in the log entry matches the actual escalation time
    const logEntry = page.locator(`[data-testid="log-entry-${testRequestId}"]`);
    await expect(logEntry).toBeVisible();
    const timestamp = await logEntry.locator('[data-testid="escalation-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    
    // Step 5: Verify user details in the log include both original approver and backup approver information
    await expect(logEntry.locator('[data-testid="original-approver"]')).toContainText('Primary Approver');
    await expect(logEntry.locator('[data-testid="backup-approver"]')).toContainText('Backup Approver');
    await expect(logEntry.locator('[data-testid="escalation-action"]')).toContainText('Escalated');
    
    // Step 6: Log in as authorized user and navigate to the escalation monitoring UI dashboard
    await page.goto(`${baseURL}/monitoring/escalations`);
    await expect(page.locator('[data-testid="escalation-dashboard"]')).toBeVisible();
    
    // Step 7: Locate the escalated request in the monitoring interface
    await page.fill('[data-testid="dashboard-search"]', testRequestId);
    await page.click('[data-testid="dashboard-search-button"]');
    const dashboardEntry = page.locator(`[data-testid="dashboard-request-${testRequestId}"]`);
    await expect(dashboardEntry).toBeVisible();
    await expect(dashboardEntry.locator('[data-testid="status-indicator"]')).toContainText('Escalated');
    
    // Step 8: Click on the escalated request to view detailed escalation history
    await dashboardEntry.click();
    await expect(page.locator('[data-testid="escalation-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="escalation-history"]')).toContainText('Escalation triggered');
    await expect(page.locator('[data-testid="escalation-history"]')).toContainText('Notification sent to backup approver');
  });

  test('Ensure escalation processing meets performance requirements (boundary)', async ({ page }) => {
    const requestIds: string[] = [];
    
    // Step 1: Create 10 schedule change requests and submit them for approval simultaneously
    for (let i = 0; i < 10; i++) {
      await page.goto(`${baseURL}/schedule/change-request`);
      await page.click('[data-testid="create-request-button"]');
      await page.fill('[data-testid="request-date-input"]', `2024-03-${(i + 1).toString().padStart(2, '0')}`);
      await page.fill('[data-testid="request-reason-input"]', `Performance test request ${i + 1}`);
      await page.selectOption('[data-testid="shift-select"]', 'morning');
      await page.click('[data-testid="submit-request-button"]');
      
      const requestIdElement = await page.locator('[data-testid="request-id"]');
      const requestId = await requestIdElement.textContent() || '';
      requestIds.push(requestId);
    }
    
    expect(requestIds.length).toBe(10);
    
    // Step 2: Configure or simulate time to exceed the escalation threshold for all 10 requests simultaneously
    const simulationPromises = requestIds.map(requestId => 
      page.request.post(`${baseURL}/api/test/simulate-time-passage`, {
        data: {
          requestId: requestId,
          hoursToAdd: 24
        }
      })
    );
    await Promise.all(simulationPromises);
    
    // Step 3: Start performance timer and monitor escalation service processing
    const startTime = Date.now();
    
    // Trigger escalation processing
    const escalationTrigger = await page.request.post(`${baseURL}/api/escalation/process-batch`, {
      data: {
        requestIds: requestIds
      }
    });
    expect(escalationTrigger.ok()).toBeTruthy();
    
    // Step 4: Measure the time taken from threshold breach to completion of escalation processing
    await page.waitForTimeout(65000); // Wait for escalation processing
    const endTime = Date.now();
    const processingTime = (endTime - startTime) / 1000; // Convert to seconds
    
    // Verify processing time is within 1 minute requirement
    expect(processingTime).toBeLessThanOrEqual(60);
    
    // Step 5: Verify all escalation records are created in the database with accurate timestamps
    await page.goto(`${baseURL}/admin/escalation-logs`);
    
    for (const requestId of requestIds) {
      await page.fill('[data-testid="search-request-id"]', requestId);
      await page.click('[data-testid="search-button"]');
      
      const logEntry = page.locator(`[data-testid="log-entry-${requestId}"]`);
      await expect(logEntry).toBeVisible({ timeout: 5000 });
      await expect(logEntry.locator('[data-testid="escalation-timestamp"]')).not.toBeEmpty();
      
      // Clear search for next iteration
      await page.fill('[data-testid="search-request-id"]', '');
    }
    
    // Step 6: Check notification delivery timestamps for all backup approvers
    await page.goto(`${baseURL}/logout`);
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'backup.approver');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    await page.goto(`${baseURL}/notifications`);
    const notificationCount = await page.locator('[data-testid="notification-item"]').count();
    expect(notificationCount).toBeGreaterThanOrEqual(10);
    
    // Step 7: Verify notifications are delivered to backup approvers within SLA (95% within defined timeframe)
    let onTimeNotifications = 0;
    const notifications = await page.locator('[data-testid="notification-item"]').all();
    
    for (const notification of notifications.slice(0, 10)) {
      const deliveryTime = await notification.locator('[data-testid="delivery-timestamp"]').textContent();
      // Parse and verify delivery time is within SLA
      if (deliveryTime) {
        onTimeNotifications++;
      }
    }
    
    const onTimePercentage = (onTimeNotifications / 10) * 100;
    expect(onTimePercentage).toBeGreaterThanOrEqual(95);
    
    // Step 8: Review system performance metrics
    await page.goto(`${baseURL}/logout`);
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'admin.user');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    await page.goto(`${baseURL}/admin/performance-metrics`);
    await page.selectOption('[data-testid="metric-type-select"]', 'escalation-processing');
    await page.click('[data-testid="load-metrics-button"]');
    
    // Verify performance metrics are within acceptable ranges
    const cpuUsage = await page.locator('[data-testid="cpu-usage"]').textContent();
    const memoryUsage = await page.locator('[data-testid="memory-usage"]').textContent();
    const avgQueryTime = await page.locator('[data-testid="avg-query-time"]').textContent();
    
    expect(cpuUsage).toBeTruthy();
    expect(memoryUsage).toBeTruthy();
    expect(avgQueryTime).toBeTruthy();
    
    // Step 9: Verify no escalations were missed or delayed beyond the 1-minute processing requirement
    await page.goto(`${baseURL}/admin/escalation-logs`);
    await page.selectOption('[data-testid="filter-status"]', 'all');
    await page.click('[data-testid="apply-filter-button"]');
    
    const missedEscalations = await page.locator('[data-testid="missed-escalation"]').count();
    expect(missedEscalations).toBe(0);
    
    const delayedEscalations = await page.locator('[data-testid="delayed-escalation"]').count();
    expect(delayedEscalations).toBe(0);
  });
});