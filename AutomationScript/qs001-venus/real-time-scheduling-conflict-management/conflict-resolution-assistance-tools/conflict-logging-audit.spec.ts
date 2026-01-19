import { test, expect } from '@playwright/test';

test.describe('Conflict Logging and Audit System', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_URL = process.env.API_URL || 'http://localhost:3000/api';
  let authToken: string;
  let conflictId: string;

  test.beforeEach(async ({ page }) => {
    // Login as scheduler to obtain auth token
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'scheduler@test.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(`${BASE_URL}/dashboard`);
    
    // Extract auth token from localStorage or cookies
    authToken = await page.evaluate(() => localStorage.getItem('authToken') || '');
  });

  test('Validate logging of detected conflicts - happy path', async ({ page, request }) => {
    // Step 1: Create a scheduling conflict by assigning the same resource to two overlapping time slots
    await page.goto(`${BASE_URL}/scheduling`);
    
    // Create first schedule
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource-A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T09:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:00');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Create second schedule with same resource and overlapping time
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource-A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T12:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify conflict event is logged with correct details and timestamp
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    const conflictMessage = await page.locator('[data-testid="conflict-message"]').textContent();
    expect(conflictMessage).toContain('Resource-A');
    expect(conflictMessage).toContain('overlapping');
    
    // Step 2: Retrieve conflict logs via API
    const logsResponse = await request.get(`${API_URL}/conflicts/logs`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    expect(logsResponse.ok()).toBeTruthy();
    const logsData = await logsResponse.json();
    
    // Verify logged conflict is returned with accurate information
    expect(logsData.logs).toBeDefined();
    expect(logsData.logs.length).toBeGreaterThan(0);
    
    const recentConflict = logsData.logs[0];
    expect(recentConflict.timestamp).toBeDefined();
    expect(recentConflict.conflictType).toBe('resource_overlap');
    expect(recentConflict.affectedResources).toContain('Resource-A');
    expect(recentConflict.details).toBeDefined();
    
    conflictId = recentConflict.id;
    
    // Step 3: Verify logs are accessible only to authorized users
    // Attempt to access conflict logs API endpoint using credentials without proper authorization
    await page.goto(`${BASE_URL}/logout`);
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'viewer@test.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(`${BASE_URL}/dashboard`);
    
    const unauthorizedToken = await page.evaluate(() => localStorage.getItem('authToken') || '');
    
    const unauthorizedResponse = await request.get(`${API_URL}/conflicts/logs`, {
      headers: {
        'Authorization': `Bearer ${unauthorizedToken}`
      }
    });
    
    // Verify access control enforced and unauthorized access denied
    expect(unauthorizedResponse.status()).toBe(403);
    
    // Attempt to access conflict logs API endpoint without authentication token
    const noAuthResponse = await request.get(`${API_URL}/conflicts/logs`);
    expect(noAuthResponse.status()).toBe(401);
  });

  test('Verify logging of conflict resolution actions - happy path', async ({ page, request }) => {
    // Step 1: Navigate to the conflict management interface and locate an existing scheduling conflict
    await page.goto(`${BASE_URL}/conflicts`);
    await page.waitForSelector('[data-testid="conflict-list"]');
    
    const conflictItem = page.locator('[data-testid="conflict-item"]').first();
    await expect(conflictItem).toBeVisible();
    
    const conflictIdText = await conflictItem.getAttribute('data-conflict-id');
    
    // Click the 'Acknowledge' button for the displayed conflict
    await conflictItem.locator('[data-testid="acknowledge-button"]').click();
    await expect(page.locator('[data-testid="acknowledgment-success"]')).toBeVisible();
    
    // Select a resolution action and apply the resolution
    await conflictItem.locator('[data-testid="resolve-button"]').click();
    await page.waitForSelector('[data-testid="resolution-modal"]');
    
    await page.selectOption('[data-testid="resolution-action-select"]', 'reassign_resource');
    await page.fill('[data-testid="new-resource-input"]', 'Resource-B');
    await page.click('[data-testid="apply-resolution-button"]');
    
    // Verify the resolution action is logged
    await expect(page.locator('[data-testid="resolution-success-message"]')).toBeVisible();
    
    // Step 2: Query logs for resolution entries
    const resolutionLogsResponse = await request.get(`${API_URL}/conflicts/logs?type=resolution`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    expect(resolutionLogsResponse.ok()).toBeTruthy();
    const resolutionData = await resolutionLogsResponse.json();
    
    // Verify the returned resolution log entries contain accurate data
    expect(resolutionData.logs).toBeDefined();
    const recentResolution = resolutionData.logs.find((log: any) => log.conflictId === conflictIdText);
    
    expect(recentResolution).toBeDefined();
    expect(recentResolution.userId).toBeDefined();
    expect(recentResolution.timestamp).toBeDefined();
    expect(recentResolution.actionType).toBe('reassign_resource');
    expect(recentResolution.resolutionDetails).toBeDefined();
    
    // Step 3: Export conflict logs
    await page.goto(`${BASE_URL}/conflicts/logs`);
    await page.waitForSelector('[data-testid="export-logs-button"]');
    
    // Select export format
    await page.selectOption('[data-testid="export-format-select"]', 'csv');
    
    // Click 'Export' button to generate conflict logs export file
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-logs-button"]');
    const download = await downloadPromise;
    
    // Verify exported file contains complete conflict and resolution data
    expect(download.suggestedFilename()).toContain('conflict_logs');
    expect(download.suggestedFilename()).toContain('.csv');
    
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('Ensure logging does not degrade system performance - edge case', async ({ page, request }) => {
    // Step 1: Record baseline system performance metrics
    const baselineStart = Date.now();
    
    await page.goto(`${BASE_URL}/scheduling`);
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource-Baseline');
    await page.fill('[data-testid="start-time-input"]', '2024-01-20T09:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-20T10:00');
    await page.click('[data-testid="save-schedule-button"]');
    await page.waitForSelector('[data-testid="success-message"]');
    
    const baselineResponseTime = Date.now() - baselineStart;
    
    // Step 2: Execute automated script to simulate high volume of conflict detections
    const conflictPromises = [];
    const highVolumeStart = Date.now();
    
    for (let i = 0; i < 100; i++) {
      const conflictPromise = request.post(`${API_URL}/schedules`, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        },
        data: {
          resourceId: 'Resource-HighVolume',
          startTime: '2024-01-25T09:00:00',
          endTime: '2024-01-25T11:00:00',
          description: `High volume test ${i}`
        }
      });
      conflictPromises.push(conflictPromise);
    }
    
    // Monitor system response time during high volume conflict detection
    const responses = await Promise.all(conflictPromises);
    const highVolumeResponseTime = Date.now() - highVolumeStart;
    
    // Verify system performance remains within SLA thresholds (3 seconds per acceptance criteria)
    expect(highVolumeResponseTime).toBeLessThan(180000); // 3 seconds * 100 requests with some buffer
    
    // Step 3: Verify all conflict events are logged correctly
    await page.waitForTimeout(2000); // Allow time for async logging
    
    const logsResponse = await request.get(`${API_URL}/conflicts/logs?limit=150`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    expect(logsResponse.ok()).toBeTruthy();
    const logsData = await logsResponse.json();
    
    // Verify logging operations do not cause bottlenecks
    const highVolumeConflicts = logsData.logs.filter((log: any) => 
      log.affectedResources?.includes('Resource-HighVolume')
    );
    
    expect(highVolumeConflicts.length).toBeGreaterThanOrEqual(90); // Allow for some async processing
    
    // Step 4: Execute standard scheduling operations during ongoing logging activity
    const schedulingStart = Date.now();
    
    await page.goto(`${BASE_URL}/scheduling`);
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource-Performance-Test');
    await page.fill('[data-testid="start-time-input"]', '2024-01-26T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-26T15:00');
    await page.click('[data-testid="save-schedule-button"]');
    await page.waitForSelector('[data-testid="success-message"]');
    
    const schedulingResponseTime = Date.now() - schedulingStart;
    
    // Measure scheduling operation completion time and compare against baseline
    const performanceDegradation = (schedulingResponseTime - baselineResponseTime) / baselineResponseTime;
    
    // Verify no errors or delays due to logging (allow max 50% degradation)
    expect(performanceDegradation).toBeLessThan(0.5);
    
    // Review system error logs
    const errorLogsResponse = await request.get(`${API_URL}/system/logs?level=error&component=logging`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    if (errorLogsResponse.ok()) {
      const errorLogs = await errorLogsResponse.json();
      const recentErrors = errorLogs.logs?.filter((log: any) => {
        const logTime = new Date(log.timestamp).getTime();
        return logTime > highVolumeStart;
      });
      
      // Verify no logging-related errors occurred
      expect(recentErrors?.length || 0).toBe(0);
    }
  });
});