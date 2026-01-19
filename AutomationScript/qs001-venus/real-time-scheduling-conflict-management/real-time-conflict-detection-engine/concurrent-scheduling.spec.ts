import { test, expect } from '@playwright/test';
import { chromium, Browser, Page, BrowserContext } from '@playwright/test';

test.describe('Concurrent Scheduling - Data Integrity and Conflict Management', () => {
  let apiBaseUrl: string;

  test.beforeEach(async ({ page }) => {
    apiBaseUrl = process.env.API_BASE_URL || 'http://localhost:3000';
  });

  test('Verify no data loss under concurrent scheduling inputs', async ({ browser }) => {
    const concurrentUsers = 100;
    const contexts: BrowserContext[] = [];
    const pages: Page[] = [];
    const scheduleData: any[] = [];

    // Prepare unique scheduling data for each of the 100 concurrent users
    for (let i = 0; i < concurrentUsers; i++) {
      scheduleData.push({
        id: `schedule-${i}`,
        resource: `Resource-${i % 20}`,
        date: `2024-01-${15 + (i % 10)}`,
        startTime: `${9 + (i % 8)}:00`,
        endTime: `${10 + (i % 8)}:00`,
        userId: `user-${i}`
      });
    }

    try {
      // Create 100 concurrent browser contexts and pages
      for (let i = 0; i < concurrentUsers; i++) {
        const context = await browser.newContext();
        const page = await context.newPage();
        contexts.push(context);
        pages.push(page);
      }

      // Execute concurrent submission of all 100 schedules simultaneously
      const submissionPromises = pages.map(async (page, index) => {
        await page.goto(`${apiBaseUrl}/schedule`);
        await page.waitForLoadState('networkidle');
        
        // Fill in schedule form
        await page.fill('[data-testid="resource-input"]', scheduleData[index].resource);
        await page.fill('[data-testid="date-input"]', scheduleData[index].date);
        await page.fill('[data-testid="start-time-input"]', scheduleData[index].startTime);
        await page.fill('[data-testid="end-time-input"]', scheduleData[index].endTime);
        
        // Submit schedule
        const responsePromise = page.waitForResponse(response => 
          response.url().includes('/api/schedule/save') && response.status() === 200
        );
        await page.click('[data-testid="submit-schedule-btn"]');
        const response = await responsePromise;
        
        return {
          status: response.status(),
          data: await response.json()
        };
      });

      // Wait for all submissions to complete
      const results = await Promise.all(submissionPromises);
      
      // Action: Simulate 100 concurrent users submitting schedules
      // Expected Result: All schedules saved without data loss
      const successfulSubmissions = results.filter(r => r.status === 200);
      expect(successfulSubmissions.length).toBe(concurrentUsers);

      // Action: Check database consistency
      // Expected Result: No corrupted or missing records
      const verificationPage = pages[0];
      await verificationPage.goto(`${apiBaseUrl}/schedule/verify`);
      const dbRecordCount = await verificationPage.locator('[data-testid="total-records"]').textContent();
      expect(parseInt(dbRecordCount || '0')).toBe(concurrentUsers);

      // Verify no duplicate entries
      const duplicateCheck = await verificationPage.locator('[data-testid="duplicate-records"]').textContent();
      expect(parseInt(duplicateCheck || '0')).toBe(0);

      // Action: Verify conflict detection accuracy
      // Expected Result: All conflicts detected correctly
      await verificationPage.goto(`${apiBaseUrl}/schedule/conflicts`);
      const conflictAccuracy = await verificationPage.locator('[data-testid="conflict-accuracy"]').textContent();
      expect(conflictAccuracy).toBe('100%');

    } finally {
      // Cleanup: Close all contexts
      for (const context of contexts) {
        await context.close();
      }
    }
  });

  test('Ensure user feedback on concurrent conflicts', async ({ browser }) => {
    // Create two concurrent user sessions
    const context1 = await browser.newContext();
    const context2 = await browser.newContext();
    const user1Page = await context1.newPage();
    const user2Page = await context2.newPage();

    try {
      // User 1 begins creating a schedule for Conference Room A
      await user1Page.goto(`${apiBaseUrl}/schedule`);
      await user1Page.waitForLoadState('networkidle');
      await user1Page.fill('[data-testid="resource-input"]', 'Conference Room A');
      await user1Page.fill('[data-testid="date-input"]', '2024-01-15');
      await user1Page.fill('[data-testid="start-time-input"]', '10:00');
      await user1Page.fill('[data-testid="end-time-input"]', '11:00');

      // User 2 simultaneously begins creating an overlapping schedule
      await user2Page.goto(`${apiBaseUrl}/schedule`);
      await user2Page.waitForLoadState('networkidle');
      await user2Page.fill('[data-testid="resource-input"]', 'Conference Room A');
      await user2Page.fill('[data-testid="date-input"]', '2024-01-15');
      await user2Page.fill('[data-testid="start-time-input"]', '10:30');
      await user2Page.fill('[data-testid="end-time-input"]', '11:30');

      // User 1 submits the schedule first
      const user1ResponsePromise = user1Page.waitForResponse(response => 
        response.url().includes('/api/schedule/save')
      );
      await user1Page.click('[data-testid="submit-schedule-btn"]');
      await user1ResponsePromise;

      // Wait for success message
      await expect(user1Page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });

      // User 2 submits the overlapping schedule within 2 seconds
      const user2ResponsePromise = user2Page.waitForResponse(response => 
        response.url().includes('/api/schedule/save')
      );
      await user2Page.click('[data-testid="submit-schedule-btn"]');
      await user2ResponsePromise;

      // Action: Two users schedule overlapping resources simultaneously
      // Expected Result: Both users receive conflict alerts immediately
      await expect(user2Page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 3000 });
      const conflictMessage = await user2Page.locator('[data-testid="conflict-alert"]').textContent();
      expect(conflictMessage).toContain('conflict');
      expect(conflictMessage).toContain('Conference Room A');

      // Verify conflict alert details
      await expect(user2Page.locator('[data-testid="conflict-resource"]')).toContainText('Conference Room A');
      await expect(user2Page.locator('[data-testid="conflict-time"]')).toContainText('10:00');

      // Action: Users adjust schedules accordingly
      await user2Page.fill('[data-testid="start-time-input"]', '11:30');
      await user2Page.fill('[data-testid="end-time-input"]', '12:30');
      
      const user2AdjustedResponsePromise = user2Page.waitForResponse(response => 
        response.url().includes('/api/schedule/save') && response.status() === 200
      );
      await user2Page.click('[data-testid="submit-schedule-btn"]');
      await user2AdjustedResponsePromise;

      // Expected Result: Conflicts resolved and schedules saved
      await expect(user2Page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });

      // Verify both schedules exist without conflicts
      await user2Page.goto(`${apiBaseUrl}/schedule/list`);
      await expect(user2Page.locator('[data-testid="schedule-item"]')).toHaveCount(2);
      await expect(user2Page.locator('[data-testid="conflict-indicator"]')).toHaveCount(0);

      // Action: Verify system logs concurrent conflict events
      // Expected Result: Logs contain accurate concurrency conflict data
      await user2Page.goto(`${apiBaseUrl}/admin/logs`);
      await user2Page.fill('[data-testid="log-search"]', 'concurrent conflict');
      await user2Page.click('[data-testid="search-logs-btn"]');
      
      const logEntries = user2Page.locator('[data-testid="log-entry"]');
      await expect(logEntries).toHaveCount(1, { timeout: 5000 });
      
      const logContent = await logEntries.first().textContent();
      expect(logContent).toContain('Conference Room A');
      expect(logContent).toContain('2024-01-15');
      expect(logContent).toContain('conflict');

    } finally {
      await context1.close();
      await context2.close();
    }
  });

  test('Test system performance under concurrency', async ({ browser, page }) => {
    const concurrentUsers = 100;
    const contexts: BrowserContext[] = [];
    const pages: Page[] = [];
    const responseTimes: number[] = [];
    const errors: string[] = [];

    try {
      // Action: Load test with 100 concurrent scheduling users
      // Configure load testing with gradual ramp-up
      const rampUpBatches = 10;
      const usersPerBatch = concurrentUsers / rampUpBatches;
      const rampUpDelay = (2 * 60 * 1000) / rampUpBatches; // 2 minutes total ramp-up

      for (let batch = 0; batch < rampUpBatches; batch++) {
        for (let i = 0; i < usersPerBatch; i++) {
          const context = await browser.newContext();
          const userPage = await context.newPage();
          contexts.push(context);
          pages.push(userPage);
        }
        
        if (batch < rampUpBatches - 1) {
          await page.waitForTimeout(rampUpDelay);
        }
      }

      // Navigate to monitoring page to track system metrics
      await page.goto(`${apiBaseUrl}/admin/monitoring`);
      await page.waitForLoadState('networkidle');

      // Start monitoring system resources
      const initialCpuUsage = await page.locator('[data-testid="cpu-usage"]').textContent();
      const initialMemoryUsage = await page.locator('[data-testid="memory-usage"]').textContent();

      // Execute concurrent scheduling operations
      const schedulingPromises = pages.map(async (userPage, index) => {
        try {
          const startTime = Date.now();
          
          await userPage.goto(`${apiBaseUrl}/schedule`);
          await userPage.waitForLoadState('networkidle');
          
          await userPage.fill('[data-testid="resource-input"]', `Resource-${index % 20}`);
          await userPage.fill('[data-testid="date-input"]', `2024-01-${15 + (index % 10)}`);
          await userPage.fill('[data-testid="start-time-input"]', `${9 + (index % 8)}:00`);
          await userPage.fill('[data-testid="end-time-input"]', `${10 + (index % 8)}:00`);
          
          const responsePromise = userPage.waitForResponse(response => 
            response.url().includes('/api/schedule/save'),
            { timeout: 30000 }
          );
          await userPage.click('[data-testid="submit-schedule-btn"]');
          await responsePromise;
          
          const endTime = Date.now();
          const responseTime = endTime - startTime;
          responseTimes.push(responseTime);
          
          return { success: true, responseTime };
        } catch (error) {
          errors.push(`User ${index}: ${error}`);
          return { success: false, error: String(error) };
        }
      });

      // Wait for all operations to complete
      const results = await Promise.all(schedulingPromises);
      const successfulOperations = results.filter(r => r.success);

      // Expected Result: System maintains response times within SLA
      const averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
      const maxResponseTime = Math.max(...responseTimes);
      const slaThreshold = 5000; // 5 seconds SLA
      
      expect(maxResponseTime).toBeLessThan(slaThreshold);
      expect(averageResponseTime).toBeLessThan(slaThreshold / 2);

      // Action: Monitor system resource usage
      await page.reload();
      const peakCpuUsage = await page.locator('[data-testid="cpu-usage"]').textContent();
      const peakMemoryUsage = await page.locator('[data-testid="memory-usage"]').textContent();
      const dbConnections = await page.locator('[data-testid="db-connections"]').textContent();

      // Expected Result: No critical resource exhaustion
      const cpuUsagePercent = parseInt(peakCpuUsage?.replace('%', '') || '0');
      const memoryUsagePercent = parseInt(peakMemoryUsage?.replace('%', '') || '0');
      
      expect(cpuUsagePercent).toBeLessThan(90);
      expect(memoryUsagePercent).toBeLessThan(85);
      expect(parseInt(dbConnections || '0')).toBeLessThan(200);

      // Action: Verify no errors or failures during test
      // Expected Result: System operates reliably
      expect(errors.length).toBe(0);
      expect(successfulOperations.length).toBe(concurrentUsers);

      // Verify all operations completed successfully
      await page.goto(`${apiBaseUrl}/admin/logs`);
      await page.fill('[data-testid="log-level-filter"]', 'ERROR');
      await page.click('[data-testid="apply-filter-btn"]');
      
      const errorLogs = await page.locator('[data-testid="log-entry"]').count();
      expect(errorLogs).toBe(0);

      // Sustain load for stability test
      await page.waitForTimeout(10 * 60 * 1000); // 10 minutes

      // Verify system stability after sustained load
      await page.reload();
      const finalCpuUsage = await page.locator('[data-testid="cpu-usage"]').textContent();
      const finalMemoryUsage = await page.locator('[data-testid="memory-usage"]').textContent();
      
      expect(parseInt(finalCpuUsage?.replace('%', '') || '0')).toBeLessThan(90);
      expect(parseInt(finalMemoryUsage?.replace('%', '') || '0')).toBeLessThan(85);

    } finally {
      // Cleanup: Close all contexts
      for (const context of contexts) {
        await context.close();
      }
    }
  });
});