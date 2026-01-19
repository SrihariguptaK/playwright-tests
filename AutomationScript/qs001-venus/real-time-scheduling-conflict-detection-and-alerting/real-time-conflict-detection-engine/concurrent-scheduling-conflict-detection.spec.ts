import { test, expect } from '@playwright/test';
import { chromium, Browser, Page, BrowserContext } from '@playwright/test';

test.describe('Concurrent Scheduling Conflict Detection', () => {
  let browser: Browser;
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const CONCURRENT_USERS = 100;
  const CONFLICT_DETECTION_TIMEOUT = 2000;

  test.beforeAll(async () => {
    browser = await chromium.launch();
  });

  test.afterAll(async () => {
    await browser.close();
  });

  test('Validate conflict detection under concurrent scheduling (happy-path)', async () => {
    // Step 1: Prepare 100 concurrent scheduling requests with overlapping time slots
    const schedulingRequests = [];
    const contexts: BrowserContext[] = [];
    const pages: Page[] = [];
    const overlappingTimeSlot = {
      date: '2024-02-15',
      startTime: '10:00',
      endTime: '11:00',
      resource: 'Conference Room A'
    };

    // Create 100 concurrent user sessions
    for (let i = 0; i < CONCURRENT_USERS; i++) {
      const context = await browser.newContext();
      const page = await context.newPage();
      contexts.push(context);
      pages.push(page);

      // Navigate to scheduling page
      await page.goto(`${BASE_URL}/scheduling`);
      
      // Login as different users
      await page.fill('[data-testid="username-input"]', `scheduler${i}@company.com`);
      await page.fill('[data-testid="password-input"]', 'TestPassword123');
      await page.click('[data-testid="login-button"]');
      await page.waitForSelector('[data-testid="scheduling-form"]', { timeout: 5000 });
    }

    // Step 2: Execute all 100 concurrent scheduling requests simultaneously
    const startTime = Date.now();
    
    const schedulingPromises = pages.map(async (page, index) => {
      try {
        // Fill scheduling form with overlapping time slots
        await page.fill('[data-testid="schedule-date-input"]', overlappingTimeSlot.date);
        await page.fill('[data-testid="schedule-start-time-input"]', overlappingTimeSlot.startTime);
        await page.fill('[data-testid="schedule-end-time-input"]', overlappingTimeSlot.endTime);
        await page.selectOption('[data-testid="resource-select"]', overlappingTimeSlot.resource);
        await page.fill('[data-testid="schedule-title-input"]', `Meeting ${index}`);
        
        // Submit scheduling request
        await page.click('[data-testid="submit-schedule-button"]');
        
        // Wait for response (either success or conflict alert)
        await page.waitForSelector('[data-testid="schedule-response"], [data-testid="conflict-alert"]', { timeout: CONFLICT_DETECTION_TIMEOUT });
        
        return {
          userId: index,
          success: await page.isVisible('[data-testid="schedule-success"]'),
          conflict: await page.isVisible('[data-testid="conflict-alert"]'),
          alertMessage: await page.textContent('[data-testid="conflict-alert-message"]').catch(() => null)
        };
      } catch (error) {
        return {
          userId: index,
          success: false,
          conflict: false,
          error: error.message
        };
      }
    });

    const results = await Promise.all(schedulingPromises);
    const endTime = Date.now();
    const processingTime = endTime - startTime;

    // Step 3: Verify that all scheduling conflicts are detected by the system
    const successfulSchedules = results.filter(r => r.success).length;
    const conflictDetections = results.filter(r => r.conflict).length;
    const errors = results.filter(r => r.error).length;

    // Expected: Only 1 successful schedule, 99 conflicts detected
    expect(successfulSchedules).toBe(1);
    expect(conflictDetections).toBe(CONCURRENT_USERS - 1);
    expect(errors).toBe(0);

    // Step 4: Check system logs and error reports for any processing errors
    // Verify no processing errors occurred
    for (const result of results) {
      if (result.error) {
        throw new Error(`Processing error detected for user ${result.userId}: ${result.error}`);
      }
    }

    // Step 5: Query the scheduling database to verify data integrity
    const adminPage = await browser.newPage();
    await adminPage.goto(`${BASE_URL}/admin/scheduling-database`);
    await adminPage.fill('[data-testid="admin-username"]', 'admin@company.com');
    await adminPage.fill('[data-testid="admin-password"]', 'AdminPassword123');
    await adminPage.click('[data-testid="admin-login-button"]');
    await adminPage.waitForSelector('[data-testid="database-view"]');

    // Filter schedules for the test time slot
    await adminPage.fill('[data-testid="filter-date"]', overlappingTimeSlot.date);
    await adminPage.fill('[data-testid="filter-resource"]', overlappingTimeSlot.resource);
    await adminPage.click('[data-testid="apply-filter-button"]');
    await adminPage.waitForSelector('[data-testid="schedule-records"]');

    const scheduleRecords = await adminPage.locator('[data-testid="schedule-record"]').count();
    
    // Step 6: Verify data integrity is maintained - only 1 schedule should exist
    expect(scheduleRecords).toBe(1);

    // Step 7: Verify no race conditions occurred by checking for orphaned records or inconsistent states
    const orphanedRecords = await adminPage.locator('[data-testid="orphaned-record"]').count();
    expect(orphanedRecords).toBe(0);

    const inconsistentStates = await adminPage.locator('[data-testid="inconsistent-state-warning"]').count();
    expect(inconsistentStates).toBe(0);

    // Step 8: Check that conflict alerts were generated for all detected conflicts
    await adminPage.click('[data-testid="view-alerts-tab"]');
    await adminPage.waitForSelector('[data-testid="conflict-alerts-list"]');
    
    const conflictAlerts = await adminPage.locator('[data-testid="conflict-alert-item"]').count();
    expect(conflictAlerts).toBe(CONCURRENT_USERS - 1);

    // Step 9: Verify conflict alerts are delivered to all affected users
    for (let i = 0; i < pages.length; i++) {
      const page = pages[i];
      const hasConflictAlert = await page.isVisible('[data-testid="conflict-alert"]');
      const hasSuccessMessage = await page.isVisible('[data-testid="schedule-success"]');
      
      // Each user should have either success or conflict alert
      expect(hasConflictAlert || hasSuccessMessage).toBe(true);
      
      if (hasConflictAlert) {
        // Verify alert content for accuracy
        const alertMessage = await page.textContent('[data-testid="conflict-alert-message"]');
        expect(alertMessage).toContain('scheduling conflict');
        expect(alertMessage).toContain(overlappingTimeSlot.resource);
        expect(alertMessage).toContain(overlappingTimeSlot.date);
      }
    }

    // Step 10: Measure the time taken for conflict detection and alert delivery
    expect(processingTime).toBeLessThan(CONFLICT_DETECTION_TIMEOUT * CONCURRENT_USERS);
    
    // Verify average conflict detection time is under 2 seconds
    const averageDetectionTime = processingTime / CONCURRENT_USERS;
    expect(averageDetectionTime).toBeLessThan(2000);

    // Step 11: Review alert content for accuracy and completeness
    const sampleConflictPage = pages.find((_, i) => results[i].conflict);
    if (sampleConflictPage) {
      const alertDetails = await sampleConflictPage.locator('[data-testid="conflict-details"]').textContent();
      expect(alertDetails).toContain('Time:');
      expect(alertDetails).toContain('Resource:');
      expect(alertDetails).toContain('Conflicting Schedule:');
    }

    // Cleanup: Close all contexts and pages
    await adminPage.close();
    for (const context of contexts) {
      await context.close();
    }
  });

  test('Simulate 100 users scheduling concurrently with overlapping inputs', async () => {
    const contexts: BrowserContext[] = [];
    const pages: Page[] = [];
    const testData = {
      date: '2024-02-20',
      startTime: '14:00',
      endTime: '15:00',
      resource: 'Meeting Room B'
    };

    // Action: Simulate 100 users scheduling concurrently with overlapping inputs
    for (let i = 0; i < CONCURRENT_USERS; i++) {
      const context = await browser.newContext();
      const page = await context.newPage();
      contexts.push(context);
      pages.push(page);

      await page.goto(`${BASE_URL}/scheduling`);
      await page.fill('[data-testid="username-input"]', `user${i}@company.com`);
      await page.fill('[data-testid="password-input"]', 'Password123');
      await page.click('[data-testid="login-button"]');
      await page.waitForSelector('[data-testid="scheduling-form"]');
    }

    const concurrentScheduling = pages.map(async (page, index) => {
      await page.fill('[data-testid="schedule-date-input"]', testData.date);
      await page.fill('[data-testid="schedule-start-time-input"]', testData.startTime);
      await page.fill('[data-testid="schedule-end-time-input"]', testData.endTime);
      await page.selectOption('[data-testid="resource-select"]', testData.resource);
      await page.fill('[data-testid="schedule-title-input"]', `Concurrent Meeting ${index}`);
      await page.click('[data-testid="submit-schedule-button"]');
      
      return page.waitForSelector('[data-testid="schedule-response"], [data-testid="conflict-alert"]', { timeout: 5000 });
    });

    // Expected Result: System detects all conflicts without errors
    await expect(Promise.all(concurrentScheduling)).resolves.toBeDefined();

    const conflictsDetected = await Promise.all(
      pages.map(page => page.isVisible('[data-testid="conflict-alert"]'))
    );
    const successCount = conflictsDetected.filter(c => !c).length;
    
    expect(successCount).toBe(1);
    expect(conflictsDetected.filter(c => c).length).toBe(CONCURRENT_USERS - 1);

    // Cleanup
    for (const context of contexts) {
      await context.close();
    }
  });

  test('Verify no data corruption in scheduling database', async () => {
    const adminPage = await browser.newPage();
    
    // Action: Verify no data corruption in scheduling database
    await adminPage.goto(`${BASE_URL}/admin/database-integrity`);
    await adminPage.fill('[data-testid="admin-username"]', 'admin@company.com');
    await adminPage.fill('[data-testid="admin-password"]', 'AdminPassword123');
    await adminPage.click('[data-testid="admin-login-button"]');
    await adminPage.waitForSelector('[data-testid="integrity-check-panel"]');

    // Run integrity check
    await adminPage.click('[data-testid="run-integrity-check-button"]');
    await adminPage.waitForSelector('[data-testid="integrity-check-results"]', { timeout: 10000 });

    // Expected Result: Data integrity is maintained
    const integrityStatus = await adminPage.textContent('[data-testid="integrity-status"]');
    expect(integrityStatus).toContain('PASSED');

    const corruptionCount = await adminPage.textContent('[data-testid="corruption-count"]');
    expect(corruptionCount).toBe('0');

    const duplicateRecords = await adminPage.locator('[data-testid="duplicate-record"]').count();
    expect(duplicateRecords).toBe(0);

    const invalidReferences = await adminPage.locator('[data-testid="invalid-reference"]').count();
    expect(invalidReferences).toBe(0);

    await adminPage.close();
  });

  test('Check conflict alerts delivery to all affected users', async () => {
    const contexts: BrowserContext[] = [];
    const pages: Page[] = [];
    const affectedUserCount = 50;
    const testSchedule = {
      date: '2024-02-25',
      startTime: '09:00',
      endTime: '10:00',
      resource: 'Training Room'
    };

    // Setup: Create concurrent scheduling scenario
    for (let i = 0; i < affectedUserCount; i++) {
      const context = await browser.newContext();
      const page = await context.newPage();
      contexts.push(context);
      pages.push(page);

      await page.goto(`${BASE_URL}/scheduling`);
      await page.fill('[data-testid="username-input"]', `scheduler${i}@company.com`);
      await page.fill('[data-testid="password-input"]', 'TestPass123');
      await page.click('[data-testid="login-button"]');
      await page.waitForSelector('[data-testid="scheduling-form"]');
    }

    // Submit concurrent requests
    await Promise.all(pages.map(async (page, index) => {
      await page.fill('[data-testid="schedule-date-input"]', testSchedule.date);
      await page.fill('[data-testid="schedule-start-time-input"]', testSchedule.startTime);
      await page.fill('[data-testid="schedule-end-time-input"]', testSchedule.endTime);
      await page.selectOption('[data-testid="resource-select"]', testSchedule.resource);
      await page.fill('[data-testid="schedule-title-input"]', `Alert Test ${index}`);
      await page.click('[data-testid="submit-schedule-button"]');
    }));

    // Action: Check conflict alerts delivery to all affected users
    const alertDeliveryResults = await Promise.all(pages.map(async (page, index) => {
      const alertVisible = await page.waitForSelector('[data-testid="conflict-alert"], [data-testid="schedule-success"]', { timeout: CONFLICT_DETECTION_TIMEOUT });
      const hasAlert = await page.isVisible('[data-testid="conflict-alert"]');
      const hasSuccess = await page.isVisible('[data-testid="schedule-success"]');
      
      let alertTimestamp = null;
      if (hasAlert) {
        alertTimestamp = await page.getAttribute('[data-testid="conflict-alert"]', 'data-timestamp');
      }

      return {
        userId: index,
        alertReceived: hasAlert,
        successReceived: hasSuccess,
        timestamp: alertTimestamp
      };
    }));

    // Expected Result: Alerts are received correctly and timely
    const alertsReceived = alertDeliveryResults.filter(r => r.alertReceived).length;
    const successReceived = alertDeliveryResults.filter(r => r.successReceived).length;

    expect(successReceived).toBe(1);
    expect(alertsReceived).toBe(affectedUserCount - 1);

    // Verify all alerts were delivered within acceptable timeframe
    const alertTimestamps = alertDeliveryResults
      .filter(r => r.timestamp)
      .map(r => parseInt(r.timestamp));
    
    if (alertTimestamps.length > 0) {
      const maxTimestamp = Math.max(...alertTimestamps);
      const minTimestamp = Math.min(...alertTimestamps);
      const deliveryTimeSpan = maxTimestamp - minTimestamp;
      
      expect(deliveryTimeSpan).toBeLessThan(CONFLICT_DETECTION_TIMEOUT);
    }

    // Cleanup
    for (const context of contexts) {
      await context.close();
    }
  });
});