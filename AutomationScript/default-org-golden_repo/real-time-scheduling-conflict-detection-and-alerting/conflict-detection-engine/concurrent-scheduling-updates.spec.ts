import { test, expect, chromium, Browser, BrowserContext, Page } from '@playwright/test';

test.describe('Concurrent Scheduling Updates - Data Integrity', () => {
  let browser: Browser;
  let context1: BrowserContext;
  let context2: BrowserContext;
  let page1: Page;
  let page2: Page;
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const testAppointmentId = 'test-appointment-12345';

  test.beforeEach(async () => {
    browser = await chromium.launch();
    context1 = await browser.newContext();
    context2 = await browser.newContext();
    page1 = await context1.newPage();
    page2 = await context2.newPage();

    // Login for both users
    await page1.goto(`${baseURL}/login`);
    await page1.fill('[data-testid="username-input"]', 'scheduler1@test.com');
    await page1.fill('[data-testid="password-input"]', 'password123');
    await page1.click('[data-testid="login-button"]');
    await page1.waitForURL(`${baseURL}/dashboard`);

    await page2.goto(`${baseURL}/login`);
    await page2.fill('[data-testid="username-input"]', 'scheduler2@test.com');
    await page2.fill('[data-testid="password-input"]', 'password123');
    await page2.click('[data-testid="login-button"]');
    await page2.waitForURL(`${baseURL}/dashboard`);
  });

  test.afterEach(async () => {
    await context1.close();
    await context2.close();
    await browser.close();
  });

  test('Handle concurrent scheduling updates without data corruption (happy-path)', async () => {
    // Step 1: User 1 opens the existing appointment for editing and loads appointment details
    await page1.goto(`${baseURL}/appointments`);
    await page1.waitForSelector('[data-testid="appointments-list"]');
    await page1.click(`[data-testid="appointment-${testAppointmentId}"]`);
    await page1.waitForSelector('[data-testid="appointment-details"]');
    await page1.click('[data-testid="edit-appointment-button"]');
    await page1.waitForSelector('[data-testid="appointment-form"]');
    
    const initialTime1 = await page1.inputValue('[data-testid="appointment-time-input"]');
    expect(initialTime1).toBeTruthy();

    // Step 2: User 2 simultaneously opens the same appointment for editing
    await page2.goto(`${baseURL}/appointments`);
    await page2.waitForSelector('[data-testid="appointments-list"]');
    await page2.click(`[data-testid="appointment-${testAppointmentId}"]`);
    await page2.waitForSelector('[data-testid="appointment-details"]');
    await page2.click('[data-testid="edit-appointment-button"]');
    await page2.waitForSelector('[data-testid="appointment-form"]');
    
    const initialTime2 = await page2.inputValue('[data-testid="appointment-time-input"]');
    expect(initialTime2).toBe(initialTime1);

    // Step 3: User 1 modifies the appointment time from 2:00 PM to 3:00 PM and clicks Save
    await page1.fill('[data-testid="appointment-time-input"]', '15:00');
    await page1.click('[data-testid="save-appointment-button"]');
    await page1.waitForSelector('[data-testid="save-success-message"]');
    
    const successMessage1 = await page1.textContent('[data-testid="save-success-message"]');
    expect(successMessage1).toContain('Appointment saved successfully');

    // Step 4: User 2 modifies the appointment location and clicks Save without refreshing
    await page2.fill('[data-testid="appointment-location-input"]', 'Conference Room B');
    await page2.click('[data-testid="save-appointment-button"]');
    
    // Step 5: Verify conflict notification is displayed to User 2
    await page2.waitForSelector('[data-testid="conflict-notification"]', { timeout: 2000 });
    const conflictNotification = await page2.textContent('[data-testid="conflict-notification"]');
    expect(conflictNotification).toContain('conflict');
    expect(conflictNotification).toContain('updated by another user');

    // Verify notification displayed within 2 seconds (already verified by timeout above)
    const notificationVisible = await page2.isVisible('[data-testid="conflict-notification"]');
    expect(notificationVisible).toBe(true);

    // Step 6: User 2 clicks Refresh button to reload the appointment
    await page2.click('[data-testid="refresh-appointment-button"]');
    await page2.waitForSelector('[data-testid="appointment-form"]');
    
    const updatedTime = await page2.inputValue('[data-testid="appointment-time-input"]');
    expect(updatedTime).toBe('15:00');

    // Step 7: User 2 reapplies their location change and clicks Save
    await page2.fill('[data-testid="appointment-location-input"]', 'Conference Room B');
    await page2.click('[data-testid="save-appointment-button"]');
    await page2.waitForSelector('[data-testid="save-success-message"]');
    
    const successMessage2 = await page2.textContent('[data-testid="save-success-message"]');
    expect(successMessage2).toContain('Appointment saved successfully');

    // Step 8: Verify final appointment data in database
    await page1.reload();
    await page1.waitForSelector('[data-testid="appointment-details"]');
    
    const finalTime = await page1.textContent('[data-testid="appointment-time-display"]');
    const finalLocation = await page1.textContent('[data-testid="appointment-location-display"]');
    
    expect(finalTime).toContain('3:00 PM');
    expect(finalLocation).toContain('Conference Room B');

    // Verify data integrity maintained
    await page2.reload();
    await page2.waitForSelector('[data-testid="appointment-details"]');
    
    const finalTime2 = await page2.textContent('[data-testid="appointment-time-display"]');
    const finalLocation2 = await page2.textContent('[data-testid="appointment-location-display"]');
    
    expect(finalTime2).toBe(finalTime);
    expect(finalLocation2).toBe(finalLocation);
  });

  test('Maintain performance under high concurrency (boundary)', async () => {
    const concurrentUsers = 100;
    const performanceMetrics: any[] = [];
    let contexts: BrowserContext[] = [];
    let pages: Page[] = [];

    try {
      // Step 1: Configure load testing tool to simulate 100 concurrent scheduler users
      for (let i = 0; i < concurrentUsers; i++) {
        const context = await browser.newContext();
        const page = await context.newPage();
        contexts.push(context);
        pages.push(page);

        // Login each user
        await page.goto(`${baseURL}/login`);
        await page.fill('[data-testid="username-input"]', `scheduler${i}@test.com`);
        await page.fill('[data-testid="password-input"]', 'password123');
        await page.click('[data-testid="login-button"]');
        await page.waitForURL(`${baseURL}/dashboard`);
      }

      // Step 2: Start performance monitoring and capture baseline metrics
      const baselineStart = Date.now();
      await pages[0].goto(`${baseURL}/appointments`);
      const baselineEnd = Date.now();
      const baselineResponseTime = baselineEnd - baselineStart;
      
      performanceMetrics.push({
        operation: 'baseline',
        responseTime: baselineResponseTime
      });

      // Step 3: Initiate concurrent load test with all 100 users performing read operations
      const readOperationStart = Date.now();
      const readPromises = pages.map(async (page, index) => {
        const startTime = Date.now();
        await page.goto(`${baseURL}/appointments`);
        await page.waitForSelector('[data-testid="appointments-list"]');
        const endTime = Date.now();
        return { operation: 'read', responseTime: endTime - startTime, user: index };
      });
      
      const readResults = await Promise.all(readPromises);
      const readOperationEnd = Date.now();
      performanceMetrics.push(...readResults);
      
      const avgReadTime = readResults.reduce((sum, r) => sum + r.responseTime, 0) / readResults.length;
      expect(avgReadTime).toBeLessThan(5000); // SLA: 5 seconds average response time

      // Step 4: Execute concurrent write operations with 100 users creating new appointments
      const createPromises = pages.map(async (page, index) => {
        const startTime = Date.now();
        await page.click('[data-testid="create-appointment-button"]');
        await page.waitForSelector('[data-testid="appointment-form"]');
        await page.fill('[data-testid="appointment-title-input"]', `Concurrent Test Appointment ${index}`);
        await page.fill('[data-testid="appointment-date-input"]', '2024-12-31');
        await page.fill('[data-testid="appointment-time-input"]', '14:00');
        await page.fill('[data-testid="appointment-location-input"]', `Room ${index}`);
        await page.click('[data-testid="save-appointment-button"]');
        await page.waitForSelector('[data-testid="save-success-message"]');
        const endTime = Date.now();
        return { operation: 'create', responseTime: endTime - startTime, user: index };
      });
      
      const createResults = await Promise.all(createPromises);
      performanceMetrics.push(...createResults);
      
      const avgCreateTime = createResults.reduce((sum, r) => sum + r.responseTime, 0) / createResults.length;
      expect(avgCreateTime).toBeLessThan(8000); // SLA: 8 seconds for create operations

      // Step 5: Execute concurrent update operations with 100 users modifying different appointments
      const updatePromises = pages.map(async (page, index) => {
        const startTime = Date.now();
        await page.goto(`${baseURL}/appointments`);
        await page.waitForSelector('[data-testid="appointments-list"]');
        const appointments = await page.$$('[data-testid^="appointment-"]');
        if (appointments.length > 0) {
          await appointments[index % appointments.length].click();
          await page.waitForSelector('[data-testid="appointment-details"]');
          await page.click('[data-testid="edit-appointment-button"]');
          await page.waitForSelector('[data-testid="appointment-form"]');
          await page.fill('[data-testid="appointment-location-input"]', `Updated Room ${index}`);
          await page.click('[data-testid="save-appointment-button"]');
          await page.waitForSelector('[data-testid="save-success-message"]');
        }
        const endTime = Date.now();
        return { operation: 'update', responseTime: endTime - startTime, user: index };
      });
      
      const updateResults = await Promise.all(updatePromises);
      performanceMetrics.push(...updateResults);
      
      const avgUpdateTime = updateResults.reduce((sum, r) => sum + r.responseTime, 0) / updateResults.length;
      expect(avgUpdateTime).toBeLessThan(8000); // SLA: 8 seconds for update operations

      // Step 6: Execute mixed operations
      const mixedPromises = pages.map(async (page, index) => {
        const startTime = Date.now();
        let operation = '';
        
        if (index < 50) {
          // Read operation
          operation = 'mixed-read';
          await page.goto(`${baseURL}/appointments`);
          await page.waitForSelector('[data-testid="appointments-list"]');
        } else if (index < 80) {
          // Update operation
          operation = 'mixed-update';
          await page.goto(`${baseURL}/appointments`);
          await page.waitForSelector('[data-testid="appointments-list"]');
          const appointments = await page.$$('[data-testid^="appointment-"]');
          if (appointments.length > 0) {
            await appointments[0].click();
            await page.waitForSelector('[data-testid="appointment-details"]');
            await page.click('[data-testid="edit-appointment-button"]');
            await page.fill('[data-testid="appointment-location-input"]', `Mixed Update ${index}`);
            await page.click('[data-testid="save-appointment-button"]');
            await page.waitForSelector('[data-testid="save-success-message"]');
          }
        } else {
          // Create operation
          operation = 'mixed-create';
          await page.click('[data-testid="create-appointment-button"]');
          await page.waitForSelector('[data-testid="appointment-form"]');
          await page.fill('[data-testid="appointment-title-input"]', `Mixed Create ${index}`);
          await page.fill('[data-testid="appointment-date-input"]', '2024-12-31');
          await page.fill('[data-testid="appointment-time-input"]', '15:00');
          await page.click('[data-testid="save-appointment-button"]');
          await page.waitForSelector('[data-testid="save-success-message"]');
        }
        
        const endTime = Date.now();
        return { operation, responseTime: endTime - startTime, user: index };
      });
      
      const mixedResults = await Promise.all(mixedPromises);
      performanceMetrics.push(...mixedResults);

      // Step 7: Monitor system resource utilization during peak concurrent load
      // Note: This would typically be done via external monitoring tools
      // Here we verify response times as a proxy for system health
      const allResponseTimes = performanceMetrics.map(m => m.responseTime);
      const avgResponseTime = allResponseTimes.reduce((sum, t) => sum + t, 0) / allResponseTimes.length;
      
      // Step 8: Review performance metrics and calculate average response times
      console.log(`Average response time across all operations: ${avgResponseTime}ms`);
      console.log(`Total operations performed: ${performanceMetrics.length}`);
      
      expect(avgResponseTime).toBeLessThan(10000); // Overall SLA: 10 seconds average

      // Step 9: Verify data integrity by checking random sample of 50 appointments
      const sampleSize = 50;
      const randomPages = [];
      for (let i = 0; i < sampleSize; i++) {
        const randomIndex = Math.floor(Math.random() * pages.length);
        randomPages.push(pages[randomIndex]);
      }

      const integrityChecks = randomPages.map(async (page, index) => {
        await page.goto(`${baseURL}/appointments`);
        await page.waitForSelector('[data-testid="appointments-list"]');
        const appointments = await page.$$('[data-testid^="appointment-"]');
        return appointments.length > 0;
      });
      
      const integrityResults = await Promise.all(integrityChecks);
      const integrityPassed = integrityResults.filter(r => r === true).length;
      
      expect(integrityPassed).toBe(sampleSize);
      expect(integrityPassed / sampleSize).toBeGreaterThanOrEqual(0.99); // 99% data integrity

      // Verify system maintains response times within SLA
      const maxResponseTime = Math.max(...allResponseTimes);
      expect(maxResponseTime).toBeLessThan(15000); // Max acceptable response time: 15 seconds

    } finally {
      // Cleanup all contexts
      for (const context of contexts) {
        await context.close();
      }
    }
  });
});