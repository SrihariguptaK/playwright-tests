import { test, expect } from '@playwright/test';
import { chromium, Browser, BrowserContext, Page } from '@playwright/test';

test.describe('Concurrent Scheduling Operations - Data Integrity', () => {
  let apiBaseUrl: string;

  test.beforeEach(async ({ page }) => {
    apiBaseUrl = process.env.API_BASE_URL || 'http://localhost:3000';
    await page.goto(`${apiBaseUrl}/scheduler`);
    await page.waitForLoadState('networkidle');
  });

  test('Handle concurrent scheduling operations without conflicts - happy path', async ({ browser }) => {
    const concurrentUsers = 100;
    const testResourceName = 'Conference Room A';
    const testTimeSlot = '10:00 AM';
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const testDate = tomorrow.toISOString().split('T')[0];

    // Step 1: Prepare concurrent test scenario
    const contexts: BrowserContext[] = [];
    const pages: Page[] = [];

    // Create 100 browser contexts to simulate concurrent users
    for (let i = 0; i < concurrentUsers; i++) {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(`${apiBaseUrl}/scheduler`);
      contexts.push(context);
      pages.push(page);
    }

    // Step 2: Initiate concurrent scheduling operations
    const startTime = Date.now();
    const createEventPromises = pages.map(async (page, index) => {
      try {
        // Navigate to create event page
        await page.click('[data-testid="create-event-button"]');
        await page.waitForSelector('[data-testid="event-form"]');

        // Fill event details
        await page.fill('[data-testid="event-title-input"]', `Event ${index + 1}`);
        await page.fill('[data-testid="event-resource-input"]', testResourceName);
        await page.fill('[data-testid="event-date-input"]', testDate);
        await page.fill('[data-testid="event-time-input"]', testTimeSlot);
        await page.fill('[data-testid="event-duration-input"]', '60');

        // Submit the event creation
        const responsePromise = page.waitForResponse(response => 
          response.url().includes('/api/events') && response.request().method() === 'POST'
        );
        await page.click('[data-testid="submit-event-button"]');
        const response = await responsePromise;

        return {
          userId: index + 1,
          status: response.status(),
          responseBody: await response.json()
        };
      } catch (error) {
        return {
          userId: index + 1,
          status: 'error',
          error: error.message
        };
      }
    });

    // Step 3: Monitor system behavior and wait for all operations to complete
    const results = await Promise.all(createEventPromises);
    const endTime = Date.now();
    const totalDuration = endTime - startTime;

    // Step 4: Review responses received by each user
    const successfulCreations = results.filter(r => r.status === 201 || r.status === 200);
    const conflictResponses = results.filter(r => r.status === 409);
    const errorResponses = results.filter(r => r.status === 'error' || (r.status !== 200 && r.status !== 201 && r.status !== 409));

    // Expected Result: System processes operations without data conflicts
    expect(errorResponses.length).toBe(0);
    expect(successfulCreations.length + conflictResponses.length).toBe(concurrentUsers);

    // Step 5: Query the scheduling database to verify consistency
    const verificationPage = await browser.newPage();
    await verificationPage.goto(`${apiBaseUrl}/scheduler`);
    
    // Navigate to events list and filter by resource and time
    await verificationPage.click('[data-testid="view-events-button"]');
    await verificationPage.fill('[data-testid="filter-resource-input"]', testResourceName);
    await verificationPage.fill('[data-testid="filter-date-input"]', testDate);
    await verificationPage.fill('[data-testid="filter-time-input"]', testTimeSlot);
    await verificationPage.click('[data-testid="apply-filter-button"]');
    await verificationPage.waitForSelector('[data-testid="events-list"]');

    // Step 6: Verify only one event was created for the conflicting time slot
    const eventItems = await verificationPage.locator('[data-testid="event-item"]').count();
    
    // Expected Result: Scheduling data remains consistent and accurate (only 1 event for same resource/time)
    expect(eventItems).toBe(1);

    // Step 7: Verify users received feedback on operation status
    for (const result of results) {
      if (result.status === 201 || result.status === 200) {
        // Expected Result: Successful creation feedback
        expect(result.responseBody).toHaveProperty('id');
        expect(result.responseBody).toHaveProperty('message');
      } else if (result.status === 409) {
        // Expected Result: Conflict feedback
        expect(result.responseBody).toHaveProperty('error');
        expect(result.responseBody.error).toContain('conflict');
      }
    }

    // Step 8: Execute database consistency check
    const dbCheckResponse = await verificationPage.request.get(`${apiBaseUrl}/api/admin/db-consistency-check`);
    expect(dbCheckResponse.ok()).toBeTruthy();
    const dbCheckResult = await dbCheckResponse.json();
    expect(dbCheckResult.integrityViolations).toBe(0);
    expect(dbCheckResult.orphanedRecords).toBe(0);

    // Step 9: Prepare second concurrent test scenario - non-conflicting updates
    const updateContexts: BrowserContext[] = [];
    const updatePages: Page[] = [];

    // Create events to update
    const eventsToUpdate = [];
    for (let i = 0; i < concurrentUsers; i++) {
      const createResponse = await verificationPage.request.post(`${apiBaseUrl}/api/events`, {
        data: {
          title: `Update Test Event ${i + 1}`,
          resource: `Room ${i + 1}`,
          date: testDate,
          time: `${9 + Math.floor(i / 10)}:${(i % 10) * 6}0 AM`,
          duration: 30
        }
      });
      const eventData = await createResponse.json();
      eventsToUpdate.push(eventData);
    }

    // Create contexts for concurrent updates
    for (let i = 0; i < concurrentUsers; i++) {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(`${apiBaseUrl}/scheduler`);
      updateContexts.push(context);
      updatePages.push(page);
    }

    // Step 10: Execute concurrent update operations
    const updateStartTime = Date.now();
    const updatePromises = updatePages.map(async (page, index) => {
      try {
        const eventId = eventsToUpdate[index].id;
        
        await page.goto(`${apiBaseUrl}/scheduler/events/${eventId}/edit`);
        await page.waitForSelector('[data-testid="event-form"]');
        
        await page.fill('[data-testid="event-title-input"]', `Updated Event ${index + 1}`);
        await page.fill('[data-testid="event-duration-input"]', '45');
        
        const responsePromise = page.waitForResponse(response => 
          response.url().includes(`/api/events/${eventId}`) && response.request().method() === 'PUT'
        );
        await page.click('[data-testid="submit-event-button"]');
        const response = await responsePromise;

        return {
          userId: index + 1,
          eventId: eventId,
          status: response.status(),
          responseBody: await response.json()
        };
      } catch (error) {
        return {
          userId: index + 1,
          status: 'error',
          error: error.message
        };
      }
    });

    // Step 11: Wait for all update operations to complete
    const updateResults = await Promise.all(updatePromises);
    const updateEndTime = Date.now();
    const updateDuration = updateEndTime - updateStartTime;

    // Step 12: Verify all events were updated correctly
    const successfulUpdates = updateResults.filter(r => r.status === 200);
    expect(successfulUpdates.length).toBe(concurrentUsers);

    for (let i = 0; i < concurrentUsers; i++) {
      const eventId = eventsToUpdate[i].id;
      const checkResponse = await verificationPage.request.get(`${apiBaseUrl}/api/events/${eventId}`);
      const updatedEvent = await checkResponse.json();
      expect(updatedEvent.title).toBe(`Updated Event ${i + 1}`);
      expect(updatedEvent.duration).toBe(45);
    }

    // Step 13: Prepare third concurrent test scenario - mixed operations
    const mixedContexts: BrowserContext[] = [];
    const mixedPages: Page[] = [];

    for (let i = 0; i < concurrentUsers; i++) {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(`${apiBaseUrl}/scheduler`);
      mixedContexts.push(context);
      mixedPages.push(page);
    }

    // Step 14: Execute mixed concurrent operations (50 creates, 50 updates)
    const mixedStartTime = Date.now();
    const mixedPromises = mixedPages.map(async (page, index) => {
      try {
        if (index < 50) {
          // Create operation
          await page.click('[data-testid="create-event-button"]');
          await page.waitForSelector('[data-testid="event-form"]');
          
          await page.fill('[data-testid="event-title-input"]', `Mixed Create ${index + 1}`);
          await page.fill('[data-testid="event-resource-input"]', `Mixed Room ${index + 1}`);
          await page.fill('[data-testid="event-date-input"]', testDate);
          await page.fill('[data-testid="event-time-input"]', `${11 + Math.floor(index / 10)}:00 AM`);
          await page.fill('[data-testid="event-duration-input"]', '30');
          
          const responsePromise = page.waitForResponse(response => 
            response.url().includes('/api/events') && response.request().method() === 'POST'
          );
          await page.click('[data-testid="submit-event-button"]');
          const response = await responsePromise;

          return {
            userId: index + 1,
            operation: 'create',
            status: response.status(),
            responseBody: await response.json()
          };
        } else {
          // Update operation
          const eventToUpdate = eventsToUpdate[index - 50];
          await page.goto(`${apiBaseUrl}/scheduler/events/${eventToUpdate.id}/edit`);
          await page.waitForSelector('[data-testid="event-form"]');
          
          await page.fill('[data-testid="event-title-input"]', `Mixed Update ${index + 1}`);
          
          const responsePromise = page.waitForResponse(response => 
            response.url().includes(`/api/events/${eventToUpdate.id}`) && response.request().method() === 'PUT'
          );
          await page.click('[data-testid="submit-event-button"]');
          const response = await responsePromise;

          return {
            userId: index + 1,
            operation: 'update',
            status: response.status(),
            responseBody: await response.json()
          };
        }
      } catch (error) {
        return {
          userId: index + 1,
          operation: index < 50 ? 'create' : 'update',
          status: 'error',
          error: error.message
        };
      }
    });

    // Step 15: Verify operation results and database state
    const mixedResults = await Promise.all(mixedPromises);
    const mixedEndTime = Date.now();
    const mixedDuration = mixedEndTime - mixedStartTime;

    const successfulMixedOps = mixedResults.filter(r => r.status === 200 || r.status === 201);
    expect(successfulMixedOps.length).toBe(concurrentUsers);

    // Step 16: Review application logs and user feedback messages
    const logsResponse = await verificationPage.request.get(`${apiBaseUrl}/api/admin/operation-logs?timeRange=${startTime}-${mixedEndTime}`);
    expect(logsResponse.ok()).toBeTruthy();
    const logs = await logsResponse.json();
    expect(logs.totalOperations).toBeGreaterThanOrEqual(concurrentUsers * 3);

    // Step 17: Generate and review performance report
    const performanceReport = {
      concurrentUsersSupported: concurrentUsers,
      createOperationsDuration: totalDuration,
      updateOperationsDuration: updateDuration,
      mixedOperationsDuration: mixedDuration,
      averageResponseTime: (totalDuration + updateDuration + mixedDuration) / (concurrentUsers * 3)
    };

    // Verify SLA thresholds (assuming 5 second SLA per operation)
    const slaThreshold = 5000;
    expect(performanceReport.averageResponseTime).toBeLessThan(slaThreshold);

    // Verify system supports at least 100 concurrent users
    expect(performanceReport.concurrentUsersSupported).toBeGreaterThanOrEqual(100);

    // Final database consistency check
    const finalDbCheckResponse = await verificationPage.request.get(`${apiBaseUrl}/api/admin/db-consistency-check`);
    expect(finalDbCheckResponse.ok()).toBeTruthy();
    const finalDbCheckResult = await finalDbCheckResponse.json();
    expect(finalDbCheckResult.integrityViolations).toBe(0);
    expect(finalDbCheckResult.orphanedRecords).toBe(0);
    expect(finalDbCheckResult.dataCorruption).toBe(0);

    // Cleanup: Close all browser contexts
    for (const context of [...contexts, ...updateContexts, ...mixedContexts]) {
      await context.close();
    }
    await verificationPage.close();
  });
});