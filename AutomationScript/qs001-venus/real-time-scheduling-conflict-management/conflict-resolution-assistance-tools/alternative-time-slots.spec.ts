import { test, expect } from '@playwright/test';

test.describe('Alternative Time Slot Suggestions', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling interface
    await page.goto('/scheduling');
    // Assume user is already authenticated
    await page.waitForLoadState('networkidle');
  });

  test('Validate generation of alternative time slot suggestions (happy-path)', async ({ page }) => {
    // Step 1: Navigate to scheduling interface and create conflicting schedule
    await page.click('[data-testid="create-schedule-button"]');
    await page.waitForSelector('[data-testid="schedule-form"]');
    
    // Fill in schedule details that will conflict
    await page.fill('[data-testid="schedule-title"]', 'Team Meeting');
    await page.fill('[data-testid="schedule-date"]', '2024-03-15');
    await page.fill('[data-testid="schedule-start-time"]', '10:00');
    await page.fill('[data-testid="schedule-end-time"]', '11:00');
    await page.selectOption('[data-testid="schedule-resource"]', 'Conference Room A');
    
    // Attempt to save the conflicting schedule
    const startTime = Date.now();
    await page.click('[data-testid="save-schedule-button"]');
    
    // Step 1 Expected Result: System generates alternative time slot suggestions within 2 seconds
    await page.waitForSelector('[data-testid="conflict-alert"]', { timeout: 5000 });
    await page.waitForSelector('[data-testid="alternative-suggestions"]', { timeout: 5000 });
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    expect(responseTime).toBeLessThan(2000);
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    // Step 2: Scheduler views alternative suggestions
    const alternativeSuggestions = page.locator('[data-testid="alternative-suggestion-item"]');
    await expect(alternativeSuggestions).toHaveCount(await alternativeSuggestions.count());
    expect(await alternativeSuggestions.count()).toBeGreaterThan(0);
    
    // Step 2 Expected Result: Suggestions displayed clearly with no conflicts
    const firstSuggestion = alternativeSuggestions.first();
    await expect(firstSuggestion).toBeVisible();
    await expect(firstSuggestion.locator('[data-testid="suggestion-time"]')).toBeVisible();
    await expect(firstSuggestion.locator('[data-testid="suggestion-resource"]')).toBeVisible();
    await expect(firstSuggestion.locator('[data-testid="no-conflict-badge"]')).toBeVisible();
    
    // Step 3: Scheduler selects an alternative and saves schedule
    await firstSuggestion.click();
    await page.click('[data-testid="apply-alternative-button"]');
    
    // Step 3 Expected Result: Schedule updated and conflict alert removed
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');
    
    // Verify schedule appears in the calendar
    await expect(page.locator('[data-testid="schedule-item"]').filter({ hasText: 'Team Meeting' })).toBeVisible();
  });

  test('Ensure suggestions do not conflict with existing schedules (edge-case)', async ({ page }) => {
    // Step 1: Create a schedule that conflicts with an existing booking
    await page.click('[data-testid="create-schedule-button"]');
    await page.waitForSelector('[data-testid="schedule-form"]');
    
    await page.fill('[data-testid="schedule-title"]', 'Project Review');
    await page.fill('[data-testid="schedule-date"]', '2024-03-15');
    await page.fill('[data-testid="schedule-start-time"]', '14:00');
    await page.fill('[data-testid="schedule-end-time"]', '15:00');
    await page.selectOption('[data-testid="schedule-resource"]', 'Conference Room B');
    
    await page.click('[data-testid="save-schedule-button"]');
    await page.waitForSelector('[data-testid="alternative-suggestions"]');
    
    // Step 1 Expected Result: All suggested time slots are free of conflicts
    const alternativeSuggestions = page.locator('[data-testid="alternative-suggestion-item"]');
    const suggestionCount = await alternativeSuggestions.count();
    expect(suggestionCount).toBeGreaterThan(0);
    
    // Step 2: Review each suggested alternative and verify no conflicts
    for (let i = 0; i < suggestionCount; i++) {
      const suggestion = alternativeSuggestions.nth(i);
      await expect(suggestion.locator('[data-testid="no-conflict-badge"]')).toBeVisible();
      await expect(suggestion.locator('[data-testid="conflict-indicator"]')).not.toBeVisible();
    }
    
    // Step 2 Expected Result: Resources are available and not double-booked
    const firstSuggestion = alternativeSuggestions.first();
    const suggestionTime = await firstSuggestion.locator('[data-testid="suggestion-time"]').textContent();
    const suggestionResource = await firstSuggestion.locator('[data-testid="suggestion-resource"]').textContent();
    
    // Verify resource availability by checking the calendar
    await page.click('[data-testid="view-calendar-button"]');
    await page.waitForSelector('[data-testid="calendar-view"]');
    
    // Check that the suggested time slot is not occupied
    const conflictingBookings = page.locator(`[data-testid="calendar-event"][data-time="${suggestionTime}"][data-resource="${suggestionResource}"]`);
    await expect(conflictingBookings).toHaveCount(0);
    
    // Navigate back to suggestions
    await page.goBack();
    await page.waitForSelector('[data-testid="alternative-suggestions"]');
    
    // Step 3: Scheduler selects suggestion and saves
    await alternativeSuggestions.first().click();
    await page.click('[data-testid="apply-alternative-button"]');
    
    // Step 3 Expected Result: Schedule saved successfully without conflicts
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Verify the saved schedule in the resource availability calendar
    await page.click('[data-testid="view-calendar-button"]');
    await expect(page.locator('[data-testid="calendar-event"]').filter({ hasText: 'Project Review' })).toBeVisible();
  });

  test('Test performance of suggestion generation under load (boundary)', async ({ page, context }) => {
    // Step 1: Simulate multiple concurrent schedulers creating conflicting schedules
    const concurrentRequests = 15;
    const responseTimes: number[] = [];
    const pages = [];
    
    // Create multiple browser pages to simulate concurrent users
    for (let i = 0; i < concurrentRequests; i++) {
      const newPage = await context.newPage();
      pages.push(newPage);
      await newPage.goto('/scheduling');
      await newPage.waitForLoadState('networkidle');
    }
    
    // Step 1 & 2: Create conflicting schedules concurrently and measure response times
    const conflictCreationPromises = pages.map(async (schedulerPage, index) => {
      await schedulerPage.click('[data-testid="create-schedule-button"]');
      await schedulerPage.waitForSelector('[data-testid="schedule-form"]');
      
      await schedulerPage.fill('[data-testid="schedule-title"]', `Concurrent Meeting ${index + 1}`);
      await schedulerPage.fill('[data-testid="schedule-date"]', '2024-03-16');
      await schedulerPage.fill('[data-testid="schedule-start-time"]', '09:00');
      await schedulerPage.fill('[data-testid="schedule-end-time"]', '10:00');
      await schedulerPage.selectOption('[data-testid="schedule-resource"]', 'Conference Room A');
      
      const startTime = Date.now();
      await schedulerPage.click('[data-testid="save-schedule-button"]');
      
      try {
        await schedulerPage.waitForSelector('[data-testid="alternative-suggestions"]', { timeout: 5000 });
        const endTime = Date.now();
        const responseTime = endTime - startTime;
        responseTimes.push(responseTime);
        
        // Verify suggestions are generated
        const suggestions = schedulerPage.locator('[data-testid="alternative-suggestion-item"]');
        const count = await suggestions.count();
        expect(count).toBeGreaterThan(0);
        
        return { success: true, responseTime, pageIndex: index };
      } catch (error) {
        return { success: false, error: error.message, pageIndex: index };
      }
    });
    
    const results = await Promise.all(conflictCreationPromises);
    
    // Step 1 Expected Result: Alternative suggestions generated within 2 seconds for all requests
    const successfulRequests = results.filter(r => r.success);
    expect(successfulRequests.length).toBe(concurrentRequests);
    
    responseTimes.forEach((time, index) => {
      expect(time).toBeLessThan(2000);
    });
    
    // Step 2 Expected Result: Performance meets SLA requirements
    const averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
    const maxResponseTime = Math.max(...responseTimes);
    
    expect(averageResponseTime).toBeLessThan(2000);
    expect(maxResponseTime).toBeLessThan(2000);
    
    // Step 3: Review logs for errors or delays
    // Verify no error messages appeared on any page
    for (let i = 0; i < pages.length; i++) {
      const schedulerPage = pages[i];
      await expect(schedulerPage.locator('[data-testid="error-message"]')).not.toBeVisible();
      await expect(schedulerPage.locator('[data-testid="timeout-error"]')).not.toBeVisible();
    }
    
    // Step 3 Expected Result: No errors or significant delays observed
    const failedRequests = results.filter(r => !r.success);
    expect(failedRequests.length).toBe(0);
    
    // Verify all suggestions are accurate and conflict-free
    for (const schedulerPage of pages) {
      const suggestions = schedulerPage.locator('[data-testid="alternative-suggestion-item"]');
      const count = await suggestions.count();
      
      for (let i = 0; i < count; i++) {
        const suggestion = suggestions.nth(i);
        await expect(suggestion.locator('[data-testid="no-conflict-badge"]')).toBeVisible();
      }
    }
    
    // Clean up: close all additional pages
    for (const schedulerPage of pages) {
      await schedulerPage.close();
    }
  });
});