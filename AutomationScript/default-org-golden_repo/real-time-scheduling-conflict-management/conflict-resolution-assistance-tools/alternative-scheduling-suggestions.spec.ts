import { test, expect } from '@playwright/test';

test.describe('Alternative Scheduling Suggestions', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling interface before each test
    await page.goto('/scheduling');
    // Wait for page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate generation of alternative scheduling suggestions (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the scheduling interface (done in beforeEach)
    
    // Step 2: Attempt to schedule an appointment that conflicts with an existing appointment
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', '2024-02-15');
    await page.fill('[data-testid="appointment-time-input"]', '10:00');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Resource A' });
    await page.fill('[data-testid="appointment-duration-input"]', '60');
    
    // Step 3: Trigger the alternative suggestions feature
    await page.click('[data-testid="schedule-appointment-button"]');
    
    // Expected Result: Conflict should be detected and alternatives button should appear
    await expect(page.locator('[data-testid="conflict-notification"]')).toBeVisible();
    
    // Click on View Alternatives button
    await page.click('[data-testid="view-alternatives-button"]');
    
    // Step 4: Review the suggestions displayed in the UI
    // Expected Result: Alternative suggestions are generated and displayed
    await expect(page.locator('[data-testid="alternatives-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="alternative-suggestion"]')).toHaveCount(3, { timeout: 2000 });
    
    // Verify suggestions display available time slots and resources
    const firstSuggestion = page.locator('[data-testid="alternative-suggestion"]').first();
    await expect(firstSuggestion.locator('[data-testid="suggestion-time"]')).toBeVisible();
    await expect(firstSuggestion.locator('[data-testid="suggestion-resource"]')).toBeVisible();
    
    // Step 5: Select one of the suggested alternative time slots from the list
    await firstSuggestion.click();
    await expect(firstSuggestion).toHaveClass(/selected/);
    
    // Step 6: Click the apply or confirm button to apply the selected suggestion
    await page.click('[data-testid="apply-suggestion-button"]');
    
    // Step 7: Verify the updated appointment in the calendar view
    // Expected Result: Appointment is updated accordingly
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment scheduled successfully');
    
    // Verify appointment appears in calendar
    await page.click('[data-testid="calendar-view-button"]');
    await expect(page.locator('[data-testid="calendar-appointment"]')).toBeVisible();
  });

  test('Verify suggestion generation latency under 2 seconds (boundary)', async ({ page }) => {
    // Step 1: Open browser developer tools and navigate to the Network tab (handled by Playwright)
    
    // Step 2: Navigate to the scheduling interface (done in beforeEach)
    
    // Step 3: Attempt to create an appointment that will trigger a scheduling conflict
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', '2024-02-15');
    await page.fill('[data-testid="appointment-time-input"]', '14:00');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Resource B' });
    await page.fill('[data-testid="appointment-duration-input"]', '30');
    
    // Step 4: Note the timestamp when requesting alternative suggestions and trigger the suggestion generation
    const startTime = Date.now();
    
    await page.click('[data-testid="schedule-appointment-button"]');
    await page.click('[data-testid="view-alternatives-button"]');
    
    // Step 5: Monitor the Network tab for the API response time
    // Wait for suggestions to appear and measure time
    await expect(page.locator('[data-testid="alternatives-panel"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="alternative-suggestion"]').first()).toBeVisible();
    
    const endTime = Date.now();
    const latency = endTime - startTime;
    
    // Step 6: Verify the total time from request initiation to suggestions appearing in the UI
    // Expected Result: Suggestions appear within 2 seconds
    expect(latency).toBeLessThan(2000);
    
    // Step 7: Repeat the test 3 more times with different conflict scenarios
    for (let i = 0; i < 3; i++) {
      await page.click('[data-testid="close-alternatives-button"]');
      await page.click('[data-testid="cancel-appointment-button"]');
      
      await page.click('[data-testid="create-appointment-button"]');
      await page.fill('[data-testid="appointment-date-input"]', `2024-02-${16 + i}`);
      await page.fill('[data-testid="appointment-time-input"]', `${15 + i}:00`);
      await page.selectOption('[data-testid="resource-select"]', { index: i + 1 });
      await page.fill('[data-testid="appointment-duration-input"]', '45');
      
      const iterationStartTime = Date.now();
      await page.click('[data-testid="schedule-appointment-button"]');
      await page.click('[data-testid="view-alternatives-button"]');
      await expect(page.locator('[data-testid="alternatives-panel"]')).toBeVisible({ timeout: 2000 });
      const iterationEndTime = Date.now();
      const iterationLatency = iterationEndTime - iterationStartTime;
      
      expect(iterationLatency).toBeLessThan(2000);
    }
  });

  test('Ensure suggestions reflect current resource availability (happy-path)', async ({ page }) => {
    // Step 1: Open the resource management view and document the current availability
    await page.goto('/resources');
    await page.waitForLoadState('networkidle');
    
    // Document current resource schedules
    const resourceSchedules: Record<string, string[]> = {};
    const resourceRows = page.locator('[data-testid="resource-row"]');
    const resourceCount = await resourceRows.count();
    
    for (let i = 0; i < resourceCount; i++) {
      const resourceRow = resourceRows.nth(i);
      const resourceName = await resourceRow.locator('[data-testid="resource-name"]').textContent();
      const bookedSlots = await resourceRow.locator('[data-testid="booked-slot"]').allTextContents();
      if (resourceName) {
        resourceSchedules[resourceName] = bookedSlots;
      }
    }
    
    // Step 2: Identify specific time slots where certain resources are already booked
    const conflictingResource = Object.keys(resourceSchedules)[0];
    const conflictingTimeSlot = resourceSchedules[conflictingResource][0];
    
    // Step 3: Navigate to the scheduling interface and attempt to create an appointment that triggers a conflict
    await page.goto('/scheduling');
    await page.waitForLoadState('networkidle');
    
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', '2024-02-20');
    await page.fill('[data-testid="appointment-time-input"]', '11:00');
    await page.selectOption('[data-testid="resource-select"]', { label: conflictingResource });
    await page.fill('[data-testid="appointment-duration-input"]', '60');
    
    // Step 4: Request alternative scheduling suggestions
    await page.click('[data-testid="schedule-appointment-button"]');
    await page.click('[data-testid="view-alternatives-button"]');
    
    // Step 5: Review each suggested time slot and resource combination
    await expect(page.locator('[data-testid="alternatives-panel"]')).toBeVisible();
    const suggestions = page.locator('[data-testid="alternative-suggestion"]');
    const suggestionCount = await suggestions.count();
    
    // Step 6: Cross-reference each suggested resource and time slot against documented schedules
    for (let i = 0; i < suggestionCount; i++) {
      const suggestion = suggestions.nth(i);
      const suggestedResource = await suggestion.locator('[data-testid="suggestion-resource"]').textContent();
      const suggestedTime = await suggestion.locator('[data-testid="suggestion-time"]').textContent();
      
      // Step 7: Verify that resources with known conflicts are NOT included in suggestions
      // Expected Result: Suggestions only include available resources and times
      if (suggestedResource && suggestedTime) {
        const resourceBookedSlots = resourceSchedules[suggestedResource] || [];
        const hasConflict = resourceBookedSlots.some(slot => slot === suggestedTime);
        expect(hasConflict).toBe(false);
      }
    }
    
    // Step 8: Check that suggestions only include time slots within valid scheduling hours
    for (let i = 0; i < suggestionCount; i++) {
      const suggestion = suggestions.nth(i);
      const suggestedTime = await suggestion.locator('[data-testid="suggestion-time"]').textContent();
      
      if (suggestedTime) {
        const hour = parseInt(suggestedTime.split(':')[0]);
        // Expected Result: Suggestions within valid working hours (8 AM to 6 PM)
        expect(hour).toBeGreaterThanOrEqual(8);
        expect(hour).toBeLessThan(18);
      }
    }
    
    // Verify at least one valid suggestion is provided
    expect(suggestionCount).toBeGreaterThan(0);
  });
});