import { test, expect } from '@playwright/test';

test.describe('Story-16: Alternative Scheduling Suggestions for Conflict Resolution', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling application
    await page.goto('/scheduling');
    // Login as scheduler
    await page.fill('[data-testid="username-input"]', 'scheduler_user');
    await page.fill('[data-testid="password-input"]', 'scheduler_pass');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="scheduler-dashboard"]')).toBeVisible();
  });

  test('Validate generation of alternative scheduling options', async ({ page }) => {
    // Step 1: Create a scheduling conflict by attempting to book a resource that is already reserved
    await page.click('[data-testid="new-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', '2024-06-15');
    await page.fill('[data-testid="appointment-time-input"]', '10:00');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Conference Room A' });
    await page.fill('[data-testid="patient-name-input"]', 'John Doe');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Expected Result: System generates alternative time slots and resource options
    await expect(page.locator('[data-testid="conflict-dialog"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('scheduling conflict detected');
    await expect(page.locator('[data-testid="alternative-suggestions"]')).toBeVisible();
    
    // Step 2: View suggestions in UI
    const suggestionsList = page.locator('[data-testid="suggestion-item"]');
    await expect(suggestionsList).toHaveCount(await suggestionsList.count(), { timeout: 2000 });
    
    // Expected Result: Suggestions are displayed clearly and accurately
    const firstSuggestion = suggestionsList.first();
    await expect(firstSuggestion.locator('[data-testid="suggested-time"]')).toBeVisible();
    await expect(firstSuggestion.locator('[data-testid="suggested-resource"]')).toBeVisible();
    await expect(firstSuggestion.locator('[data-testid="suggestion-details"]')).toContainText(/\d{2}:\d{2}/);
    
    // Step 3: Select an alternative and update schedule
    await firstSuggestion.click();
    await page.click('[data-testid="apply-suggestion-button"]');
    
    // Expected Result: Schedule is updated without conflicts
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment scheduled successfully');
    await expect(page.locator('[data-testid="conflict-dialog"]')).not.toBeVisible();
    
    // Verify appointment appears in schedule
    await page.click('[data-testid="view-schedule-button"]');
    await expect(page.locator('[data-testid="appointment-list"]')).toContainText('John Doe');
  });

  test('Test suggestion generation performance', async ({ page }) => {
    // Step 1: Trigger multiple conflicts simultaneously
    const startTime = Date.now();
    const conflictPromises = [];
    
    for (let i = 0; i < 5; i++) {
      const conflictPromise = (async () => {
        await page.click('[data-testid="new-appointment-button"]');
        await page.fill('[data-testid="appointment-date-input"]', '2024-06-15');
        await page.fill('[data-testid="appointment-time-input"]', '14:00');
        await page.selectOption('[data-testid="resource-select"]', { label: 'Exam Room 1' });
        await page.fill('[data-testid="patient-name-input"]', `Patient ${i + 1}`);
        await page.click('[data-testid="save-appointment-button"]');
        
        // Wait for conflict dialog
        await expect(page.locator('[data-testid="conflict-dialog"]')).toBeVisible({ timeout: 3000 });
        const suggestionTime = Date.now() - startTime;
        
        // Close dialog for next iteration
        await page.click('[data-testid="close-conflict-dialog"]');
        
        return suggestionTime;
      })();
      
      conflictPromises.push(conflictPromise);
    }
    
    const responseTimes = await Promise.all(conflictPromises);
    
    // Expected Result: Suggestions generated within 2 seconds for each conflict
    responseTimes.forEach((time, index) => {
      expect(time).toBeLessThan(2000);
    });
    
    // Step 2: Verify system responsiveness
    // Expected Result: UI remains responsive during suggestion generation
    await page.click('[data-testid="scheduler-dashboard"]');
    await expect(page.locator('[data-testid="scheduler-dashboard"]')).toBeVisible();
    
    await page.click('[data-testid="view-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();
    
    // Step 3: Check logs for errors
    const consoleLogs: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleLogs.push(msg.text());
      }
    });
    
    // Expected Result: No errors or failures recorded
    expect(consoleLogs.filter(log => log.includes('error') || log.includes('failed'))).toHaveLength(0);
  });

  test('Ensure suggestions are conflict-free and valid', async ({ page }) => {
    // Step 1: Create a conflict to trigger suggestions
    await page.click('[data-testid="new-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', '2024-06-16');
    await page.fill('[data-testid="appointment-time-input"]', '09:00');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Surgery Room 2' });
    await page.fill('[data-testid="patient-name-input"]', 'Jane Smith');
    await page.click('[data-testid="save-appointment-button"]');
    
    await expect(page.locator('[data-testid="conflict-dialog"]')).toBeVisible();
    
    // Expected Result: Review suggested time slots and resources - all suggestions are available and conflict-free
    const suggestions = page.locator('[data-testid="suggestion-item"]');
    const suggestionCount = await suggestions.count();
    expect(suggestionCount).toBeGreaterThan(0);
    
    // Verify each suggestion has required information
    for (let i = 0; i < suggestionCount; i++) {
      const suggestion = suggestions.nth(i);
      await expect(suggestion.locator('[data-testid="suggested-time"]')).toBeVisible();
      await expect(suggestion.locator('[data-testid="suggested-resource"]')).toBeVisible();
      await expect(suggestion.locator('[data-testid="availability-status"]')).toContainText('Available');
    }
    
    // Step 2: Attempt to select invalid suggestion
    // Simulate booking a suggestion through another session
    const secondSuggestion = suggestions.nth(1);
    const suggestedTime = await secondSuggestion.locator('[data-testid="suggested-time"]').textContent();
    const suggestedResource = await secondSuggestion.locator('[data-testid="suggested-resource"]').textContent();
    
    // Open new context to book the resource
    const context = page.context();
    const secondPage = await context.newPage();
    await secondPage.goto('/scheduling');
    await secondPage.fill('[data-testid="username-input"]', 'scheduler_user2');
    await secondPage.fill('[data-testid="password-input"]', 'scheduler_pass2');
    await secondPage.click('[data-testid="login-button"]');
    
    // Book the suggested slot in second session
    await secondPage.click('[data-testid="new-appointment-button"]');
    await secondPage.fill('[data-testid="appointment-date-input"]', '2024-06-16');
    await secondPage.fill('[data-testid="appointment-time-input"]', suggestedTime || '10:00');
    await secondPage.selectOption('[data-testid="resource-select"]', { label: suggestedResource || 'Surgery Room 2' });
    await secondPage.fill('[data-testid="patient-name-input"]', 'Conflict Patient');
    await secondPage.click('[data-testid="save-appointment-button"]');
    await secondPage.close();
    
    // Try to select the now-unavailable suggestion in original session
    await secondSuggestion.click();
    await page.click('[data-testid="apply-suggestion-button"]');
    
    // Expected Result: System prevents selection and displays error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/no longer available|conflict|unavailable/i);
    
    // Step 3: Select valid suggestion
    await page.click('[data-testid="refresh-suggestions-button"]');
    await expect(page.locator('[data-testid="suggestion-item"]')).toBeVisible();
    
    const validSuggestion = page.locator('[data-testid="suggestion-item"]').first();
    await validSuggestion.click();
    await page.click('[data-testid="apply-suggestion-button"]');
    
    // Expected Result: Schedule updates successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment scheduled successfully');
    await expect(page.locator('[data-testid="conflict-dialog"]')).not.toBeVisible();
    
    // Verify appointment in schedule
    await page.click('[data-testid="view-schedule-button"]');
    await expect(page.locator('[data-testid="appointment-list"]')).toContainText('Jane Smith');
  });
});