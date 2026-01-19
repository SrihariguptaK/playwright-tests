import { test, expect } from '@playwright/test';

test.describe('Alternative Time Slot Suggestions', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SUGGESTION_TIMEOUT = 2000;

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/scheduling`);
    await expect(page).toHaveTitle(/Scheduling|Schedule/);
  });

  test('Verify alternative time slot suggestions generation', async ({ page }) => {
    // Step 1: Navigate to scheduling form and create a conflict
    await page.fill('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="date-input"]', '2024-06-15');
    await page.fill('[data-testid="time-input"]', '10:00');
    await page.fill('[data-testid="duration-input"]', '60');
    
    // Trigger conflict detection
    await page.click('[data-testid="check-availability-button"]');
    
    // Start timer and wait for suggestions
    const startTime = Date.now();
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="alternative-suggestions-container"]')).toBeVisible({ timeout: SUGGESTION_TIMEOUT });
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    // Verify suggestions generated within 2 seconds
    expect(responseTime).toBeLessThanOrEqual(SUGGESTION_TIMEOUT);
    
    // Step 2: Review suggested slots
    const suggestionItems = page.locator('[data-testid="alternative-slot-item"]');
    const suggestionCount = await suggestionItems.count();
    expect(suggestionCount).toBeGreaterThan(0);
    
    // Verify suggestions are valid and conflict-free
    for (let i = 0; i < suggestionCount; i++) {
      const suggestion = suggestionItems.nth(i);
      await expect(suggestion).toBeVisible();
      await expect(suggestion.locator('[data-testid="slot-time"]')).toContainText(/\d{1,2}:\d{2}/);
      await expect(suggestion.locator('[data-testid="conflict-status"]')).toContainText(/Available|Free/);
    }
    
    // Step 3: Select an alternative slot
    await suggestionItems.first().click();
    
    // Verify scheduling form updates with selected slot
    await expect(page.locator('[data-testid="time-input"]')).not.toHaveValue('10:00');
    const updatedTime = await page.locator('[data-testid="time-input"]').inputValue();
    expect(updatedTime).toBeTruthy();
    expect(updatedTime).toMatch(/\d{1,2}:\d{2}/);
  });

  test('Test application of selected alternative slot', async ({ page }) => {
    // Create a conflict scenario
    await page.fill('[data-testid="resource-select"]', 'Meeting Room B');
    await page.fill('[data-testid="date-input"]', '2024-06-16');
    await page.fill('[data-testid="time-input"]', '14:00');
    await page.fill('[data-testid="duration-input"]', '90');
    await page.fill('[data-testid="title-input"]', 'Team Meeting');
    
    await page.click('[data-testid="check-availability-button"]');
    
    // Wait for conflict and suggestions
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="alternative-suggestions-container"]')).toBeVisible();
    
    // Step 1: Select alternative slot from suggestions
    const alternativeSlot = page.locator('[data-testid="alternative-slot-item"]').nth(1);
    const selectedTime = await alternativeSlot.locator('[data-testid="slot-time"]').textContent();
    await alternativeSlot.click();
    
    // Verify scheduling form fields update accordingly
    await expect(page.locator('[data-testid="time-input"]')).toHaveValue(selectedTime || '');
    await expect(page.locator('[data-testid="resource-select"]')).toHaveValue('Meeting Room B');
    await expect(page.locator('[data-testid="date-input"]')).toHaveValue('2024-06-16');
    await expect(page.locator('[data-testid="title-input"]')).toHaveValue('Team Meeting');
    
    // Step 2: Submit schedule with alternative slot
    await page.click('[data-testid="submit-booking-button"]');
    
    // Wait for confirmation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/Success|Confirmed|Booked/);
    
    // Step 3: Verify no conflict alerts displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Verify booking in calendar view
    await page.click('[data-testid="view-calendar-link"]');
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
    await expect(page.locator(`[data-testid="booking-item"]:has-text("Team Meeting")`)).toBeVisible();
  });

  test('Ensure suggestion generation performance', async ({ page }) => {
    // Step 1: Request alternative slots during conflict
    await page.fill('[data-testid="resource-select"]', 'Training Room C');
    await page.fill('[data-testid="date-input"]', '2024-06-20');
    await page.fill('[data-testid="time-input"]', '09:00');
    await page.fill('[data-testid="duration-input"]', '120');
    
    // Measure performance
    const performanceStartTime = Date.now();
    await page.click('[data-testid="check-availability-button"]');
    
    // Wait for conflict detection
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    // Wait for suggestions and measure time
    await expect(page.locator('[data-testid="alternative-suggestions-container"]')).toBeVisible();
    const performanceEndTime = Date.now();
    const suggestionGenerationTime = performanceEndTime - performanceStartTime;
    
    // Verify suggestions returned within 2 seconds
    expect(suggestionGenerationTime).toBeLessThanOrEqual(SUGGESTION_TIMEOUT);
    
    // Step 2: Monitor system performance (verify no degradation)
    const suggestionItems = page.locator('[data-testid="alternative-slot-item"]');
    const itemCount = await suggestionItems.count();
    expect(itemCount).toBeGreaterThan(0);
    expect(itemCount).toBeLessThanOrEqual(10); // Reasonable number of suggestions
    
    // Verify page remains responsive
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeEnabled();
    
    // Step 3: Verify suggestion accuracy - all suggested slots are conflict-free
    for (let i = 0; i < itemCount; i++) {
      const suggestion = suggestionItems.nth(i);
      
      // Verify each suggestion has required information
      await expect(suggestion.locator('[data-testid="slot-time"]')).toBeVisible();
      await expect(suggestion.locator('[data-testid="slot-date"]')).toBeVisible();
      await expect(suggestion.locator('[data-testid="conflict-status"]')).toContainText(/Available|Free|No Conflict/);
      
      // Verify slot time format
      const slotTime = await suggestion.locator('[data-testid="slot-time"]').textContent();
      expect(slotTime).toMatch(/\d{1,2}:\d{2}/);
      
      // Verify no conflict indicator
      await expect(suggestion.locator('[data-testid="conflict-indicator"]')).not.toBeVisible();
    }
    
    // Test with different resource to ensure consistent performance
    await page.fill('[data-testid="resource-select"]', 'Conference Room D');
    await page.fill('[data-testid="date-input"]', '2024-06-21');
    await page.fill('[data-testid="time-input"]', '15:00');
    
    const secondTestStartTime = Date.now();
    await page.click('[data-testid="check-availability-button"]');
    await expect(page.locator('[data-testid="alternative-suggestions-container"]')).toBeVisible();
    const secondTestEndTime = Date.now();
    const secondTestTime = secondTestEndTime - secondTestStartTime;
    
    // Verify consistent performance across different resources
    expect(secondTestTime).toBeLessThanOrEqual(SUGGESTION_TIMEOUT);
  });
});