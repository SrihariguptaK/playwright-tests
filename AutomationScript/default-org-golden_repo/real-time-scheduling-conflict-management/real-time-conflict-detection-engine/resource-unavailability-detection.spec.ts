import { test, expect } from '@playwright/test';

test.describe('Resource Unavailability Conflict Detection', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling page before each test
    await page.goto(`${BASE_URL}/scheduling`);
  });

  test('Validate detection of resource unavailability conflicts (happy-path)', async ({ page }) => {
    // Step 1: Navigate to scheduling page
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();
    
    // Step 2: Fill in appointment date and time fields
    await page.fill('[data-testid="appointment-date"]', '2024-12-15');
    await page.fill('[data-testid="appointment-time"]', '10:00');
    
    // Step 3: Select a resource that is marked as unavailable from the resource dropdown
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-unavailable"]');
    
    // Step 4: Verify the alert message contains resource name, unavailability reason, and time period
    const alertMessage = page.locator('[data-testid="unavailability-alert"]');
    await expect(alertMessage).toBeVisible({ timeout: 1000 });
    await expect(alertMessage).toContainText(/resource name/i);
    await expect(alertMessage).toContainText(/unavailability reason/i);
    await expect(alertMessage).toContainText(/time period/i);
    
    // Step 5: Attempt to save the appointment with the unavailable resource without override
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Verify system blocks save
    const errorMessage = page.locator('[data-testid="save-blocked-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/cannot save.*unavailable resource/i);
    
    // Step 6: Click on override option (if available) and confirm the override action
    const overrideButton = page.locator('[data-testid="override-unavailability-btn"]');
    if (await overrideButton.isVisible()) {
      await overrideButton.click();
      
      // Step 7: Confirm the override and save the appointment
      await page.click('[data-testid="confirm-override-btn"]');
      await page.click('[data-testid="save-appointment-btn"]');
      
      // Verify successful save with override
      const successMessage = page.locator('[data-testid="appointment-saved-message"]');
      await expect(successMessage).toBeVisible();
      await expect(successMessage).toContainText(/appointment saved/i);
    }
  });

  test('Verify alert latency under 1 second (boundary)', async ({ page }) => {
    // Step 1: Navigate to the scheduling page and prepare to measure response time
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();
    
    const unavailableResources = ['resource-1-unavailable', 'resource-2-unavailable', 'resource-3-unavailable'];
    const latencyResults: number[] = [];
    
    for (const resourceId of unavailableResources) {
      // Step 2: Start timer and input appointment date and time
      await page.fill('[data-testid="appointment-date"]', '2024-12-15');
      await page.fill('[data-testid="appointment-time"]', '14:00');
      
      // Step 3: Select a resource marked as unavailable and stop timer when alert appears
      const startTime = Date.now();
      await page.click('[data-testid="resource-dropdown"]');
      await page.click(`[data-testid="${resourceId}"]`);
      
      // Wait for alert to appear and measure time
      await page.waitForSelector('[data-testid="unavailability-alert"]', { state: 'visible' });
      const endTime = Date.now();
      const latency = endTime - startTime;
      
      // Step 4: Record the exact time taken for alert to appear
      latencyResults.push(latency);
      
      // Step 6: Verify alert content is complete and not truncated due to speed optimization
      const alertContent = page.locator('[data-testid="unavailability-alert"]');
      await expect(alertContent).toContainText(/resource/i);
      await expect(alertContent).toContainText(/unavailable/i);
      
      // Verify latency is under 1 second (1000ms)
      expect(latency).toBeLessThan(1000);
      
      // Clear selection for next iteration
      await page.click('[data-testid="clear-resource-btn"]');
    }
    
    // Step 5: Verify all iterations met the latency requirement
    const averageLatency = latencyResults.reduce((a, b) => a + b, 0) / latencyResults.length;
    expect(averageLatency).toBeLessThan(1000);
  });

  test('Ensure detection supports all resource types (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the scheduling page
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();
    
    const resourceTypes = [
      { category: 'Room', testId: 'room-unavailable-1', categoryTestId: 'category-room' },
      { category: 'Equipment', testId: 'equipment-unavailable-1', categoryTestId: 'category-equipment' },
      { category: 'Personnel', testId: 'personnel-unavailable-1', categoryTestId: 'category-personnel' },
      { category: 'Vehicle', testId: 'vehicle-unavailable-1', categoryTestId: 'category-vehicle' }
    ];
    
    for (const resourceType of resourceTypes) {
      // Fill in appointment details
      await page.fill('[data-testid="appointment-date"]', '2024-12-20');
      await page.fill('[data-testid="appointment-time"]', '09:00');
      
      // Step 2-5: Select resource category and choose unavailable resource
      await page.click('[data-testid="resource-category-dropdown"]');
      await page.click(`[data-testid="${resourceType.categoryTestId}"]`);
      
      await page.click('[data-testid="resource-dropdown"]');
      await page.click(`[data-testid="${resourceType.testId}"]`);
      
      // Verify alert is displayed
      const alert = page.locator('[data-testid="unavailability-alert"]');
      await expect(alert).toBeVisible({ timeout: 1000 });
      
      // Step 6: Verify each alert contains category-specific unavailability information
      await expect(alert).toContainText(new RegExp(resourceType.category, 'i'));
      await expect(alert).toContainText(/unavailable/i);
      
      // Step 7: Attempt to save appointments with each unavailable resource type
      await page.click('[data-testid="save-appointment-btn"]');
      
      // Verify save is blocked
      const blockMessage = page.locator('[data-testid="save-blocked-message"]');
      await expect(blockMessage).toBeVisible();
      
      // Clear selection for next iteration
      await page.click('[data-testid="clear-selection-btn"]');
    }
    
    // Step 8: Test with available resources from each category
    for (const resourceType of resourceTypes) {
      await page.fill('[data-testid="appointment-date"]', '2024-12-20');
      await page.fill('[data-testid="appointment-time"]', '11:00');
      
      await page.click('[data-testid="resource-category-dropdown"]');
      await page.click(`[data-testid="${resourceType.categoryTestId}"]`);
      
      await page.click('[data-testid="resource-dropdown"]');
      await page.click(`[data-testid="${resourceType.testId.replace('unavailable', 'available')}"]`);
      
      // Verify no alert is displayed for available resources
      const alert = page.locator('[data-testid="unavailability-alert"]');
      await expect(alert).not.toBeVisible();
      
      // Verify save is allowed
      await page.click('[data-testid="save-appointment-btn"]');
      const successMessage = page.locator('[data-testid="appointment-saved-message"]');
      await expect(successMessage).toBeVisible();
      
      // Clear for next iteration
      await page.click('[data-testid="new-appointment-btn"]');
    }
  });
});