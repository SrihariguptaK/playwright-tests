import { test, expect } from '@playwright/test';

test.describe('Cross-Calendar Conflict Detection', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling system
    await page.goto('/scheduling');
    // Wait for the page to load
    await page.waitForLoadState('networkidle');
  });

  test('Detect conflicts across multiple calendars', async ({ page }) => {
    // Step 1: Navigate to Team A Calendar and create a booking for a shared resource
    await page.click('[data-testid="calendar-selector"]');
    await page.click('text=Team A Calendar');
    await page.waitForSelector('[data-testid="team-a-calendar"]');
    
    // Create booking in Team A Calendar
    await page.click('[data-testid="create-booking-btn"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room 1');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.click('[data-testid="submit-booking-btn"]');
    
    // Verify booking created successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('text=Conference Room 1')).toBeVisible();
    
    // Step 2: Navigate to Team B Calendar
    await page.click('[data-testid="calendar-selector"]');
    await page.click('text=Team B Calendar');
    await page.waitForSelector('[data-testid="team-b-calendar"]');
    
    // Step 3: Attempt to create a booking with overlapping time slot
    await page.click('[data-testid="create-booking-btn"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room 1');
    await page.fill('[data-testid="start-time-input"]', '14:30');
    await page.fill('[data-testid="end-time-input"]', '15:30');
    await page.click('[data-testid="submit-booking-btn"]');
    
    // Expected Result: System detects conflict involving multiple calendars
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 5000 });
    
    // Step 4: Receive alert with cross-calendar conflict details
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toContainText('Conference Room 1');
    await expect(conflictAlert).toContainText('Team A Calendar');
    await expect(conflictAlert).toContainText('14:00');
    await expect(conflictAlert).toContainText('15:00');
    
    // Expected Result: Alert accurately reflects all conflicting bookings
    const conflictDetails = await page.locator('[data-testid="conflict-details"]').textContent();
    expect(conflictDetails).toBeTruthy();
    
    // Step 5: Navigate back to Team B Calendar booking form
    await page.click('[data-testid="close-conflict-alert"]');
    
    // Step 6: Modify the booking time to a non-conflicting time slot
    await page.fill('[data-testid="start-time-input"]', '15:30');
    await page.fill('[data-testid="end-time-input"]', '16:30');
    await page.click('[data-testid="submit-booking-btn"]');
    
    // Expected Result: Conflict alert is cleared
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 7: Verify both calendars show correct bookings without conflicts
    await page.click('[data-testid="calendar-selector"]');
    await page.click('text=Team A Calendar');
    await expect(page.locator('text=Conference Room 1').first()).toBeVisible();
    await expect(page.locator('text=14:00')).toBeVisible();
    
    await page.click('[data-testid="calendar-selector"]');
    await page.click('text=Team B Calendar');
    await expect(page.locator('text=Conference Room 1').first()).toBeVisible();
    await expect(page.locator('text=15:30')).toBeVisible();
  });

  test('Verify conflict detection latency with multiple calendars', async ({ page }) => {
    // Prepare: Create a booking in Calendar A first
    await page.click('[data-testid="calendar-selector"]');
    await page.click('text=Calendar A');
    await page.waitForSelector('[data-testid="calendar-a"]');
    
    await page.click('[data-testid="create-booking-btn"]');
    await page.fill('[data-testid="resource-input"]', 'Projector X');
    await page.fill('[data-testid="start-time-input"]', '13:00');
    await page.fill('[data-testid="end-time-input"]', '14:00');
    await page.click('[data-testid="submit-booking-btn"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 1: Navigate to Calendar C
    await page.click('[data-testid="calendar-selector"]');
    await page.click('text=Calendar C');
    await page.waitForSelector('[data-testid="calendar-c"]');
    
    // Step 2: Start timer and input booking with overlapping time
    const startTime = Date.now();
    
    await page.click('[data-testid="create-booking-btn"]');
    await page.fill('[data-testid="resource-input"]', 'Projector X');
    await page.fill('[data-testid="start-time-input"]', '13:30');
    await page.fill('[data-testid="end-time-input"]', '14:30');
    await page.click('[data-testid="submit-booking-btn"]');
    
    // Step 3: Wait for conflict alert and measure latency
    await page.waitForSelector('[data-testid="conflict-alert"]', { timeout: 3000 });
    const endTime = Date.now();
    const latency = endTime - startTime;
    
    // Expected Result: Conflict detected within 2 seconds
    expect(latency).toBeLessThan(2000);
    console.log(`Conflict detection latency: ${latency}ms`);
    
    // Verify conflict alert is displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Projector X');
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Calendar A');
    
    // Close the conflict alert
    await page.click('[data-testid="close-conflict-alert"]');
    
    // Test iteration 2: Calendar B to Calendar C
    await page.click('[data-testid="calendar-selector"]');
    await page.click('text=Calendar B');
    await page.waitForSelector('[data-testid="calendar-b"]');
    
    await page.click('[data-testid="create-booking-btn"]');
    await page.fill('[data-testid="resource-input"]', 'Meeting Room 5');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.click('[data-testid="submit-booking-btn"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    await page.click('[data-testid="calendar-selector"]');
    await page.click('text=Calendar C');
    
    const startTime2 = Date.now();
    await page.click('[data-testid="create-booking-btn"]');
    await page.fill('[data-testid="resource-input"]', 'Meeting Room 5');
    await page.fill('[data-testid="start-time-input"]', '10:30');
    await page.fill('[data-testid="end-time-input"]', '11:30');
    await page.click('[data-testid="submit-booking-btn"]');
    
    await page.waitForSelector('[data-testid="conflict-alert"]', { timeout: 3000 });
    const endTime2 = Date.now();
    const latency2 = endTime2 - startTime2;
    
    expect(latency2).toBeLessThan(2000);
    console.log(`Conflict detection latency (iteration 2): ${latency2}ms`);
    
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Meeting Room 5');
    
    // Test iteration 3: Calendar A to Calendar B
    await page.click('[data-testid="close-conflict-alert"]');
    await page.click('[data-testid="calendar-selector"]');
    await page.click('text=Calendar A');
    
    await page.click('[data-testid="create-booking-btn"]');
    await page.fill('[data-testid="resource-input"]', 'Laptop Cart');
    await page.fill('[data-testid="start-time-input"]', '15:00');
    await page.fill('[data-testid="end-time-input"]', '16:00');
    await page.click('[data-testid="submit-booking-btn"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    await page.click('[data-testid="calendar-selector"]');
    await page.click('text=Calendar B');
    
    const startTime3 = Date.now();
    await page.click('[data-testid="create-booking-btn"]');
    await page.fill('[data-testid="resource-input"]', 'Laptop Cart');
    await page.fill('[data-testid="start-time-input"]', '15:30');
    await page.fill('[data-testid="end-time-input"]', '16:30');
    await page.click('[data-testid="submit-booking-btn"]');
    
    await page.waitForSelector('[data-testid="conflict-alert"]', { timeout: 3000 });
    const endTime3 = Date.now();
    const latency3 = endTime3 - startTime3;
    
    expect(latency3).toBeLessThan(2000);
    console.log(`Conflict detection latency (iteration 3): ${latency3}ms`);
    
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Laptop Cart');
    
    // Verify average latency across all iterations
    const averageLatency = (latency + latency2 + latency3) / 3;
    console.log(`Average conflict detection latency: ${averageLatency}ms`);
    expect(averageLatency).toBeLessThan(2000);
  });
});