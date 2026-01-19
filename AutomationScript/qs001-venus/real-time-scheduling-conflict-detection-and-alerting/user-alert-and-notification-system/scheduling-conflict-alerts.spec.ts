import { test, expect } from '@playwright/test';

test.describe('Story-13: In-app alerts for scheduling conflicts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/scheduler');
    
    // Login as scheduler
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="scheduler-dashboard"]')).toBeVisible();
  });

  test('Verify in-app alert displays upon scheduling conflict', async ({ page }) => {
    // Step 1: Create an existing booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="booking-start-time"]', '10:00');
    await page.fill('[data-testid="booking-end-time"]', '11:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();
    
    // Step 2: Create a conflicting booking (same resource, overlapping time)
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="booking-start-time"]', '10:30');
    await page.fill('[data-testid="booking-end-time"]', '11:30');
    await page.click('[data-testid="save-booking-button"]');
    
    // Expected Result: In-app alert is displayed immediately
    const alert = page.locator('[data-testid="conflict-alert"]');
    await expect(alert).toBeVisible({ timeout: 2000 });
    
    // Step 3: Scheduler reviews alert details
    // Expected Result: Alert shows accurate conflict information
    await expect(alert.locator('[data-testid="conflict-resource"]')).toContainText('Conference Room A');
    await expect(alert.locator('[data-testid="conflict-time"]')).toContainText('10:30');
    await expect(alert.locator('[data-testid="conflict-details"]')).toBeVisible();
    
    // Step 4: Scheduler acknowledges and dismisses alert
    await page.click('[data-testid="acknowledge-alert-button"]');
    
    // Expected Result: Alert is removed from the interface
    await expect(alert).not.toBeVisible();
  });

  test('Ensure alerts persist until user dismissal or conflict resolution', async ({ page }) => {
    // Setup: Create a conflict to trigger an alert
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Meeting Room B');
    await page.fill('[data-testid="booking-date"]', '2024-03-16');
    await page.fill('[data-testid="booking-start-time"]', '14:00');
    await page.fill('[data-testid="booking-end-time"]', '15:00');
    await page.click('[data-testid="save-booking-button"]');
    
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Meeting Room B');
    await page.fill('[data-testid="booking-date"]', '2024-03-16');
    await page.fill('[data-testid="booking-start-time"]', '14:30');
    await page.fill('[data-testid="booking-end-time"]', '15:30');
    await page.click('[data-testid="save-booking-button"]');
    
    // Step 1: Scheduler receives alert for unresolved conflict
    const alert = page.locator('[data-testid="conflict-alert"]');
    // Expected Result: Alert remains visible
    await expect(alert).toBeVisible();
    
    // Step 2: Scheduler navigates to different pages without taking action
    await page.click('[data-testid="bookings-tab"]');
    // Expected Result: Alert persists on screen
    await expect(alert).toBeVisible();
    
    await page.click('[data-testid="resources-tab"]');
    await expect(alert).toBeVisible();
    
    await page.click('[data-testid="dashboard-tab"]');
    await expect(alert).toBeVisible();
    
    // Step 3: Scheduler dismisses alert
    await page.click('[data-testid="dismiss-alert-button"]');
    
    // Expected Result: Alert is removed
    await expect(alert).not.toBeVisible();
  });

  test('Test alert delivery latency under 1 second', async ({ page }) => {
    // Setup: Create initial booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Training Room C');
    await page.fill('[data-testid="booking-date"]', '2024-03-17');
    await page.fill('[data-testid="booking-start-time"]', '09:00');
    await page.fill('[data-testid="booking-end-time"]', '10:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();
    
    // Step 1: Record timestamp when conflict is created
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Training Room C');
    await page.fill('[data-testid="booking-date"]', '2024-03-17');
    await page.fill('[data-testid="booking-start-time"]', '09:15');
    await page.fill('[data-testid="booking-end-time"]', '10:15');
    
    const startTime = Date.now();
    await page.click('[data-testid="save-booking-button"]');
    
    // Step 2: Wait for alert to appear and record timestamp
    const alert = page.locator('[data-testid="conflict-alert"]');
    await alert.waitFor({ state: 'visible', timeout: 2000 });
    const endTime = Date.now();
    
    // Step 3: Calculate time difference
    const latency = endTime - startTime;
    
    // Expected Result: Alert appears in-app within 1 second (1000ms)
    expect(latency).toBeLessThan(1000);
    
    // Verify alert is actually visible
    await expect(alert).toBeVisible();
    await expect(alert.locator('[data-testid="conflict-resource"]')).toContainText('Training Room C');
  });
});