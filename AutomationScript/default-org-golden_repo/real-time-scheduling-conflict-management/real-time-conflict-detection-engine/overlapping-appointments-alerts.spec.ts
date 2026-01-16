import { test, expect } from '@playwright/test';

test.describe('Overlapping Appointments Alert System', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to the application and ensure logged in as Scheduler
    await page.goto(BASE_URL);
    // Assuming authentication is handled or user is already logged in
  });

  test('Validate real-time detection of overlapping appointments', async ({ page }) => {
    // Step 1: Navigate to appointment creation page
    await page.click('button:has-text("Create Appointment"), a:has-text("Create Appointment")');
    await expect(page.locator('[data-testid="appointment-form"], form')).toBeVisible();

    // Step 2: Enter appointment details overlapping with existing appointment
    // Assuming existing appointment: Room A, 10:00 AM - 11:00 AM on today's date
    const today = new Date().toISOString().split('T')[0];
    
    await page.fill('[data-testid="appointment-date"], input[name="date"], input[type="date"]', today);
    await page.fill('[data-testid="appointment-start-time"], input[name="startTime"], input[type="time"]', '10:30');
    await page.fill('[data-testid="appointment-duration"], input[name="duration"], select[name="duration"]', '60');
    await page.selectOption('[data-testid="resource-select"], select[name="resource"]', { label: 'Room A' });

    // Expected Result: Real-time alert is displayed indicating conflict
    await expect(page.locator('[data-testid="conflict-alert"], .alert-conflict, .conflict-warning')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-alert"], .alert-conflict, .conflict-warning')).toContainText(/conflict|overlap|already booked/i);

    // Step 3: Attempt to save appointment without resolving conflict
    await page.click('[data-testid="save-appointment"], button:has-text("Save"), button[type="submit"]');

    // Expected Result: System prevents save and displays confirmation prompt
    await expect(page.locator('[data-testid="confirmation-dialog"], .confirmation-modal, dialog')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-dialog"], .confirmation-modal, dialog')).toContainText(/confirm|override|conflict/i);
  });

  test('Verify conflict detection latency under 1 second', async ({ page }) => {
    // Step 1: Navigate to appointment creation page
    await page.click('button:has-text("Create Appointment"), a:has-text("Create Appointment")');
    await expect(page.locator('[data-testid="appointment-form"], form')).toBeVisible();

    // Setup network monitoring
    const apiCalls: number[] = [];
    page.on('response', response => {
      if (response.url().includes('/appointments/check-conflict')) {
        apiCalls.push(Date.now());
      }
    });

    // Step 2: Input appointment details triggering conflict and measure time
    const today = new Date().toISOString().split('T')[0];
    
    await page.fill('[data-testid="appointment-date"], input[name="date"], input[type="date"]', today);
    await page.fill('[data-testid="appointment-start-time"], input[name="startTime"], input[type="time"]', '10:30');
    await page.fill('[data-testid="appointment-duration"], input[name="duration"], select[name="duration"]', '60');
    
    const startTime = Date.now();
    await page.selectOption('[data-testid="resource-select"], select[name="resource"]', { label: 'Room A' });

    // Wait for alert to appear and measure latency
    await page.waitForSelector('[data-testid="conflict-alert"], .alert-conflict, .conflict-warning', { timeout: 2000 });
    const endTime = Date.now();
    const latency = endTime - startTime;

    // Expected Result: Latency is less than 1 second (1000ms)
    expect(latency).toBeLessThan(1000);
    await expect(page.locator('[data-testid="conflict-alert"], .alert-conflict, .conflict-warning')).toBeVisible();
  });

  test('Ensure conflict detection supports multiple resource types - Personnel', async ({ page }) => {
    // Step 1: Navigate to appointment creation page and select Personnel resource type
    await page.click('button:has-text("Create Appointment"), a:has-text("Create Appointment")');
    await expect(page.locator('[data-testid="appointment-form"], form')).toBeVisible();

    // Step 2: Create appointment with personnel resource conflict
    const today = new Date().toISOString().split('T')[0];
    
    await page.selectOption('[data-testid="resource-type"], select[name="resourceType"]', { label: 'Personnel' });
    await page.fill('[data-testid="appointment-date"], input[name="date"], input[type="date"]', today);
    await page.fill('[data-testid="appointment-start-time"], input[name="startTime"], input[type="time"]', '14:30');
    await page.fill('[data-testid="appointment-duration"], input[name="duration"], select[name="duration"]', '60');
    await page.selectOption('[data-testid="resource-select"], select[name="resource"]', { label: 'Dr. Smith' });

    // Expected Result: Conflict alert is displayed for personnel
    await expect(page.locator('[data-testid="conflict-alert"], .alert-conflict, .conflict-warning')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-alert"], .alert-conflict, .conflict-warning')).toContainText(/conflict|overlap|Dr. Smith/i);
  });

  test('Ensure conflict detection supports multiple resource types - Room', async ({ page }) => {
    // Step 1: Navigate to appointment creation page and select Room resource type
    await page.click('button:has-text("Create Appointment"), a:has-text("Create Appointment")');
    await expect(page.locator('[data-testid="appointment-form"], form')).toBeVisible();

    // Step 2: Create appointment with room resource conflict
    const today = new Date().toISOString().split('T')[0];
    
    await page.selectOption('[data-testid="resource-type"], select[name="resourceType"]', { label: 'Room' });
    await page.fill('[data-testid="appointment-date"], input[name="date"], input[type="date"]', today);
    await page.fill('[data-testid="appointment-start-time"], input[name="startTime"], input[type="time"]', '15:15');
    await page.fill('[data-testid="appointment-duration"], input[name="duration"], select[name="duration"]', '60');
    await page.selectOption('[data-testid="resource-select"], select[name="resource"]', { label: 'Conference Room B' });

    // Expected Result: Conflict alert is displayed for room
    await expect(page.locator('[data-testid="conflict-alert"], .alert-conflict, .conflict-warning')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-alert"], .alert-conflict, .conflict-warning')).toContainText(/conflict|overlap|Conference Room B/i);
  });
});