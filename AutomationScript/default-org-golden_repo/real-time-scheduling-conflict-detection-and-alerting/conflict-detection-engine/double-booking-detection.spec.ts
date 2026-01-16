import { test, expect } from '@playwright/test';

test.describe('Double-Booking Detection for Resources Across Multiple Schedules', () => {
  
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/schedules');
    // Ensure user is authenticated
    await expect(page).toHaveURL(/.*schedules/);
  });

  test('Detect double-booking of resource across multiple schedules', async ({ page }) => {
    // Step 1: Create an appointment for Resource B in Schedule 1 from 14:00 to 15:00
    await page.click('[data-testid="schedule-1-link"]');
    await page.click('[data-testid="create-appointment-btn"]');
    
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Resource B' });
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.fill('[data-testid="appointment-title-input"]', 'Appointment 1 - Resource B');
    await page.fill('[data-testid="appointment-description-input"]', 'First appointment for Resource B');
    
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Expected Result: Appointment saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment saved successfully');
    
    // Step 2: Create an overlapping appointment for Resource B in Schedule 2 from 14:30 to 15:30
    await page.goto('/schedules');
    await page.click('[data-testid="schedule-2-link"]');
    await page.click('[data-testid="create-appointment-btn"]');
    
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Resource B' });
    await page.fill('[data-testid="start-time-input"]', '14:30');
    await page.fill('[data-testid="end-time-input"]', '15:30');
    await page.fill('[data-testid="appointment-title-input"]', 'Appointment 2 - Resource B');
    await page.fill('[data-testid="appointment-description-input"]', 'Second appointment for Resource B');
    
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Expected Result: System detects double-booking and flags conflict
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('double-booking');
    
    // Step 3: Review conflict details in UI
    await page.click('[data-testid="view-conflict-details-btn"]');
    
    // Expected Result: Conflict shows both appointments and schedules involved
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toContainText('Resource B');
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toContainText('Schedule 1');
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toContainText('Schedule 2');
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toContainText('14:00');
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toContainText('14:30');
  });

  test('Ensure conflict detection latency under 3 seconds', async ({ page }) => {
    // Create initial appointment for Resource C in Schedule 1
    await page.click('[data-testid="schedule-1-link"]');
    await page.click('[data-testid="create-appointment-btn"]');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Resource C' });
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.fill('[data-testid="appointment-title-input"]', 'Initial Appointment');
    await page.click('[data-testid="save-appointment-btn"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 1: Create or update appointment causing double-booking and measure latency
    await page.goto('/schedules');
    await page.click('[data-testid="schedule-2-link"]');
    await page.click('[data-testid="create-appointment-btn"]');
    
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Resource C' });
    await page.fill('[data-testid="start-time-input"]', '10:30');
    await page.fill('[data-testid="end-time-input"]', '11:30');
    await page.fill('[data-testid="appointment-title-input"]', 'Conflicting Appointment');
    
    const startTime = Date.now();
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Expected Result: System detects conflict within 3 seconds
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 3000 });
    const endTime = Date.now();
    const latency = endTime - startTime;
    
    expect(latency).toBeLessThan(3000);
    
    // Step 2: Verify conflict alert visibility
    // Expected Result: Alert is displayed promptly in UI
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('conflict');
  });

  test('Prevent saving double-booked appointments without override', async ({ page }) => {
    // Setup: Create initial appointment for Resource D in Schedule 1
    await page.click('[data-testid="schedule-1-link"]');
    await page.click('[data-testid="create-appointment-btn"]');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Resource D' });
    await page.fill('[data-testid="start-time-input"]', '16:00');
    await page.fill('[data-testid="end-time-input"]', '17:00');
    await page.fill('[data-testid="appointment-title-input"]', 'Original Appointment');
    await page.click('[data-testid="save-appointment-btn"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Log out current user
    await page.click('[data-testid="user-menu-btn"]');
    await page.click('[data-testid="logout-btn"]');
    
    // Step 1: Log in as user without override permission
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler_no_override');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-btn"]');
    await expect(page).toHaveURL(/.*schedules/);
    
    // Attempt to create double-booked appointment
    await page.click('[data-testid="schedule-2-link"]');
    await page.click('[data-testid="create-appointment-btn"]');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Resource D' });
    await page.fill('[data-testid="start-time-input"]', '16:30');
    await page.fill('[data-testid="end-time-input"]', '17:30');
    await page.fill('[data-testid="appointment-title-input"]', 'Conflicting Appointment');
    
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Expected Result: System blocks save and displays error message
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot save double-booked appointment');
    
    // Verify override option is not available
    await expect(page.locator('[data-testid="override-checkbox"]')).not.toBeVisible();
    
    // Verify appointment was not saved
    await page.goto('/schedules');
    await page.click('[data-testid="schedule-2-link"]');
    await expect(page.locator('text=Conflicting Appointment')).not.toBeVisible();
    
    // Step 2: Log out and log in as user with override permission
    await page.click('[data-testid="user-menu-btn"]');
    await page.click('[data-testid="logout-btn"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler_with_override');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-btn"]');
    await expect(page).toHaveURL(/.*schedules/);
    
    // Create the same double-booked appointment with override permission
    await page.click('[data-testid="schedule-2-link"]');
    await page.click('[data-testid="create-appointment-btn"]');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Resource D' });
    await page.fill('[data-testid="start-time-input"]', '16:30');
    await page.fill('[data-testid="end-time-input"]', '17:30');
    await page.fill('[data-testid="appointment-title-input"]', 'Conflicting Appointment with Override');
    
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Conflict warning should appear
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    // Override option should be available
    await expect(page.locator('[data-testid="override-checkbox"]')).toBeVisible();
    await page.check('[data-testid="override-checkbox"]');
    
    // Confirm override
    await page.click('[data-testid="confirm-override-btn"]');
    
    // Expected Result: System allows save and logs override action
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment saved with override');
    
    // Verify appointment was saved
    await page.goto('/schedules');
    await page.click('[data-testid="schedule-2-link"]');
    await expect(page.locator('text=Conflicting Appointment with Override')).toBeVisible();
    
    // Verify override action was logged
    await page.goto('/audit-logs');
    await expect(page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'override' })).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Resource D' })).toBeVisible();
  });
});