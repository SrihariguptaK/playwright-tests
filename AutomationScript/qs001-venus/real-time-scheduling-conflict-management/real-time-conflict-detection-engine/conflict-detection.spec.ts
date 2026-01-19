import { test, expect } from '@playwright/test';

test.describe('Conflict Detection for Schedule Creation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate immediate conflict detection on overlapping schedule creation (happy-path)', async ({ page }) => {
    // Step 1: Navigate to schedule creation page from main dashboard
    await page.click('[data-testid="schedule-creation-link"]');
    await expect(page.locator('[data-testid="schedule-creation-form"]')).toBeVisible();
    
    // Step 2: Select a date from the date picker that has existing bookings
    await page.click('[data-testid="date-picker"]');
    await page.click('[data-testid="date-option-with-bookings"]');
    
    // Step 3: Enter a start time that overlaps with an existing booking (10:00 AM when 9:00 AM - 11:00 AM is already booked)
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.selectOption('[data-testid="start-time-period"]', 'AM');
    
    // Step 4: Enter an end time for the schedule (12:00 PM)
    await page.fill('[data-testid="end-time-input"]', '12:00');
    await page.selectOption('[data-testid="end-time-period"]', 'PM');
    
    // Step 5: Select a resource from the dropdown that is already booked for the selected time slot
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Conference Room A' });
    
    // Verify conflict alert is displayed instantly
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('conflict');
    
    // Step 6: Attempt to click the 'Save' or 'Submit' button to save the schedule
    await page.click('[data-testid="save-schedule-button"]');
    
    // Step 7: Verify system blocks submission and shows conflict details
    await expect(page.locator('[data-testid="conflict-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('Conference Room A');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('9:00 AM - 11:00 AM');
    await expect(page.locator('[data-testid="save-schedule-button"]')).toBeDisabled();
  });

  test('Verify conflict detection response time under 1 second (boundary)', async ({ page }) => {
    // Step 1: Open the schedule creation interface
    await page.click('[data-testid="schedule-creation-link"]');
    await expect(page.locator('[data-testid="schedule-creation-form"]')).toBeVisible();
    
    // Step 2: Start performance timer and enter conflicting schedule data
    const startTime = Date.now();
    
    await page.click('[data-testid="date-picker"]');
    await page.click('[data-testid="date-option-with-bookings"]');
    await page.fill('[data-testid="start-time-input"]', '09:30');
    await page.selectOption('[data-testid="start-time-period"]', 'AM');
    await page.fill('[data-testid="end-time-input"]', '10:30');
    await page.selectOption('[data-testid="end-time-period"]', 'AM');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Conference Room A' });
    
    // Step 3: Observe and measure time from last input to conflict alert display
    await page.waitForSelector('[data-testid="conflict-alert"]', { timeout: 1000 });
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    // Step 4: Verify response time is under 1 second
    expect(responseTime).toBeLessThan(1000);
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    // Step 5: Verify system logs response times (check via API or monitoring endpoint)
    const response = await page.request.get('/api/monitoring/performance-logs?operation=conflict-detection');
    expect(response.ok()).toBeTruthy();
    const logs = await response.json();
    expect(logs.averageResponseTime).toBeLessThan(1000);
  });

  test('Ensure system supports multiple resource types in conflict detection (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the schedule creation page
    await page.click('[data-testid="schedule-creation-link"]');
    await expect(page.locator('[data-testid="schedule-creation-form"]')).toBeVisible();
    
    // Step 2: Select 'Room' as the resource type
    await page.selectOption('[data-testid="resource-type-dropdown"]', 'Room');
    
    // Step 3: Enter date and time that conflicts with existing room booking
    await page.click('[data-testid="date-picker"]');
    await page.click('[data-testid="date-option-with-bookings"]');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.selectOption('[data-testid="start-time-period"]', 'AM');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.selectOption('[data-testid="end-time-period"]', 'AM');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Conference Room A' });
    
    // Verify conflict alert for Room resource type
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 1000 });
    
    // Step 4: Clear the form and select 'Equipment' as the resource type
    await page.click('[data-testid="clear-form-button"]');
    await page.selectOption('[data-testid="resource-type-dropdown"]', 'Equipment');
    
    // Step 5: Enter date and time that conflicts with existing equipment booking
    await page.click('[data-testid="date-picker"]');
    await page.click('[data-testid="date-option-with-bookings"]');
    await page.fill('[data-testid="start-time-input"]', '02:00');
    await page.selectOption('[data-testid="start-time-period"]', 'PM');
    await page.fill('[data-testid="end-time-input"]', '03:00');
    await page.selectOption('[data-testid="end-time-period"]', 'PM');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Projector 1' });
    
    // Verify conflict alert for Equipment resource type
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 1000 });
    
    // Step 6: Clear the form and select 'Personnel' as the resource type
    await page.click('[data-testid="clear-form-button"]');
    await page.selectOption('[data-testid="resource-type-dropdown"]', 'Personnel');
    
    // Step 7: Enter date and time that conflicts with existing personnel booking
    await page.click('[data-testid="date-picker"]');
    await page.click('[data-testid="date-option-with-bookings"]');
    await page.fill('[data-testid="start-time-input"]', '03:00');
    await page.selectOption('[data-testid="start-time-period"]', 'PM');
    await page.fill('[data-testid="end-time-input"]', '04:00');
    await page.selectOption('[data-testid="end-time-period"]', 'PM');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Dr. Smith' });
    
    // Verify conflict alert for Personnel resource type
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 1000 });
    
    // Step 8: Clear the form and select 'Room' resource type again
    await page.click('[data-testid="clear-form-button"]');
    await page.selectOption('[data-testid="resource-type-dropdown"]', 'Room');
    
    // Step 9: Enter non-conflicting room schedule
    await page.click('[data-testid="date-picker"]');
    await page.click('[data-testid="date-option-available"]');
    await page.fill('[data-testid="start-time-input"]', '01:00');
    await page.selectOption('[data-testid="start-time-period"]', 'PM');
    await page.fill('[data-testid="end-time-input"]', '02:00');
    await page.selectOption('[data-testid="end-time-period"]', 'PM');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Conference Room B' });
    
    // Verify no conflict alert is displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    
    // Step 10: Repeat for 'Equipment' resource type with non-conflicting schedule
    await page.click('[data-testid="clear-form-button"]');
    await page.selectOption('[data-testid="resource-type-dropdown"]', 'Equipment');
    await page.click('[data-testid="date-picker"]');
    await page.click('[data-testid="date-option-available"]');
    await page.fill('[data-testid="start-time-input"]', '04:00');
    await page.selectOption('[data-testid="start-time-period"]', 'PM');
    await page.fill('[data-testid="end-time-input"]', '05:00');
    await page.selectOption('[data-testid="end-time-period"]', 'PM');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Projector 2' });
    
    // Verify no conflict alert is displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    
    // Step 11: Repeat for 'Personnel' resource type with non-conflicting schedule
    await page.click('[data-testid="clear-form-button"]');
    await page.selectOption('[data-testid="resource-type-dropdown"]', 'Personnel');
    await page.click('[data-testid="date-picker"]');
    await page.click('[data-testid="date-option-available"]');
    await page.fill('[data-testid="start-time-input"]', '05:00');
    await page.selectOption('[data-testid="start-time-period"]', 'PM');
    await page.fill('[data-testid="end-time-input"]', '06:00');
    await page.selectOption('[data-testid="end-time-period"]', 'PM');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Dr. Johnson' });
    
    // Verify no conflict alert is displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    
    // Step 12: Click the 'Save' button to save the valid non-conflicting personnel schedule
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule saved successfully');
    
    // Step 13: Navigate back to schedule creation and create another non-conflicting schedule for room resource
    await page.click('[data-testid="schedule-creation-link"]');
    await page.selectOption('[data-testid="resource-type-dropdown"]', 'Room');
    await page.click('[data-testid="date-picker"]');
    await page.click('[data-testid="date-option-available"]');
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.selectOption('[data-testid="start-time-period"]', 'AM');
    await page.fill('[data-testid="end-time-input"]', '10:00');
    await page.selectOption('[data-testid="end-time-period"]', 'AM');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Conference Room C' });
    
    // Step 14: Enter valid non-conflicting room schedule details and click 'Save'
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 15: Create a third non-conflicting schedule for equipment resource and save
    await page.click('[data-testid="schedule-creation-link"]');
    await page.selectOption('[data-testid="resource-type-dropdown"]', 'Equipment');
    await page.click('[data-testid="date-picker"]');
    await page.click('[data-testid="date-option-available"]');
    await page.fill('[data-testid="start-time-input"]', '11:00');
    await page.selectOption('[data-testid="start-time-period"]', 'AM');
    await page.fill('[data-testid="end-time-input"]', '12:00');
    await page.selectOption('[data-testid="end-time-period"]', 'PM');
    await page.selectOption('[data-testid="resource-dropdown"]', { label: 'Laptop 5' });
    
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule saved successfully');
  });
});