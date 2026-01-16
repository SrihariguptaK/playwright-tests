import { test, expect } from '@playwright/test';

test.describe('Story-11: Detect overlapping appointments to prevent double-booking resources', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to the application and ensure user is logged in as Scheduler
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Detect overlapping appointments for the same resource (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the appointment creation page
    await page.goto(`${BASE_URL}/appointments/create`);
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Step 2: Select Resource A from the resource dropdown
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-A"]');
    await expect(page.locator('[data-testid="resource-dropdown"]')).toContainText('Resource A');

    // Step 3: Set appointment start time to 10:00 and end time to 11:00
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');

    // Step 4: Fill in all other required appointment details
    await page.fill('[data-testid="appointment-title-input"]', 'First Appointment');
    await page.fill('[data-testid="appointment-description-input"]', 'Initial booking for Resource A');
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date-input"]', today);

    // Step 5: Click Save
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: Appointment is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment saved successfully');

    // Step 6: Navigate back to appointment creation page to create a second appointment
    await page.goto(`${BASE_URL}/appointments/create`);
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Step 7: Select Resource A from the resource dropdown
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-A"]');

    // Step 8: Set appointment start time to 10:30 and end time to 11:30
    await page.fill('[data-testid="start-time-input"]', '10:30');
    await page.fill('[data-testid="end-time-input"]', '11:30');

    // Step 9: Fill in all other required appointment details
    await page.fill('[data-testid="appointment-title-input"]', 'Second Appointment');
    await page.fill('[data-testid="appointment-description-input"]', 'Overlapping booking for Resource A');
    await page.fill('[data-testid="appointment-date-input"]', today);

    // Step 10: Click Save
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: System detects overlap and flags conflict immediately
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Conflict detected');

    // Step 11: Review conflict details displayed in UI
    // Expected Result: Conflict information shows both appointment times and IDs
    await expect(page.locator('[data-testid="conflict-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('10:00');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('11:00');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('10:30');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('11:30');
    await expect(page.locator('[data-testid="conflict-appointment-ids"]')).toBeVisible();
  });

  test('Ensure conflict detection latency is under 2 seconds (happy-path)', async ({ page }) => {
    // Pre-requisite: Create an existing appointment
    await page.goto(`${BASE_URL}/appointments/create`);
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-B"]');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.fill('[data-testid="appointment-title-input"]', 'Existing Appointment');
    await page.fill('[data-testid="appointment-description-input"]', 'Base appointment');
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date-input"]', today);
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 1: Start timer and navigate to appointment creation or update page
    const startTime = Date.now();
    await page.goto(`${BASE_URL}/appointments/create`);
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Step 2: Create or update an appointment that overlaps with an existing appointment
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-B"]');
    await page.fill('[data-testid="start-time-input"]', '14:30');
    await page.fill('[data-testid="end-time-input"]', '15:30');
    await page.fill('[data-testid="appointment-title-input"]', 'Overlapping Appointment');
    await page.fill('[data-testid="appointment-description-input"]', 'Testing latency');
    await page.fill('[data-testid="appointment-date-input"]', today);

    // Step 3: Click Save and measure time until conflict detection completes
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: System processes conflict detection within 2 seconds
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 2000 });
    const endTime = Date.now();
    const latency = endTime - startTime;

    // Verify latency is under 2 seconds (2000ms)
    expect(latency).toBeLessThan(2000);

    // Step 4: Verify conflict flag appears in UI
    // Expected Result: Conflict flag is visible without delay
    await expect(page.locator('[data-testid="conflict-flag"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Conflict detected');

    // Step 5: Confirm no performance degradation under load
    // Expected Result: System maintains latency under SLA during concurrent operations
    // Note: This would typically require multiple browser contexts or external load testing
    // For this test, we verify the system responds consistently
    await page.reload();
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible({ timeout: 2000 });
  });

  test('Support conflict detection across time zones (edge-case)', async ({ page }) => {
    // Step 1: Navigate to appointment creation page
    await page.goto(`${BASE_URL}/appointments/create`);
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Step 2: Select a resource and set time zone to 'America/New_York' (Time Zone A)
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-C"]');
    await page.click('[data-testid="timezone-dropdown"]');
    await page.fill('[data-testid="timezone-search-input"]', 'America/New_York');
    await page.click('[data-testid="timezone-option-america-new-york"]');
    await expect(page.locator('[data-testid="timezone-dropdown"]')).toContainText('America/New_York');

    // Step 3: Create an appointment from 14:00 to 15:00 EST and save
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.fill('[data-testid="appointment-title-input"]', 'EST Appointment');
    await page.fill('[data-testid="appointment-description-input"]', 'Appointment in Eastern Time');
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date-input"]', today);
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: Appointment saved with correct time zone metadata
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment saved successfully');

    // Step 4: Navigate to create a new appointment for the same resource
    await page.goto(`${BASE_URL}/appointments/create`);
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Step 5: Select the same resource and set time zone to 'Europe/London' (Time Zone B)
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-C"]');
    await page.click('[data-testid="timezone-dropdown"]');
    await page.fill('[data-testid="timezone-search-input"]', 'Europe/London');
    await page.click('[data-testid="timezone-option-europe-london"]');
    await expect(page.locator('[data-testid="timezone-dropdown"]')).toContainText('Europe/London');

    // Step 6: Create an overlapping appointment from 19:00 to 20:00 GMT (equivalent to 14:00-15:00 EST) and attempt to save
    await page.fill('[data-testid="start-time-input"]', '19:00');
    await page.fill('[data-testid="end-time-input"]', '20:00');
    await page.fill('[data-testid="appointment-title-input"]', 'GMT Appointment');
    await page.fill('[data-testid="appointment-description-input"]', 'Appointment in London Time');
    await page.fill('[data-testid="appointment-date-input"]', today);
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: System detects conflict considering time zone differences
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Conflict detected');

    // Step 7: Review the conflict alert details
    await expect(page.locator('[data-testid="conflict-details"]')).toBeVisible();

    // Step 8: Verify that both appointments display correct local times in the conflict details
    // Expected Result: Conflict alert shows appointment times adjusted to user's time zone
    const conflictDetails = page.locator('[data-testid="conflict-details"]');
    await expect(conflictDetails).toContainText('14:00');
    await expect(conflictDetails).toContainText('15:00');
    await expect(conflictDetails).toContainText('19:00');
    await expect(conflictDetails).toContainText('20:00');
    
    // Verify timezone information is displayed
    await expect(page.locator('[data-testid="conflict-timezone-info"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-timezone-info"]')).toContainText('America/New_York');
    await expect(page.locator('[data-testid="conflict-timezone-info"]')).toContainText('Europe/London');
  });
});