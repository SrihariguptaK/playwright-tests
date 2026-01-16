import { test, expect } from '@playwright/test';

test.describe('Overlapping Appointments Detection', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the appointment scheduling interface
    await page.goto('/appointments/schedule');
    // Wait for the page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate detection of overlapping appointments (happy-path)', async ({ page }) => {
    // Step 1: Create first appointment
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date"]', today);
    await page.fill('[data-testid="appointment-start-time"]', '10:00');
    await page.fill('[data-testid="appointment-end-time"]', '11:00');
    await page.fill('[data-testid="appointment-title"]', 'First Appointment');
    
    await page.click('[data-testid="save-appointment-button"]');
    
    // Verify first appointment is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment is saved successfully');
    
    // Step 2: Navigate back to create overlapping appointment
    await page.click('[data-testid="create-new-appointment-button"]');
    
    // Select the same resource
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    
    // Enter overlapping appointment details
    await page.fill('[data-testid="appointment-date"]', today);
    await page.fill('[data-testid="appointment-start-time"]', '10:30');
    await page.fill('[data-testid="appointment-end-time"]', '11:30');
    await page.fill('[data-testid="appointment-title"]', 'Overlapping Appointment');
    
    await page.click('[data-testid="save-appointment-button"]');
    
    // Step 3: Verify conflict alert is displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('System detects conflict');
    
    // Step 4: Review conflict details in the alert
    const conflictDetails = page.locator('[data-testid="conflict-details"]');
    await expect(conflictDetails).toBeVisible();
    await expect(conflictDetails).toContainText('Conference Room A');
    await expect(conflictDetails).toContainText('10:00');
    await expect(conflictDetails).toContainText('11:00');
    await expect(conflictDetails).toContainText('First Appointment');
    
    // Step 5: Verify overlapping appointment was not saved
    await page.click('[data-testid="close-conflict-alert"]');
    await page.goto('/appointments/schedule');
    
    const appointmentList = page.locator('[data-testid="appointment-list-item"]');
    await expect(appointmentList).toHaveCount(1);
    await expect(page.locator('text=Overlapping Appointment')).not.toBeVisible();
  });

  test('Verify conflict detection latency under 2 seconds (boundary)', async ({ page }) => {
    // Step 1: Create baseline appointment
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-meeting-room-b"]');
    
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date"]', today);
    await page.fill('[data-testid="appointment-start-time"]', '14:00');
    await page.fill('[data-testid="appointment-end-time"]', '15:00');
    await page.fill('[data-testid="appointment-title"]', 'Baseline Appointment');
    
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 2: Create overlapping appointment and measure latency
    await page.click('[data-testid="create-new-appointment-button"]');
    
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-meeting-room-b"]');
    
    await page.fill('[data-testid="appointment-date"]', today);
    await page.fill('[data-testid="appointment-start-time"]', '14:30');
    await page.fill('[data-testid="appointment-end-time"]', '15:30');
    await page.fill('[data-testid="appointment-title"]', 'Conflicting Appointment');
    
    // Start timer and click save
    const startTime = Date.now();
    
    // Listen for the conflict detection API response
    const responsePromise = page.waitForResponse(response => 
      response.url().includes('/appointments') && response.status() === 409
    );
    
    await page.click('[data-testid="save-appointment-button"]');
    
    // Wait for conflict alert to appear
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    const endTime = Date.now();
    const latency = (endTime - startTime) / 1000; // Convert to seconds
    
    // Verify latency is under 2 seconds
    expect(latency).toBeLessThan(2);
    
    // Verify API response time
    const response = await responsePromise;
    expect(response.status()).toBe(409);
    
    // Step 3: Test latency for modifying existing appointment
    await page.click('[data-testid="close-conflict-alert"]');
    await page.goto('/appointments/schedule');
    
    // Find and edit the baseline appointment
    await page.click('[data-testid="appointment-list-item"]:has-text("Baseline Appointment")');
    await page.click('[data-testid="edit-appointment-button"]');
    
    // Modify to create conflict with another time slot
    await page.fill('[data-testid="appointment-start-time"]', '14:00');
    await page.fill('[data-testid="appointment-end-time"]', '15:00');
    
    const modifyStartTime = Date.now();
    
    await page.click('[data-testid="save-appointment-button"]');
    
    const modifyEndTime = Date.now();
    const modifyLatency = (modifyEndTime - modifyStartTime) / 1000;
    
    // Verify modification detection latency is also under 2 seconds
    expect(modifyLatency).toBeLessThan(2);
  });

  test('Ensure logging of detected conflicts (happy-path)', async ({ page }) => {
    // Step 1: Create first appointment
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date"]', today);
    await page.fill('[data-testid="appointment-start-time"]', '09:00');
    await page.fill('[data-testid="appointment-end-time"]', '10:00');
    await page.fill('[data-testid="appointment-title"]', 'Morning Meeting');
    
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 2: Note current system time before creating conflict
    const conflictTimestamp = new Date();
    const timestampString = conflictTimestamp.toISOString();
    
    // Step 3: Create overlapping appointment to trigger conflict
    await page.click('[data-testid="create-new-appointment-button"]');
    
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    
    await page.fill('[data-testid="appointment-date"]', today);
    await page.fill('[data-testid="appointment-start-time"]', '09:30');
    await page.fill('[data-testid="appointment-end-time"]', '10:30');
    await page.fill('[data-testid="appointment-title"]', 'Conflicting Meeting');
    
    await page.click('[data-testid="save-appointment-button"]');
    
    // Step 4: Verify conflict is detected
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    // Step 5: Acknowledge conflict alert
    await page.click('[data-testid="close-conflict-alert"]');
    
    // Step 6: Navigate to conflict logs section
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="conflict-logs-link"]');
    
    // Wait for logs page to load
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="conflict-logs-page"]')).toBeVisible();
    
    // Step 7: Search for conflicts around the noted timestamp
    const searchDate = conflictTimestamp.toISOString().split('T')[0];
    await page.fill('[data-testid="log-date-filter"]', searchDate);
    await page.click('[data-testid="search-logs-button"]');
    
    // Step 8: Locate the log entry for the triggered conflict
    const logEntry = page.locator('[data-testid="conflict-log-entry"]').first();
    await expect(logEntry).toBeVisible();
    
    // Step 9: Review log entry details for completeness
    await logEntry.click();
    
    const logDetails = page.locator('[data-testid="conflict-log-details"]');
    await expect(logDetails).toBeVisible();
    
    // Verify resource details are logged
    await expect(logDetails).toContainText('Conference Room A');
    await expect(logDetails).toContainText('09:00');
    await expect(logDetails).toContainText('10:00');
    await expect(logDetails).toContainText('09:30');
    await expect(logDetails).toContainText('10:30');
    
    // Step 10: Verify timestamp format and accuracy
    const logTimestamp = await logDetails.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    
    // Verify timestamp is within reasonable range (within 5 minutes of conflict creation)
    const logDate = new Date(logTimestamp!);
    const timeDifference = Math.abs(logDate.getTime() - conflictTimestamp.getTime());
    expect(timeDifference).toBeLessThan(5 * 60 * 1000); // 5 minutes in milliseconds
    
    // Step 11: Verify all resource details are accurately logged
    await expect(logDetails.locator('[data-testid="log-resource-name"]')).toContainText('Conference Room A');
    await expect(logDetails.locator('[data-testid="log-conflict-type"]')).toContainText('Overlapping Appointment');
    await expect(logDetails.locator('[data-testid="log-original-appointment"]')).toContainText('Morning Meeting');
    await expect(logDetails.locator('[data-testid="log-conflicting-appointment"]')).toContainText('Conflicting Meeting');
  });
});