import { test, expect } from '@playwright/test';

test.describe('Detect Overlapping Appointments', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/appointments');
    // Wait for the page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Detect overlapping appointments on creation (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the appointment creation page
    await page.click('[data-testid="create-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Step 2: Enter appointment details that overlap with existing appointment
    // Existing appointment is 2:00 PM - 3:00 PM, creating 2:30 PM - 3:30 PM
    await page.fill('[data-testid="appointment-title"]', 'Overlapping Appointment Test');
    await page.fill('[data-testid="appointment-start-time"]', '14:30');
    await page.fill('[data-testid="appointment-end-time"]', '15:30');
    await page.fill('[data-testid="appointment-date"]', new Date().toISOString().split('T')[0]);

    // Step 3: Click 'Save' or 'Create Appointment' button
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: System flags the new appointment as conflicting
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText('conflict');

    // Step 4: Attempt to save the appointment without making changes
    // Expected Result: System prevents saving and displays conflict warning
    const saveButton = page.locator('[data-testid="save-appointment-button"]');
    await expect(saveButton).toBeDisabled();
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('cannot save');

    // Step 5: Adjust the appointment time to a non-overlapping slot
    await page.fill('[data-testid="appointment-start-time"]', '15:30');
    await page.fill('[data-testid="appointment-end-time"]', '16:30');

    // Wait for conflict check to complete
    await page.waitForTimeout(500);

    // Step 6: Click 'Save' or 'Create Appointment' button
    await expect(saveButton).toBeEnabled();
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: Appointment is saved successfully without conflict
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('successfully created');
  });

  test('Detect overlapping appointments on update (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the appointment list and select Appointment B (4:00 PM - 5:00 PM) to edit
    await page.click('[data-testid="appointment-list-item"]:has-text("4:00 PM - 5:00 PM")');
    await page.click('[data-testid="edit-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Step 2: Modify the appointment time to overlap with Appointment A
    // Change start time to 2:30 PM, end time to 3:30 PM (overlapping with 2:00 PM - 3:00 PM)
    await page.fill('[data-testid="appointment-start-time"]', '14:30');
    await page.fill('[data-testid="appointment-end-time"]', '15:30');

    // Step 3: Click 'Save' or 'Update Appointment' button
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: System flags the updated appointment as conflicting
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText('conflict');

    // Step 4: Attempt to save the updated appointment without resolving the conflict
    // Expected Result: System prevents saving and displays conflict warning
    const saveButton = page.locator('[data-testid="save-appointment-button"]');
    await expect(saveButton).toBeDisabled();
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('cannot save');

    // Step 5: Click 'Cancel' button to abandon the update
    await page.click('[data-testid="cancel-appointment-button"]');

    // Step 6: Verify Appointment B details in the schedule
    // Expected Result: Original appointment remains unchanged
    await expect(page.locator('[data-testid="appointment-list-item"]:has-text("4:00 PM - 5:00 PM")')).toBeVisible();
    const appointmentDetails = page.locator('[data-testid="appointment-list-item"]:has-text("4:00 PM - 5:00 PM")');
    await expect(appointmentDetails).toContainText('4:00 PM');
    await expect(appointmentDetails).toContainText('5:00 PM');
  });

  test('Performance test for overlap detection latency (boundary)', async ({ page }) => {
    // Step 1: Record the current timestamp and create a new appointment that overlaps
    await page.click('[data-testid="create-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    await page.fill('[data-testid="appointment-title"]', 'Performance Test Appointment');
    await page.fill('[data-testid="appointment-start-time"]', '14:30');
    await page.fill('[data-testid="appointment-end-time"]', '15:30');
    await page.fill('[data-testid="appointment-date"]', new Date().toISOString().split('T')[0]);

    // Step 2: Click 'Save' button and measure the time until conflict detection message appears
    const startTime = Date.now();
    await page.click('[data-testid="save-appointment-button"]');

    // Wait for conflict detection message
    await page.waitForSelector('[data-testid="conflict-warning"]', { timeout: 2000 });
    const endTime = Date.now();

    // Step 3: Record the elapsed time from submission to conflict detection
    const elapsedTime = endTime - startTime;

    // Expected Result: System detects conflicts within 2 seconds
    expect(elapsedTime).toBeLessThan(2000);
    console.log(`Conflict detection latency: ${elapsedTime}ms`);

    // Step 4: Cancel the conflicting appointment creation
    await page.click('[data-testid="cancel-appointment-button"]');

    // Step 5: Initiate multiple concurrent appointment creations
    // Expected Result: System processes all conflict detections within SLA
    const concurrentTests = [];
    const concurrentCount = 5;

    for (let i = 0; i < concurrentCount; i++) {
      concurrentTests.push(
        (async () => {
          const testStartTime = Date.now();
          await page.click('[data-testid="create-appointment-button"]');
          await page.fill('[data-testid="appointment-title"]', `Concurrent Test ${i + 1}`);
          await page.fill('[data-testid="appointment-start-time"]', '14:30');
          await page.fill('[data-testid="appointment-end-time"]', '15:30');
          await page.fill('[data-testid="appointment-date"]', new Date().toISOString().split('T')[0]);
          await page.click('[data-testid="save-appointment-button"]');
          await page.waitForSelector('[data-testid="conflict-warning"]', { timeout: 2000 });
          const testEndTime = Date.now();
          const testElapsedTime = testEndTime - testStartTime;
          await page.click('[data-testid="cancel-appointment-button"]');
          return testElapsedTime;
        })()
      );
    }

    // Step 6: Monitor and measure the conflict detection response time for each concurrent request
    const results = await Promise.all(concurrentTests);

    // Step 7: Review performance logs and metrics
    // Expected Result: All concurrent requests processed within 2 seconds
    results.forEach((time, index) => {
      console.log(`Concurrent test ${index + 1} latency: ${time}ms`);
      expect(time).toBeLessThan(2000);
    });

    const averageLatency = results.reduce((sum, time) => sum + time, 0) / results.length;
    console.log(`Average concurrent conflict detection latency: ${averageLatency}ms`);
    expect(averageLatency).toBeLessThan(2000);
  });
});