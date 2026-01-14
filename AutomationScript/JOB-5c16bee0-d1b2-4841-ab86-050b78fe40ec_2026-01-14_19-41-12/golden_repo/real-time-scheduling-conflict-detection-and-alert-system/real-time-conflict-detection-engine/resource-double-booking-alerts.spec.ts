import { test, expect } from '@playwright/test';

test.describe('Resource Double-Booking Alerts', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Login as scheduler
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'scheduler@test.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate detection of resource double-bookings with alert', async ({ page }) => {
    // Navigate to the appointment creation or resource assignment page
    await page.goto(`${BASE_URL}/appointments/create`);
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Create a new appointment or select an existing appointment for the same time period (10:00 AM to 11:00 AM)
    await page.fill('[data-testid="appointment-title"]', 'First Appointment');
    await page.fill('[data-testid="appointment-start-time"]', '10:00');
    await page.fill('[data-testid="appointment-end-time"]', '11:00');
    
    // Select and assign the same resource (Resource A) that is already booked for the overlapping time period
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-A"]');
    
    // Click 'Save' or 'Assign Resource' button
    await page.click('[data-testid="save-appointment-button"]');
    
    // Expected Result: System detects double-booking and displays alert
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Resource A');
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('double-booking');
    
    // Review the alert notification displayed on screen
    const alertText = await page.locator('[data-testid="conflict-alert-message"]').textContent();
    expect(alertText).toContain('10:00');
    expect(alertText).toContain('11:00');
    
    // Click the 'Acknowledge' button on the alert
    await page.click('[data-testid="acknowledge-alert-button"]');
    
    // Expected Result: Alert is marked acknowledged and logged
    await expect(page.locator('[data-testid="conflict-alert"]')).toHaveAttribute('data-status', 'acknowledged');
    
    // Navigate to the conflict audit log or resource conflict log section
    await page.goto(`${BASE_URL}/logs/conflicts`);
    await expect(page.locator('[data-testid="conflict-log-table"]')).toBeVisible();
    
    // Search for the recent resource conflict entry using resource name or timestamp
    await page.fill('[data-testid="log-search-input"]', 'Resource A');
    await page.click('[data-testid="log-search-button"]');
    
    // Expected Result: Conflict and acknowledgment recorded
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry).toContainText('Resource A');
    await expect(logEntry).toContainText('acknowledged');
    await expect(logEntry).toContainText('double-booking');
  });

  test('Verify no alerts for non-conflicting resource assignments', async ({ page }) => {
    // Navigate to the appointment creation page
    await page.goto(`${BASE_URL}/appointments/create`);
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Create first appointment and assign Resource A for time slot 9:00 AM to 10:00 AM
    await page.fill('[data-testid="appointment-title"]', 'Appointment 1');
    await page.fill('[data-testid="appointment-start-time"]', '09:00');
    await page.fill('[data-testid="appointment-end-time"]', '10:00');
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-A"]');
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Expected Result: No conflict alerts generated
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();

    // Create second appointment and assign Resource B (different resource) for the same time slot 9:00 AM to 10:00 AM
    await page.goto(`${BASE_URL}/appointments/create`);
    await page.fill('[data-testid="appointment-title"]', 'Appointment 2');
    await page.fill('[data-testid="appointment-start-time"]', '09:00');
    await page.fill('[data-testid="appointment-end-time"]', '10:00');
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-B"]');
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();

    // Create third appointment and assign Resource A for a non-overlapping time slot 10:00 AM to 11:00 AM
    await page.goto(`${BASE_URL}/appointments/create`);
    await page.fill('[data-testid="appointment-title"]', 'Appointment 3');
    await page.fill('[data-testid="appointment-start-time"]', '10:00');
    await page.fill('[data-testid="appointment-end-time"]', '11:00');
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-A"]');
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Verify the UI notification area for any alerts
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="notification-area"]')).not.toContainText('conflict');

    // Navigate to the system logs or resource conflict logs section
    await page.goto(`${BASE_URL}/logs/conflicts`);
    await expect(page.locator('[data-testid="conflict-log-table"]')).toBeVisible();
    
    // Search for conflict records related to the recently assigned resources
    await page.fill('[data-testid="log-search-input"]', 'Resource A');
    await page.click('[data-testid="log-search-button"]');
    
    // Expected Result: No conflict records created
    const noResultsMessage = page.locator('[data-testid="no-conflicts-message"]');
    await expect(noResultsMessage).toBeVisible();
    
    // Check the scheduler's notification panel or alert history
    await page.goto(`${BASE_URL}/notifications`);
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    
    // Expected Result: No notifications shown to scheduler
    const conflictNotifications = page.locator('[data-testid="notification-item"]').filter({ hasText: 'conflict' });
    await expect(conflictNotifications).toHaveCount(0);
  });

  test('Test system performance under concurrent resource assignments', async ({ page, context }) => {
    const startTime = Date.now();
    const conflictDetectionTimes: number[] = [];
    
    // Prepare 10-15 resource assignment scenarios with intentional double-bookings
    const assignments = [
      { title: 'Concurrent Appt 1', resource: 'A', startTime: '10:00', endTime: '11:00' },
      { title: 'Concurrent Appt 2', resource: 'A', startTime: '10:30', endTime: '11:30' },
      { title: 'Concurrent Appt 3', resource: 'B', startTime: '14:00', endTime: '15:00' },
      { title: 'Concurrent Appt 4', resource: 'B', startTime: '14:30', endTime: '15:30' },
      { title: 'Concurrent Appt 5', resource: 'C', startTime: '09:00', endTime: '10:00' },
      { title: 'Concurrent Appt 6', resource: 'C', startTime: '09:30', endTime: '10:30' },
      { title: 'Concurrent Appt 7', resource: 'D', startTime: '13:00', endTime: '14:00' },
      { title: 'Concurrent Appt 8', resource: 'D', startTime: '13:30', endTime: '14:30' },
      { title: 'Concurrent Appt 9', resource: 'E', startTime: '11:00', endTime: '12:00' },
      { title: 'Concurrent Appt 10', resource: 'E', startTime: '11:30', endTime: '12:30' }
    ];

    // Initiate concurrent resource assignments from multiple scheduler accounts simultaneously
    const pages = [page];
    for (let i = 1; i < 3; i++) {
      const newPage = await context.newPage();
      await newPage.goto(`${BASE_URL}/login`);
      await newPage.fill('[data-testid="username-input"]', `scheduler${i}@test.com`);
      await newPage.fill('[data-testid="password-input"]', 'password123');
      await newPage.click('[data-testid="login-button"]');
      pages.push(newPage);
    }

    // Create assignments concurrently
    const assignmentPromises = assignments.map(async (assignment, index) => {
      const assignmentPage = pages[index % pages.length];
      const assignmentStartTime = Date.now();
      
      await assignmentPage.goto(`${BASE_URL}/appointments/create`);
      await assignmentPage.fill('[data-testid="appointment-title"]', assignment.title);
      await assignmentPage.fill('[data-testid="appointment-start-time"]', assignment.startTime);
      await assignmentPage.fill('[data-testid="appointment-end-time"]', assignment.endTime);
      await assignmentPage.click('[data-testid="resource-dropdown"]');
      await assignmentPage.click(`[data-testid="resource-option-${assignment.resource}"]`);
      await assignmentPage.click('[data-testid="save-appointment-button"]');
      
      // Check for conflict alert
      const alertVisible = await assignmentPage.locator('[data-testid="conflict-alert"]').isVisible({ timeout: 2000 }).catch(() => false);
      
      if (alertVisible) {
        const detectionTime = Date.now() - assignmentStartTime;
        conflictDetectionTimes.push(detectionTime);
        
        // Expected Result: All conflicts detected within 1 second
        expect(detectionTime).toBeLessThan(1000);
        
        // Verify alert delivery to schedulers
        await expect(assignmentPage.locator('[data-testid="conflict-alert"]')).toBeVisible();
        await expect(assignmentPage.locator('[data-testid="conflict-alert-message"]')).toContainText(`Resource ${assignment.resource}`);
      }
    });

    // Wait for all assignments to complete
    await Promise.all(assignmentPromises);
    
    // Expected Result: All alerts received promptly
    expect(conflictDetectionTimes.length).toBeGreaterThan(0);
    const avgDetectionTime = conflictDetectionTimes.reduce((a, b) => a + b, 0) / conflictDetectionTimes.length;
    expect(avgDetectionTime).toBeLessThan(1000);

    // Navigate to system logs and error logs section
    await page.goto(`${BASE_URL}/logs/system`);
    await expect(page.locator('[data-testid="system-log-table"]')).toBeVisible();
    
    // Review logs for any errors, exceptions, or missed conflict detections
    await page.fill('[data-testid="log-level-filter"]', 'ERROR');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Expected Result: No errors or missed conflicts
    const errorLogs = page.locator('[data-testid="log-entry"]').filter({ hasText: 'ERROR' });
    const errorCount = await errorLogs.count();
    expect(errorCount).toBe(0);
    
    // Verify no conflicts were missed during concurrent load test
    await page.goto(`${BASE_URL}/logs/conflicts`);
    const conflictLogs = page.locator('[data-testid="log-entry"]');
    const conflictCount = await conflictLogs.count();
    expect(conflictCount).toBeGreaterThan(0);
    
    // Analyze performance metrics
    await page.goto(`${BASE_URL}/admin/performance`);
    const detectionLatency = await page.locator('[data-testid="conflict-detection-latency"]').textContent();
    const latencyValue = parseFloat(detectionLatency || '0');
    expect(latencyValue).toBeLessThan(1000);
    
    // Close additional pages
    for (let i = 1; i < pages.length; i++) {
      await pages[i].close();
    }
  });
});