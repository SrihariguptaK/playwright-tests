import { test, expect } from '@playwright/test';

test.describe('Real-time Alerts for Overlapping Appointments', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler_user');
    await page.fill('[data-testid="password-input"]', 'scheduler_pass');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate detection of overlapping appointments with real-time alert', async ({ page }) => {
    // Step 1: Navigate to the appointment creation page
    await page.click('[data-testid="appointments-menu"]');
    await page.click('[data-testid="create-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Step 2: Enter appointment details that overlap with existing Appointment A
    await page.fill('[data-testid="appointment-title-input"]', 'Overlapping Appointment Test');
    await page.fill('[data-testid="appointment-date-input"]', '2024-01-15');
    await page.fill('[data-testid="appointment-start-time-input"]', '10:30');
    await page.fill('[data-testid="appointment-end-time-input"]', '11:30');
    await page.fill('[data-testid="appointment-resource-input"]', 'Resource A');

    // Step 3: Click 'Save' or 'Create Appointment' button
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: System detects conflict and displays real-time alert
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('overlapping');
    await expect(page.locator('[data-testid="conflict-alert-details"]')).toBeVisible();

    // Step 4: Review the alert details displayed on screen
    const alertDetails = page.locator('[data-testid="conflict-alert-details"]');
    await expect(alertDetails).toContainText('10:30');
    await expect(alertDetails).toContainText('11:30');

    // Step 5: Click the 'Acknowledge' button on the alert
    await page.click('[data-testid="acknowledge-alert-button"]');

    // Expected Result: Alert is marked acknowledged and logged
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="alert-acknowledged-message"]')).toBeVisible();

    // Step 6: Navigate to the conflict audit log or system logs section
    await page.click('[data-testid="system-logs-menu"]');
    await page.click('[data-testid="conflict-log-submenu"]');
    await expect(page).toHaveURL(/.*logs\/conflicts/);

    // Step 7: Search for the recent conflict entry using appointment details or timestamp
    await page.fill('[data-testid="log-search-input"]', 'Overlapping Appointment Test');
    await page.click('[data-testid="search-button"]');

    // Expected Result: Conflict and acknowledgment recorded in audit log
    const logEntry = page.locator('[data-testid="conflict-log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry).toContainText('Overlapping Appointment Test');
    await expect(logEntry).toContainText('acknowledged');
    await expect(logEntry).toContainText('10:30');
    await expect(logEntry).toContainText('11:30');
  });

  test('Verify system performance under concurrent appointment creations', async ({ page, context }) => {
    // Step 1: Prepare 10-15 appointment creation requests with intentional overlaps
    const appointmentData = [
      { title: 'Concurrent Appt 1', date: '2024-01-16', startTime: '09:00', endTime: '10:00', resource: 'Resource B' },
      { title: 'Concurrent Appt 2', date: '2024-01-16', startTime: '09:30', endTime: '10:30', resource: 'Resource B' },
      { title: 'Concurrent Appt 3', date: '2024-01-16', startTime: '09:45', endTime: '10:45', resource: 'Resource B' },
      { title: 'Concurrent Appt 4', date: '2024-01-16', startTime: '11:00', endTime: '12:00', resource: 'Resource C' },
      { title: 'Concurrent Appt 5', date: '2024-01-16', startTime: '11:15', endTime: '12:15', resource: 'Resource C' },
      { title: 'Concurrent Appt 6', date: '2024-01-16', startTime: '14:00', endTime: '15:00', resource: 'Resource D' },
      { title: 'Concurrent Appt 7', date: '2024-01-16', startTime: '14:30', endTime: '15:30', resource: 'Resource D' },
      { title: 'Concurrent Appt 8', date: '2024-01-16', startTime: '16:00', endTime: '17:00', resource: 'Resource E' },
      { title: 'Concurrent Appt 9', date: '2024-01-16', startTime: '16:20', endTime: '17:20', resource: 'Resource E' },
      { title: 'Concurrent Appt 10', date: '2024-01-16', startTime: '16:40', endTime: '17:40', resource: 'Resource E' }
    ];

    // Step 2: Initiate concurrent appointment creation from multiple scheduler accounts
    const pages = [page];
    for (let i = 0; i < 4; i++) {
      const newPage = await context.newPage();
      await newPage.goto('/login');
      await newPage.fill('[data-testid="username-input"]', `scheduler_user_${i + 2}`);
      await newPage.fill('[data-testid="password-input"]', 'scheduler_pass');
      await newPage.click('[data-testid="login-button"]');
      pages.push(newPage);
    }

    const startTime = Date.now();
    const creationPromises = appointmentData.map(async (appt, index) => {
      const currentPage = pages[index % pages.length];
      await currentPage.click('[data-testid="appointments-menu"]');
      await currentPage.click('[data-testid="create-appointment-button"]');
      await currentPage.fill('[data-testid="appointment-title-input"]', appt.title);
      await currentPage.fill('[data-testid="appointment-date-input"]', appt.date);
      await currentPage.fill('[data-testid="appointment-start-time-input"]', appt.startTime);
      await currentPage.fill('[data-testid="appointment-end-time-input"]', appt.endTime);
      await currentPage.fill('[data-testid="appointment-resource-input"]', appt.resource);
      await currentPage.click('[data-testid="save-appointment-button"]');
      
      const alertAppeared = await currentPage.locator('[data-testid="conflict-alert"]').isVisible({ timeout: 2000 }).catch(() => false);
      return { page: currentPage, alertAppeared, timestamp: Date.now() };
    });

    const results = await Promise.all(creationPromises);
    const endTime = Date.now();

    // Expected Result: All conflicts detected within 1 second latency
    results.forEach((result, index) => {
      const latency = result.timestamp - startTime;
      if ([1, 2, 4, 6, 8, 9].includes(index)) {
        expect(result.alertAppeared).toBe(true);
        expect(latency).toBeLessThan(1000);
      }
    });

    // Step 3: Check alert delivery to all schedulers
    for (const currentPage of pages) {
      const hasAlerts = await currentPage.locator('[data-testid="conflict-alert"], [data-testid="alert-notification"]').count();
      // Expected Result: All relevant users receive alerts promptly
      if (hasAlerts > 0) {
        await expect(currentPage.locator('[data-testid="conflict-alert"], [data-testid="alert-notification"]').first()).toBeVisible();
      }
    }

    // Step 4: Navigate to system logs and error logs section
    await page.click('[data-testid="system-logs-menu"]');
    await page.click('[data-testid="error-log-submenu"]');

    // Step 5: Review system logs for errors
    await page.fill('[data-testid="log-search-input"]', 'Concurrent Appt');
    await page.click('[data-testid="search-button"]');

    // Expected Result: No errors or missed conflicts
    const errorCount = await page.locator('[data-testid="error-log-entry"]').count();
    expect(errorCount).toBe(0);

    // Step 6: Verify performance metrics
    await page.click('[data-testid="performance-metrics-menu"]');
    const detectionLatency = await page.locator('[data-testid="conflict-detection-latency"]').textContent();
    const latencyValue = parseFloat(detectionLatency || '0');
    expect(latencyValue).toBeLessThan(1.0);

    // Cleanup additional pages
    for (let i = 1; i < pages.length; i++) {
      await pages[i].close();
    }
  });

  test('Ensure no alerts for non-overlapping appointments', async ({ page }) => {
    // Step 1: Navigate to the appointment creation page
    await page.click('[data-testid="appointments-menu"]');
    await page.click('[data-testid="create-appointment-button"]');

    // Step 2: Create first appointment with specific time slot (9:00 AM to 10:00 AM)
    await page.fill('[data-testid="appointment-title-input"]', 'Non-Overlapping Appt 1');
    await page.fill('[data-testid="appointment-date-input"]', '2024-01-17');
    await page.fill('[data-testid="appointment-start-time-input"]', '09:00');
    await page.fill('[data-testid="appointment-end-time-input"]', '10:00');
    await page.fill('[data-testid="appointment-resource-input"]', 'Resource F');
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: No conflict alerts are generated
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="appointment-saved-message"]')).toBeVisible();

    // Step 3: Create second appointment with non-overlapping time slot (10:00 AM to 11:00 AM)
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-title-input"]', 'Non-Overlapping Appt 2');
    await page.fill('[data-testid="appointment-date-input"]', '2024-01-17');
    await page.fill('[data-testid="appointment-start-time-input"]', '10:00');
    await page.fill('[data-testid="appointment-end-time-input"]', '11:00');
    await page.fill('[data-testid="appointment-resource-input"]', 'Resource F');
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: No conflict alerts are generated
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="appointment-saved-message"]')).toBeVisible();

    // Step 4: Create third appointment with completely separate time slot (2:00 PM to 3:00 PM)
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-title-input"]', 'Non-Overlapping Appt 3');
    await page.fill('[data-testid="appointment-date-input"]', '2024-01-17');
    await page.fill('[data-testid="appointment-start-time-input"]', '14:00');
    await page.fill('[data-testid="appointment-end-time-input"]', '15:00');
    await page.fill('[data-testid="appointment-resource-input"]', 'Resource F');
    await page.click('[data-testid="save-appointment-button"]');

    // Expected Result: No conflict alerts are generated
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="appointment-saved-message"]')).toBeVisible();

    // Step 5: Verify the UI notification area or alert panel
    const notificationPanel = page.locator('[data-testid="notification-panel"]');
    const alertCount = await page.locator('[data-testid="conflict-alert"]').count();
    expect(alertCount).toBe(0);

    // Step 6: Navigate to the system logs or conflict log section
    await page.click('[data-testid="system-logs-menu"]');
    await page.click('[data-testid="conflict-log-submenu"]');

    // Step 7: Search for conflict records related to the recently created appointments
    await page.fill('[data-testid="log-search-input"]', 'Non-Overlapping Appt');
    await page.click('[data-testid="search-button"]');

    // Expected Result: No conflict records created
    const conflictLogCount = await page.locator('[data-testid="conflict-log-entry"]').count();
    expect(conflictLogCount).toBe(0);
    await expect(page.locator('[data-testid="no-conflicts-message"]')).toBeVisible();

    // Step 8: Check the scheduler's notification history or alert inbox
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="alert-history-submenu"]');
    await page.fill('[data-testid="alert-search-input"]', 'Non-Overlapping Appt');
    await page.click('[data-testid="search-button"]');

    // Expected Result: No alert notifications displayed
    const alertHistoryCount = await page.locator('[data-testid="alert-history-entry"]').count();
    expect(alertHistoryCount).toBe(0);
  });
});