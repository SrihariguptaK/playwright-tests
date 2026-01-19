import { test, expect } from '@playwright/test';

test.describe('Real-time Conflict Alerts for Schedulers', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling interface and login
    await page.goto('/scheduling');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="scheduling-dashboard"]')).toBeVisible();
  });

  test('Validate real-time alert display on conflict detection (happy-path)', async ({ page }) => {
    // Step 1: Scheduler creates a new schedule entry that conflicts with an existing schedule
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:00');
    await page.fill('[data-testid="title-input"]', 'Team Meeting');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Alert displayed immediately on scheduling interface
    const alert = page.locator('[data-testid="conflict-alert"]');
    await expect(alert).toBeVisible({ timeout: 1000 });
    await expect(alert).toContainText('Scheduling Conflict Detected');
    
    // Step 2: Scheduler clicks on the alert to view details
    await page.click('[data-testid="conflict-alert"]');
    
    // Expected Result: Detailed conflict information is shown
    const alertDetails = page.locator('[data-testid="alert-details-modal"]');
    await expect(alertDetails).toBeVisible();
    await expect(alertDetails.locator('[data-testid="conflict-resource"]')).toContainText('Conference Room A');
    await expect(alertDetails.locator('[data-testid="conflict-time"]')).toContainText('10:00');
    await expect(alertDetails.locator('[data-testid="existing-schedule-info"]')).toBeVisible();
    
    // Step 3: Scheduler clicks the acknowledge button on the alert
    await page.click('[data-testid="acknowledge-alert-button"]');
    
    // Expected Result: Alert is dismissed from interface
    await expect(alert).not.toBeVisible();
    await expect(alertDetails).not.toBeVisible();
  });

  test('Verify email notification delivery for conflicts (happy-path)', async ({ page }) => {
    // Step 1: Verify that scheduler has email notifications enabled in system preferences
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="preferences-link"]');
    
    const emailNotificationToggle = page.locator('[data-testid="email-notification-toggle"]');
    await expect(emailNotificationToggle).toBeChecked();
    
    // If not enabled, enable it
    if (!(await emailNotificationToggle.isChecked())) {
      await emailNotificationToggle.check();
      await page.click('[data-testid="save-preferences-button"]');
      await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();
    }
    
    await page.click('[data-testid="close-preferences-button"]');
    
    // Step 2: Create a scheduling conflict by adding an overlapping schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Meeting Room B');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T15:00');
    await page.fill('[data-testid="title-input"]', 'Client Presentation');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: System sends email upon conflict detection
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="email-notification-sent-indicator"]')).toBeVisible();
    
    // Step 3: Scheduler opens their email inbox and locates the conflict notification email
    // Navigate to email interface (simulated)
    await page.goto('/email-inbox');
    await page.fill('[data-testid="email-search-input"]', 'Scheduling Conflict');
    await page.click('[data-testid="email-search-button"]');
    
    const conflictEmail = page.locator('[data-testid="email-item"]').filter({ hasText: 'Scheduling Conflict Detected' });
    await expect(conflictEmail).toBeVisible();
    await expect(conflictEmail).toContainText('Meeting Room B');
    
    // Step 4: Scheduler clicks the link provided in the email to view the conflict
    await conflictEmail.click();
    const emailLink = page.locator('[data-testid="view-conflict-link"]');
    await expect(emailLink).toBeVisible();
    await emailLink.click();
    
    // Expected Result: Navigated to scheduling interface with conflict highlighted
    await expect(page).toHaveURL(/.*scheduling.*conflict.*/);
    const highlightedConflict = page.locator('[data-testid="highlighted-conflict"]');
    await expect(highlightedConflict).toBeVisible();
    await expect(highlightedConflict).toContainText('Meeting Room B');
  });

  test('Ensure alert delivery within 1 second (boundary)', async ({ page }) => {
    const alertDeliveryTimes: number[] = [];
    const numberOfTests = 10;
    
    // Step 1 & 2: Note the current time and trigger scheduling conflicts, monitoring delivery times
    for (let i = 0; i < numberOfTests; i++) {
      await page.click('[data-testid="create-schedule-button"]');
      await page.fill('[data-testid="resource-input"]', `Test Resource ${i}`);
      await page.fill('[data-testid="start-time-input"]', `2024-01-16T${10 + i}:00`);
      await page.fill('[data-testid="end-time-input"]', `2024-01-16T${11 + i}:00`);
      await page.fill('[data-testid="title-input"]', `Performance Test ${i}`);
      
      // Record start time
      const startTime = Date.now();
      
      // Trigger conflict
      await page.click('[data-testid="save-schedule-button"]');
      
      // Wait for alert and record delivery time
      const alert = page.locator('[data-testid="conflict-alert"]');
      await expect(alert).toBeVisible({ timeout: 2000 });
      
      const endTime = Date.now();
      const deliveryTime = endTime - startTime;
      alertDeliveryTimes.push(deliveryTime);
      
      // Expected Result: Alert displayed within 1 second
      expect(deliveryTime).toBeLessThanOrEqual(1000);
      
      // Dismiss alert for next iteration
      await page.click('[data-testid="acknowledge-alert-button"]');
      await expect(alert).not.toBeVisible();
    }
    
    // Expected Result: All alerts delivered within SLA
    const allWithinSLA = alertDeliveryTimes.every(time => time <= 1000);
    expect(allWithinSLA).toBeTruthy();
    
    const averageDeliveryTime = alertDeliveryTimes.reduce((a, b) => a + b, 0) / alertDeliveryTimes.length;
    console.log(`Average alert delivery time: ${averageDeliveryTime}ms`);
    console.log(`Alert delivery times: ${alertDeliveryTimes.join(', ')}ms`);
    
    // Step 3: Review system logs for alert latency
    await page.goto('/admin/system-logs');
    await page.fill('[data-testid="log-filter-input"]', 'alert_latency');
    await page.click('[data-testid="apply-filter-button"]');
    
    const latencyMetrics = page.locator('[data-testid="latency-metrics-table"]');
    await expect(latencyMetrics).toBeVisible();
    
    // Expected Result: Latency metrics meet performance criteria
    const maxLatencyCell = page.locator('[data-testid="max-latency-value"]');
    const maxLatencyText = await maxLatencyCell.textContent();
    const maxLatency = parseInt(maxLatencyText?.replace('ms', '') || '0');
    expect(maxLatency).toBeLessThanOrEqual(1000);
    
    const avgLatencyCell = page.locator('[data-testid="avg-latency-value"]');
    const avgLatencyText = await avgLatencyCell.textContent();
    const avgLatency = parseInt(avgLatencyText?.replace('ms', '') || '0');
    expect(avgLatency).toBeLessThanOrEqual(1000);
  });
});