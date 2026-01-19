import { test, expect } from '@playwright/test';

test.describe('Attendance Anomaly Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Login as supervisor
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'supervisor@company.com');
    await page.fill('[data-testid="password-input"]', 'SupervisorPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate notification sent on attendance anomaly detection (happy-path)', async ({ page }) => {
    // Step 1: Record attendance data with an anomaly (e.g., employee arrives 30 minutes late)
    await page.goto('/attendance/record');
    await page.fill('[data-testid="employee-id-input"]', 'EMP001');
    await page.fill('[data-testid="check-in-time-input"]', '09:30');
    await page.selectOption('[data-testid="attendance-status-select"]', 'late');
    await page.click('[data-testid="record-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance recorded successfully');
    
    // Verify system detects anomaly and triggers notification
    await expect(page.locator('[data-testid="anomaly-detected-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-triggered-message"]')).toContainText('Anomaly notification triggered');
    
    // Step 2: Check supervisor's email inbox for notification
    await page.goto('/test-email-inbox');
    await page.waitForSelector('[data-testid="email-list"]');
    const emailNotification = page.locator('[data-testid="email-item"]').filter({ hasText: 'Attendance Anomaly Alert' }).first();
    await expect(emailNotification).toBeVisible();
    await emailNotification.click();
    await expect(page.locator('[data-testid="email-subject"]')).toContainText('Attendance Anomaly Alert');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('EMP001');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('late arrival');
    
    // Step 3: Check supervisor's mobile phone for SMS notification (simulated)
    await page.goto('/test-sms-inbox');
    const smsNotification = page.locator('[data-testid="sms-item"]').filter({ hasText: 'Attendance Anomaly' }).first();
    await expect(smsNotification).toBeVisible();
    await expect(smsNotification).toContainText('EMP001');
    await expect(smsNotification).toContainText('late');
    
    // Step 4: Open the application and navigate to notifications section
    await page.goto('/notifications');
    await expect(page).toHaveURL(/.*notifications/);
    
    // Step 5: Click on the in-app notification to view full details
    const inAppNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'EMP001' }).first();
    await expect(inAppNotification).toBeVisible();
    await inAppNotification.click();
    await expect(page.locator('[data-testid="notification-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-details"]')).toContainText('EMP001');
    await expect(page.locator('[data-testid="anomaly-type"]')).toContainText('Late Arrival');
    await expect(page.locator('[data-testid="anomaly-timestamp"]')).toBeVisible();
    
    // Step 6: Click the 'Acknowledge' button on the notification
    await page.click('[data-testid="acknowledge-button"]');
    await expect(page.locator('[data-testid="comment-section"]')).toBeVisible();
    
    // Step 7: Enter comment 'Contacted employee, valid reason provided' and submit acknowledgment
    await page.fill('[data-testid="comment-input"]', 'Contacted employee, valid reason provided');
    await page.click('[data-testid="submit-acknowledgment-button"]');
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toContainText('Acknowledgment recorded successfully');
    
    // Step 8: Navigate to notification logs/audit trail section
    await page.goto('/notifications/audit-trail');
    await expect(page).toHaveURL(/.*audit-trail/);
    const auditEntry = page.locator('[data-testid="audit-entry"]').filter({ hasText: 'EMP001' }).first();
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry).toContainText('Acknowledged');
    await expect(auditEntry).toContainText('Contacted employee, valid reason provided');
  });

  test('Verify notification retry mechanism on failure (error-case)', async ({ page }) => {
    // Step 1: Configure test environment to simulate email delivery failure
    await page.goto('/admin/test-settings');
    await page.click('[data-testid="simulate-email-failure-toggle"]');
    await expect(page.locator('[data-testid="email-failure-enabled-message"]')).toContainText('Email delivery failure simulation enabled');
    
    // Step 2: Record attendance data with anomaly to trigger notification
    await page.goto('/attendance/record');
    await page.fill('[data-testid="employee-id-input"]', 'EMP002');
    await page.fill('[data-testid="check-in-time-input"]', '09:45');
    await page.selectOption('[data-testid="attendance-status-select"]', 'late');
    await page.click('[data-testid="record-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance recorded successfully');
    
    // Step 3: Monitor notification service logs for first delivery attempt
    await page.goto('/admin/notification-logs');
    await page.waitForTimeout(2000);
    const firstAttempt = page.locator('[data-testid="log-entry"]').filter({ hasText: 'EMP002' }).filter({ hasText: 'Attempt 1' }).first();
    await expect(firstAttempt).toBeVisible();
    await expect(firstAttempt).toContainText('Failed');
    
    // Step 4: Wait for first retry attempt (based on retry interval configuration)
    await page.waitForTimeout(5000);
    await page.reload();
    
    // Step 5: Check notification logs for second attempt
    const secondAttempt = page.locator('[data-testid="log-entry"]').filter({ hasText: 'EMP002' }).filter({ hasText: 'Attempt 2' }).first();
    await expect(secondAttempt).toBeVisible();
    await expect(secondAttempt).toContainText('Failed');
    
    // Step 6: Wait for second retry attempt
    await page.waitForTimeout(5000);
    await page.reload();
    
    // Step 7: Check notification logs for third attempt
    const thirdAttempt = page.locator('[data-testid="log-entry"]').filter({ hasText: 'EMP002' }).filter({ hasText: 'Attempt 3' }).first();
    await expect(thirdAttempt).toBeVisible();
    await expect(thirdAttempt).toContainText('Failed');
    
    // Step 8: Verify system behavior after maximum retries exhausted
    await page.waitForTimeout(3000);
    await page.reload();
    const maxRetriesEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: 'EMP002' }).filter({ hasText: 'Max retries exhausted' }).first();
    await expect(maxRetriesEntry).toBeVisible();
    
    // Step 9: Query notification logs database for the specific notification ID
    const notificationId = await page.locator('[data-testid="notification-id"]').first().textContent();
    await page.fill('[data-testid="search-notification-input"]', notificationId || '');
    await page.click('[data-testid="search-button"]');
    const searchResults = page.locator('[data-testid="search-results"]');
    await expect(searchResults).toContainText('3 attempts');
    await expect(searchResults).toContainText('Failed');
    
    // Step 10: Restore email service to working state and trigger new anomaly
    await page.goto('/admin/test-settings');
    await page.click('[data-testid="simulate-email-failure-toggle"]');
    await expect(page.locator('[data-testid="email-failure-disabled-message"]')).toContainText('Email delivery failure simulation disabled');
    
    await page.goto('/attendance/record');
    await page.fill('[data-testid="employee-id-input"]', 'EMP003');
    await page.fill('[data-testid="check-in-time-input"]', '09:50');
    await page.selectOption('[data-testid="attendance-status-select"]', 'late');
    await page.click('[data-testid="record-attendance-button"]');
    
    // Step 11: Check logs for successful delivery
    await page.goto('/admin/notification-logs');
    await page.waitForTimeout(2000);
    const successfulDelivery = page.locator('[data-testid="log-entry"]').filter({ hasText: 'EMP003' }).filter({ hasText: 'Attempt 1' }).first();
    await expect(successfulDelivery).toBeVisible();
    await expect(successfulDelivery).toContainText('Success');
  });

  test('Ensure notifications meet delivery SLA (boundary)', async ({ page }) => {
    const anomalies = [
      { employeeId: 'EMPA', time: '09:15', status: 'late', type: 'late arrival' },
      { employeeId: 'EMPB', time: '09:00', status: 'absent', type: 'absence without notice' },
      { employeeId: 'EMPC', time: '16:30', status: 'early-departure', type: 'early departure' },
      { employeeId: 'EMPD', time: '12:00', status: 'extended-break', type: 'extended break' },
      { employeeId: 'EMPE', time: '09:20', status: 'late', type: 'late arrival' }
    ];
    
    const detectionTimestamps: { [key: string]: number } = {};
    
    // Steps 1-5: Record attendance anomalies for Employees A through E
    for (const anomaly of anomalies) {
      await page.goto('/attendance/record');
      detectionTimestamps[anomaly.employeeId] = Date.now();
      await page.fill('[data-testid="employee-id-input"]', anomaly.employeeId);
      await page.fill('[data-testid="check-in-time-input"]', anomaly.time);
      await page.selectOption('[data-testid="attendance-status-select"]', anomaly.status);
      await page.click('[data-testid="record-attendance-button"]');
      await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance recorded successfully');
    }
    
    // Steps 6-10: Monitor notification delivery for each employee anomaly
    await page.goto('/admin/notification-logs');
    await page.waitForTimeout(12000); // Wait for all notifications to be processed
    
    const deliveryTimes: { [key: string]: number } = {};
    
    for (const anomaly of anomalies) {
      await page.reload();
      const logEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: anomaly.employeeId }).first();
      await expect(logEntry).toBeVisible({ timeout: 15000 });
      
      const deliveryTimestampText = await logEntry.locator('[data-testid="delivery-timestamp"]').textContent();
      const deliveryTimestamp = deliveryTimestampText ? new Date(deliveryTimestampText).getTime() : Date.now();
      deliveryTimes[anomaly.employeeId] = deliveryTimestamp;
    }
    
    // Step 11: Calculate delivery time for each notification
    await page.goto('/admin/sla-report');
    
    for (const anomaly of anomalies) {
      const deliveryTime = (deliveryTimes[anomaly.employeeId] - detectionTimestamps[anomaly.employeeId]) / 1000 / 60;
      const slaEntry = page.locator('[data-testid="sla-entry"]').filter({ hasText: anomaly.employeeId }).first();
      await expect(slaEntry).toBeVisible();
      
      const deliveryTimeElement = slaEntry.locator('[data-testid="delivery-time-minutes"]');
      const displayedTime = await deliveryTimeElement.textContent();
      const timeInMinutes = parseFloat(displayedTime || '0');
      
      // Verify delivery time is within 10 minutes SLA
      expect(timeInMinutes).toBeLessThanOrEqual(10);
      await expect(slaEntry.locator('[data-testid="sla-status"]')).toContainText('Met');
    }
    
    // Step 12: Query system performance logs for notification processing metrics
    await page.goto('/admin/performance-logs');
    await page.fill('[data-testid="filter-type-input"]', 'notification-processing');
    await page.click('[data-testid="apply-filter-button"]');
    
    const performanceMetrics = page.locator('[data-testid="performance-metrics"]');
    await expect(performanceMetrics).toBeVisible();
    await expect(performanceMetrics.locator('[data-testid="average-processing-time"]')).toBeVisible();
    
    const avgProcessingTime = await performanceMetrics.locator('[data-testid="average-processing-time"]').textContent();
    const avgTime = parseFloat(avgProcessingTime?.replace(/[^0-9.]/g, '') || '0');
    expect(avgTime).toBeLessThanOrEqual(10);
    
    // Step 13: Review system error logs for any delays or failures during test period
    await page.goto('/admin/error-logs');
    await page.fill('[data-testid="filter-category-input"]', 'notification');
    await page.click('[data-testid="apply-filter-button"]');
    
    const errorCount = await page.locator('[data-testid="error-count"]').textContent();
    expect(parseInt(errorCount || '0')).toBe(0);
    
    const noErrorsMessage = page.locator('[data-testid="no-errors-message"]');
    await expect(noErrorsMessage).toContainText('No errors found');
    
    // Step 14: Generate SLA compliance report from notification system
    await page.goto('/admin/sla-report');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-generated-message"]')).toContainText('SLA compliance report generated');
    
    const complianceRate = await page.locator('[data-testid="sla-compliance-rate"]').textContent();
    const compliancePercentage = parseFloat(complianceRate?.replace(/[^0-9.]/g, '') || '0');
    expect(compliancePercentage).toBeGreaterThanOrEqual(90);
    
    await expect(page.locator('[data-testid="total-notifications"]')).toContainText('5');
    await expect(page.locator('[data-testid="notifications-within-sla"]')).toContainText('5');
  });
});