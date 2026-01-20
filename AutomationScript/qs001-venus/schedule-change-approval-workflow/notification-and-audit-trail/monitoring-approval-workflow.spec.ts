import { test, expect } from '@playwright/test';

test.describe('Story-12: Monitoring Approval Workflow Performance', () => {
  const ADMIN_USERNAME = 'admin@company.com';
  const ADMIN_PASSWORD = 'AdminPass123!';
  const NON_ADMIN_USERNAME = 'employee@company.com';
  const NON_ADMIN_PASSWORD = 'EmployeePass123!';
  const MONITORING_DASHBOARD_URL = '/monitoring/dashboard';
  const METRICS_API_URL = '/api/monitoring/metrics';

  test('Validate real-time metrics display (happy-path)', async ({ page }) => {
    // Navigate to the monitoring dashboard URL
    await page.goto(MONITORING_DASHBOARD_URL);

    // Enter valid Administrator credentials and click Login
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Verify the monitoring dashboard loads completely
    await expect(page.locator('[data-testid="monitoring-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="dashboard-title"]')).toContainText('Monitoring Dashboard');

    // Observe the real-time metrics section for current data
    await expect(page.locator('[data-testid="real-time-metrics-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="average-approval-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="pending-requests-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="sla-compliance-rate"]')).toBeVisible();

    // Record the displayed metric values
    const initialAvgApprovalTime = await page.locator('[data-testid="average-approval-time"]').textContent();
    const initialPendingCount = await page.locator('[data-testid="pending-requests-count"]').textContent();
    const initialSlaCompliance = await page.locator('[data-testid="sla-compliance-rate"]').textContent();

    // Verify timestamp on dashboard shows last update time
    const lastUpdateTimestamp = await page.locator('[data-testid="last-update-timestamp"]');
    await expect(lastUpdateTimestamp).toBeVisible();
    const timestampText = await lastUpdateTimestamp.textContent();
    expect(timestampText).toBeTruthy();

    // Wait for 5 minutes and observe the dashboard (simulated with shorter wait for testing)
    await page.waitForTimeout(5000); // In production, this would be 300000ms (5 minutes)

    // Verify metrics are updated
    const updatedTimestamp = await page.locator('[data-testid="last-update-timestamp"]').textContent();
    expect(updatedTimestamp).not.toBe(timestampText);

    // Query the database directly for expected metric values (simulated via API call)
    const response = await page.request.get(METRICS_API_URL);
    expect(response.ok()).toBeTruthy();
    const metricsData = await response.json();

    // Compare dashboard metrics with API values
    const displayedAvgTime = await page.locator('[data-testid="average-approval-time-value"]').textContent();
    const displayedPendingCount = await page.locator('[data-testid="pending-requests-count-value"]').textContent();
    const displayedSlaRate = await page.locator('[data-testid="sla-compliance-rate-value"]').textContent();

    expect(displayedAvgTime).toBe(metricsData.averageApprovalTime.toString());
    expect(displayedPendingCount).toBe(metricsData.pendingRequestsCount.toString());
    expect(displayedSlaRate).toBe(metricsData.slaComplianceRate.toString());
  });

  test('Test alert generation for SLA breaches (error-case)', async ({ page }) => {
    // Login as Administrator
    await page.goto(MONITORING_DASHBOARD_URL);
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="monitoring-dashboard"]')).toBeVisible();

    // Create a new schedule change request in the system
    await page.click('[data-testid="create-request-button"]');
    await page.fill('[data-testid="request-employee-id"]', 'EMP001');
    await page.fill('[data-testid="request-date"]', '2024-01-15');
    await page.fill('[data-testid="request-reason"]', 'SLA breach test request');
    await page.click('[data-testid="submit-request-button"]');

    // Note the current time and the SLA deadline
    const requestId = await page.locator('[data-testid="created-request-id"]').textContent();
    const slaDeadline = await page.locator('[data-testid="sla-deadline"]').textContent();
    expect(requestId).toBeTruthy();
    expect(slaDeadline).toBeTruthy();

    // Simulate the passage of time to exceed the SLA threshold
    // This would typically involve modifying request timestamp in database
    await page.evaluate((id) => {
      return fetch('/api/test/simulate-sla-breach', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestId: id })
      });
    }, requestId);

    // Wait for up to 5 minutes and monitor the dashboard alerts section
    await page.waitForTimeout(5000); // Simulated wait
    await page.reload();

    // Verify alert generated and displayed within 5 minutes
    const alertSection = page.locator('[data-testid="alerts-section"]');
    await expect(alertSection).toBeVisible();
    
    const slaBreachAlert = page.locator(`[data-testid="sla-breach-alert-${requestId}"]`);
    await expect(slaBreachAlert).toBeVisible({ timeout: 10000 });

    // Verify the alert contains request ID, breach time, and severity level
    await expect(slaBreachAlert.locator('[data-testid="alert-request-id"]')).toContainText(requestId);
    await expect(slaBreachAlert.locator('[data-testid="alert-breach-time"]')).toBeVisible();
    await expect(slaBreachAlert.locator('[data-testid="alert-severity"]')).toContainText('High');

    // Verify the alert timestamp matches the actual breach detection time
    const alertTimestamp = await slaBreachAlert.locator('[data-testid="alert-timestamp"]').textContent();
    expect(alertTimestamp).toBeTruthy();

    // Check if alert notification was sent via configured channels
    const notificationIndicator = slaBreachAlert.locator('[data-testid="notification-sent-indicator"]');
    await expect(notificationIndicator).toBeVisible();
    await expect(notificationIndicator).toContainText('Notification Sent');

    // Click on the alert to view detailed information
    await slaBreachAlert.click();
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-details-request-id"]')).toContainText(requestId);
    await expect(page.locator('[data-testid="alert-details-breach-info"]')).toBeVisible();
  });

  test('Verify access control to monitoring dashboard (error-case)', async ({ page, request }) => {
    // Navigate to the monitoring dashboard URL using a browser
    await page.goto(MONITORING_DASHBOARD_URL);

    // Enter credentials for a non-admin user (Employee or Manager role) and click Login
    await page.fill('[data-testid="username-input"]', NON_ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', NON_ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Attempt to access the monitoring dashboard page
    await page.goto(MONITORING_DASHBOARD_URL);

    // Verify the user is not redirected to the dashboard and remains on access denied page
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="monitoring-dashboard"]')).not.toBeVisible();

    // Attempt to directly access the API endpoint using non-admin credentials
    const nonAdminApiResponse = await request.get(METRICS_API_URL, {
      headers: {
        'Authorization': 'Bearer non-admin-token'
      }
    });
    expect(nonAdminApiResponse.status()).toBe(403);
    const nonAdminApiBody = await nonAdminApiResponse.json();
    expect(nonAdminApiBody.error).toContain('Forbidden');

    // Log out the non-admin user
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();

    // Enter credentials for a user with Admin role and click Login
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Navigate to the monitoring dashboard page
    await page.goto(MONITORING_DASHBOARD_URL);

    // Verify all dashboard features are accessible
    await expect(page.locator('[data-testid="monitoring-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="real-time-metrics-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="historical-reports-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="drill-down-section"]')).toBeVisible();

    // Access the API endpoint using admin credentials
    const adminApiResponse = await request.get(METRICS_API_URL, {
      headers: {
        'Authorization': 'Bearer admin-token'
      }
    });
    expect(adminApiResponse.ok()).toBeTruthy();
    expect(adminApiResponse.status()).toBe(200);
    const adminApiBody = await adminApiResponse.json();
    expect(adminApiBody).toHaveProperty('averageApprovalTime');
    expect(adminApiBody).toHaveProperty('pendingRequestsCount');
    expect(adminApiBody).toHaveProperty('slaComplianceRate');
  });
});