import { test, expect } from '@playwright/test';

test.describe('Story-7: Scheduling Conflict and Alert Logging', () => {
  let conflictId: string;
  let alertId: string;
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Login as scheduler with appropriate permissions
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'scheduler_user');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 10000 });
  });

  test('Verify logging of scheduling conflicts (happy-path)', async ({ page }) => {
    // Step 1: Create or trigger a scheduling conflict by attempting to book overlapping appointments
    await page.goto(`${baseURL}/scheduling`);
    await page.click('[data-testid="create-appointment-button"]');
    
    // Fill in first appointment details
    await page.fill('[data-testid="resource-select"]', 'Resource-101');
    await page.fill('[data-testid="appointment-date"]', '2024-06-15');
    await page.fill('[data-testid="appointment-start-time"]', '10:00');
    await page.fill('[data-testid="appointment-end-time"]', '11:00');
    await page.fill('[data-testid="patient-id"]', 'Patient-001');
    await page.click('[data-testid="save-appointment-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment created successfully');
    
    // Create overlapping appointment to trigger conflict
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource-101');
    await page.fill('[data-testid="appointment-date"]', '2024-06-15');
    await page.fill('[data-testid="appointment-start-time"]', '10:30');
    await page.fill('[data-testid="appointment-end-time"]', '11:30');
    await page.fill('[data-testid="patient-id"]', 'Patient-002');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Step 2: Verify conflict details are logged with complete metadata
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Scheduling conflict detected');
    
    // Extract conflict ID from the alert
    const conflictMessage = await page.locator('[data-testid="conflict-id"]').textContent();
    conflictId = conflictMessage?.match(/CONFLICT-\d+/)?.[0] || '';
    expect(conflictId).toBeTruthy();
    
    // Step 3: Navigate to the system log query interface
    await page.goto(`${baseURL}/admin/logs`);
    await expect(page.locator('[data-testid="log-query-interface"]')).toBeVisible();
    
    // Step 4: Search for the conflict entry using the conflict ID
    await page.fill('[data-testid="log-search-input"]', conflictId);
    await page.click('[data-testid="search-logs-button"]');
    
    // Wait for search results
    await expect(page.locator('[data-testid="log-results"]')).toBeVisible({ timeout: 3000 });
    
    // Step 5: Review the retrieved log entry and verify all metadata fields
    const logEntry = page.locator(`[data-testid="log-entry-${conflictId}"]`).first();
    await expect(logEntry).toBeVisible();
    
    // Verify conflict type
    await expect(logEntry.locator('[data-testid="log-conflict-type"]')).toContainText('RESOURCE_OVERLAP');
    
    // Verify timestamp is present and recent
    const timestamp = await logEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    const logTime = new Date(timestamp || '');
    const now = new Date();
    const timeDiff = now.getTime() - logTime.getTime();
    expect(timeDiff).toBeLessThan(60000); // Within last minute
    
    // Verify user ID
    await expect(logEntry.locator('[data-testid="log-user-id"]')).toContainText('scheduler_user');
    
    // Verify affected resources
    await expect(logEntry.locator('[data-testid="log-affected-resources"]')).toContainText('Resource-101');
    
    // Verify appointment IDs are logged
    const appointmentIds = await logEntry.locator('[data-testid="log-appointment-ids"]').textContent();
    expect(appointmentIds).toContain('Patient-001');
    expect(appointmentIds).toContain('Patient-002');
    
    // Verify logging completed within 500ms (check log metadata)
    const loggingDuration = await logEntry.locator('[data-testid="log-processing-time"]').textContent();
    const durationMs = parseInt(loggingDuration?.replace('ms', '') || '0');
    expect(durationMs).toBeLessThan(500);
  });

  test('Verify logging of alerts and acknowledgments (happy-path)', async ({ page }) => {
    // Step 1: Trigger a scheduling conflict that generates an alert
    await page.goto(`${baseURL}/scheduling`);
    await page.click('[data-testid="create-appointment-button"]');
    
    // Create first appointment
    await page.fill('[data-testid="resource-select"]', 'Resource-202');
    await page.fill('[data-testid="appointment-date"]', '2024-06-20');
    await page.fill('[data-testid="appointment-start-time"]', '14:00');
    await page.fill('[data-testid="appointment-end-time"]', '15:00');
    await page.fill('[data-testid="patient-id"]', 'Patient-003');
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Create conflicting appointment to trigger alert
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource-202');
    await page.fill('[data-testid="appointment-date"]', '2024-06-20');
    await page.fill('[data-testid="appointment-start-time"]', '14:30');
    await page.fill('[data-testid="appointment-end-time"]', '15:30');
    await page.fill('[data-testid="patient-id"]', 'Patient-004');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Step 2: Verify the alert is sent to the user
    await expect(page.locator('[data-testid="alert-notification"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="alert-notification"]')).toContainText('Conflict alert');
    
    // Extract alert ID
    const alertMessage = await page.locator('[data-testid="alert-id"]').textContent();
    alertId = alertMessage?.match(/ALERT-\d+/)?.[0] || '';
    expect(alertId).toBeTruthy();
    
    // Step 3: As the recipient user, acknowledge the received alert
    await page.click('[data-testid="acknowledge-alert-button"]');
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toContainText('Alert acknowledged');
    
    // Step 4: Verify the user acknowledgment is logged with timestamp, user ID, and alert reference
    await page.goto(`${baseURL}/admin/logs`);
    await page.fill('[data-testid="log-search-input"]', alertId);
    await page.click('[data-testid="search-logs-button"]');
    
    await expect(page.locator('[data-testid="log-results"]')).toBeVisible({ timeout: 3000 });
    
    // Step 5: Query the logs to retrieve both alert delivery and acknowledgment entries
    const alertDeliveryLog = page.locator(`[data-testid="log-entry-${alertId}-delivery"]`).first();
    await expect(alertDeliveryLog).toBeVisible();
    await expect(alertDeliveryLog.locator('[data-testid="log-event-type"]')).toContainText('ALERT_SENT');
    await expect(alertDeliveryLog.locator('[data-testid="log-user-id"]')).toContainText('scheduler_user');
    
    const acknowledgmentLog = page.locator(`[data-testid="log-entry-${alertId}-acknowledgment"]`).first();
    await expect(acknowledgmentLog).toBeVisible();
    await expect(acknowledgmentLog.locator('[data-testid="log-event-type"]')).toContainText('ALERT_ACKNOWLEDGED');
    await expect(acknowledgmentLog.locator('[data-testid="log-user-id"]')).toContainText('scheduler_user');
    await expect(acknowledgmentLog.locator('[data-testid="log-alert-reference"]')).toContainText(alertId);
    
    // Verify timestamp is present
    const ackTimestamp = await acknowledgmentLog.locator('[data-testid="log-timestamp"]').textContent();
    expect(ackTimestamp).toBeTruthy();
    
    // Step 6: Log out and log in as an unauthorized user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    
    // Login as unauthorized user
    await page.fill('[data-testid="username-input"]', 'regular_user');
    await page.fill('[data-testid="password-input"]', 'RegularPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Step 7: Attempt to access the system logs as unauthorized user
    await page.goto(`${baseURL}/admin/logs`);
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('You do not have permission to view system logs');
    
    // Verify log query interface is not accessible
    await expect(page.locator('[data-testid="log-query-interface"]')).not.toBeVisible();
    
    // Attempt direct API access to logs (should also be denied)
    const response = await page.request.get(`${baseURL}/api/logs?alertId=${alertId}`);
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Unauthorized');
  });
});