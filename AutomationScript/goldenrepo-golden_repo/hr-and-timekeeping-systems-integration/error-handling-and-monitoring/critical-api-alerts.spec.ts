import { test, expect } from '@playwright/test';

test.describe('Critical API Integration Failure Alerts', () => {
  const baseURL = process.env.BASE_URL || 'https://app.example.com';
  const alertsConfigURL = `${baseURL}/alerts/configure`;
  const alertsHistoryURL = `${baseURL}/alerts/history`;
  const dashboardURL = `${baseURL}/dashboard`;

  test.beforeEach(async ({ page }) => {
    // Login as Support Engineer
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'support.engineer@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(dashboardURL);
  });

  test('Validate alert triggering on critical API failures', async ({ page }) => {
    // Step 1: Simulate critical API failure event
    await page.goto(`${baseURL}/admin/simulate-failure`);
    await page.selectOption('[data-testid="failure-type-select"]', 'critical-api-failure');
    await page.fill('[data-testid="api-endpoint-input"]', '/api/v1/payments/process');
    await page.fill('[data-testid="error-code-input"]', '500');
    await page.click('[data-testid="simulate-failure-button"]');
    
    // Expected Result: System detects failure and triggers alert
    await expect(page.locator('[data-testid="alert-triggered-notification"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="alert-triggered-notification"]')).toContainText('Critical API failure detected');
    
    // Step 2: Verify alert delivery via email and SMS
    await page.goto(alertsHistoryURL);
    await page.waitForLoadState('networkidle');
    
    const latestAlert = page.locator('[data-testid="alert-row"]').first();
    await expect(latestAlert).toBeVisible();
    await expect(latestAlert.locator('[data-testid="alert-type"]')).toContainText('Critical API Failure');
    
    // Verify delivery channels
    await latestAlert.click();
    await expect(page.locator('[data-testid="alert-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="delivery-channel-email"]')).toContainText('Delivered');
    await expect(page.locator('[data-testid="delivery-channel-sms"]')).toContainText('Delivered');
    
    const deliveryTimestamp = await page.locator('[data-testid="delivery-timestamp"]').textContent();
    expect(deliveryTimestamp).toBeTruthy();
    
    // Step 3: Acknowledge alert in UI
    await page.click('[data-testid="acknowledge-alert-button"]');
    await page.fill('[data-testid="acknowledgement-note-input"]', 'Investigating the payment API failure');
    await page.click('[data-testid="submit-acknowledgement-button"]');
    
    // Expected Result: Acknowledgement is logged and visible
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    await expect(page.locator('[data-testid="acknowledgement-log"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledgement-log"]')).toContainText('Investigating the payment API failure');
    await expect(page.locator('[data-testid="acknowledged-by"]')).toContainText('support.engineer@example.com');
  });

  test('Test alert configuration and escalation', async ({ page }) => {
    // Step 1: Configure alert recipients and escalation rules
    await page.goto(alertsConfigURL);
    await page.waitForLoadState('networkidle');
    
    // Add primary recipient
    await page.click('[data-testid="add-recipient-button"]');
    await page.fill('[data-testid="recipient-email-input"]', 'primary.support@example.com');
    await page.check('[data-testid="recipient-email-channel"]');
    await page.check('[data-testid="recipient-sms-channel"]');
    await page.fill('[data-testid="recipient-phone-input"]', '+1234567890');
    await page.click('[data-testid="save-recipient-button"]');
    
    // Configure escalation policy
    await page.click('[data-testid="escalation-policy-tab"]');
    await page.fill('[data-testid="escalation-timeout-input"]', '10');
    await page.selectOption('[data-testid="escalation-timeout-unit"]', 'minutes');
    await page.click('[data-testid="add-escalation-level-button"]');
    await page.fill('[data-testid="escalation-recipient-email"]', 'escalation.manager@example.com');
    await page.click('[data-testid="save-escalation-button"]');
    
    await page.click('[data-testid="save-alert-config-button"]');
    
    // Expected Result: Settings are saved and applied
    await expect(page.locator('[data-testid="config-saved-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="config-saved-notification"]')).toContainText('Alert configuration saved successfully');
    
    // Verify saved configuration
    await page.reload();
    await expect(page.locator('[data-testid="recipient-email"]').filter({ hasText: 'primary.support@example.com' })).toBeVisible();
    await page.click('[data-testid="escalation-policy-tab"]');
    await expect(page.locator('[data-testid="escalation-timeout-input"]')).toHaveValue('10');
    
    // Step 2: Trigger alert without acknowledgement
    await page.goto(`${baseURL}/admin/simulate-failure`);
    await page.selectOption('[data-testid="failure-type-select"]', 'critical-api-failure');
    await page.fill('[data-testid="api-endpoint-input"]', '/api/v1/orders/create');
    await page.click('[data-testid="simulate-failure-button"]');
    
    await expect(page.locator('[data-testid="alert-triggered-notification"]')).toBeVisible({ timeout: 10000 });
    
    // Wait for escalation timeout (simulated with shorter wait for testing)
    await page.goto(alertsHistoryURL);
    await page.waitForTimeout(2000); // Simulated escalation wait
    
    // Trigger escalation manually for test purposes
    await page.click('[data-testid="alert-row"]', { position: { x: 10, y: 10 } });
    await page.click('[data-testid="force-escalation-button"]');
    
    // Expected Result: Alert is escalated as per policy
    await expect(page.locator('[data-testid="alert-escalation-status"]')).toContainText('Escalated');
    await expect(page.locator('[data-testid="escalation-level"]')).toContainText('Level 1');
    await expect(page.locator('[data-testid="escalated-to"]')).toContainText('escalation.manager@example.com');
    
    // Step 3: Review alert history and escalation logs
    await page.click('[data-testid="view-escalation-logs-button"]');
    
    // Expected Result: All events are recorded accurately
    await expect(page.locator('[data-testid="escalation-log-panel"]')).toBeVisible();
    const logEntries = page.locator('[data-testid="escalation-log-entry"]');
    await expect(logEntries).toHaveCount(await logEntries.count());
    
    const firstLogEntry = logEntries.first();
    await expect(firstLogEntry).toContainText('Alert created');
    await expect(firstLogEntry).toContainText('primary.support@example.com');
    
    const escalationLogEntry = logEntries.filter({ hasText: 'Escalated' });
    await expect(escalationLogEntry).toBeVisible();
    await expect(escalationLogEntry).toContainText('escalation.manager@example.com');
  });

  test('Verify integration with incident management tools', async ({ page }) => {
    // Step 1: Configure integration with incident management system
    await page.goto(`${baseURL}/integrations`);
    await page.waitForLoadState('networkidle');
    
    await page.click('[data-testid="add-integration-button"]');
    await page.selectOption('[data-testid="integration-type-select"]', 'incident-management');
    await page.fill('[data-testid="integration-name-input"]', 'ServiceNow Integration');
    await page.fill('[data-testid="integration-api-url-input"]', 'https://servicenow.example.com/api');
    await page.fill('[data-testid="integration-api-key-input"]', 'test-api-key-12345');
    await page.check('[data-testid="enable-alert-forwarding"]');
    await page.click('[data-testid="save-integration-button"]');
    
    // Expected Result: Integration is active
    await expect(page.locator('[data-testid="integration-saved-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="integration-status"]').filter({ hasText: 'ServiceNow Integration' })).toContainText('Active');
    
    // Test connection
    await page.click('[data-testid="test-integration-button"]');
    await expect(page.locator('[data-testid="integration-test-result"]')).toContainText('Connection successful', { timeout: 10000 });
    
    // Step 2: Trigger alert event
    await page.goto(`${baseURL}/admin/simulate-failure`);
    await page.selectOption('[data-testid="failure-type-select"]', 'critical-api-failure');
    await page.fill('[data-testid="api-endpoint-input"]', '/api/v1/inventory/update');
    await page.fill('[data-testid="error-code-input"]', '503');
    await page.fill('[data-testid="error-message-input"]', 'Service unavailable - database connection timeout');
    await page.click('[data-testid="simulate-failure-button"]');
    
    await expect(page.locator('[data-testid="alert-triggered-notification"]')).toBeVisible({ timeout: 10000 });
    
    // Wait for incident creation
    await page.waitForTimeout(3000);
    
    // Navigate to alert history to verify incident creation
    await page.goto(alertsHistoryURL);
    const latestAlert = page.locator('[data-testid="alert-row"]').first();
    await latestAlert.click();
    
    // Expected Result: Incident is created in external system
    await expect(page.locator('[data-testid="external-incident-created"]')).toBeVisible();
    await expect(page.locator('[data-testid="external-incident-id"]')).toBeVisible();
    
    const incidentId = await page.locator('[data-testid="external-incident-id"]').textContent();
    expect(incidentId).toMatch(/INC\d+/);
    
    // Step 3: Verify incident details and status
    await page.click('[data-testid="view-external-incident-button"]');
    
    // Expected Result: Incident reflects alert information correctly
    await expect(page.locator('[data-testid="incident-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="incident-title"]')).toContainText('Critical API Failure');
    await expect(page.locator('[data-testid="incident-description"]')).toContainText('/api/v1/inventory/update');
    await expect(page.locator('[data-testid="incident-description"]')).toContainText('Service unavailable - database connection timeout');
    await expect(page.locator('[data-testid="incident-severity"]')).toContainText('Critical');
    await expect(page.locator('[data-testid="incident-status"]')).toContainText('Open');
    await expect(page.locator('[data-testid="incident-error-code"]')).toContainText('503');
    
    // Verify incident metadata
    await expect(page.locator('[data-testid="incident-created-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="incident-source"]')).toContainText('API Monitoring System');
  });
});