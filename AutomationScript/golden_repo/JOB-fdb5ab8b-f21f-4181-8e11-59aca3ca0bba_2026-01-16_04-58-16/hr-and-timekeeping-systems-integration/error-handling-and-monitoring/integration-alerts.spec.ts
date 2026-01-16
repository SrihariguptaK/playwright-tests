import { test, expect } from '@playwright/test';

test.describe('Integration Failure Alerts - Story 20', () => {
  const adminEmail = 'admin@test.com';
  const adminPassword = 'Admin123!';
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', adminEmail);
    await page.fill('[data-testid="password-input"]', adminPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify alert triggering on critical integration failure', async ({ page }) => {
    // Record the current system timestamp before simulating the failure
    const failureTimestamp = new Date();
    
    // Navigate to integration monitoring or testing section
    await page.click('[data-testid="integrations-menu"]');
    await page.click('[data-testid="integration-testing-link"]');
    await expect(page.locator('[data-testid="integration-testing-page"]')).toBeVisible();
    
    // Simulate a critical integration failure
    await page.click('[data-testid="simulate-failure-button"]');
    await page.selectOption('[data-testid="failure-type-select"]', 'critical');
    await page.click('[data-testid="trigger-failure-button"]');
    
    // Verify that alert is triggered automatically by checking system logs
    await page.click('[data-testid="system-logs-link"]');
    await expect(page.locator('[data-testid="alert-triggered-log"]').first()).toBeVisible({ timeout: 10000 });
    const alertLog = await page.locator('[data-testid="alert-triggered-log"]').first().textContent();
    expect(alertLog).toContain('Critical integration failure detected');
    
    // Navigate to alerts section
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alerts-section-link"]');
    await expect(page.locator('[data-testid="alerts-list"]')).toBeVisible();
    
    // Verify alert appears in the list
    const alertItem = page.locator('[data-testid="alert-item"]').first();
    await expect(alertItem).toBeVisible({ timeout: 60000 });
    
    // Check alert delivery time (within 1 minute)
    const alertTimestamp = await alertItem.locator('[data-testid="alert-timestamp"]').textContent();
    const alertTime = new Date(alertTimestamp || '');
    const timeDifference = (alertTime.getTime() - failureTimestamp.getTime()) / 1000;
    expect(timeDifference).toBeLessThanOrEqual(60);
    
    // Verify alert delivery channels
    await alertItem.click();
    await expect(page.locator('[data-testid="alert-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-delivery-status"]')).toContainText('Delivered');
    await expect(page.locator('[data-testid="sms-delivery-status"]')).toContainText('Delivered');
    
    // Acknowledge alert in system
    await page.click('[data-testid="acknowledge-alert-button"]');
    await page.fill('[data-testid="acknowledgment-notes"]', 'Alert acknowledged - investigating issue');
    await page.click('[data-testid="submit-acknowledgment-button"]');
    
    // Verify acknowledgment is logged successfully
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    
    // Check alert history for acknowledgment log
    await page.click('[data-testid="alert-history-tab"]');
    const acknowledgmentLog = page.locator('[data-testid="acknowledgment-log-entry"]').first();
    await expect(acknowledgmentLog).toBeVisible();
    await expect(acknowledgmentLog).toContainText('Alert acknowledged');
    await expect(acknowledgmentLog).toContainText('investigating issue');
  });

  test('Test alert configuration UI functionality', async ({ page }) => {
    // Navigate to Settings or Configuration menu
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="alert-configuration-link"]');
    
    // UI loads with current settings
    await expect(page.locator('[data-testid="alert-configuration-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-alert-settings"]')).toBeVisible();
    
    // Review the current alert configuration settings
    const currentContactsCount = await page.locator('[data-testid="alert-contact-item"]').count();
    expect(currentContactsCount).toBeGreaterThanOrEqual(0);
    
    // Add a new contact
    await page.click('[data-testid="add-contact-button"]');
    await expect(page.locator('[data-testid="add-contact-modal"]')).toBeVisible();
    await page.fill('[data-testid="contact-name-input"]', 'John Doe');
    await page.fill('[data-testid="contact-email-input"]', 'john.doe@test.com');
    await page.fill('[data-testid="contact-sms-input"]', '+1234567890');
    await page.click('[data-testid="save-contact-button"]');
    await expect(page.locator('[data-testid="contact-saved-message"]')).toBeVisible();
    
    // Modify an existing contact's email address
    const existingContact = page.locator('[data-testid="alert-contact-item"]').first();
    await existingContact.locator('[data-testid="edit-contact-button"]').click();
    await expect(page.locator('[data-testid="edit-contact-modal"]')).toBeVisible();
    await page.fill('[data-testid="contact-email-input"]', 'updated.email@test.com');
    await page.click('[data-testid="save-contact-button"]');
    await expect(page.locator('[data-testid="contact-updated-message"]')).toBeVisible();
    
    // Navigate to escalation rules section
    await page.click('[data-testid="escalation-rules-tab"]');
    await expect(page.locator('[data-testid="escalation-rules-section"]')).toBeVisible();
    
    // Modify the escalation time threshold
    const escalationRule = page.locator('[data-testid="escalation-rule-item"]').first();
    await escalationRule.locator('[data-testid="edit-rule-button"]').click();
    await page.fill('[data-testid="escalation-threshold-input"]', '10');
    await page.click('[data-testid="save-rule-button"]');
    
    // Add a new escalation level
    await page.click('[data-testid="add-escalation-level-button"]');
    await page.fill('[data-testid="escalation-time-input"]', '15');
    await page.selectOption('[data-testid="escalation-contact-select"]', 'john.doe@test.com');
    await page.click('[data-testid="save-escalation-level-button"]');
    
    // Save all modifications
    await page.click('[data-testid="save-configuration-button"]');
    await expect(page.locator('[data-testid="configuration-saved-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="configuration-saved-message"]')).toContainText('Changes saved and applied');
    
    // Verify changes are persisted by logging out and logging back in
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
    
    // Log back in
    await page.fill('[data-testid="email-input"]', adminEmail);
    await page.fill('[data-testid="password-input"]', adminPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Access alert configuration again
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="alert-configuration-link"]');
    
    // Verify the new contact exists
    const contactsList = page.locator('[data-testid="alert-contact-item"]');
    await expect(contactsList.filter({ hasText: 'john.doe@test.com' })).toBeVisible();
    
    // Trigger a test alert
    await page.click('[data-testid="send-test-alert-button"]');
    await page.selectOption('[data-testid="test-alert-type-select"]', 'integration-failure');
    await page.click('[data-testid="trigger-test-alert-button"]');
    await expect(page.locator('[data-testid="test-alert-sent-message"]')).toBeVisible();
    
    // Navigate to alerts section to verify alert was sent
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alerts-section-link"]');
    
    // Verify alert is sent to newly configured contacts
    const testAlert = page.locator('[data-testid="alert-item"]').filter({ hasText: 'Test Alert' }).first();
    await expect(testAlert).toBeVisible({ timeout: 60000 });
    await testAlert.click();
    
    // Check email delivery to new contact
    const emailRecipients = await page.locator('[data-testid="email-recipients"]').textContent();
    expect(emailRecipients).toContain('john.doe@test.com');
    
    // Check SMS delivery to new contact
    const smsRecipients = await page.locator('[data-testid="sms-recipients"]').textContent();
    expect(smsRecipients).toContain('+1234567890');
    
    // Verify updated escalation rules are applied
    await page.click('[data-testid="escalation-details-tab"]');
    const escalationThreshold = await page.locator('[data-testid="escalation-threshold-value"]').first().textContent();
    expect(escalationThreshold).toContain('10');
  });
});