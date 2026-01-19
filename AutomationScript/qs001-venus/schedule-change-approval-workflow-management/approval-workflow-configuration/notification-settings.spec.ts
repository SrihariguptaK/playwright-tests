import { test, expect } from '@playwright/test';

test.describe('Notification Settings Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Create and save notification template successfully', async ({ page }) => {
    // Administrator clicks on 'Settings' menu and selects 'Notification Configuration' option
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="notification-configuration-option"]');
    
    // Expected Result: Notification configuration UI is displayed
    await expect(page.locator('[data-testid="notification-config-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Notification Configuration');

    // Administrator clicks 'Create New Template' button
    await page.click('[data-testid="create-new-template-button"]');
    
    // Expected Result: Template editor accepts input
    await expect(page.locator('[data-testid="template-editor"]')).toBeVisible();

    // Administrator selects 'Approval' from the event type dropdown
    await page.click('[data-testid="event-type-dropdown"]');
    await page.click('[data-testid="event-type-approval"]');

    // Administrator enters template name 'Schedule Change Approved Notification'
    await page.fill('[data-testid="template-name-input"]', 'Schedule Change Approved Notification');

    // Administrator enters subject line 'Your Schedule Change Request Has Been Approved'
    await page.fill('[data-testid="subject-line-input"]', 'Your Schedule Change Request Has Been Approved');

    // Administrator enters message body in the template editor
    const messageBody = 'Dear {{requester_name}}, Your schedule change request #{{request_id}} has been approved by {{approver_name}} on {{approval_date}}. The changes will be effective from {{effective_date}}.';
    await page.fill('[data-testid="message-body-input"]', messageBody);

    // Administrator configures recipients by selecting 'Requester' and 'Manager' roles
    await page.click('[data-testid="recipient-requester-checkbox"]');
    await page.click('[data-testid="recipient-manager-checkbox"]');

    // Administrator selects notification delivery method as 'Email'
    await page.click('[data-testid="delivery-method-email-radio"]');

    // Administrator clicks 'Save Template' button
    await page.click('[data-testid="save-template-button"]');

    // Expected Result: System confirms successful save
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template saved successfully');
    
    // Verify template appears in the list
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Schedule Change Approved Notification');
  });

  test('Prevent saving notification template with invalid syntax', async ({ page }) => {
    // Administrator navigates to notification settings page and clicks 'Create New Template' button
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="notification-configuration-option"]');
    await page.click('[data-testid="create-new-template-button"]');

    // Administrator enters template name 'Invalid Syntax Test Template' and selects event type 'Rejection'
    await page.fill('[data-testid="template-name-input"]', 'Invalid Syntax Test Template');
    await page.click('[data-testid="event-type-dropdown"]');
    await page.click('[data-testid="event-type-rejection"]');

    // Administrator enters subject line 'Schedule Change Request Rejected'
    await page.fill('[data-testid="subject-line-input"]', 'Schedule Change Request Rejected');

    // Administrator enters message body with invalid template syntax
    const invalidMessageBody = 'Dear {{requester_name, Your request {{request_id} has been rejected by {{approver_name on {{rejection_date}}.';
    await page.fill('[data-testid="message-body-input"]', invalidMessageBody);

    // Administrator configures recipients as 'Requester' and selects 'Email' as delivery method
    await page.click('[data-testid="recipient-requester-checkbox"]');
    await page.click('[data-testid="delivery-method-email-radio"]');

    // Administrator clicks 'Save Template' button
    await page.click('[data-testid="save-template-button"]');

    // Expected Result: System displays validation error
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Invalid template syntax');

    // Administrator reviews the validation errors and corrects the message body
    const correctedMessageBody = 'Dear {{requester_name}}, Your request {{request_id}} has been rejected by {{approver_name}} on {{rejection_date}}.';
    await page.fill('[data-testid="message-body-input"]', correctedMessageBody);

    // Administrator clicks 'Save Template' button again
    await page.click('[data-testid="save-template-button"]');

    // Expected Result: Template is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template saved successfully');
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Invalid Syntax Test Template');
  });

  test('Test notification delivery', async ({ page }) => {
    // Administrator navigates to notification settings page
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="notification-configuration-option"]');
    await expect(page.locator('[data-testid="notification-config-page"]')).toBeVisible();

    // Administrator selects an existing notification template 'Schedule Change Approved Notification' from the template list
    await page.click('[data-testid="template-list-item"]:has-text("Schedule Change Approved Notification")');
    await expect(page.locator('[data-testid="template-details"]')).toBeVisible();

    // Administrator clicks 'Test Notification' button
    await page.click('[data-testid="test-notification-button"]');
    await expect(page.locator('[data-testid="test-notification-dialog"]')).toBeVisible();

    // Administrator enters test recipient email address 'admin.test@company.com' in the recipient field
    await page.fill('[data-testid="test-recipient-email-input"]', 'admin.test@company.com');

    // Administrator reviews the notification preview showing sample data populated in template variables
    await expect(page.locator('[data-testid="notification-preview"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-preview"]')).toContainText('Dear');
    await expect(page.locator('[data-testid="notification-preview"]')).toContainText('schedule change request');

    // Administrator clicks 'Send Test Notification' button
    await page.click('[data-testid="send-test-notification-button"]');

    // Expected Result: Notification is sent to configured recipient
    await expect(page.locator('[data-testid="sending-notification-indicator"]')).toBeVisible();
    
    // System completes notification delivery and administrator observes the result
    await page.waitForSelector('[data-testid="delivery-confirmation"]', { timeout: 10000 });

    // Expected Result: System displays success message
    await expect(page.locator('[data-testid="delivery-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="delivery-confirmation"]')).toContainText('Test notification sent successfully');
    await expect(page.locator('[data-testid="delivery-confirmation"]')).toContainText('admin.test@company.com');
    
    // Administrator views the delivery confirmation on screen
    await expect(page.locator('[data-testid="delivery-status"]')).toContainText('Delivered');
  });
});