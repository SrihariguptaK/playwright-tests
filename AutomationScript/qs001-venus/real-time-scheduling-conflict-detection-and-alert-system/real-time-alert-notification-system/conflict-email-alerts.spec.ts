import { test, expect } from '@playwright/test';

test.describe('Story-17: Email Conflict Alerts for Schedulers', () => {
  let testEmail: string;
  let conflictTimestamp: number;

  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/dashboard');
    // Login as scheduler user
    await page.fill('[data-testid="email-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
    testEmail = 'scheduler@example.com';
  });

  test('Verify email alert delivery within 5 seconds', async ({ page, request }) => {
    // Step 1: Trigger a scheduling conflict
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="create-schedule-button"]');
    
    // Assign resource to first time slot
    await page.selectOption('[data-testid="resource-select"]', { label: 'Conference Room A' });
    await page.fill('[data-testid="start-time-input"]', '2024-02-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-15T11:00');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Create overlapping schedule to trigger conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Conference Room A' });
    await page.fill('[data-testid="start-time-input"]', '2024-02-15T10:30');
    await page.fill('[data-testid="end-time-input"]', '2024-02-15T11:30');
    
    // Record timestamp before creating conflict
    conflictTimestamp = Date.now();
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Conflict detected
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Scheduling conflict detected');
    
    // Step 2: Check user email inbox
    // Simulate checking email via API call to email service
    const emailCheckResponse = await request.get('/api/test/emails', {
      params: {
        recipient: testEmail,
        since: conflictTimestamp
      }
    });
    
    expect(emailCheckResponse.ok()).toBeTruthy();
    const emails = await emailCheckResponse.json();
    
    // Expected Result: Email alert received within 5 seconds
    expect(emails.length).toBeGreaterThan(0);
    const conflictEmail = emails.find((email: any) => 
      email.subject.includes('Scheduling Conflict Alert')
    );
    expect(conflictEmail).toBeDefined();
    
    const emailReceivedTimestamp = new Date(conflictEmail.receivedAt).getTime();
    const deliveryTime = emailReceivedTimestamp - conflictTimestamp;
    expect(deliveryTime).toBeLessThanOrEqual(5000);
    
    // Verify email sender and subject
    expect(conflictEmail.from).toContain('notifications@scheduler.com');
    expect(conflictEmail.subject).toContain('Scheduling Conflict Alert');
  });

  test('Validate email alert content and formatting', async ({ page, request }) => {
    // Create a conflict to receive email
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="create-schedule-button"]');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Meeting Room B' });
    await page.fill('[data-testid="start-time-input"]', '2024-02-16T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-16T15:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    await page.click('[data-testid="create-schedule-button"]');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Meeting Room B' });
    await page.fill('[data-testid="start-time-input"]', '2024-02-16T14:30');
    await page.fill('[data-testid="end-time-input"]', '2024-02-16T15:30');
    await page.click('[data-testid="save-schedule-button"]');
    
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    // Wait for email to be sent
    await page.waitForTimeout(2000);
    
    // Step 1: Open received email alert
    const emailResponse = await request.get('/api/test/emails/latest', {
      params: { recipient: testEmail }
    });
    expect(emailResponse.ok()).toBeTruthy();
    const emailData = await emailResponse.json();
    
    // Expected Result: Email displays detailed conflict information clearly
    // Verify email contains conflict type information
    expect(emailData.htmlBody).toContain('Resource Conflict');
    expect(emailData.htmlBody).toContain('conflict type');
    
    // Verify email contains affected resources details
    expect(emailData.htmlBody).toContain('Meeting Room B');
    expect(emailData.htmlBody).toContain('affected resource');
    
    // Verify email contains time and date information
    expect(emailData.htmlBody).toContain('2024-02-16');
    expect(emailData.htmlBody).toContain('14:00');
    expect(emailData.htmlBody).toContain('15:00');
    
    // Verify email contains actionable links or instructions
    expect(emailData.htmlBody).toContain('View Conflict');
    expect(emailData.htmlBody).toContain('Resolve Now');
    expect(emailData.htmlBody).toMatch(/https?:\/\/.+\/conflicts\/\d+/);
    
    // Verify mobile formatting - check for responsive design elements
    expect(emailData.htmlBody).toContain('viewport');
    expect(emailData.htmlBody).toContain('max-width');
    
    // Verify text is readable on mobile (no small fonts)
    expect(emailData.htmlBody).not.toContain('font-size: 8px');
    expect(emailData.htmlBody).not.toContain('font-size: 9px');
    
    // Verify desktop rendering
    expect(emailData.textBody).toContain('Scheduling Conflict Alert');
    expect(emailData.textBody).toContain('Meeting Room B');
  });

  test('Test user preference changes for email alerts', async ({ page, request }) => {
    // Step 1: Navigate to user preferences or settings page
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-link"]');
    await expect(page.locator('[data-testid="settings-page-header"]')).toBeVisible();
    
    // Navigate to notifications tab
    await page.click('[data-testid="notifications-tab"]');
    await expect(page.locator('[data-testid="notification-preferences"]')).toBeVisible();
    
    // Step 2: Locate and disable email alerts
    const emailAlertsToggle = page.locator('[data-testid="email-alerts-toggle"]');
    await expect(emailAlertsToggle).toBeVisible();
    
    // Verify current state (should be enabled by default)
    const isChecked = await emailAlertsToggle.isChecked();
    if (isChecked) {
      await emailAlertsToggle.uncheck();
    }
    
    // Step 3: Save preferences
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preference saved successfully
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Preferences saved successfully');
    
    // Step 4: Refresh and verify persistence
    await page.reload();
    await page.click('[data-testid="notifications-tab"]');
    const toggleAfterRefresh = page.locator('[data-testid="email-alerts-toggle"]');
    await expect(toggleAfterRefresh).not.toBeChecked();
    
    // Step 5: Create a scheduling conflict
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="create-schedule-button"]');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Training Room C' });
    await page.fill('[data-testid="start-time-input"]', '2024-02-17T09:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-17T10:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    await page.click('[data-testid="create-schedule-button"]');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Training Room C' });
    await page.fill('[data-testid="start-time-input"]', '2024-02-17T09:30');
    await page.fill('[data-testid="end-time-input"]', '2024-02-17T10:30');
    
    const conflictTime = Date.now();
    await page.click('[data-testid="save-schedule-button"]');
    
    // Step 6: Wait for 10 seconds and check email inbox
    await page.waitForTimeout(10000);
    
    const emailCheckResponse = await request.get('/api/test/emails', {
      params: {
        recipient: testEmail,
        since: conflictTime
      }
    });
    
    expect(emailCheckResponse.ok()).toBeTruthy();
    const emails = await emailCheckResponse.json();
    
    // Expected Result: No email alert is sent
    const conflictEmails = emails.filter((email: any) => 
      email.subject.includes('Scheduling Conflict Alert')
    );
    expect(conflictEmails.length).toBe(0);
    
    // Step 7: Verify in-app notification is still displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Training Room C');
  });
});