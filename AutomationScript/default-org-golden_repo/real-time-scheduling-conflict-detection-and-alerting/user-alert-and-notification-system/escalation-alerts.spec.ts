import { test, expect } from '@playwright/test';

test.describe('Story-16: Escalation Alerts for Unresolved Scheduling Conflicts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling system
    await page.goto('/scheduling');
    // Login as scheduler
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Trigger escalation alert after unresolved conflict threshold', async ({ page }) => {
    // Step 1: Create a scheduling conflict by overlapping two resource bookings
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name"]', 'Conference Room A');
    await page.fill('[data-testid="booking-date"]', '2024-06-15');
    await page.fill('[data-testid="start-time"]', '10:00');
    await page.fill('[data-testid="end-time"]', '12:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Booking created successfully');

    // Create overlapping booking to trigger conflict
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name"]', 'Conference Room A');
    await page.fill('[data-testid="booking-date"]', '2024-06-15');
    await page.fill('[data-testid="start-time"]', '11:00');
    await page.fill('[data-testid="end-time"]', '13:00');
    await page.click('[data-testid="save-booking-button"]');
    
    // Step 2: Verify that initial alert is sent to the primary scheduler
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('Scheduling conflict detected');
    
    // Navigate to alerts page
    await page.click('[data-testid="alerts-menu"]');
    await expect(page.locator('[data-testid="initial-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Unresolved');
    
    // Get conflict ID for monitoring
    const conflictId = await page.locator('[data-testid="conflict-id"]').textContent();
    
    // Step 3: Monitor the conflict status and wait for the configured escalation time threshold
    // Set escalation threshold to 2 minutes for testing purposes
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="escalation-settings"]');
    await page.fill('[data-testid="escalation-threshold-minutes"]', '2');
    await page.click('[data-testid="save-settings-button"]');
    await expect(page.locator('[data-testid="settings-saved-message"]')).toBeVisible();
    
    // Return to alerts page and wait for escalation threshold
    await page.click('[data-testid="alerts-menu"]');
    await page.locator(`[data-testid="conflict-${conflictId}"]`).click();
    
    // Wait for escalation time to pass (2 minutes + buffer)
    await page.waitForTimeout(125000);
    
    // Step 4: Verify that escalation alert is automatically triggered
    await page.reload();
    await expect(page.locator('[data-testid="escalation-alert"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="escalation-status"]')).toContainText('Escalated');
    
    // Step 5: Check that escalation recipients receive the alert
    await page.click('[data-testid="escalation-recipients-link"]');
    await expect(page.locator('[data-testid="recipient-list"]')).toBeVisible();
    const recipients = page.locator('[data-testid="recipient-item"]');
    await expect(recipients).toHaveCount(await recipients.count());
    await expect(recipients.first()).toContainText('@');
    
    // Verify notification channels
    await expect(page.locator('[data-testid="notification-channel"]')).toContainText('Email');
    
    // Step 6: Have each escalation recipient acknowledge the alert
    // Logout and login as escalation recipient
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.fill('[data-testid="username-input"]', 'escalation.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'EscalationPass123');
    await page.click('[data-testid="login-button"]');
    
    // Navigate to escalation alerts
    await page.click('[data-testid="escalation-alerts-menu"]');
    await expect(page.locator('[data-testid="escalation-alert-item"]')).toBeVisible();
    
    // Acknowledge the escalation alert
    await page.click('[data-testid="acknowledge-button"]');
    await page.fill('[data-testid="acknowledgment-notes"]', 'Reviewing conflict and will resolve shortly');
    await page.click('[data-testid="submit-acknowledgment-button"]');
    
    // Step 7: Verify that all acknowledgments are logged with details and timestamps
    await expect(page.locator('[data-testid="acknowledgment-success"]')).toContainText('Acknowledgment recorded');
    
    await page.click('[data-testid="view-acknowledgment-log"]');
    await expect(page.locator('[data-testid="acknowledgment-log"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledged-by"]')).toContainText('escalation.manager@example.com');
    await expect(page.locator('[data-testid="acknowledgment-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledgment-notes-display"]')).toContainText('Reviewing conflict and will resolve shortly');
  });

  test('Validate secure delivery of escalation alerts', async ({ page, context }) => {
    // Step 1: Trigger an escalation alert from an unresolved conflict
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name"]', 'Meeting Room B');
    await page.fill('[data-testid="booking-date"]', '2024-06-16');
    await page.fill('[data-testid="start-time"]', '14:00');
    await page.fill('[data-testid="end-time"]', '16:00');
    await page.click('[data-testid="save-booking-button"]');
    
    // Create conflicting booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name"]', 'Meeting Room B');
    await page.fill('[data-testid="booking-date"]', '2024-06-16');
    await page.fill('[data-testid="start-time"]', '15:00');
    await page.fill('[data-testid="end-time"]', '17:00');
    await page.click('[data-testid="save-booking-button"]');
    
    // Force immediate escalation for testing
    await page.click('[data-testid="alerts-menu"]');
    const conflictId = await page.locator('[data-testid="conflict-id"]').first().textContent();
    await page.click('[data-testid="force-escalate-button"]');
    await expect(page.locator('[data-testid="escalation-triggered"]')).toBeVisible();
    
    // Step 2: Monitor the alert delivery process and verify encryption protocol
    const [request] = await Promise.all([
      page.waitForRequest(request => request.url().includes('/alerts/escalate') && request.method() === 'POST'),
      page.click('[data-testid="view-escalation-details"]')
    ]);
    
    // Verify HTTPS protocol is used
    expect(request.url()).toContain('https://');
    
    // Step 3: Verify that recipient authentication is required
    const escalationUrl = page.url();
    
    // Step 4: Log in as authorized escalation recipient and access the alert
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.fill('[data-testid="username-input"]', 'escalation.recipient@example.com');
    await page.fill('[data-testid="password-input"]', 'RecipientPass123');
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="escalation-alerts-menu"]');
    await expect(page.locator('[data-testid="escalation-alert-item"]')).toBeVisible();
    await page.click('[data-testid="escalation-alert-item"]');
    await expect(page.locator('[data-testid="escalation-details"]')).toBeVisible();
    
    // Step 5: Log out and attempt to access the escalation alert URL directly
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Attempt direct URL access without authentication
    const response = await page.goto(escalationUrl);
    
    // Verify redirect to login or access denied
    expect(page.url()).toContain('/login');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    
    // Step 6: Log in as user without escalation privileges
    await page.fill('[data-testid="username-input"]', 'regular.user@example.com');
    await page.fill('[data-testid="password-input"]', 'RegularPass123');
    await page.click('[data-testid="login-button"]');
    
    // Attempt to access escalation alerts menu
    const escalationMenu = page.locator('[data-testid="escalation-alerts-menu"]');
    await expect(escalationMenu).not.toBeVisible();
    
    // Try direct navigation to escalation alerts
    await page.goto('/escalation-alerts');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    
    // Step 7: Attempt to access escalation alert data through API without proper authentication
    const apiResponse = await page.request.get('/api/alerts/escalate', {
      headers: {
        'Authorization': 'Bearer invalid_token_12345'
      }
    });
    
    expect(apiResponse.status()).toBe(401);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Unauthorized');
    
    // Attempt without any authentication header
    const unauthResponse = await page.request.get('/api/alerts/escalate');
    expect(unauthResponse.status()).toBe(401);
    
    // Step 8: Verify that all unauthorized access attempts are logged
    // Login as admin to check security audit trail
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123');
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="security-audit-link"]');
    await expect(page.locator('[data-testid="audit-log"]')).toBeVisible();
    
    // Filter for unauthorized access attempts
    await page.fill('[data-testid="audit-search"]', 'unauthorized');
    await page.click('[data-testid="search-button"]');
    
    const auditEntries = page.locator('[data-testid="audit-entry"]');
    await expect(auditEntries).toHaveCount(await auditEntries.count());
    
    // Verify audit log contains unauthorized access attempts
    await expect(auditEntries.first()).toContainText('Unauthorized access attempt');
    await expect(page.locator('[data-testid="audit-timestamp"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-user"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-action"]').first()).toContainText('escalation-alerts');
  });
});