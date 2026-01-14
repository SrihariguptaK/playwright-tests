import { test, expect } from '@playwright/test';

test.describe('Email Notifications for Scheduling Conflicts - Story 13', () => {
  let conflictTimestamp: number;
  let testEmail: string;

  test.beforeEach(async ({ page }) => {
    // Login to the scheduling system with scheduler credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    testEmail = 'scheduler@example.com';
  });

  test('Validate email notification sent upon conflict detection', async ({ page, request }) => {
    // Navigate to scheduling section
    await page.goto('/scheduling');
    await expect(page.locator('[data-testid="scheduling-page"]')).toBeVisible();

    // Create a new scheduling entry that conflicts with an existing schedule
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="date-input"]', '2024-03-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    
    // Note the exact timestamp when the conflict was triggered
    conflictTimestamp = Date.now();
    await page.click('[data-testid="save-schedule-button"]');
    
    // Wait for conflict detection alert
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 5000 });
    const conflictMessage = await page.locator('[data-testid="conflict-alert"]').textContent();
    expect(conflictMessage).toContain('scheduling conflict');

    // Check email delivery via API endpoint
    const emailLogsResponse = await request.get('/notifications/email/logs', {
      params: {
        recipient: testEmail,
        timestamp: conflictTimestamp
      }
    });
    expect(emailLogsResponse.ok()).toBeTruthy();
    const emailLogs = await emailLogsResponse.json();
    
    // Verify email notification is generated and sent
    expect(emailLogs.emails).toHaveLength(1);
    const sentEmail = emailLogs.emails[0];
    expect(sentEmail.recipient).toBe(testEmail);
    expect(sentEmail.subject).toContain('Scheduling Conflict Detected');
    
    // Verify email contains conflict details
    expect(sentEmail.body).toContain('Conference Room A');
    expect(sentEmail.body).toContain('2024-03-15');
    expect(sentEmail.body).toContain('10:00');
    expect(sentEmail.body).toContain('11:00');
    
    // Verify delivery timestamp is within 5 seconds of conflict detection
    const deliveryTimestamp = new Date(sentEmail.deliveredAt).getTime();
    const timeDifference = deliveryTimestamp - conflictTimestamp;
    expect(timeDifference).toBeLessThanOrEqual(5000);
    
    // Verify email delivery and read status logged correctly
    expect(sentEmail.deliveryStatus).toBe('delivered');
    expect(sentEmail).toHaveProperty('readStatus');
  });

  test('Verify user notification preference settings', async ({ page, request }) => {
    // Navigate to user settings or preferences section
    await page.goto('/settings');
    await page.click('[data-testid="preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences"]')).toBeVisible();

    // Locate the email notification toggle for conflict notifications
    const emailToggle = page.locator('[data-testid="email-notifications-toggle"]');
    await expect(emailToggle).toBeVisible();
    
    // Disable email notifications
    const isChecked = await emailToggle.isChecked();
    if (isChecked) {
      await emailToggle.uncheck();
    }
    
    // Save preferences
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    expect(await page.locator('[data-testid="success-message"]').textContent()).toContain('Preference saved successfully');

    // Verify preference change is persisted
    await page.reload();
    await page.click('[data-testid="preferences-tab"]');
    const toggleAfterReload = page.locator('[data-testid="email-notifications-toggle"]');
    expect(await toggleAfterReload.isChecked()).toBeFalsy();

    // Trigger a scheduling conflict
    await page.goto('/scheduling');
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room B');
    await page.fill('[data-testid="date-input"]', '2024-03-16');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    const noEmailTimestamp = Date.now();
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();

    // Wait 5 seconds and verify no email was sent
    await page.waitForTimeout(5000);
    const noEmailResponse = await request.get('/notifications/email/logs', {
      params: {
        recipient: testEmail,
        timestamp: noEmailTimestamp
      }
    });
    const noEmailLogs = await noEmailResponse.json();
    expect(noEmailLogs.emails).toHaveLength(0);

    // Re-enable email notifications
    await page.goto('/settings');
    await page.click('[data-testid="preferences-tab"]');
    await page.locator('[data-testid="email-notifications-toggle"]').check();
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Trigger another conflict and verify email is sent
    await page.goto('/scheduling');
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room C');
    await page.fill('[data-testid="date-input"]', '2024-03-17');
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.fill('[data-testid="end-time-input"]', '10:00');
    const resumeEmailTimestamp = Date.now();
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();

    // Verify email notification resumed
    await page.waitForTimeout(5000);
    const resumeEmailResponse = await request.get('/notifications/email/logs', {
      params: {
        recipient: testEmail,
        timestamp: resumeEmailTimestamp
      }
    });
    const resumeEmailLogs = await resumeEmailResponse.json();
    expect(resumeEmailLogs.emails.length).toBeGreaterThan(0);
  });

  test('Test email format and content correctness', async ({ page, request, context }) => {
    // Trigger a scheduling conflict with known details
    await page.goto('/scheduling');
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Meeting Room Delta');
    await page.fill('[data-testid="date-input"]', '2024-04-10');
    await page.fill('[data-testid="start-time-input"]', '13:00');
    await page.fill('[data-testid="end-time-input"]', '14:30');
    await page.fill('[data-testid="parties-input"]', 'John Doe, Jane Smith');
    
    const emailTimestamp = Date.now();
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();

    // Retrieve the email content via API
    await page.waitForTimeout(5000);
    const emailResponse = await request.get('/notifications/email/logs', {
      params: {
        recipient: testEmail,
        timestamp: emailTimestamp,
        includeContent: true
      }
    });
    const emailData = await emailResponse.json();
    expect(emailData.emails).toHaveLength(1);
    const email = emailData.emails[0];

    // Verify email subject line clearly indicates a scheduling conflict
    expect(email.subject).toMatch(/scheduling conflict/i);
    expect(email.subject).toContain('Detected');

    // Check email body for conflict details
    const emailBody = email.body;
    expect(emailBody).toContain('Meeting Room Delta');
    expect(emailBody).toContain('2024-04-10');
    expect(emailBody).toContain('13:00');
    expect(emailBody).toContain('14:30');
    expect(emailBody).toContain('John Doe');
    expect(emailBody).toContain('Jane Smith');

    // Verify the email contains resolution instructions
    expect(emailBody).toMatch(/resolution|resolve|instructions|guidance/i);
    expect(emailBody).toMatch(/how to|steps to|please/i);

    // Check for contact information
    expect(emailBody).toMatch(/support@|help@|contact/i);
    expect(emailBody).toMatch(/\d{3}[-.]?\d{3}[-.]?\d{4}|help desk/i);

    // Verify email branding and formatting
    expect(email.htmlContent).toContain('<img');
    expect(email.htmlContent).toMatch(/logo|brand/i);
    expect(email.htmlContent).toContain('<!DOCTYPE html');
    expect(email.htmlContent).toContain('<table');

    // Verify responsive design meta tags for mobile
    expect(email.htmlContent).toContain('viewport');
    expect(email.htmlContent).toMatch(/max-width|media query/i);

    // Test hyperlinks in the email
    const linkMatches = email.htmlContent.match(/href="([^"]+)"/g);
    expect(linkMatches).toBeTruthy();
    expect(linkMatches.length).toBeGreaterThan(0);

    // Verify 'View Conflict' or 'Resolve Now' button exists
    expect(email.htmlContent).toMatch(/View Conflict|Resolve Now|View Details/i);
    const viewConflictLink = email.htmlContent.match(/href="([^"]+)"[^>]*>\s*(?:View Conflict|Resolve Now)/i);
    expect(viewConflictLink).toBeTruthy();

    // Test the View Conflict link redirects correctly
    if (viewConflictLink && viewConflictLink[1]) {
      const conflictUrl = viewConflictLink[1];
      await page.goto(conflictUrl);
      await expect(page.locator('[data-testid="conflict-details"]')).toBeVisible();
      expect(await page.locator('[data-testid="conflict-resource"]').textContent()).toContain('Meeting Room Delta');
    }

    // Verify email footer contains unsubscribe or preference management link
    expect(email.htmlContent).toMatch(/unsubscribe|manage preferences|notification settings/i);
    const unsubscribeLink = email.htmlContent.match(/href="([^"]+)"[^>]*>\s*(?:Unsubscribe|Manage Preferences)/i);
    expect(unsubscribeLink).toBeTruthy();

    // Verify contact email addresses and phone numbers for accuracy
    const emailAddresses = email.htmlContent.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
    expect(emailAddresses).toBeTruthy();
    expect(emailAddresses.length).toBeGreaterThan(0);
    emailAddresses.forEach(addr => {
      expect(addr).toMatch(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
    });

    // Verify all links are functional by checking HTTP status
    if (linkMatches) {
      for (const linkMatch of linkMatches.slice(0, 3)) {
        const url = linkMatch.match(/href="([^"]+)"/)[1];
        if (url.startsWith('http')) {
          const linkResponse = await request.get(url);
          expect(linkResponse.status()).toBeLessThan(400);
        }
      }
    }
  });
});