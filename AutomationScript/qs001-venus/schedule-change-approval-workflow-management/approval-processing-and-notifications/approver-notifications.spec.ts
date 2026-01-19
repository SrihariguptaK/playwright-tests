import { test, expect } from '@playwright/test';

test.describe('Story-3: Approver Notification System', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const schedulerEmail = 'scheduler@example.com';
  const schedulerPassword = 'Scheduler123!';
  const approverEmail = 'approver@example.com';
  const approverPassword = 'Approver123!';
  
  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate notification sent upon schedule change request submission (happy-path)', async ({ page, context }) => {
    // Step 1: Scheduler navigates to the schedule change request submission form
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.click('[data-testid="schedule-change-request-link"]');
    await expect(page).toHaveURL(/.*schedule-change-request/);
    
    // Step 2: Scheduler fills in all required fields and submits the schedule change request
    const requestDate = new Date().toISOString().split('T')[0];
    const requestTime = '09:00';
    const requestReason = 'Medical appointment - urgent care needed';
    
    await page.fill('[data-testid="change-date-input"]', requestDate);
    await page.fill('[data-testid="change-time-input"]', requestTime);
    await page.fill('[data-testid="change-reason-textarea"]', requestReason);
    await page.selectOption('[data-testid="shift-type-select"]', 'morning');
    
    await page.click('[data-testid="submit-request-button"]');
    
    // Step 3: System processes the request and identifies the assigned approver
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');
    
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    expect(requestId).toBeTruthy();
    
    // Step 4: Check approver's email inbox for notification (simulated via API check)
    const notificationResponse = await page.request.get(`${baseURL}/api/notifications/check`, {
      params: {
        email: approverEmail,
        requestId: requestId
      }
    });
    expect(notificationResponse.ok()).toBeTruthy();
    const notificationData = await notificationResponse.json();
    expect(notificationData.emailSent).toBe(true);
    
    // Step 5: Approver logs into the system and checks in-app notifications
    const approverPage = await context.newPage();
    await approverPage.goto(`${baseURL}/login`);
    await approverPage.fill('[data-testid="email-input"]', approverEmail);
    await approverPage.fill('[data-testid="password-input"]', approverPassword);
    await approverPage.click('[data-testid="login-button"]');
    await expect(approverPage).toHaveURL(/.*dashboard/);
    
    // Step 6: Approver clicks on the in-app notification link
    await approverPage.click('[data-testid="notifications-bell-icon"]');
    await expect(approverPage.locator('[data-testid="notification-dropdown"]')).toBeVisible();
    
    const notificationItem = approverPage.locator(`[data-testid="notification-item-${requestId}"]`);
    await expect(notificationItem).toBeVisible();
    
    // Step 7: Verify notification content accuracy
    await expect(notificationItem).toContainText('New schedule change request');
    await expect(notificationItem).toContainText(requestDate);
    
    await notificationItem.click();
    await expect(approverPage).toHaveURL(new RegExp(`.*schedule-change-request/${requestId}`));
    
    // Verify request details page shows correct information
    await expect(approverPage.locator('[data-testid="request-date"]')).toContainText(requestDate);
    await expect(approverPage.locator('[data-testid="request-time"]')).toContainText(requestTime);
    await expect(approverPage.locator('[data-testid="request-reason"]')).toContainText(requestReason);
    
    await approverPage.close();
  });

  test('Verify no duplicate notifications for the same pending approval (edge-case)', async ({ page, context }) => {
    // Setup: Create a schedule change request first
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="schedule-change-request-link"]');
    await page.fill('[data-testid="change-date-input"]', '2024-06-15');
    await page.fill('[data-testid="change-time-input"]', '14:00');
    await page.fill('[data-testid="change-reason-textarea"]', 'Personal appointment');
    await page.click('[data-testid="submit-request-button"]');
    
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    
    // Step 1: Verify initial notification was sent by checking NotificationQueue
    const initialNotificationCheck = await page.request.get(`${baseURL}/api/notifications/queue`, {
      params: { requestId: requestId }
    });
    expect(initialNotificationCheck.ok()).toBeTruthy();
    const initialNotifications = await initialNotificationCheck.json();
    const initialCount = initialNotifications.notifications.length;
    expect(initialCount).toBeGreaterThan(0);
    
    // Step 2: Count the number of email notifications in approver's inbox
    const emailNotificationCheck = await page.request.get(`${baseURL}/api/notifications/email-count`, {
      params: {
        email: approverEmail,
        requestId: requestId
      }
    });
    const emailData = await emailNotificationCheck.json();
    const initialEmailCount = emailData.count;
    expect(initialEmailCount).toBe(1);
    
    // Step 3: Count the number of in-app notifications
    const approverPage = await context.newPage();
    await approverPage.goto(`${baseURL}/login`);
    await approverPage.fill('[data-testid="email-input"]', approverEmail);
    await approverPage.fill('[data-testid="password-input"]', approverPassword);
    await approverPage.click('[data-testid="login-button"]');
    
    await approverPage.click('[data-testid="notifications-bell-icon"]');
    const inAppNotifications = await approverPage.locator(`[data-testid^="notification-item-${requestId}"]`).count();
    expect(inAppNotifications).toBe(1);
    
    // Step 4: Trigger a system event that would normally generate a notification
    const triggerResponse = await page.request.post(`${baseURL}/api/notifications/trigger`, {
      data: {
        requestId: requestId,
        eventType: 'workflow_refresh'
      }
    });
    expect(triggerResponse.ok()).toBeTruthy();
    
    // Step 5: Wait 2 minutes and check approver's email inbox again
    await page.waitForTimeout(2000); // Simulated wait (2 seconds for testing)
    
    const emailCheckAfterTrigger = await page.request.get(`${baseURL}/api/notifications/email-count`, {
      params: {
        email: approverEmail,
        requestId: requestId
      }
    });
    const emailDataAfter = await emailCheckAfterTrigger.json();
    expect(emailDataAfter.count).toBe(initialEmailCount);
    
    // Step 6: Check in-app notification center for duplicate notifications
    await approverPage.reload();
    await approverPage.click('[data-testid="notifications-bell-icon"]');
    const inAppNotificationsAfter = await approverPage.locator(`[data-testid^="notification-item-${requestId}"]`).count();
    expect(inAppNotificationsAfter).toBe(1);
    
    // Step 7: Query NotificationQueue table for all notifications related to this request ID
    const finalNotificationCheck = await page.request.get(`${baseURL}/api/notifications/queue`, {
      params: { requestId: requestId }
    });
    const finalNotifications = await finalNotificationCheck.json();
    expect(finalNotifications.notifications.length).toBe(initialCount);
    
    // Step 8: Review system logs for duplicate prevention messages
    const logsResponse = await page.request.get(`${baseURL}/api/system/logs`, {
      params: {
        requestId: requestId,
        logType: 'duplicate_prevention'
      }
    });
    expect(logsResponse.ok()).toBeTruthy();
    const logsData = await logsResponse.json();
    expect(logsData.logs.some((log: any) => log.message.includes('Duplicate notification prevented'))).toBe(true);
    
    await approverPage.close();
  });

  test('Ensure escalation notifications are sent for overdue approvals (edge-case)', async ({ page, context }) => {
    // Setup: Create a schedule change request and simulate time passage
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="schedule-change-request-link"]');
    await page.fill('[data-testid="change-date-input"]', '2024-07-01');
    await page.fill('[data-testid="change-time-input"]', '10:00');
    await page.fill('[data-testid="change-reason-textarea"]', 'Urgent schedule change needed');
    await page.click('[data-testid="submit-request-button"]');
    
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    
    // Step 1: Verify the schedule change request submission timestamp
    const requestDetailsResponse = await page.request.get(`${baseURL}/api/schedule-change-requests/${requestId}`);
    expect(requestDetailsResponse.ok()).toBeTruthy();
    const requestDetails = await requestDetailsResponse.json();
    const submissionTimestamp = new Date(requestDetails.submittedAt);
    expect(submissionTimestamp).toBeInstanceOf(Date);
    
    // Step 2: Check the request status in the system
    expect(requestDetails.status).toBe('pending');
    
    // Step 3: Manually trigger escalation check (simulating time passage)
    const escalationTriggerResponse = await page.request.post(`${baseURL}/api/notifications/trigger-escalation`, {
      data: {
        requestId: requestId,
        forceEscalation: true
      }
    });
    expect(escalationTriggerResponse.ok()).toBeTruthy();
    
    // Step 4: Query NotificationQueue table for escalation notifications
    await page.waitForTimeout(1000);
    const escalationNotificationsResponse = await page.request.get(`${baseURL}/api/notifications/queue`, {
      params: {
        requestId: requestId,
        notificationType: 'escalation'
      }
    });
    expect(escalationNotificationsResponse.ok()).toBeTruthy();
    const escalationNotifications = await escalationNotificationsResponse.json();
    expect(escalationNotifications.notifications.length).toBeGreaterThan(0);
    
    // Step 5: Check email inbox of designated escalation recipients
    const escalationEmailCheck = await page.request.get(`${baseURL}/api/notifications/email-count`, {
      params: {
        email: 'manager@example.com',
        requestId: requestId,
        notificationType: 'escalation'
      }
    });
    const escalationEmailData = await escalationEmailCheck.json();
    expect(escalationEmailData.count).toBeGreaterThan(0);
    
    // Step 6: Check in-app notifications for escalation recipients
    const managerPage = await context.newPage();
    await managerPage.goto(`${baseURL}/login`);
    await managerPage.fill('[data-testid="email-input"]', 'manager@example.com');
    await managerPage.fill('[data-testid="password-input"]', 'Manager123!');
    await managerPage.click('[data-testid="login-button"]');
    
    await managerPage.click('[data-testid="notifications-bell-icon"]');
    const escalationNotificationItem = managerPage.locator(`[data-testid="notification-item-${requestId}"]`);
    await expect(escalationNotificationItem).toBeVisible();
    
    // Step 7: Verify escalation notification content includes overdue information
    await expect(escalationNotificationItem).toContainText('Escalation');
    await expect(escalationNotificationItem).toContainText('overdue');
    
    await escalationNotificationItem.click();
    await expect(managerPage).toHaveURL(new RegExp(`.*schedule-change-request/${requestId}`));
    await expect(managerPage.locator('[data-testid="escalation-badge"]')).toBeVisible();
    
    // Step 8: Check that original approver also receives escalation reminder notification
    const approverPage = await context.newPage();
    await approverPage.goto(`${baseURL}/login`);
    await approverPage.fill('[data-testid="email-input"]', approverEmail);
    await approverPage.fill('[data-testid="password-input"]', approverPassword);
    await approverPage.click('[data-testid="login-button"]');
    
    await approverPage.click('[data-testid="notifications-bell-icon"]');
    const approverEscalationNotifications = await approverPage.locator(`[data-testid^="notification-item-${requestId}"]`).count();
    expect(approverEscalationNotifications).toBeGreaterThan(1);
    
    const reminderNotification = approverPage.locator('[data-testid^="notification-item"]').filter({ hasText: 'reminder' }).first();
    await expect(reminderNotification).toBeVisible();
    
    // Step 9: Review system audit logs for escalation event
    const auditLogsResponse = await page.request.get(`${baseURL}/api/system/audit-logs`, {
      params: {
        requestId: requestId,
        eventType: 'escalation'
      }
    });
    expect(auditLogsResponse.ok()).toBeTruthy();
    const auditLogs = await auditLogsResponse.json();
    expect(auditLogs.logs.length).toBeGreaterThan(0);
    expect(auditLogs.logs.some((log: any) => log.action === 'escalation_triggered')).toBe(true);
    
    await managerPage.close();
    await approverPage.close();
  });
});