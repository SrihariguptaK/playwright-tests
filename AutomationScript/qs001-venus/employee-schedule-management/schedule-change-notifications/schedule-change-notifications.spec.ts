import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications - Story 16', () => {
  const employeeCredentials = {
    username: 'employee.user@company.com',
    password: 'TestPassword123!'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to employee portal login page
    await page.goto('/employee/login');
    
    // Login with valid employee credentials
    await page.fill('[data-testid="username-input"]', employeeCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="employee-dashboard"]')).toBeVisible();
  });

  test('Validate real-time notification display on dashboard', async ({ page }) => {
    // Trigger a schedule change event for the employee (simulated via API or admin action)
    // In real scenario, this would be done by manager/admin in separate session
    // For automation, we can trigger via API call
    const scheduleChangeData = {
      employeeId: 'EMP001',
      changeType: 'Shift Time Modified',
      oldSchedule: {
        date: '2024-01-15',
        startTime: '09:00',
        endTime: '17:00',
        location: 'Office A'
      },
      newSchedule: {
        date: '2024-01-15',
        startTime: '10:00',
        endTime: '18:00',
        location: 'Office A'
      }
    };

    // Wait for notification to appear on dashboard (within 15 minutes, using shorter timeout for test)
    const notificationLocator = page.locator('[data-testid="notification-item"]').first();
    await expect(notificationLocator).toBeVisible({ timeout: 900000 }); // 15 minutes max

    // Verify notification content includes required details
    await expect(notificationLocator).toContainText('Shift Time Modified');
    await expect(notificationLocator).toContainText('09:00');
    await expect(notificationLocator).toContainText('10:00');
    
    // Verify timestamp is present
    const timestamp = notificationLocator.locator('[data-testid="notification-timestamp"]');
    await expect(timestamp).toBeVisible();

    // Click on notification to view full details
    await notificationLocator.click();
    
    // Verify full notification details are displayed
    const notificationDetails = page.locator('[data-testid="notification-details"]');
    await expect(notificationDetails).toBeVisible();
    await expect(notificationDetails).toContainText('Old Schedule');
    await expect(notificationDetails).toContainText('New Schedule');
    await expect(notificationDetails).toContainText('2024-01-15');

    // Click the Acknowledge button
    const acknowledgeButton = page.locator('[data-testid="acknowledge-button"]');
    await acknowledgeButton.click();

    // Verify acknowledgment is recorded and notification marked as read
    await expect(notificationLocator).toHaveAttribute('data-status', 'read');
    const acknowledgedBadge = notificationLocator.locator('[data-testid="acknowledged-badge"]');
    await expect(acknowledgedBadge).toBeVisible();
    await expect(acknowledgedBadge).toContainText('Acknowledged');
  });

  test('Verify email alert delivery for schedule changes', async ({ page, request }) => {
    const employeeEmail = 'employee.user@company.com';
    
    // Trigger schedule change event (simulated)
    const scheduleChange = {
      employeeId: 'EMP001',
      changeType: 'Shift Date Changed',
      originalDate: '2024-01-20',
      newDate: '2024-01-21',
      startTime: '09:00',
      endTime: '17:00'
    };

    // Monitor email delivery system logs (via API endpoint)
    const emailLogsResponse = await request.get('/api/email-logs', {
      params: {
        recipient: employeeEmail,
        timeRange: '15m'
      }
    });
    expect(emailLogsResponse.ok()).toBeTruthy();
    const emailLogs = await emailLogsResponse.json();
    
    // Verify email dispatch confirmation within 15 minutes
    const scheduleChangeEmail = emailLogs.find((log: any) => 
      log.subject.includes('Schedule Change') && 
      log.timestamp > Date.now() - 900000
    );
    expect(scheduleChangeEmail).toBeDefined();

    // Navigate to email verification page (test email inbox)
    await page.goto('/test/email-inbox');
    await page.fill('[data-testid="email-search"]', employeeEmail);
    await page.click('[data-testid="search-button"]');

    // Locate the schedule change email
    const emailItem = page.locator('[data-testid="email-item"]').filter({ hasText: 'Schedule Change' }).first();
    await expect(emailItem).toBeVisible({ timeout: 900000 }); // 15 minutes

    // Verify sender address matches system notification address
    await emailItem.click();
    const senderAddress = page.locator('[data-testid="email-sender"]');
    await expect(senderAddress).toContainText('notifications@company.com');

    // Review email subject line
    const subjectLine = page.locator('[data-testid="email-subject"]');
    await expect(subjectLine).toContainText('Schedule Change Notification');

    // Verify email content includes required details
    const emailBody = page.locator('[data-testid="email-body"]');
    await expect(emailBody).toContainText('Original Schedule');
    await expect(emailBody).toContainText('2024-01-20');
    await expect(emailBody).toContainText('New Schedule');
    await expect(emailBody).toContainText('2024-01-21');
    await expect(emailBody).toContainText('Shift Date Changed');
    await expect(emailBody).toContainText('Effective Date');

    // Check for portal link in email
    const portalLink = emailBody.locator('a[href*="/employee/notifications"]');
    await expect(portalLink).toBeVisible();

    // Compare email content with dashboard notification
    await page.goto('/employee/dashboard');
    const dashboardNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(dashboardNotification).toContainText('2024-01-21');
    await expect(dashboardNotification).toContainText('Shift Date Changed');
  });

  test('Test notification history access', async ({ page }) => {
    // From employee dashboard, locate and click notification history link
    const notificationHistoryLink = page.locator('[data-testid="notification-history-link"]');
    await notificationHistoryLink.click();

    // Verify notification history page loads completely
    await expect(page).toHaveURL(/.*\/notifications\/history/);
    const historyPage = page.locator('[data-testid="notification-history-page"]');
    await expect(historyPage).toBeVisible();

    // Review the list of notifications displayed
    const notificationList = page.locator('[data-testid="notification-list"]');
    await expect(notificationList).toBeVisible();

    // Verify each notification entry shows key information
    const firstNotification = page.locator('[data-testid="history-notification-item"]').first();
    await expect(firstNotification).toBeVisible();
    
    // Check for date/time of change
    const dateTime = firstNotification.locator('[data-testid="notification-datetime"]');
    await expect(dateTime).toBeVisible();
    
    // Check for change type
    const changeType = firstNotification.locator('[data-testid="notification-change-type"]');
    await expect(changeType).toBeVisible();
    
    // Check for old schedule details
    const oldSchedule = firstNotification.locator('[data-testid="notification-old-schedule"]');
    await expect(oldSchedule).toBeVisible();
    
    // Check for new schedule details
    const newSchedule = firstNotification.locator('[data-testid="notification-new-schedule"]');
    await expect(newSchedule).toBeVisible();
    
    // Check for acknowledgment status
    const acknowledgmentStatus = firstNotification.locator('[data-testid="notification-ack-status"]');
    await expect(acknowledgmentStatus).toBeVisible();

    // Verify acknowledged notifications show timestamp
    const acknowledgedNotification = page.locator('[data-testid="history-notification-item"][data-acknowledged="true"]').first();
    if (await acknowledgedNotification.count() > 0) {
      const ackTimestamp = acknowledgedNotification.locator('[data-testid="acknowledgment-timestamp"]');
      await expect(ackTimestamp).toBeVisible();
    }

    // Verify unacknowledged notifications are clearly marked
    const unacknowledgedNotification = page.locator('[data-testid="history-notification-item"][data-acknowledged="false"]').first();
    if (await unacknowledgedNotification.count() > 0) {
      const unacknowledgedBadge = unacknowledgedNotification.locator('[data-testid="unacknowledged-badge"]');
      await expect(unacknowledgedBadge).toBeVisible();
      
      // Verify acknowledgment can be done from history page
      const ackButtonInHistory = unacknowledgedNotification.locator('[data-testid="acknowledge-button"]');
      await expect(ackButtonInHistory).toBeVisible();
      await ackButtonInHistory.click();
      
      // Verify status updates
      await expect(unacknowledgedNotification).toHaveAttribute('data-acknowledged', 'true');
    }

    // Test pagination if more than 10-20 notifications exist
    const notificationCount = await page.locator('[data-testid="history-notification-item"]').count();
    if (notificationCount >= 10) {
      const paginationControls = page.locator('[data-testid="pagination-controls"]');
      await expect(paginationControls).toBeVisible();
      
      const nextPageButton = page.locator('[data-testid="next-page-button"]');
      if (await nextPageButton.isEnabled()) {
        await nextPageButton.click();
        await expect(page).toHaveURL(/.*page=2/);
      }
    }

    // Apply date range filter
    const dateFilterButton = page.locator('[data-testid="date-filter-button"]');
    await dateFilterButton.click();
    
    const startDateInput = page.locator('[data-testid="start-date-input"]');
    await startDateInput.fill('2024-01-01');
    
    const endDateInput = page.locator('[data-testid="end-date-input"]');
    await endDateInput.fill('2024-01-31');
    
    const applyFilterButton = page.locator('[data-testid="apply-filter-button"]');
    await applyFilterButton.click();
    
    // Verify filtered results
    await expect(notificationList).toBeVisible();

    // Apply acknowledgment status filter
    const statusFilter = page.locator('[data-testid="status-filter-dropdown"]');
    await statusFilter.click();
    
    const unacknowledgedOption = page.locator('[data-testid="filter-unacknowledged"]');
    await unacknowledgedOption.click();
    
    // Verify only unacknowledged notifications are shown
    const visibleNotifications = page.locator('[data-testid="history-notification-item"]');
    const count = await visibleNotifications.count();
    for (let i = 0; i < count; i++) {
      await expect(visibleNotifications.nth(i)).toHaveAttribute('data-acknowledged', 'false');
    }

    // Click on a specific notification to view full details
    const specificNotification = page.locator('[data-testid="history-notification-item"]').nth(0);
    await specificNotification.click();
    
    // Verify full details modal/page opens
    const detailsModal = page.locator('[data-testid="notification-details-modal"]');
    await expect(detailsModal).toBeVisible();
    await expect(detailsModal).toContainText('Schedule Change Details');
  });
});