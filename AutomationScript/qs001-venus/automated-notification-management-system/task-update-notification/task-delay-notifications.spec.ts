import { test, expect } from '@playwright/test';

test.describe('Task Delay Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to task management dashboard
    await page.goto('/dashboard');
    // Login as task manager
    await page.fill('[data-testid="username-input"]', 'taskmanager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
  });

  test('Validate notification sent on task delay detection', async ({ page }) => {
    // Step 1: Create or select a task with a deadline set to the current date and time minus 1 hour
    await page.click('[data-testid="tasks-menu"]');
    await page.click('[data-testid="create-task-button"]');
    await page.fill('[data-testid="task-name-input"]', 'Delayed Task Test');
    await page.fill('[data-testid="task-description-input"]', 'Testing delay notification');
    
    // Set deadline to 1 hour ago
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const deadlineValue = oneHourAgo.toISOString().slice(0, 16);
    await page.fill('[data-testid="task-deadline-input"]', deadlineValue);
    await page.selectOption('[data-testid="task-status-select"]', 'In Progress');
    await page.fill('[data-testid="delay-reason-input"]', 'Resource constraints');
    await page.click('[data-testid="save-task-button"]');
    await expect(page.locator('[data-testid="task-created-message"]')).toBeVisible();

    // Step 2: Trigger the system's delay detection process
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="trigger-delay-detection"]');
    await expect(page.locator('[data-testid="delay-detection-triggered"]')).toBeVisible();

    // Step 3: Check the task manager's email inbox for the delay notification
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="email-notifications-tab"]');
    await expect(page.locator('[data-testid="notification-item"]').first()).toBeVisible();
    const emailNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(emailNotification).toContainText('Delayed Task Test');
    await expect(emailNotification).toContainText('Resource constraints');

    // Step 4: Check the task manager's mobile device for SMS notification
    await page.click('[data-testid="sms-notifications-tab"]');
    const smsNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(smsNotification).toBeVisible();
    await expect(smsNotification).toContainText('Delayed Task Test');

    // Step 5: Check the in-app notification center for the delay alert
    await page.click('[data-testid="in-app-notifications-tab"]');
    const inAppNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(inAppNotification).toBeVisible();

    // Step 6: Click on the in-app notification to open the task details page
    await inAppNotification.click();
    await expect(page.locator('[data-testid="task-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-name"]')).toContainText('Delayed Task Test');

    // Step 7: Click the 'Acknowledge' button on the notification or task details page
    await page.click('[data-testid="acknowledge-button"]');
    await expect(page.locator('[data-testid="acknowledgment-modal"]')).toBeVisible();

    // Step 8: Enter comment and submit the acknowledgment
    await page.fill('[data-testid="acknowledgment-comment-input"]', 'Reviewing resource allocation to address delay');
    await page.click('[data-testid="submit-acknowledgment-button"]');
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();

    // Step 9: Navigate to the notification logs or history section
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="notification-logs-tab"]');
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry).toContainText('Acknowledged');
    await expect(logEntry).toContainText('Reviewing resource allocation to address delay');
  });

  test('Verify retry mechanism on notification failure', async ({ page }) => {
    // Step 1: Configure the test environment to simulate SMS notification delivery failure
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="test-settings"]');
    await page.click('[data-testid="notification-settings-tab"]');
    await page.check('[data-testid="simulate-sms-failure-checkbox"]');
    await page.click('[data-testid="save-settings-button"]');
    await expect(page.locator('[data-testid="settings-saved-message"]')).toBeVisible();

    // Step 2: Set a task deadline to current time minus 30 minutes
    await page.click('[data-testid="tasks-menu"]');
    await page.click('[data-testid="create-task-button"]');
    await page.fill('[data-testid="task-name-input"]', 'Retry Test Task');
    const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
    const deadlineValue = thirtyMinutesAgo.toISOString().slice(0, 16);
    await page.fill('[data-testid="task-deadline-input"]', deadlineValue);
    await page.selectOption('[data-testid="task-status-select"]', 'In Progress');
    await page.click('[data-testid="save-task-button"]');

    // Step 3: Trigger the delay detection process
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="trigger-delay-detection"]');
    await expect(page.locator('[data-testid="delay-detection-triggered"]')).toBeVisible();

    // Step 4: Monitor the notification service logs for initial SMS delivery failure
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="notification-logs"]');
    await page.fill('[data-testid="search-logs-input"]', 'Retry Test Task');
    await page.click('[data-testid="search-button"]');
    
    const initialAttempt = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Attempt 1' });
    await expect(initialAttempt).toBeVisible();
    await expect(initialAttempt).toContainText('SMS');
    await expect(initialAttempt).toContainText('Failed');

    // Step 5: Continue monitoring for second retry attempt
    await page.waitForTimeout(2000);
    await page.click('[data-testid="refresh-logs-button"]');
    const secondAttempt = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Attempt 2' });
    await expect(secondAttempt).toBeVisible();
    await expect(secondAttempt).toContainText('SMS');
    await expect(secondAttempt).toContainText('Failed');

    // Step 6: Observe the third and final retry attempt
    await page.waitForTimeout(2000);
    await page.click('[data-testid="refresh-logs-button"]');
    const thirdAttempt = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Attempt 3' });
    await expect(thirdAttempt).toBeVisible();
    await expect(thirdAttempt).toContainText('SMS');
    await expect(thirdAttempt).toContainText('Failed');

    // Step 7: Access the notification logs dashboard and verify log entries
    const allLogEntries = page.locator('[data-testid="log-entry"]');
    const count = await allLogEntries.count();
    expect(count).toBeGreaterThanOrEqual(3);
    
    for (let i = 0; i < Math.min(3, count); i++) {
      const logEntry = allLogEntries.nth(i);
      await expect(logEntry).toContainText('Retry Test Task');
      await expect(logEntry).toContainText('SMS');
    }

    // Step 8: Check if email and in-app notifications were delivered successfully
    await page.click('[data-testid="filter-by-channel"]');
    await page.selectOption('[data-testid="channel-filter-select"]', 'Email');
    await page.click('[data-testid="apply-filter-button"]');
    const emailSuccess = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Success' }).first();
    await expect(emailSuccess).toBeVisible();

    await page.selectOption('[data-testid="channel-filter-select"]', 'In-App');
    await page.click('[data-testid="apply-filter-button"]');
    const inAppSuccess = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Success' }).first();
    await expect(inAppSuccess).toBeVisible();

    // Step 9: Remove the failure simulation
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="test-settings"]');
    await page.click('[data-testid="notification-settings-tab"]');
    await page.uncheck('[data-testid="simulate-sms-failure-checkbox"]');
    await page.click('[data-testid="save-settings-button"]');

    // Step 10: Create another delayed task to trigger a new notification
    await page.click('[data-testid="tasks-menu"]');
    await page.click('[data-testid="create-task-button"]');
    await page.fill('[data-testid="task-name-input"]', 'Retry Success Task');
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
    const newDeadlineValue = fifteenMinutesAgo.toISOString().slice(0, 16);
    await page.fill('[data-testid="task-deadline-input"]', newDeadlineValue);
    await page.selectOption('[data-testid="task-status-select"]', 'In Progress');
    await page.click('[data-testid="save-task-button"]');

    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="trigger-delay-detection"]');

    // Step 11: Verify that the new notification is delivered successfully via all channels
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="notification-logs"]');
    await page.fill('[data-testid="search-logs-input"]', 'Retry Success Task');
    await page.click('[data-testid="search-button"]');

    const smsSuccessLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'SMS' }).filter({ hasText: 'Success' });
    await expect(smsSuccessLog).toBeVisible();
  });

  test('Ensure immediate notification delivery upon delay detection', async ({ page }) => {
    // Step 1: Record the current system timestamp as the test baseline
    const baselineTimestamp = Date.now();
    const deliveryTimes: number[] = [];

    // Step 2: Create Task #1 with deadline set to current time minus 15 minutes
    await page.click('[data-testid="tasks-menu"]');
    await page.click('[data-testid="create-task-button"]');
    await page.fill('[data-testid="task-name-input"]', 'Performance Test Task 1');
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
    await page.fill('[data-testid="task-deadline-input"]', fifteenMinutesAgo.toISOString().slice(0, 16));
    await page.selectOption('[data-testid="task-status-select"]', 'In Progress');
    await page.click('[data-testid="save-task-button"]');

    // Step 3: Trigger the delay detection process and record timestamp
    const detectionTime1 = Date.now();
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="trigger-delay-detection"]');
    await expect(page.locator('[data-testid="delay-detection-triggered"]')).toBeVisible();

    // Step 4: Monitor the in-app notification center and record delivery timestamp
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="in-app-notifications-tab"]');
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: 'Performance Test Task 1' })).toBeVisible();
    const deliveryTime1 = Date.now();

    // Step 5: Calculate and document the time difference
    const timeDiff1 = deliveryTime1 - detectionTime1;
    deliveryTimes.push(timeDiff1);
    expect(timeDiff1).toBeLessThan(5000); // Should be delivered within 5 seconds

    // Step 6: Create Task #2 with deadline set to current time minus 45 minutes
    await page.click('[data-testid="tasks-menu"]');
    await page.click('[data-testid="create-task-button"]');
    await page.fill('[data-testid="task-name-input"]', 'Performance Test Task 2');
    const fortyFiveMinutesAgo = new Date(Date.now() - 45 * 60 * 1000);
    await page.fill('[data-testid="task-deadline-input"]', fortyFiveMinutesAgo.toISOString().slice(0, 16));
    await page.selectOption('[data-testid="task-status-select"]', 'Not Started');
    await page.click('[data-testid="save-task-button"]');

    // Step 7: Trigger delay detection for Task #2 and record timestamps
    const detectionTime2 = Date.now();
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="trigger-delay-detection"]');
    await expect(page.locator('[data-testid="delay-detection-triggered"]')).toBeVisible();

    // Step 8: Monitor and record the notification delivery timestamp for Task #2
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="in-app-notifications-tab"]');
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: 'Performance Test Task 2' })).toBeVisible();
    const deliveryTime2 = Date.now();
    const timeDiff2 = deliveryTime2 - detectionTime2;
    deliveryTimes.push(timeDiff2);
    expect(timeDiff2).toBeLessThan(5000);

    // Step 9: Create Task #3 with deadline set to current time minus 2 hours
    await page.click('[data-testid="tasks-menu"]');
    await page.click('[data-testid="create-task-button"]');
    await page.fill('[data-testid="task-name-input"]', 'Performance Test Task 3');
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
    await page.fill('[data-testid="task-deadline-input"]', twoHoursAgo.toISOString().slice(0, 16));
    await page.selectOption('[data-testid="task-status-select"]', 'In Progress');
    await page.click('[data-testid="save-task-button"]');

    // Step 10: Trigger delay detection for Task #3 and record timestamps
    const detectionTime3 = Date.now();
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="trigger-delay-detection"]');
    await expect(page.locator('[data-testid="delay-detection-triggered"]')).toBeVisible();

    // Step 11: Monitor and record the notification delivery timestamp for Task #3
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="in-app-notifications-tab"]');
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: 'Performance Test Task 3' })).toBeVisible();
    const deliveryTime3 = Date.now();
    const timeDiff3 = deliveryTime3 - detectionTime3;
    deliveryTimes.push(timeDiff3);
    expect(timeDiff3).toBeLessThan(5000);

    // Step 12: Access the system logs and filter for all three delay notification events
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="notification-logs"]');
    await page.fill('[data-testid="search-logs-input"]', 'Performance Test Task');
    await page.click('[data-testid="search-button"]');

    // Step 13: Review the logs for any errors, warnings, delays, or performance issues
    const errorLogs = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Error' });
    const errorCount = await errorLogs.count();
    expect(errorCount).toBe(0);

    const warningLogs = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Warning' });
    const warningCount = await warningLogs.count();
    expect(warningCount).toBe(0);

    // Step 14: Generate a performance summary report
    const averageDeliveryTime = deliveryTimes.reduce((a, b) => a + b, 0) / deliveryTimes.length;
    expect(averageDeliveryTime).toBeLessThan(5000); // Average should be under 5 seconds

    // Step 15: Verify that notification delivery metrics are recorded in the system dashboard
    await page.click('[data-testid="dashboard-menu"]');
    await page.click('[data-testid="performance-metrics-tab"]');
    await expect(page.locator('[data-testid="notification-metrics-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="average-delivery-time"]')).toBeVisible();
    const displayedMetric = await page.locator('[data-testid="average-delivery-time"]').textContent();
    expect(displayedMetric).toBeTruthy();
  });
});