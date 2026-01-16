import { test, expect } from '@playwright/test';

test.describe('Story-10: Approver Request Additional Information', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const approverEmail = 'approver@company.com';
  const approverPassword = 'ApproverPass123!';
  const coordinatorEmail = 'coordinator@company.com';
  const coordinatorPassword = 'CoordinatorPass123!';
  let scheduleChangeRequestId: string;

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate approver can request additional information', async ({ page, context }) => {
    // Step 1: Open a pending schedule change request as Approver
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to schedule change requests dashboard
    await page.click('[data-testid="schedule-changes-menu"]');
    await expect(page.locator('[data-testid="schedule-changes-dashboard"]')).toBeVisible();

    // Select and open a pending schedule change request
    const pendingRequest = page.locator('[data-testid="schedule-change-request"]').filter({ hasText: 'Pending' }).first();
    await expect(pendingRequest).toBeVisible();
    scheduleChangeRequestId = await pendingRequest.getAttribute('data-request-id') || 'REQ-001';
    await pendingRequest.click();

    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');

    // Step 2: Click 'Request More Info' and enter comments
    await page.click('[data-testid="request-more-info-button"]');
    await expect(page.locator('[data-testid="info-request-modal"]')).toBeVisible();

    const infoRequestComment = 'Please provide justification for the extended hours and manager approval';
    await page.fill('[data-testid="info-request-comment-field"]', infoRequestComment);
    await page.click('[data-testid="submit-info-request-button"]');

    // Expected Result: Request is submitted and confirmation shown
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Information request sent successfully');

    // Verify the request status has changed to 'Info Requested'
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Info Requested');

    // Step 3: Verify notification is sent to requester
    // Check notification logs or system notifications panel
    await page.click('[data-testid="notifications-icon"]');
    const notificationLog = page.locator('[data-testid="notification-log"]').filter({ hasText: scheduleChangeRequestId });
    await expect(notificationLog).toBeVisible();

    // Log in as requester in new context to verify notification
    const requesterPage = await context.newPage();
    await requesterPage.goto(`${baseURL}/login`);
    await requesterPage.fill('[data-testid="email-input"]', coordinatorEmail);
    await requesterPage.fill('[data-testid="password-input"]', coordinatorPassword);
    await requesterPage.click('[data-testid="login-button"]');
    await expect(requesterPage).toHaveURL(/.*dashboard/);

    // Expected Result: Requester receives notification
    await requesterPage.click('[data-testid="notifications-icon"]');
    const requesterNotification = requesterPage.locator('[data-testid="notification-item"]').filter({ hasText: 'Additional information requested' });
    await expect(requesterNotification).toBeVisible();
    await expect(requesterNotification).toContainText(scheduleChangeRequestId);

    await requesterPage.close();
  });

  test('Verify requester can submit additional information', async ({ page, context }) => {
    // Step 1: Log in as Schedule Coordinator with info request notification
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', coordinatorEmail);
    await page.fill('[data-testid="password-input"]', coordinatorPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the notifications panel
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Expected Result: Notification is visible
    const infoRequestNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Additional information requested' }).first();
    await expect(infoRequestNotification).toBeVisible();

    // Step 2: Open request and submit additional information
    await infoRequestNotification.click();
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Info Requested');

    // Locate the 'Submit Additional Information' section
    await expect(page.locator('[data-testid="submit-additional-info-section"]')).toBeVisible();

    const additionalInfo = 'Manager approval attached. Extended hours needed due to project deadline on March 15th';
    await page.fill('[data-testid="additional-info-response-field"]', additionalInfo);

    // Attach supporting documents if applicable
    const fileInput = page.locator('[data-testid="supporting-documents-upload"]');
    if (await fileInput.isVisible()) {
      await fileInput.setInputFiles('test-data/manager-approval.pdf');
    }

    await page.click('[data-testid="submit-response-button"]');

    // Expected Result: Information is saved and linked to original request
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Additional information submitted successfully');

    // Verify the request status has changed to 'Pending Review'
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending Review');

    // Verify the submitted information is linked to the original request
    await expect(page.locator('[data-testid="request-timeline"]')).toContainText(additionalInfo);

    // Step 3: Approver reviews updated request
    const approverPage = await context.newPage();
    await approverPage.goto(`${baseURL}/login`);
    await approverPage.fill('[data-testid="email-input"]', approverEmail);
    await approverPage.fill('[data-testid="password-input"]', approverPassword);
    await approverPage.click('[data-testid="login-button"]');
    await expect(approverPage).toHaveURL(/.*dashboard/);

    // Navigate to schedule changes and open the same request
    await approverPage.click('[data-testid="schedule-changes-menu"]');
    const updatedRequest = approverPage.locator('[data-testid="schedule-change-request"]').filter({ hasText: 'Pending Review' }).first();
    await updatedRequest.click();

    // Expected Result: Additional information is visible
    await expect(approverPage.locator('[data-testid="additional-info-section"]')).toBeVisible();
    await expect(approverPage.locator('[data-testid="additional-info-section"]')).toContainText(additionalInfo);
    await expect(approverPage.locator('[data-testid="request-timeline"]')).toContainText('Additional information submitted');

    await approverPage.close();
  });

  test('Ensure all info request actions are logged', async ({ page }) => {
    // Step 1: Request additional info as Approver
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to schedule change requests
    await page.click('[data-testid="schedule-changes-menu"]');
    const pendingRequest = page.locator('[data-testid="schedule-change-request"]').filter({ hasText: 'Pending' }).first();
    scheduleChangeRequestId = await pendingRequest.getAttribute('data-request-id') || 'REQ-002';
    await pendingRequest.click();

    // Click 'Request More Info' button and enter comments
    await page.click('[data-testid="request-more-info-button"]');
    await page.fill('[data-testid="info-request-comment-field"]', 'Need clarification on shift timing');
    await page.click('[data-testid="submit-info-request-button"]');
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();

    // Navigate to the audit log section
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-log-menu-item"]');
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();

    // Filter or search for the schedule change request ID
    await page.fill('[data-testid="audit-log-search-field"]', scheduleChangeRequestId);
    await page.click('[data-testid="audit-log-search-button"]');

    // Expected Result: Action is logged with user and timestamp
    const infoRequestLog = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Info Request' }).first();
    await expect(infoRequestLog).toBeVisible();
    await expect(infoRequestLog).toContainText(scheduleChangeRequestId);
    await expect(infoRequestLog).toContainText(approverEmail);
    await expect(infoRequestLog).toContainText('Need clarification on shift timing');

    // Verify timestamp is present
    const timestamp = infoRequestLog.locator('[data-testid="audit-log-timestamp"]');
    await expect(timestamp).toBeVisible();

    // Step 2: Submit additional info as Requester
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Log in as Schedule Coordinator
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', coordinatorEmail);
    await page.fill('[data-testid="password-input"]', coordinatorPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the schedule change request with info request
    await page.click('[data-testid="schedule-changes-menu"]');
    const infoRequestedRequest = page.locator('[data-testid="schedule-change-request"]').filter({ hasText: 'Info Requested' }).first();
    await infoRequestedRequest.click();

    // Submit additional information
    await page.fill('[data-testid="additional-info-response-field"]', 'Shift timing is 2 PM to 10 PM');
    await page.click('[data-testid="submit-response-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate back to the audit log section
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-log-menu-item"]');
    await page.fill('[data-testid="audit-log-search-field"]', scheduleChangeRequestId);
    await page.click('[data-testid="audit-log-search-button"]');

    // Expected Result: Action is logged in audit trail
    const infoResponseLog = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Info Response' }).first();
    await expect(infoResponseLog).toBeVisible();
    await expect(infoResponseLog).toContainText(scheduleChangeRequestId);
    await expect(infoResponseLog).toContainText(coordinatorEmail);
    await expect(infoResponseLog).toContainText('Shift timing is 2 PM to 10 PM');

    // Verify both actions are visible in chronological order
    const allLogEntries = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: scheduleChangeRequestId });
    await expect(allLogEntries).toHaveCount(2);

    const firstEntry = allLogEntries.nth(0);
    const secondEntry = allLogEntries.nth(1);

    await expect(firstEntry).toContainText('Info Request');
    await expect(secondEntry).toContainText('Info Response');

    // Verify complete details are logged
    await expect(firstEntry.locator('[data-testid="audit-log-user"]')).toContainText(approverEmail);
    await expect(secondEntry.locator('[data-testid="audit-log-user"]')).toContainText(coordinatorEmail);
    await expect(firstEntry.locator('[data-testid="audit-log-timestamp"]')).toBeVisible();
    await expect(secondEntry.locator('[data-testid="audit-log-timestamp"]')).toBeVisible();
  });
});