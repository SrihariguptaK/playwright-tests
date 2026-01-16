import { test, expect } from '@playwright/test';

test.describe('Story-10: Approver Request Additional Information', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const approverEmail = 'approver@company.com';
  const approverPassword = 'ApproverPass123!';
  const coordinatorEmail = 'coordinator@company.com';
  const coordinatorPassword = 'CoordinatorPass123!';

  test('Validate approver can request additional information', async ({ page }) => {
    // Step 1: Login as Approver
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to schedule change requests dashboard
    await page.click('[data-testid="schedule-changes-menu"]');
    await expect(page.locator('[data-testid="schedule-changes-dashboard"]')).toBeVisible();

    // Step 3: Select and open a pending schedule change request
    await page.click('[data-testid="pending-requests-tab"]');
    const firstPendingRequest = page.locator('[data-testid="schedule-request-row"]').first();
    await expect(firstPendingRequest).toBeVisible();
    const requestId = await firstPendingRequest.getAttribute('data-request-id');
    await firstPendingRequest.click();

    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toContainText(requestId || '');

    // Step 4: Locate and click the 'Request More Info' button
    const requestInfoButton = page.locator('[data-testid="request-more-info-button"]');
    await expect(requestInfoButton).toBeVisible();
    await requestInfoButton.click();

    // Step 5: Enter detailed comments explaining what additional information is needed
    const commentsModal = page.locator('[data-testid="info-request-modal"]');
    await expect(commentsModal).toBeVisible();
    const commentsTextarea = page.locator('[data-testid="info-request-comments"]');
    await commentsTextarea.fill('Please provide justification for the extended hours and manager approval');

    // Step 6: Click 'Submit' or 'Send Request' button
    await page.click('[data-testid="submit-info-request-button"]');

    // Expected Result: Request is submitted and confirmation shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Information request sent successfully');

    // Step 7: Verify the request status has changed to 'Info Requested'
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Info Requested');

    // Step 8: Verify the info request appears in the request history or activity log
    await page.click('[data-testid="activity-log-tab"]');
    const latestActivity = page.locator('[data-testid="activity-log-entry"]').first();
    await expect(latestActivity).toContainText('Information requested');
    await expect(latestActivity).toContainText('Please provide justification for the extended hours and manager approval');

    // Step 9: Verify notification is sent to requester (check notification system)
    await page.goto(`${baseURL}/notifications`);
    const notificationSent = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Information request sent' });
    await expect(notificationSent).toBeVisible();
  });

  test('Verify requester can submit additional information', async ({ page, context }) => {
    // Step 1: Log in to the system as Schedule Coordinator
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', coordinatorEmail);
    await page.fill('[data-testid="password-input"]', coordinatorPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Check the notifications panel or inbox
    await page.click('[data-testid="notifications-icon"]');
    const notificationsPanel = page.locator('[data-testid="notifications-panel"]');
    await expect(notificationsPanel).toBeVisible();

    // Expected Result: Notification is visible
    const infoRequestNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Additional information requested' }).first();
    await expect(infoRequestNotification).toBeVisible();

    // Step 3: Click on the notification to open the associated schedule change request
    await infoRequestNotification.click();
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();

    // Step 4: Locate the 'Respond to Info Request' or 'Submit Additional Information' section
    const respondSection = page.locator('[data-testid="respond-to-info-request-section"]');
    await expect(respondSection).toBeVisible();

    // Step 5: Enter the additional information requested by the approver
    const additionalInfoTextarea = page.locator('[data-testid="additional-info-textarea"]');
    await additionalInfoTextarea.fill('Manager approval attached. Extended hours needed due to project deadline on March 15th');

    // Step 6: Attach any supporting documents if applicable
    const fileInput = page.locator('[data-testid="attachment-upload-input"]');
    if (await fileInput.isVisible()) {
      await fileInput.setInputFiles('test-data/manager-approval.pdf');
    }

    // Step 7: Click 'Submit' or 'Send Response' button
    await page.click('[data-testid="submit-additional-info-button"]');

    // Expected Result: Information is saved and linked to original request
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Additional information submitted successfully');

    // Step 8: Verify the request status changes to 'Pending Approval' or 'Under Review'
    await expect(page.locator('[data-testid="request-status"]')).toContainText(/Pending Approval|Under Review/);

    // Step 9: Log in as the Approver who requested the information
    await page.goto(`${baseURL}/logout`);
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');

    // Step 10: Navigate to the schedule change request that had the info request
    await page.click('[data-testid="schedule-changes-menu"]');
    await page.click('[data-testid="pending-requests-tab"]');
    const requestWithInfo = page.locator('[data-testid="schedule-request-row"]').filter({ hasText: 'Info Provided' }).first();
    await requestWithInfo.click();

    // Step 11: Review the request details and locate the additional information section
    const additionalInfoSection = page.locator('[data-testid="additional-information-section"]');
    await expect(additionalInfoSection).toBeVisible();

    // Expected Result: Additional information is visible
    await expect(additionalInfoSection).toContainText('Manager approval attached. Extended hours needed due to project deadline on March 15th');

    // Step 12: Verify timestamp and requester name are displayed with the additional information
    await expect(additionalInfoSection.locator('[data-testid="info-submitter-name"]')).toBeVisible();
    await expect(additionalInfoSection.locator('[data-testid="info-submission-timestamp"]')).toBeVisible();
  });

  test('Ensure all info request actions are logged', async ({ page }) => {
    // Step 1: Log in as Approver
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Open a pending schedule change request
    await page.click('[data-testid="schedule-changes-menu"]');
    await page.click('[data-testid="pending-requests-tab"]');
    const pendingRequest = page.locator('[data-testid="schedule-request-row"]').first();
    const requestId = await pendingRequest.getAttribute('data-request-id');
    await pendingRequest.click();

    // Step 3: Click 'Request More Info' button and enter comments
    await page.click('[data-testid="request-more-info-button"]');
    await page.fill('[data-testid="info-request-comments"]', 'Need clarification on shift timing');

    // Step 4: Submit the information request
    await page.click('[data-testid="submit-info-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 5: Navigate to the audit log or activity history section of the request
    await page.click('[data-testid="audit-log-tab"]');
    const auditLog = page.locator('[data-testid="audit-log-section"]');
    await expect(auditLog).toBeVisible();

    // Step 6: Locate the most recent entry for the information request action
    const latestLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(latestLogEntry).toBeVisible();

    // Step 7: Verify all required fields are captured in the log entry
    await expect(latestLogEntry.locator('[data-testid="log-action-type"]')).toContainText('Information Requested');
    await expect(latestLogEntry.locator('[data-testid="log-user"]')).toContainText(approverEmail);
    await expect(latestLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(latestLogEntry.locator('[data-testid="log-details"]')).toContainText('Need clarification on shift timing');

    // Expected Result: Action is logged with user and timestamp
    const timestamp = await latestLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();

    // Step 8: Log out and log in as Schedule Coordinator (Requester)
    await page.goto(`${baseURL}/logout`);
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', coordinatorEmail);
    await page.fill('[data-testid="password-input"]', coordinatorPassword);
    await page.click('[data-testid="login-button"]');

    // Step 9: Open the schedule change request with the info request
    await page.click('[data-testid="notifications-icon"]');
    const infoRequestNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Additional information requested' }).first();
    await infoRequestNotification.click();

    // Step 10: Submit additional information in response to the info request
    await page.fill('[data-testid="additional-info-textarea"]', 'Shift timing is 2 PM to 10 PM as per department needs');
    await page.click('[data-testid="submit-additional-info-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 11: Navigate to the audit log or activity history section
    await page.click('[data-testid="audit-log-tab"]');
    await expect(page.locator('[data-testid="audit-log-section"]')).toBeVisible();

    // Step 12: Locate the log entry for the additional information submission
    const infoSubmissionEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(infoSubmissionEntry).toBeVisible();

    // Expected Result: Action is logged in audit trail
    await expect(infoSubmissionEntry.locator('[data-testid="log-action-type"]')).toContainText('Additional Information Submitted');
    await expect(infoSubmissionEntry.locator('[data-testid="log-user"]')).toContainText(coordinatorEmail);
    await expect(infoSubmissionEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(infoSubmissionEntry.locator('[data-testid="log-details"]')).toContainText('Shift timing is 2 PM to 10 PM as per department needs');

    // Step 13: Verify the chronological order of log entries
    const allLogEntries = page.locator('[data-testid="audit-log-entry"]');
    const entryCount = await allLogEntries.count();
    expect(entryCount).toBeGreaterThanOrEqual(2);

    // Verify first entry is the most recent (additional info submission)
    const firstEntry = allLogEntries.nth(0);
    await expect(firstEntry.locator('[data-testid="log-action-type"]')).toContainText('Additional Information Submitted');

    // Verify second entry is the info request
    const secondEntry = allLogEntries.nth(1);
    await expect(secondEntry.locator('[data-testid="log-action-type"]')).toContainText('Information Requested');

    // Step 14: Verify log entries are immutable and cannot be edited or deleted
    const editButton = firstEntry.locator('[data-testid="edit-log-button"]');
    const deleteButton = firstEntry.locator('[data-testid="delete-log-button"]');
    await expect(editButton).not.toBeVisible();
    await expect(deleteButton).not.toBeVisible();
  });
});