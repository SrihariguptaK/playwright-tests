import { test, expect } from '@playwright/test';

test.describe('Approver Request Additional Information', () => {
  test.beforeEach(async ({ page }) => {
    // Login as approver
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'approver123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate approver can request additional information', async ({ page }) => {
    // Approver navigates to the pending schedule change requests queue from the dashboard
    await page.click('[data-testid="pending-requests-link"]');
    await expect(page.locator('[data-testid="pending-requests-header"]')).toBeVisible();

    // Approver clicks on a specific schedule change request to view details
    await page.click('[data-testid="schedule-request-item"]:first-child');
    
    // Action: Approver selects a schedule change request
    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule"]')).toBeVisible();

    // Approver reviews the request details and identifies missing or unclear information
    const requestId = await page.locator('[data-testid="request-id"]').textContent();

    // Approver clicks the 'Request Additional Information' button
    await page.click('[data-testid="request-additional-info-button"]');
    await expect(page.locator('[data-testid="additional-info-modal"]')).toBeVisible();

    // Approver enters detailed comments in the text area specifying the required information
    await page.fill(
      '[data-testid="additional-info-comments"]',
      'Please provide the business justification for this schedule change and confirm coverage for your current shift'
    );

    // Approver clicks the 'Submit Request' button in the modal dialog
    await page.click('[data-testid="submit-info-request-button"]');

    // Action: Approver requests additional information with comments
    // Expected Result: Request status updates and notification sent to employee
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Additional information requested');

    // Approver verifies the request status has been updated in the request details page
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Additional Information Required');

    // Approver checks that a notification has been sent to the employee
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible();
  });

  test('Verify employee can respond to additional information requests', async ({ page }) => {
    // Logout as approver and login as employee
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'employee123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Employee logs into the system and views the notification center icon/badge
    // Action: Employee receives notification for additional information request
    // Expected Result: Notification is visible in notification center
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();
    const notificationCount = await page.locator('[data-testid="notification-badge"]').textContent();
    expect(parseInt(notificationCount || '0')).toBeGreaterThan(0);

    // Employee clicks on the notification center icon to open the notification panel
    await page.click('[data-testid="notification-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();

    // Employee clicks on the notification for the additional information request
    await page.click('[data-testid="notification-item"]:has-text("Additional information requested")');

    // Employee reviews the approver's comments to understand what information is needed
    await expect(page.locator('[data-testid="approver-comments"]')).toBeVisible();
    await expect(page.locator('[data-testid="approver-comments"]')).toContainText('business justification');

    // Employee clicks the 'Update Request' or 'Provide Additional Information' button
    await page.click('[data-testid="update-request-button"]');
    await expect(page.locator('[data-testid="update-request-form"]')).toBeVisible();

    // Employee enters the required additional information in the designated field
    await page.fill(
      '[data-testid="additional-information-field"]',
      'Business justification: Need to attend mandatory training session. Shift coverage: John Smith has agreed to cover my shift from 9 AM to 5 PM.'
    );

    // Employee clicks the 'Submit Updates' or 'Resubmit Request' button
    await page.click('[data-testid="submit-updates-button"]');

    // Action: Employee updates schedule change request with required information
    // Expected Result: Updates are saved and approver is notified
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request updated successfully');

    // Employee verifies the updated information is saved and visible in the request details
    await expect(page.locator('[data-testid="additional-information-display"]')).toContainText('mandatory training session');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending Review');

    // System sends notification to the approver about the updated information
    await expect(page.locator('[data-testid="approver-notified-indicator"]')).toBeVisible();
  });

  test('Ensure audit trail of information requests and responses', async ({ page }) => {
    // Logout and login as admin to access audit logs
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'admin123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // User navigates to the audit log or system logs section from the admin dashboard
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // User enters the schedule change request ID in the search field or filters by request ID
    const testRequestId = 'SCR-12345';
    await page.fill('[data-testid="audit-search-input"]', testRequestId);
    await page.click('[data-testid="audit-search-button"]');

    // Action: Retrieve audit log for a schedule change request
    // Expected Result: All information requests and responses are recorded with timestamps
    await expect(page.locator('[data-testid="audit-log-results"]')).toBeVisible();

    // User reviews the audit log entries for the information request action
    const infoRequestEntry = page.locator('[data-testid="audit-entry"]:has-text("Additional Information Requested")');
    await expect(infoRequestEntry).toBeVisible();
    await expect(infoRequestEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(infoRequestEntry.locator('[data-testid="audit-user"]')).toContainText('approver@company.com');
    await expect(infoRequestEntry.locator('[data-testid="audit-action"]')).toContainText('Additional Information Requested');

    // User reviews the audit log entries for the employee's response action
    const responseEntry = page.locator('[data-testid="audit-entry"]:has-text("Additional Information Provided")');
    await expect(responseEntry).toBeVisible();
    await expect(responseEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(responseEntry.locator('[data-testid="audit-user"]')).toContainText('employee@company.com');
    await expect(responseEntry.locator('[data-testid="audit-action"]')).toContainText('Additional Information Provided');

    // User verifies the chronological order of audit entries
    const auditEntries = page.locator('[data-testid="audit-entry"]');
    const entryCount = await auditEntries.count();
    expect(entryCount).toBeGreaterThanOrEqual(2);

    // User checks for notification-related audit entries
    const notificationEntry = page.locator('[data-testid="audit-entry"]:has-text("Notification Sent")');
    await expect(notificationEntry.first()).toBeVisible();

    // User verifies all audit entries contain required metadata
    for (let i = 0; i < Math.min(entryCount, 5); i++) {
      const entry = auditEntries.nth(i);
      await expect(entry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
      await expect(entry.locator('[data-testid="audit-user"]')).toBeVisible();
      await expect(entry.locator('[data-testid="audit-action"]')).toBeVisible();
      await expect(entry.locator('[data-testid="audit-request-id"]')).toContainText(testRequestId);
    }

    // User attempts to export the audit trail for the schedule change request
    await page.click('[data-testid="export-audit-button"]');
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    
    // Verify download initiated
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="download-audit-report-button"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('audit-trail');
  });
});