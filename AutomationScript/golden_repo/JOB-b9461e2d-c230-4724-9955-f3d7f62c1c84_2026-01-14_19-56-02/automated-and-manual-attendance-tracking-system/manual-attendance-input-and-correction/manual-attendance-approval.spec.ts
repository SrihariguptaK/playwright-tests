import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Approval - Story 2', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const MANAGER_EMAIL = 'attendance.manager@company.com';
  const MANAGER_PASSWORD = 'Manager@123';
  const UNAUTHORIZED_EMAIL = 'regular.employee@company.com';
  const UNAUTHORIZED_PASSWORD = 'Employee@123';

  test('Approve manual attendance entry successfully', async ({ page }) => {
    // Step 1: Navigate to the attendance management portal login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveTitle(/Attendance Management/i);

    // Step 2: Enter valid Attendance Manager credentials and click Login button
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Access granted to approval section
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.locator('[data-testid="user-role"]')).toContainText('Attendance Manager');

    // Step 3: Verify access to the manual attendance approval section in the navigation menu
    const approvalLink = page.locator('[data-testid="manual-attendance-approval-link"]');
    await expect(approvalLink).toBeVisible();

    // Step 4: Click on the manual attendance approval section link
    await approvalLink.click();
    await expect(page).toHaveURL(/\/manual-attendance\/approval/);

    // Step 5: View the list of pending manual attendance entries
    await page.waitForSelector('[data-testid="pending-entries-list"]');
    const pendingEntriesList = page.locator('[data-testid="pending-entries-list"]');
    await expect(pendingEntriesList).toBeVisible();

    // Expected Result: List displays all pending entries
    const entryCount = await page.locator('[data-testid="pending-entry-item"]').count();
    expect(entryCount).toBeGreaterThan(0);

    // Step 6: Select a specific pending entry from the list by clicking on it
    const firstEntry = page.locator('[data-testid="pending-entry-item"]').first();
    const entryId = await firstEntry.getAttribute('data-entry-id');
    await firstEntry.click();

    // Step 7: Review all details of the selected entry for accuracy and completeness
    await expect(page.locator('[data-testid="entry-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="entry-employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="entry-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="entry-time-in"]')).toBeVisible();
    await expect(page.locator('[data-testid="entry-time-out"]')).toBeVisible();
    await expect(page.locator('[data-testid="entry-reason"]')).toBeVisible();

    // Step 8: Click the Approve button for the reviewed entry
    await page.click('[data-testid="approve-button"]');

    // Step 9: Confirm the approval action in the dialog
    await expect(page.locator('[data-testid="confirm-approval-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-approve-button"]');

    // Expected Result: Entry status updated to approved
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Entry approved successfully');
    await page.waitForTimeout(1000);

    // Verify entry is no longer in pending list
    const updatedEntryCount = await page.locator('[data-testid="pending-entry-item"]').count();
    expect(updatedEntryCount).toBe(entryCount - 1);

    // Step 10: Verify that the submitter receives a notification about the approval
    // Check notification was sent via API or notification indicator
    const response = await page.request.get(`${BASE_URL}/api/notifications/latest?entryId=${entryId}`);
    expect(response.ok()).toBeTruthy();
    const notification = await response.json();
    expect(notification.type).toBe('approval');
    expect(notification.status).toBe('sent');
  });

  test('Reject manual attendance entry with comments', async ({ page }) => {
    // Step 1: Navigate to the attendance management portal login page
    await page.goto(`${BASE_URL}/login`);

    // Step 2: Enter valid Attendance Manager credentials and click Login button
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Access granted to approval section
    await expect(page).toHaveURL(/\/dashboard/);

    // Step 3: Verify access to the manual attendance approval section in the navigation menu
    await expect(page.locator('[data-testid="manual-attendance-approval-link"]')).toBeVisible();

    // Step 4: Navigate to the manual attendance approval section
    await page.click('[data-testid="manual-attendance-approval-link"]');
    await expect(page).toHaveURL(/\/manual-attendance\/approval/);

    // Step 5: Select a pending manual attendance entry from the list
    await page.waitForSelector('[data-testid="pending-entries-list"]');
    const firstEntry = page.locator('[data-testid="pending-entry-item"]').first();
    const entryId = await firstEntry.getAttribute('data-entry-id');
    await firstEntry.click();

    // Step 6: Review the entry details and identify issues requiring rejection
    await expect(page.locator('[data-testid="entry-details-modal"]')).toBeVisible();
    const entryDetails = {
      employeeName: await page.locator('[data-testid="entry-employee-name"]').textContent(),
      date: await page.locator('[data-testid="entry-date"]').textContent(),
      timeIn: await page.locator('[data-testid="entry-time-in"]').textContent()
    };

    // Step 7: Click the Reject button for the selected entry
    await page.click('[data-testid="reject-button"]');

    // Step 8: Enter detailed rejection comments explaining the reason for rejection
    await expect(page.locator('[data-testid="rejection-dialog"]')).toBeVisible();
    const rejectionComment = 'Invalid time entry - conflicts with existing biometric record';
    await page.fill('[data-testid="rejection-comments-textarea"]', rejectionComment);

    // Step 9: Click Confirm Rejection button
    await page.click('[data-testid="confirm-reject-button"]');

    // Expected Result: Entry status updated to rejected and comments saved
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Entry rejected successfully');

    // Step 10: Verify that rejection details are recorded in the system
    const auditResponse = await page.request.get(`${BASE_URL}/api/manual-attendance/audit/${entryId}`);
    expect(auditResponse.ok()).toBeTruthy();
    const auditLog = await auditResponse.json();
    expect(auditLog.action).toBe('rejected');
    expect(auditLog.comments).toBe(rejectionComment);
    expect(auditLog.userId).toBeTruthy();
    expect(auditLog.timestamp).toBeTruthy();

    // Step 11: Check that the submitter receives a rejection notification
    const notificationResponse = await page.request.get(`${BASE_URL}/api/notifications/latest?entryId=${entryId}`);
    expect(notificationResponse.ok()).toBeTruthy();
    const notification = await notificationResponse.json();
    expect(notification.type).toBe('rejection');
    expect(notification.status).toBe('sent');

    // Step 12: Verify the notification contains the rejection comments
    expect(notification.message).toContain(rejectionComment);
  });

  test('Prevent unauthorized user from accessing approval functionality', async ({ page, request }) => {
    // Step 1: Navigate to the attendance management portal login page
    await page.goto(`${BASE_URL}/login`);

    // Step 2: Enter credentials of a user without approval permissions
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Login successful but without manager privileges
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.locator('[data-testid="user-role"]')).not.toContainText('Attendance Manager');

    // Step 3: Check the navigation menu for manual attendance approval section
    const approvalLink = page.locator('[data-testid="manual-attendance-approval-link"]');
    await expect(approvalLink).not.toBeVisible();

    // Step 4: Attempt to manually navigate to the approval section URL
    await page.goto(`${BASE_URL}/manual-attendance/approval`);

    // Expected Result: Access to approval section is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/Access Denied|Unauthorized|403/);

    // Step 5: Verify that no approval functionality is accessible through the UI
    await expect(page.locator('[data-testid="pending-entries-list"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="approve-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="reject-button"]')).not.toBeVisible();

    // Get authentication token from cookies or local storage
    const authToken = await page.evaluate(() => {
      return localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
    });

    // Step 6: Attempt to call GET /api/manual-attendance/pending endpoint with unauthorized token
    const getPendingResponse = await request.get(`${BASE_URL}/api/manual-attendance/pending`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });

    // Expected Result: System returns authorization error
    expect(getPendingResponse.status()).toBe(403);
    const getPendingBody = await getPendingResponse.json();
    expect(getPendingBody.error).toMatch(/unauthorized|forbidden|access denied/i);

    // Step 7: Attempt to call POST /api/manual-attendance/approve endpoint with unauthorized token
    const approveResponse = await request.post(`${BASE_URL}/api/manual-attendance/approve`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        entryId: 'test-entry-123',
        action: 'approve',
        comments: 'Attempting unauthorized approval'
      }
    });

    // Expected Result: System returns authorization error
    expect(approveResponse.status()).toBe(403);
    const approveBody = await approveResponse.json();
    expect(approveBody.error).toMatch(/unauthorized|forbidden|access denied/i);

    // Step 8: Verify that no data is returned or modified by the unauthorized API calls
    expect(getPendingBody.data).toBeUndefined();
    expect(approveBody.success).toBeFalsy();

    // Step 9: Check audit logs for the unauthorized access attempts
    // Note: This would typically require admin access to verify
    // For testing purposes, we verify the response indicates the attempt was logged
    expect(approveBody.logged).toBeTruthy();
  });
});