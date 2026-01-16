import { test, expect } from '@playwright/test';

test.describe('Story-13: Request Additional Information on Schedule Change Requests', () => {
  const approverEmail = 'approver@example.com';
  const approverPassword = 'ApproverPass123!';
  const requesterEmail = 'requester@example.com';
  const requesterPassword = 'RequesterPass123!';
  const baseURL = 'https://app.example.com';

  test('Verify approver can request additional information with comments', async ({ page, context }) => {
    // Step 1: Log in as approver and navigate to approval dashboard
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to approval dashboard
    await page.click('[data-testid="approvals-nav-link"]');
    await expect(page.locator('[data-testid="approval-dashboard"]')).toBeVisible();

    // Step 2: Click on a specific schedule change request from pending list
    await page.click('[data-testid="pending-requests-tab"]');
    const firstRequest = page.locator('[data-testid="schedule-change-request-item"]').first();
    await expect(firstRequest).toBeVisible();
    const requestId = await firstRequest.getAttribute('data-request-id');
    await firstRequest.click();

    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toContainText(requestId || '');

    // Step 3: Click 'Request Additional Information' button
    await page.click('[data-testid="request-info-button"]');
    await expect(page.locator('[data-testid="request-info-modal"]')).toBeVisible();

    // Step 4: Enter specific comments describing additional information needed
    const commentText = 'Please provide coverage plan for your current shift assignments during the requested time off period';
    await page.fill('[data-testid="info-request-comments"]', commentText);

    // Step 5: Submit the information request
    await page.click('[data-testid="submit-info-request-button"]');

    // Expected Result: System accepts input and sends notification to requester
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Information request sent successfully');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Information Requested');

    // Step 6: Log out as approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 7: Log in as requester
    await page.fill('[data-testid="email-input"]', requesterEmail);
    await page.fill('[data-testid="password-input"]', requesterPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 8: Navigate to schedule change requests
    await page.click('[data-testid="my-requests-nav-link"]');
    await expect(page.locator('[data-testid="my-requests-page"]')).toBeVisible();

    // Step 9: Open the request with information requested status
    await page.click(`[data-testid="schedule-change-request-item"][data-request-id="${requestId}"]`);
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Information Requested');
    await expect(page.locator('[data-testid="info-request-comments-display"]')).toContainText(commentText);

    // Step 10: Enter additional information in response field
    await page.click('[data-testid="respond-to-info-request-button"]');
    await expect(page.locator('[data-testid="response-modal"]')).toBeVisible();
    const responseText = 'I have arranged coverage with John Doe for my shifts on the requested dates. Coverage plan document attached with details of handover responsibilities.';
    await page.fill('[data-testid="info-response-field"]', responseText);

    // Step 11: Submit the response
    await page.click('[data-testid="submit-response-button"]');

    // Expected Result: Request status updates and approver is notified
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Response submitted successfully');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Information Provided');

    // Step 12: Log out as requester
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 13: Log back in as approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 14: Navigate to approvals and open the updated request
    await page.click('[data-testid="approvals-nav-link"]');
    await page.click(`[data-testid="schedule-change-request-item"][data-request-id="${requestId}"]`);
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();

    // Expected Result: Approver can review newly provided information
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Information Provided');
    await expect(page.locator('[data-testid="info-response-display"]')).toContainText(responseText);
    await expect(page.locator('[data-testid="audit-trail"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-trail"]')).toContainText('Information requested');
    await expect(page.locator('[data-testid="audit-trail"]')).toContainText('Information provided');
  });

  test('Ensure mandatory comments for information requests', async ({ page }) => {
    // Step 1: Log in as approver and navigate to approval dashboard
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to approval dashboard
    await page.click('[data-testid="approvals-nav-link"]');
    await expect(page.locator('[data-testid="approval-dashboard"]')).toBeVisible();

    // Step 3: Click on a pending schedule change request
    await page.click('[data-testid="pending-requests-tab"]');
    const firstRequest = page.locator('[data-testid="schedule-change-request-item"]').first();
    await expect(firstRequest).toBeVisible();
    const requestId = await firstRequest.getAttribute('data-request-id');
    const initialStatus = await page.locator('[data-testid="request-status"]').textContent();
    await firstRequest.click();

    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();

    // Step 4: Click 'Request Additional Information' button
    await page.click('[data-testid="request-info-button"]');
    await expect(page.locator('[data-testid="request-info-modal"]')).toBeVisible();

    // Step 5: Leave comment field empty and attempt to submit
    const commentField = page.locator('[data-testid="info-request-comments"]');
    await expect(commentField).toBeVisible();
    await commentField.clear();

    // Step 6: Click submit button without entering comments
    await page.click('[data-testid="submit-info-request-button"]');

    // Expected Result: System prevents submission and displays error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/comment.*required|please.*comment|must.*provide.*comment/i);
    await expect(page.locator('[data-testid="info-request-modal"]')).toBeVisible();

    // Verify field validation styling
    await expect(commentField).toHaveClass(/error|invalid|required/);

    // Step 7: Close modal and verify request status has not changed
    await page.click('[data-testid="cancel-info-request-button"]');
    await expect(page.locator('[data-testid="request-info-modal"]')).not.toBeVisible();

    // Expected Result: Request status has not changed
    const currentStatus = await page.locator('[data-testid="request-status"]').textContent();
    expect(currentStatus).toBe(initialStatus);
    await expect(page.locator('[data-testid="request-status"]')).not.toContainText('Information Requested');

    // Step 8: Verify no action has been logged in audit trail
    await page.click('[data-testid="audit-trail-tab"]');
    const auditEntries = page.locator('[data-testid="audit-entry"]');
    const auditCount = await auditEntries.count();
    
    // Check that no new "Information Requested" entry was added
    for (let i = 0; i < auditCount; i++) {
      const entryText = await auditEntries.nth(i).textContent();
      expect(entryText).not.toContain('Information requested');
    }
  });
});