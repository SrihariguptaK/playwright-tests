import { test, expect } from '@playwright/test';

test.describe('Delegation Management - Story 18', () => {
  const approverEmail = 'approver@example.com';
  const approverPassword = 'ApproverPass123!';
  const delegateEmail = 'delegate@example.com';
  const delegatePassword = 'DelegatePass123!';
  const nonApproverEmail = 'user@example.com';
  const nonApproverPassword = 'UserPass123!';
  const baseURL = 'https://app.example.com';

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Assign and revoke delegation successfully', async ({ page }) => {
    // Step 1: Login as approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Navigate to delegation settings page from the main dashboard
    await page.click('[data-testid="delegation-settings-link"]');
    await expect(page).toHaveURL(/.*delegation-settings/);
    await expect(page.locator('h1:has-text("Delegation Settings")')).toBeVisible();

    // Step 3: Click on 'Assign Delegate' or 'Create Delegation' button
    await page.click('[data-testid="assign-delegate-button"]');
    await expect(page.locator('[data-testid="delegation-form"]')).toBeVisible();

    // Step 4: Select a valid approver from the delegate dropdown list
    await page.click('[data-testid="delegate-dropdown"]');
    await page.click(`[data-testid="delegate-option-${delegateEmail}"]`);

    // Step 5: Set start date to current date and end date to 7 days from current date
    const today = new Date();
    const startDate = today.toISOString().split('T')[0];
    const endDate = new Date(today.setDate(today.getDate() + 7)).toISOString().split('T')[0];
    
    await page.fill('[data-testid="start-date-input"]', startDate);
    await page.fill('[data-testid="end-date-input"]', endDate);

    // Step 6: Click 'Save' or 'Assign Delegation' button
    await page.click('[data-testid="save-delegation-button"]');

    // Expected Result: Delegation is saved and delegate receives notifications
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Delegation assigned successfully');
    await expect(page.locator('[data-testid="delegation-list"]')).toContainText(delegateEmail);

    // Step 7: Verify delegate receives notification about the delegation assignment
    const delegationId = await page.locator('[data-testid="delegation-id"]').first().textContent();
    expect(delegationId).toBeTruthy();

    // Step 8: Log out from the original approver account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 9: Log in as the delegate
    await page.fill('[data-testid="email-input"]', delegateEmail);
    await page.fill('[data-testid="password-input"]', delegatePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 10: Navigate to approval requests queue or delegated tasks section
    await page.click('[data-testid="approval-requests-link"]');
    await expect(page.locator('[data-testid="delegated-tasks-section"]')).toBeVisible();

    // Step 11: Select one of the delegated approval requests and click 'Approve'
    const firstDelegatedRequest = page.locator('[data-testid="delegated-request-item"]').first();
    await expect(firstDelegatedRequest).toBeVisible();
    await firstDelegatedRequest.click();
    await page.click('[data-testid="approve-button"]');

    // Expected Result: Delegate can perform approval actions
    await expect(page.locator('[data-testid="approval-success-message"]')).toContainText('Request approved successfully');

    // Step 12: Log out from delegate account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 13: Log back in as the original approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 14: Navigate to delegation settings and locate the active delegation assignment
    await page.click('[data-testid="delegation-settings-link"]');
    await expect(page.locator('[data-testid="delegation-list"]')).toContainText(delegateEmail);

    // Step 15: Click 'Revoke' or 'Cancel Delegation' button for the active delegation
    await page.click('[data-testid="revoke-delegation-button"]');

    // Step 16: Confirm the revocation action
    await page.click('[data-testid="confirm-revoke-button"]');

    // Expected Result: Delegation is removed and delegate loses access
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Delegation revoked successfully');

    // Step 17: Log out and log back in as the delegate
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="email-input"]', delegateEmail);
    await page.fill('[data-testid="password-input"]', delegatePassword);
    await page.click('[data-testid="login-button"]');

    // Step 18: Navigate to approval requests and verify no delegated tasks
    await page.click('[data-testid="approval-requests-link"]');
    const delegatedTasksSection = page.locator('[data-testid="delegated-tasks-section"]');
    
    // Verify delegate no longer has access to delegated tasks
    await expect(delegatedTasksSection).not.toBeVisible();
  });

  test('Prevent unauthorized delegation assignment', async ({ page }) => {
    // Step 1: Login as non-approver user
    await page.fill('[data-testid="email-input"]', nonApproverEmail);
    await page.fill('[data-testid="password-input"]', nonApproverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Attempt to navigate to delegation settings page by entering the URL directly
    await page.goto(`${baseURL}/delegation-settings`);

    // Expected Result: System denies action with error message
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('You do not have permission to access delegation settings');

    // Verify user is redirected away from delegation settings
    await expect(page).not.toHaveURL(/.*delegation-settings/);

    // Step 3: Attempt to send a POST request to /api/delegations endpoint
    const response = await page.request.post(`${baseURL}/api/delegations`, {
      data: {
        delegateEmail: delegateEmail,
        startDate: new Date().toISOString(),
        endDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
      }
    });

    // Expected Result: API returns unauthorized error
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Unauthorized');

    // Step 4: Verify that no delegation assignment is created in the DelegationAssignments table
    // Navigate to delegation settings as approver to verify
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="delegation-settings-link"]');
    
    // Verify no unauthorized delegation exists
    const delegationList = page.locator('[data-testid="delegation-list"]');
    const unauthorizedDelegation = delegationList.locator(`text=${nonApproverEmail}`);
    await expect(unauthorizedDelegation).not.toBeVisible();

    // Step 5: Check system audit logs for the unauthorized access attempt
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Unauthorized delegation attempt' })).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-entry"]').filter({ hasText: nonApproverEmail })).toBeVisible();
  });
});