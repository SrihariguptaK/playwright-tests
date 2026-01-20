import { test, expect } from '@playwright/test';

test.describe('Approval Delegation - Story 11', () => {
  const approverEmail = 'approver@example.com';
  const approverPassword = 'ApproverPass123';
  const delegateEmail = 'delegate@example.com';
  const delegatePassword = 'DelegatePass123';
  const baseURL = 'https://app.example.com';

  test.beforeEach(async ({ page }) => {
    // Login as Approver before each test
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate creation of approval delegation (happy-path)', async ({ page, context }) => {
    // Step 1: Navigate to the delegation settings page from the approver dashboard
    await page.click('[data-testid="delegation-settings-link"]');
    await expect(page).toHaveURL(/.*delegation-settings/);
    await expect(page.locator('[data-testid="delegation-ui"]')).toBeVisible();

    // Step 2: Click on the delegate user dropdown and select a qualified user from the list
    await page.click('[data-testid="delegate-user-dropdown"]');
    await page.click(`[data-testid="delegate-option-${delegateEmail}"]`);
    await expect(page.locator('[data-testid="delegate-user-dropdown"]')).toContainText(delegateEmail);

    // Step 3: Set the delegation start date to current date using the date picker
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="delegation-start-date"]', currentDate);

    // Step 4: Set the delegation end date to a future date (e.g., 7 days from current date)
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const endDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="delegation-end-date"]', endDate);

    // Step 5: Click the 'Save Delegation' or 'Create Delegation' button
    await page.click('[data-testid="save-delegation-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Delegation saved successfully');

    // Step 6: Log out from the Approver account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 7: Log in with the delegate user credentials
    await page.fill('[data-testid="email-input"]', delegateEmail);
    await page.fill('[data-testid="password-input"]', delegatePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 8: Navigate to the approvals or tasks section as the delegate user
    await page.click('[data-testid="approvals-link"]');
    await expect(page).toHaveURL(/.*approvals/);

    // Verify delegate can access delegated approvals
    await expect(page.locator('[data-testid="delegated-tasks-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="delegated-approval-item"]').first()).toBeVisible();
  });

  test('Test revocation of delegation (happy-path)', async ({ page, context }) => {
    // Setup: Create a delegation first
    await page.click('[data-testid="delegation-settings-link"]');
    await page.click('[data-testid="delegate-user-dropdown"]');
    await page.click(`[data-testid="delegate-option-${delegateEmail}"]`);
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="delegation-start-date"]', currentDate);
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    await page.fill('[data-testid="delegation-end-date"]', futureDate.toISOString().split('T')[0]);
    await page.click('[data-testid="save-delegation-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 1: Navigate to the delegation settings page from the approver dashboard
    await page.click('[data-testid="delegation-settings-link"]');
    await expect(page).toHaveURL(/.*delegation-settings/);

    // Step 2: Locate the active delegation in the delegations list and identify the revoke option
    const activeDelegation = page.locator('[data-testid="active-delegation-item"]').first();
    await expect(activeDelegation).toBeVisible();

    // Step 3: Click the 'Revoke Delegation' button for the active delegation
    await activeDelegation.locator('[data-testid="revoke-delegation-button"]').click();

    // Step 4: Confirm the revocation by clicking 'Yes' or 'Confirm' in the confirmation dialog
    await page.click('[data-testid="confirm-revoke-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Delegation removed');

    // Step 5: Log out from the Approver account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 6: Log in with the delegate user credentials
    await page.fill('[data-testid="email-input"]', delegateEmail);
    await page.fill('[data-testid="password-input"]', delegatePassword);
    await page.click('[data-testid="login-button"]');

    // Step 7: Navigate to the approvals or tasks section as the delegate user
    await page.click('[data-testid="approvals-link"]');

    // Verify tasks are no longer assigned to delegate
    const delegatedTasksCount = await page.locator('[data-testid="delegated-approval-item"]').count();
    expect(delegatedTasksCount).toBe(0);

    // Step 8: Log back in as the Approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');

    // Verify the approval tasks are back in the Approver's queue
    await page.click('[data-testid="approvals-link"]');
    await expect(page.locator('[data-testid="approval-item"]').first()).toBeVisible();
  });

  test('Verify audit logging of delegation actions (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the delegation settings page and create a new delegation
    await page.click('[data-testid="delegation-settings-link"]');
    await page.click('[data-testid="delegate-user-dropdown"]');
    await page.click(`[data-testid="delegate-option-${delegateEmail}"]`);

    // Step 2: Set start and end dates
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="delegation-start-date"]', currentDate);
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    await page.fill('[data-testid="delegation-end-date"]', futureDate.toISOString().split('T')[0]);

    // Step 3: Click 'Save Delegation' to complete the delegation creation
    const creationTimestamp = new Date();
    await page.click('[data-testid="save-delegation-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 4: Navigate to the audit log section or access audit log reports
    await page.click('[data-testid="audit-log-link"]');
    await expect(page).toHaveURL(/.*audit-log/);

    // Step 5: Search or filter audit logs for delegation creation actions
    await page.fill('[data-testid="audit-log-search"]', 'delegation creation');
    await page.click('[data-testid="audit-log-filter-button"]');

    // Verify creation action is logged
    const creationLogEntry = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Delegation Created' }).first();
    await expect(creationLogEntry).toBeVisible();
    await expect(creationLogEntry).toContainText(approverEmail);
    await expect(creationLogEntry).toContainText(delegateEmail);
    await expect(creationLogEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();

    // Step 6: Return to the delegation settings page and revoke the previously created delegation
    await page.click('[data-testid="delegation-settings-link"]');
    await page.locator('[data-testid="active-delegation-item"]').first().locator('[data-testid="revoke-delegation-button"]').click();
    const revocationTimestamp = new Date();
    await page.click('[data-testid="confirm-revoke-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 7: Navigate back to the audit log section and refresh or search for recent delegation actions
    await page.click('[data-testid="audit-log-link"]');
    await page.click('[data-testid="refresh-audit-log-button"]');

    // Step 8: Search or filter audit logs for delegation revocation actions
    await page.fill('[data-testid="audit-log-search"]', 'delegation revocation');
    await page.click('[data-testid="audit-log-filter-button"]');

    // Verify revocation action is logged
    const revocationLogEntry = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Delegation Revoked' }).first();
    await expect(revocationLogEntry).toBeVisible();
    await expect(revocationLogEntry).toContainText(approverEmail);
    await expect(revocationLogEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();

    // Step 9: Verify that both audit log entries contain accurate timestamps in chronological order
    await page.fill('[data-testid="audit-log-search"]', 'delegation');
    await page.click('[data-testid="audit-log-filter-button"]');

    const allDelegationLogs = page.locator('[data-testid="audit-log-entry"]');
    const logCount = await allDelegationLogs.count();
    expect(logCount).toBeGreaterThanOrEqual(2);

    // Verify both creation and revocation are present
    await expect(page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Delegation Created' })).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Delegation Revoked' })).toBeVisible();

    // Verify timestamps are in chronological order
    const firstLogTimestamp = await page.locator('[data-testid="audit-log-entry"]').nth(0).locator('[data-testid="audit-timestamp"]').textContent();
    const secondLogTimestamp = await page.locator('[data-testid="audit-log-entry"]').nth(1).locator('[data-testid="audit-timestamp"]').textContent();
    expect(firstLogTimestamp).toBeTruthy();
    expect(secondLogTimestamp).toBeTruthy();
  });
});