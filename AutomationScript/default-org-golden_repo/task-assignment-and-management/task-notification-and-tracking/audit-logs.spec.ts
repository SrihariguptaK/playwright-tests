import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Audit Logs - Task Change Tracking', () => {
  const MANAGER_EMAIL = 'manager@example.com';
  const MANAGER_PASSWORD = 'Manager123!';
  const UNAUTHORIZED_EMAIL = 'teammember@example.com';
  const UNAUTHORIZED_PASSWORD = 'Member123!';
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('View audit logs filtered by task and date (happy-path)', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the audit log interface by clicking on 'Audit Logs' menu option
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page).toHaveURL(/.*audit-logs/);
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();

    // Select a specific task from the task filter dropdown
    await page.click('[data-testid="task-filter-dropdown"]');
    await page.click('[data-testid="task-option-1"]');
    await expect(page.locator('[data-testid="task-filter-dropdown"]')).toContainText('Task');

    // Enter start date in the 'From Date' field using date picker
    await page.click('[data-testid="from-date-picker"]');
    await page.fill('[data-testid="from-date-input"]', '2024-01-01');

    // Enter end date in the 'To Date' field using date picker
    await page.click('[data-testid="to-date-picker"]');
    await page.fill('[data-testid="to-date-input"]', '2024-12-31');

    // Click 'Apply Filters' button
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForLoadState('networkidle');

    // Verify the displayed logs contain only records for the selected task within the specified date range
    const logRows = page.locator('[data-testid="audit-log-row"]');
    await expect(logRows).toHaveCountGreaterThan(0);
    const firstLog = logRows.first();
    await expect(firstLog).toBeVisible();
    await expect(firstLog.locator('[data-testid="log-task-name"]')).toBeVisible();
    await expect(firstLog.locator('[data-testid="log-timestamp"]')).toBeVisible();

    // Click 'Export' button to download the filtered logs
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    const download = await downloadPromise;
    await expect(download.suggestedFilename()).toContain('.csv');

    // Open the downloaded CSV file
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();
    const fileContent = fs.readFileSync(downloadPath!, 'utf-8');
    expect(fileContent).toContain('Task');
    expect(fileContent).toContain('Timestamp');
    expect(fileContent).toContain('User');
  });

  test('Verify audit logs record all task changes (happy-path)', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the task management interface
    await page.click('[data-testid="tasks-menu"]');
    await expect(page).toHaveURL(/.*tasks/);

    // Select a task and reassign it to a different team member
    await page.click('[data-testid="task-item-1"]');
    await page.click('[data-testid="reassign-button"]');
    await page.click('[data-testid="assignee-dropdown"]');
    await page.click('[data-testid="assignee-option-2"]');
    await page.click('[data-testid="save-assignment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Assignment updated');

    // Modify the deadline of the same task to a new date
    await page.click('[data-testid="edit-deadline-button"]');
    await page.fill('[data-testid="deadline-input"]', '2024-12-31');
    await page.click('[data-testid="save-deadline-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Deadline updated');

    // Change the priority of the same task from current priority to a different priority level
    await page.click('[data-testid="edit-priority-button"]');
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-high"]');
    await page.click('[data-testid="save-priority-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Priority updated');

    // Navigate to the audit log interface
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page).toHaveURL(/.*audit-logs/);

    // Filter audit logs by the modified task ID or name
    await page.click('[data-testid="task-filter-dropdown"]');
    await page.click('[data-testid="task-option-1"]');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForLoadState('networkidle');

    // Verify that the assignment change is recorded in the audit logs
    const assignmentLog = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'Assignment' });
    await expect(assignmentLog).toBeVisible();
    await expect(assignmentLog.locator('[data-testid="log-change-type"]')).toContainText('Assignment');

    // Verify that the deadline change is recorded in the audit logs
    const deadlineLog = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'Deadline' });
    await expect(deadlineLog).toBeVisible();
    await expect(deadlineLog.locator('[data-testid="log-change-type"]')).toContainText('Deadline');

    // Verify that the priority change is recorded in the audit logs
    const priorityLog = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'Priority' });
    await expect(priorityLog).toBeVisible();
    await expect(priorityLog.locator('[data-testid="log-change-type"]')).toContainText('Priority');

    // Check the timestamps for all three log entries
    const allLogs = page.locator('[data-testid="audit-log-row"]');
    const logCount = await allLogs.count();
    expect(logCount).toBeGreaterThanOrEqual(3);
    
    for (let i = 0; i < Math.min(3, logCount); i++) {
      const timestamp = allLogs.nth(i).locator('[data-testid="log-timestamp"]');
      await expect(timestamp).toBeVisible();
      const timestampText = await timestamp.textContent();
      expect(timestampText).toBeTruthy();
      expect(timestampText).toMatch(/\d{4}-\d{2}-\d{2}/);
    }

    // Check the user information for all three log entries
    for (let i = 0; i < Math.min(3, logCount); i++) {
      const userInfo = allLogs.nth(i).locator('[data-testid="log-user-info"]');
      await expect(userInfo).toBeVisible();
      const userText = await userInfo.textContent();
      expect(userText).toBeTruthy();
      expect(userText).toContain(MANAGER_EMAIL.split('@')[0]);
    }
  });

  test('Ensure audit log access is restricted (error-case)', async ({ page, request }) => {
    // Log in to the system using unauthorized user credentials (e.g., team member or developer role)
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to the audit log interface by entering the audit log URL directly or clicking the menu option if visible
    const auditLogsMenuVisible = await page.locator('[data-testid="audit-logs-menu"]').isVisible().catch(() => false);
    
    if (auditLogsMenuVisible) {
      await page.click('[data-testid="audit-logs-menu"]');
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    } else {
      // Try direct URL navigation
      await page.goto(`${BASE_URL}/audit-logs`);
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    }

    // Attempt to access audit logs via API endpoint GET /api/tasks/auditlogs using unauthorized user token
    const unauthorizedToken = await page.evaluate(() => localStorage.getItem('authToken'));
    const unauthorizedResponse = await request.get(`${BASE_URL}/api/tasks/auditlogs`, {
      headers: {
        'Authorization': `Bearer ${unauthorizedToken}`
      }
    });
    expect(unauthorizedResponse.status()).toBe(403);
    const unauthorizedBody = await unauthorizedResponse.json();
    expect(unauthorizedBody.error || unauthorizedBody.message).toMatch(/forbidden|unauthorized|access denied/i);

    // Log out from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in to the system using authorized manager credentials
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the audit log interface by clicking on 'Audit Logs' menu option
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page).toHaveURL(/.*audit-logs/);

    // Verify that audit logs are visible and contain task change records
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();
    const logRows = page.locator('[data-testid="audit-log-row"]');
    await expect(logRows.first()).toBeVisible();
    const logCount = await logRows.count();
    expect(logCount).toBeGreaterThan(0);

    // Access audit logs via API endpoint GET /api/tasks/auditlogs using authorized manager token
    const authorizedToken = await page.evaluate(() => localStorage.getItem('authToken'));
    const authorizedResponse = await request.get(`${BASE_URL}/api/tasks/auditlogs`, {
      headers: {
        'Authorization': `Bearer ${authorizedToken}`
      }
    });
    expect(authorizedResponse.status()).toBe(200);
    const authorizedBody = await authorizedResponse.json();
    expect(Array.isArray(authorizedBody) || Array.isArray(authorizedBody.data)).toBeTruthy();
    const logs = Array.isArray(authorizedBody) ? authorizedBody : authorizedBody.data;
    expect(logs.length).toBeGreaterThan(0);
    expect(logs[0]).toHaveProperty('timestamp');
    expect(logs[0]).toHaveProperty('user');
  });
});