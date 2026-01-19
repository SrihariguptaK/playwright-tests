import { test, expect } from '@playwright/test';

test.describe('Task Acknowledgment - Story 17', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const employeeEmail = 'employee@company.com';
  const employeePassword = 'Employee123!';
  const managerEmail = 'manager@company.com';
  const managerPassword = 'Manager123!';
  const testTaskId = 'TASK-001';

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate employee can acknowledge assigned task', async ({ page, context }) => {
    // Step 1: Employee opens assigned task details
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to task list
    await page.click('[data-testid="tasks-menu"]');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Open assigned task details
    await page.click(`[data-testid="task-item-${testTaskId}"]`);
    
    // Expected Result: Task details page is displayed with acknowledge button
    await expect(page.locator('[data-testid="task-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledge-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledge-button"]')).toBeEnabled();
    
    // Step 2: Employee clicks acknowledge button
    const startTime = Date.now();
    await page.click('[data-testid="acknowledge-button"]');
    const endTime = Date.now();
    const processingTime = endTime - startTime;
    
    // Expected Result: Acknowledgment status is updated and confirmation displayed
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toContainText('Task acknowledged successfully');
    await expect(page.locator('[data-testid="task-status"]')).toContainText('Acknowledged');
    
    // Verify acknowledgment processing time is under 2 seconds
    expect(processingTime).toBeLessThan(2000);
    
    // Logout employee
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 3: Manager views acknowledgment status
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to task management
    await page.click('[data-testid="task-management-menu"]');
    await expect(page.locator('[data-testid="task-management-page"]')).toBeVisible();
    
    // View acknowledgment status for the task
    await page.click(`[data-testid="task-row-${testTaskId}"]`);
    
    // Expected Result: Acknowledgment is reflected accurately in manager's view
    await expect(page.locator('[data-testid="task-acknowledgment-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-acknowledgment-status"]')).toContainText('Acknowledged');
    await expect(page.locator('[data-testid="acknowledged-by"]')).toContainText(employeeEmail);
    await expect(page.locator('[data-testid="acknowledgment-timestamp"]')).toBeVisible();
  });

  test('Verify system prevents multiple acknowledgments', async ({ page }) => {
    // Step 1: Employee acknowledges a task
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to task list
    await page.click('[data-testid="tasks-menu"]');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Open assigned task
    await page.click(`[data-testid="task-item-${testTaskId}"]`);
    await expect(page.locator('[data-testid="task-details-page"]')).toBeVisible();
    
    // Click acknowledge button for the first time
    await page.click('[data-testid="acknowledge-button"]');
    
    // Expected Result: Acknowledgment is recorded
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="task-status"]')).toContainText('Acknowledged');
    
    // Wait for confirmation to disappear or close it
    await page.waitForTimeout(1000);
    
    // Step 2: Employee attempts to acknowledge the same task again
    // Refresh the task details page
    await page.reload();
    await expect(page.locator('[data-testid="task-details-page"]')).toBeVisible();
    
    // Verify acknowledge button is disabled or not visible
    const acknowledgeButton = page.locator('[data-testid="acknowledge-button"]');
    const isButtonVisible = await acknowledgeButton.isVisible().catch(() => false);
    
    if (isButtonVisible) {
      const isButtonEnabled = await acknowledgeButton.isEnabled();
      expect(isButtonEnabled).toBe(false);
    }
    
    // Verify status shows already acknowledged
    await expect(page.locator('[data-testid="task-status"]')).toContainText('Acknowledged');
    
    // Alternative: Try to click if button exists and verify error message
    if (isButtonVisible) {
      await acknowledgeButton.click({ force: true }).catch(() => {});
      
      // Expected Result: System prevents duplicate acknowledgment and displays message
      const errorMessage = page.locator('[data-testid="error-message"]');
      const duplicateMessage = page.locator('[data-testid="duplicate-acknowledgment-message"]');
      
      const hasError = await errorMessage.isVisible().catch(() => false);
      const hasDuplicateMsg = await duplicateMessage.isVisible().catch(() => false);
      
      if (hasError) {
        await expect(errorMessage).toContainText(/already acknowledged|duplicate/i);
      } else if (hasDuplicateMsg) {
        await expect(duplicateMessage).toContainText(/already acknowledged|cannot acknowledge again/i);
      }
    }
    
    // Verify task status remains acknowledged (no duplicate entry)
    await expect(page.locator('[data-testid="task-status"]')).toContainText('Acknowledged');
    
    // Verify acknowledgment count is 1 (not duplicated)
    const acknowledgmentCount = page.locator('[data-testid="acknowledgment-count"]');
    if (await acknowledgmentCount.isVisible().catch(() => false)) {
      await expect(acknowledgmentCount).toContainText('1');
    }
  });

  test('Validate employee can acknowledge assigned task - happy path', async ({ page, context }) => {
    // Employee navigates to their task list or notifications section
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to notifications or task list
    const notificationsButton = page.locator('[data-testid="notifications-button"]');
    const tasksMenu = page.locator('[data-testid="tasks-menu"]');
    
    if (await notificationsButton.isVisible().catch(() => false)) {
      await notificationsButton.click();
      await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    } else {
      await tasksMenu.click();
      await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    }
    
    // Employee selects and opens the assigned task details
    await page.click(`[data-testid="task-item-${testTaskId}"]`);
    await expect(page.locator('[data-testid="task-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-description"]')).toBeVisible();
    
    // Employee clicks the 'Acknowledge' button
    const acknowledgeButton = page.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeButton).toBeVisible();
    await expect(acknowledgeButton).toBeEnabled();
    
    const startTime = Date.now();
    await acknowledgeButton.click();
    
    // Verify acknowledgment processing time
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toBeVisible({ timeout: 2000 });
    const endTime = Date.now();
    const processingTime = endTime - startTime;
    
    expect(processingTime).toBeLessThan(2000);
    
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toContainText(/acknowledged|confirmed/i);
    await expect(page.locator('[data-testid="task-status"]')).toContainText('Acknowledged');
    
    // Logout employee
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();
    
    // Manager logs into the system and navigates to task management or team dashboard
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to task management or team dashboard
    const taskManagementMenu = page.locator('[data-testid="task-management-menu"]');
    const teamDashboardMenu = page.locator('[data-testid="team-dashboard-menu"]');
    
    if (await taskManagementMenu.isVisible().catch(() => false)) {
      await taskManagementMenu.click();
    } else {
      await teamDashboardMenu.click();
    }
    
    // Manager views the acknowledgment status for the task acknowledged by the employee
    await page.click(`[data-testid="task-row-${testTaskId}"]`);
    
    await expect(page.locator('[data-testid="task-acknowledgment-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-acknowledgment-status"]')).toContainText('Acknowledged');
    await expect(page.locator('[data-testid="acknowledged-by"]')).toContainText(employeeEmail);
    await expect(page.locator('[data-testid="acknowledgment-timestamp"]')).toBeVisible();
    
    const timestamp = await page.locator('[data-testid="acknowledgment-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
  });

  test('Verify system prevents multiple acknowledgments - error case', async ({ page }) => {
    // Employee navigates to their task list and opens an assigned task
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    await page.click('[data-testid="tasks-menu"]');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    await page.click(`[data-testid="task-item-${testTaskId}"]`);
    await expect(page.locator('[data-testid="task-details-page"]')).toBeVisible();
    
    // Employee clicks the 'Acknowledge' button for the first time
    const acknowledgeButton = page.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeButton).toBeVisible();
    await acknowledgeButton.click();
    
    // Verify acknowledgment is stored in the system
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="task-status"]')).toContainText('Acknowledged');
    
    // Wait for state to persist
    await page.waitForTimeout(1000);
    
    // Employee refreshes the task details page or navigates away and returns to the same task
    await page.click('[data-testid="tasks-menu"]');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    await page.click(`[data-testid="task-item-${testTaskId}"]`);
    await expect(page.locator('[data-testid="task-details-page"]')).toBeVisible();
    
    // Employee attempts to acknowledge the same task again by clicking the acknowledge button or attempting any workaround
    const acknowledgeButtonAfterRefresh = page.locator('[data-testid="acknowledge-button"]');
    
    // Check if button is disabled or hidden
    const isVisible = await acknowledgeButtonAfterRefresh.isVisible().catch(() => false);
    
    if (isVisible) {
      const isEnabled = await acknowledgeButtonAfterRefresh.isEnabled();
      
      if (isEnabled) {
        // Attempt to click and verify error
        await acknowledgeButtonAfterRefresh.click();
        
        const errorMessage = page.locator('[data-testid="error-message"]');
        const duplicateMessage = page.locator('[data-testid="duplicate-acknowledgment-message"]');
        
        const hasError = await errorMessage.isVisible({ timeout: 2000 }).catch(() => false);
        const hasDuplicate = await duplicateMessage.isVisible({ timeout: 2000 }).catch(() => false);
        
        expect(hasError || hasDuplicate).toBe(true);
        
        if (hasError) {
          await expect(errorMessage).toContainText(/already acknowledged|duplicate|cannot acknowledge/i);
        }
        if (hasDuplicate) {
          await expect(duplicateMessage).toContainText(/already acknowledged|duplicate|cannot acknowledge/i);
        }
      } else {
        // Button is disabled, which is correct behavior
        expect(isEnabled).toBe(false);
      }
    }
    
    // Verify database records for the task acknowledgment (via UI verification)
    await expect(page.locator('[data-testid="task-status"]')).toContainText('Acknowledged');
    
    // Verify only one acknowledgment exists
    const acknowledgmentTimestamp = page.locator('[data-testid="acknowledgment-timestamp"]');
    if (await acknowledgmentTimestamp.isVisible().catch(() => false)) {
      const timestampCount = await acknowledgmentTimestamp.count();
      expect(timestampCount).toBe(1);
    }
  });
});