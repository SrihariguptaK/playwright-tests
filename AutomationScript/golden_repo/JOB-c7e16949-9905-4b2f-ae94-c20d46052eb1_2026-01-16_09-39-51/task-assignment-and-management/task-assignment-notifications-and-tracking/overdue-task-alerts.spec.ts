import { test, expect } from '@playwright/test';

test.describe('Overdue Task Alerts Management', () => {
  let managerEmail: string;
  let managerPassword: string;
  let testTaskId: string;

  test.beforeEach(async ({ page }) => {
    // Setup test data
    managerEmail = 'manager@example.com';
    managerPassword = 'Manager123!';
    
    // Login as manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate alert generation for overdue tasks', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.goto('/tasks/create');
    await expect(page.locator('[data-testid="task-form"]')).toBeVisible();

    // Step 2: Create task with deadline in the past
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayFormatted = yesterday.toISOString().split('T')[0];

    await page.fill('[data-testid="task-title-input"]', 'Test Overdue Task');
    await page.click('[data-testid="employee-select"]');
    await page.click('[data-testid="employee-option-1"]');
    await page.fill('[data-testid="task-deadline-input"]', yesterdayFormatted);
    await page.selectOption('[data-testid="task-status-select"]', 'In Progress');

    // Step 3: Save the task
    await page.click('[data-testid="save-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 4: Note task ID for reference
    const taskIdElement = await page.locator('[data-testid="created-task-id"]');
    testTaskId = await taskIdElement.textContent() || '';

    // Step 5: Verify task is marked as overdue
    await page.goto('/tasks');
    const overdueTask = page.locator(`[data-testid="task-${testTaskId}"]`);
    await expect(overdueTask).toBeVisible();
    await expect(overdueTask.locator('[data-testid="overdue-badge"]')).toBeVisible();
    await expect(overdueTask.locator('[data-testid="overdue-badge"]')).toHaveText('Overdue');

    // Step 6: Wait for alert generation cycle (maximum 1 minute)
    await page.waitForTimeout(60000);

    // Step 7: Navigate to manager dashboard
    await page.goto('/dashboard');
    await expect(page.locator('[data-testid="manager-dashboard"]')).toBeVisible();

    // Step 8: Verify alert appears in dashboard
    const alertsSection = page.locator('[data-testid="alerts-section"]');
    await expect(alertsSection).toBeVisible();
    
    const overdueAlert = alertsSection.locator(`[data-testid="alert-task-${testTaskId}"]`);
    await expect(overdueAlert).toBeVisible();
    await expect(overdueAlert).toContainText('Test Overdue Task');
    await expect(overdueAlert).toContainText('overdue');

    // Step 9: Check manager email inbox
    await page.goto('/email-inbox');
    await expect(page.locator('[data-testid="email-inbox"]')).toBeVisible();

    // Step 10: Verify email notification received
    const emailNotification = page.locator('[data-testid="email-list"]').locator('text=Overdue Task Alert');
    await expect(emailNotification).toBeVisible();
    
    await emailNotification.click();
    const emailContent = page.locator('[data-testid="email-content"]');
    await expect(emailContent).toContainText('Test Overdue Task');
    await expect(emailContent).toContainText(testTaskId);
    await expect(emailContent).toContainText('overdue');
  });

  test('Verify alert dismissal functionality', async ({ page }) => {
    // Setup: Create an overdue task first
    await page.goto('/tasks/create');
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayFormatted = yesterday.toISOString().split('T')[0];

    await page.fill('[data-testid="task-title-input"]', 'Test Alert Dismissal Task');
    await page.click('[data-testid="employee-select"]');
    await page.click('[data-testid="employee-option-1"]');
    await page.fill('[data-testid="task-deadline-input"]', yesterdayFormatted);
    await page.selectOption('[data-testid="task-status-select"]', 'In Progress');
    await page.click('[data-testid="save-task-button"]');
    
    const taskIdElement = await page.locator('[data-testid="created-task-id"]');
    testTaskId = await taskIdElement.textContent() || '';

    // Wait for alert generation
    await page.waitForTimeout(60000);

    // Step 1: Navigate to manager dashboard
    await page.goto('/dashboard');
    await expect(page.locator('[data-testid="manager-dashboard"]')).toBeVisible();

    // Step 2: Locate alerts section
    const alertsSection = page.locator('[data-testid="alerts-section"]');
    await expect(alertsSection).toBeVisible();

    // Step 3: Identify specific overdue task alert
    const overdueAlert = alertsSection.locator(`[data-testid="alert-task-${testTaskId}"]`);
    await expect(overdueAlert).toBeVisible();

    // Step 4: Read alert content and note task details
    const alertContent = await overdueAlert.textContent();
    expect(alertContent).toContain('Test Alert Dismissal Task');
    expect(alertContent).toContain(testTaskId);

    // Step 5: Locate dismiss button
    const dismissButton = overdueAlert.locator('[data-testid="dismiss-alert-button"]');
    await expect(dismissButton).toBeVisible();

    // Step 6: Click dismiss button
    await dismissButton.click();

    // Step 7: Verify alert is removed immediately
    await expect(overdueAlert).not.toBeVisible();

    // Step 8: Refresh dashboard to confirm persistence
    await page.reload();
    await expect(page.locator('[data-testid="manager-dashboard"]')).toBeVisible();
    
    const alertsSectionAfterRefresh = page.locator('[data-testid="alerts-section"]');
    const dismissedAlert = alertsSectionAfterRefresh.locator(`[data-testid="alert-task-${testTaskId}"]`);
    await expect(dismissedAlert).not.toBeVisible();

    // Step 9: Verify underlying task still exists
    await page.goto('/tasks');
    const taskList = page.locator('[data-testid="task-list"]');
    await expect(taskList).toBeVisible();
    
    const existingTask = taskList.locator(`[data-testid="task-${testTaskId}"]`);
    await expect(existingTask).toBeVisible();
    await expect(existingTask).toContainText('Test Alert Dismissal Task');
    await expect(existingTask.locator('[data-testid="overdue-badge"]')).toBeVisible();
  });
});