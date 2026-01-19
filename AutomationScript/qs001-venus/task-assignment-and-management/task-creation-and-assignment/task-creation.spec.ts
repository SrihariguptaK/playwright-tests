import { test, expect } from '@playwright/test';

test.describe('Task Creation - Story 11', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'managerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful task creation with valid input', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.click('[data-testid="create-task-button"]');
    await expect(page).toHaveURL(/.*tasks\/create/);
    await expect(page.locator('[data-testid="task-creation-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-title-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-description-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-deadline-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-priority-select"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-selection-list"]')).toBeVisible();

    // Step 2: Enter valid task title, description, deadline, priority, and select employees
    await page.fill('[data-testid="task-title-input"]', 'Complete Q4 Financial Report');
    await expect(page.locator('[data-testid="task-title-input"]')).toHaveValue('Complete Q4 Financial Report');
    
    await page.fill('[data-testid="task-description-input"]', 'Prepare comprehensive financial report for Q4 including revenue, expenses, and projections');
    await expect(page.locator('[data-testid="task-description-input"]')).toHaveValue('Prepare comprehensive financial report for Q4 including revenue, expenses, and projections');
    
    // Set deadline to 7 days from now
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', formattedDate);
    await expect(page.locator('[data-testid="task-deadline-input"]')).toHaveValue(formattedDate);
    
    await page.selectOption('[data-testid="task-priority-select"]', 'High');
    await expect(page.locator('[data-testid="task-priority-select"]')).toHaveValue('High');
    
    await page.click('[data-testid="employee-checkbox-1"]');
    await expect(page.locator('[data-testid="employee-checkbox-1"]')).toBeChecked();
    
    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 3: Submit the task creation form
    await page.click('[data-testid="submit-task-button"]');
    
    // Verify confirmation message
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Task created successfully');
    
    // Verify notification sent message
    await expect(page.locator('[data-testid="notification-status"]')).toContainText('Notifications sent to assigned employees');
    
    // Navigate to manager's task list view
    await page.click('[data-testid="task-list-link"]');
    await expect(page).toHaveURL(/.*tasks/);
    
    // Verify task appears in the list
    await expect(page.locator('[data-testid="task-item"]').filter({ hasText: 'Complete Q4 Financial Report' })).toBeVisible();
  });

  test('Verify rejection of task creation with missing mandatory fields', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.click('[data-testid="create-task-button"]');
    await expect(page).toHaveURL(/.*tasks\/create/);
    await expect(page.locator('[data-testid="task-creation-form"]')).toBeVisible();

    // Step 2: Leave task title and deadline empty
    // Optionally enter description and select priority
    await page.fill('[data-testid="task-description-input"]', 'Some description');
    await page.selectOption('[data-testid="task-priority-select"]', 'Medium');
    
    // Trigger real-time validation by clicking outside or tabbing through
    await page.click('[data-testid="task-title-input"]');
    await page.click('[data-testid="task-description-input"]');
    
    // Verify real-time validation highlights missing fields
    await expect(page.locator('[data-testid="task-title-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-title-error"]')).toContainText('Task title is required');
    
    await page.click('[data-testid="task-deadline-input"]');
    await page.click('[data-testid="task-description-input"]');
    await expect(page.locator('[data-testid="task-deadline-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-deadline-error"]')).toContainText('Deadline is required');

    // Step 3: Attempt to submit the form
    await page.click('[data-testid="submit-task-button"]');
    
    // Verify submission is blocked and inline error messages displayed
    await expect(page.locator('[data-testid="task-title-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-title-error"]')).toContainText('Task title is required');
    await expect(page.locator('[data-testid="task-deadline-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-deadline-error"]')).toContainText('Deadline is required');
    
    // Verify still on task creation page (submission blocked)
    await expect(page).toHaveURL(/.*tasks\/create/);
    
    // Verify no confirmation message appears
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
    
    // Verify no task is created by navigating to task list
    await page.goto('/tasks');
    await expect(page.locator('[data-testid="task-item"]').filter({ hasText: 'Some description' })).not.toBeVisible();
  });

  test('Ensure system handles assignment to multiple employees', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.click('[data-testid="create-task-button"]');
    await expect(page).toHaveURL(/.*tasks\/create/);

    // Step 2: Enter valid task details
    await page.fill('[data-testid="task-title-input"]', 'Team Project Kickoff Meeting');
    await page.fill('[data-testid="task-description-input"]', 'Attend kickoff meeting for new project initiative');
    
    // Set deadline to 3 days from now
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 3);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', formattedDate);
    
    await page.selectOption('[data-testid="task-priority-select"]', 'Medium');
    
    // Step 3: Select multiple employees (3 different employees)
    await page.click('[data-testid="employee-checkbox-1"]');
    await page.click('[data-testid="employee-checkbox-2"]');
    await page.click('[data-testid="employee-checkbox-3"]');
    
    await expect(page.locator('[data-testid="employee-checkbox-1"]')).toBeChecked();
    await expect(page.locator('[data-testid="employee-checkbox-2"]')).toBeChecked();
    await expect(page.locator('[data-testid="employee-checkbox-3"]')).toBeChecked();
    
    // Verify selected count
    await expect(page.locator('[data-testid="selected-employees-count"]')).toContainText('3');

    // Step 4: Submit the task creation form
    await page.click('[data-testid="submit-task-button"]');
    
    // Verify task is created successfully
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Task created successfully');
    
    // Step 5: Verify notifications sent to each assigned employee
    await expect(page.locator('[data-testid="notification-status"]')).toContainText('Notifications sent to 3 employees');
    
    // Check notification logs or details
    await page.click('[data-testid="view-notification-details"]');
    await expect(page.locator('[data-testid="notification-recipient"]').nth(0)).toBeVisible();
    await expect(page.locator('[data-testid="notification-recipient"]').nth(1)).toBeVisible();
    await expect(page.locator('[data-testid="notification-recipient"]').nth(2)).toBeVisible();
    await page.click('[data-testid="close-notification-details"]');

    // Step 6: Navigate to manager's task list view
    await page.click('[data-testid="task-list-link"]');
    await expect(page).toHaveURL(/.*tasks/);
    
    // Verify task appears in the list
    const taskItem = page.locator('[data-testid="task-item"]').filter({ hasText: 'Team Project Kickoff Meeting' });
    await expect(taskItem).toBeVisible();
    
    // Step 7: Click on or expand the task to view assignment details
    await taskItem.click();
    await expect(page.locator('[data-testid="task-details-panel"]')).toBeVisible();
    
    // Verify assignment details show 3 employees
    await expect(page.locator('[data-testid="assigned-employees-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="assigned-employee-item"]')).toHaveCount(3);
    
    // Verify correct assignment details
    await expect(page.locator('[data-testid="task-details-title"]')).toContainText('Team Project Kickoff Meeting');
    await expect(page.locator('[data-testid="task-details-description"]')).toContainText('Attend kickoff meeting for new project initiative');
    await expect(page.locator('[data-testid="task-details-priority"]')).toContainText('Medium');
  });
});