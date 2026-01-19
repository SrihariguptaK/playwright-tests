import { test, expect } from '@playwright/test';

test.describe('Task Assignment Confirmation - Story 14', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate confirmation message after successful task assignment', async ({ page }) => {
    // Navigate to task creation/assignment page
    await page.goto('/tasks/create');
    await expect(page.locator('[data-testid="task-form"]')).toBeVisible();

    // Fill in all mandatory fields
    await page.fill('[data-testid="task-title-input"]', 'Prepare Monthly Report');
    await page.fill('[data-testid="task-description-input"]', 'Compile and analyze monthly performance metrics');
    
    // Set deadline to 5 days from today
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 5);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', formattedDate);
    
    // Set priority
    await page.selectOption('[data-testid="task-priority-select"]', 'High');
    
    // Select at least one employee
    await page.click('[data-testid="employee-select"]');
    await page.click('[data-testid="employee-option-1"]');

    // Submit the valid task assignment form
    await page.click('[data-testid="submit-task-button"]');

    // Action: Review confirmation message content | Expected Result: Confirmation message is displayed with task details
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible({ timeout: 2000 });
    const confirmationMessage = page.locator('[data-testid="confirmation-message"]');
    await expect(confirmationMessage).toContainText('successfully assigned');

    // Expected Result: Message includes task title, deadline, priority, and assigned employees
    await expect(confirmationMessage).toContainText('Prepare Monthly Report');
    await expect(confirmationMessage).toContainText(formattedDate);
    await expect(confirmationMessage).toContainText('High');
    await expect(confirmationMessage).toContainText('employee');

    // Verify the confirmation message format and clarity
    const messageText = await confirmationMessage.textContent();
    expect(messageText).toBeTruthy();
    expect(messageText!.length).toBeGreaterThan(20);

    // Navigate to task history log or audit trail section
    await page.click('[data-testid="task-history-link"]');
    await expect(page).toHaveURL(/.*tasks\/history/);

    // Search or filter for the recently created task in the task history log
    await page.fill('[data-testid="task-history-search"]', 'Prepare Monthly Report');
    await page.click('[data-testid="search-button"]');

    // Action: Check task history log | Expected Result: Confirmation message is recorded and accessible
    const historyEntry = page.locator('[data-testid="task-history-entry"]').first();
    await expect(historyEntry).toBeVisible();
    await expect(historyEntry).toContainText('Prepare Monthly Report');
    await expect(historyEntry).toContainText('assigned');

    // Verify the timestamp of the confirmation log entry
    const timestamp = historyEntry.locator('[data-testid="task-timestamp"]');
    await expect(timestamp).toBeVisible();
    const timestampText = await timestamp.textContent();
    expect(timestampText).toBeTruthy();
  });

  test('Verify error message display on assignment failure', async ({ page }) => {
    // Navigate to task creation/assignment page
    await page.goto('/tasks/create');
    await expect(page.locator('[data-testid="task-form"]')).toBeVisible();

    // Fill in the task assignment form with invalid data (past deadline date)
    await page.fill('[data-testid="task-title-input"]', 'Invalid Task');
    await page.fill('[data-testid="task-description-input"]', 'This task has invalid data');
    
    // Set deadline to past date
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 5);
    const pastFormattedDate = pastDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', pastFormattedDate);
    
    // Leave priority empty or select invalid option
    // Leave employee selection empty

    // Action: Submit task assignment form with invalid data | Expected Result: Error message is displayed indicating failure reason
    await page.click('[data-testid="submit-task-button"]');

    // Observe the system response after submission attempt
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible({ timeout: 2000 });
    const errorMessage = page.locator('[data-testid="error-message"]');
    
    // Review the error message content and formatting
    await expect(errorMessage).toContainText('error');
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText!.toLowerCase()).toMatch(/deadline|employee|required|invalid/);

    // Verify that no task was created in the system
    await page.goto('/tasks');
    await page.fill('[data-testid="task-search-input"]', 'Invalid Task');
    await page.click('[data-testid="search-button"]');
    const noResultsMessage = page.locator('[data-testid="no-results-message"]');
    await expect(noResultsMessage).toBeVisible();

    // Correct the invalid data based on the error message guidance
    await page.goto('/tasks/create');
    await page.fill('[data-testid="task-title-input"]', 'Corrected Valid Task');
    await page.fill('[data-testid="task-description-input"]', 'This task has valid corrected data');
    
    // Select a future deadline date
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const futureFormattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', futureFormattedDate);
    
    // Set valid priority
    await page.selectOption('[data-testid="task-priority-select"]', 'Medium');
    
    // Select a valid employee
    await page.click('[data-testid="employee-select"]');
    await page.click('[data-testid="employee-option-1"]');

    // Action: Attempt to resubmit after correction | Expected Result: Submission succeeds and confirmation message is displayed
    await page.click('[data-testid="submit-task-button"]');

    // Verify the response after successful resubmission
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible({ timeout: 2000 });
    const confirmationMessage = page.locator('[data-testid="confirmation-message"]');
    await expect(confirmationMessage).toContainText('successfully assigned');
    await expect(confirmationMessage).toContainText('Corrected Valid Task');

    // Verify the task now appears in the manager's task list
    await page.goto('/tasks');
    await page.fill('[data-testid="task-search-input"]', 'Corrected Valid Task');
    await page.click('[data-testid="search-button"]');
    
    const taskListItem = page.locator('[data-testid="task-list-item"]').first();
    await expect(taskListItem).toBeVisible();
    await expect(taskListItem).toContainText('Corrected Valid Task');
    await expect(taskListItem).toContainText('Medium');
  });
});