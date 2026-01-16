import { test, expect } from '@playwright/test';

test.describe('Task Creation with Detailed Descriptions', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to the application and ensure manager is logged in
    await page.goto(BASE_URL);
    // Assuming authentication is handled via session or pre-configured
  });

  test('Validate successful task creation with description', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.click('button:has-text("Create Task"), a:has-text("Create Task")');
    
    // Expected Result: Task creation form is displayed with description input
    await expect(page.locator('[data-testid="task-title-input"], input[name="title"], input[placeholder*="title" i]')).toBeVisible();
    await expect(page.locator('[data-testid="task-description-input"], textarea[name="description"], textarea[placeholder*="description" i]')).toBeVisible();

    // Step 2: Enter valid task title and description
    const taskTitle = 'Quarterly Report Preparation';
    const taskDescription = 'Prepare comprehensive quarterly financial report including revenue analysis, expense breakdown, and forecasts for Q1 2024';
    
    await page.fill('[data-testid="task-title-input"], input[name="title"], input[placeholder*="title" i]', taskTitle);
    await page.fill('[data-testid="task-description-input"], textarea[name="description"], textarea[placeholder*="description" i]', taskDescription);
    
    // Expected Result: Inputs accepted without validation errors
    await expect(page.locator('.error, [data-testid="error-message"], .validation-error')).toHaveCount(0);

    // Step 3: Submit the task creation form
    await page.click('button[type="submit"], button:has-text("Submit"), button:has-text("Create Task")');
    
    // Expected Result: Task is saved and confirmation message is displayed
    await expect(page.locator('[data-testid="success-message"], .success-message, .confirmation-message')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="success-message"], .success-message, .confirmation-message')).toContainText(/success|created|saved/i);
  });

  test('Reject task creation with empty description', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.click('button:has-text("Create Task"), a:has-text("Create Task")');
    
    // Expected Result: Task creation form is displayed
    await expect(page.locator('[data-testid="task-creation-form"], form')).toBeVisible();

    // Step 2: Enter task title but leave description empty
    const taskTitle = 'Monthly Review Meeting';
    
    await page.fill('[data-testid="task-title-input"], input[name="title"], input[placeholder*="title" i]', taskTitle);
    await page.fill('[data-testid="task-description-input"], textarea[name="description"], textarea[placeholder*="description" i]', '');
    
    // Expected Result: Validation error displayed for description field
    // Step 3: Attempt to submit the form
    await page.click('button[type="submit"], button:has-text("Submit"), button:has-text("Create Task")');
    
    // Expected Result: Submission blocked and error message shown
    await expect(page.locator('[data-testid="description-error"], .error, .validation-error, [role="alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="description-error"], .error, .validation-error, [role="alert"]')).toContainText(/description.*required|required.*description|empty|cannot be blank/i);
    
    // Verify task was not created by checking we're still on the creation page
    await expect(page.locator('[data-testid="task-creation-form"], form')).toBeVisible();
  });

  test('Ensure task creation response time is within SLA', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.click('button:has-text("Create Task"), a:has-text("Create Task")');
    await expect(page.locator('[data-testid="task-creation-form"], form')).toBeVisible();

    // Prepare task data
    const taskTitle = 'System Performance Test Task';
    const taskDescription = 'This task is created to validate system performance and response time requirements for task creation operations';
    
    await page.fill('[data-testid="task-title-input"], input[name="title"], input[placeholder*="title" i]', taskTitle);
    await page.fill('[data-testid="task-description-input"], textarea[name="description"], textarea[placeholder*="description" i]', taskDescription);

    // Step 1: Submit valid task creation request and measure response time
    const startTime = Date.now();
    await page.click('button[type="submit"], button:has-text("Submit"), button:has-text("Create Task")');
    
    // Wait for confirmation message
    await page.waitForSelector('[data-testid="success-message"], .success-message, .confirmation-message', { timeout: 3000 });
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    // Expected Result: Response received within 2 seconds
    expect(responseTime).toBeLessThan(2000);

    // Step 2: Verify task saved in database by navigating to task list
    await page.click('a:has-text("Tasks"), a:has-text("Task List"), button:has-text("View Tasks")');
    
    // Expected Result: Task record exists with correct description
    await expect(page.locator(`text=${taskTitle}`).first()).toBeVisible({ timeout: 3000 });
    
    // Click on the task to view details and verify description
    await page.click(`text=${taskTitle}`);
    await expect(page.locator('text=' + taskDescription)).toBeVisible();

    // Step 3: Check confirmation message display
    // Navigate back to verify confirmation was shown (already validated above)
    // Expected Result: Confirmation message shown to user (already validated)
  });
});