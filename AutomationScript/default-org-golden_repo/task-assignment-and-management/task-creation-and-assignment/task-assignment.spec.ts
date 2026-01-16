import { test, expect } from '@playwright/test';

test.describe('Task Assignment - Manager assigns tasks to employees', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'manager123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Assign task to active employee successfully', async ({ page }) => {
    // Step 1: Navigate to task assignment page
    await page.goto('/tasks');
    await page.click('[data-testid="task-item"]:first-child');
    await page.click('[data-testid="assign-task-button"]');
    
    // Verify assignment form displayed with active employee list
    await expect(page.locator('[data-testid="assignment-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-dropdown"]')).toBeVisible();
    
    // Step 2: Select an active employee and assign task
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option"][data-employee-name="John Smith"]');
    
    // Verify assignment accepted without errors
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    const selectedEmployee = await page.locator('[data-testid="employee-dropdown"]').textContent();
    expect(selectedEmployee).toContain('John Smith');
    
    // Step 3: Submit assignment
    await page.click('[data-testid="submit-assignment-button"]');
    
    // Verify confirmation message displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Task assigned successfully');
    
    // Verify assignment saved by checking task details
    await page.goto('/tasks');
    await page.click('[data-testid="task-item"]:first-child');
    await expect(page.locator('[data-testid="assigned-employee"]')).toContainText('John Smith');
  });

  test('Prevent assignment to inactive employee', async ({ page }) => {
    // Step 1: Navigate to task assignment page
    await page.goto('/tasks');
    await page.click('[data-testid="task-item"]:first-child');
    await page.click('[data-testid="assign-task-button"]');
    
    // Verify assignment form displayed
    await expect(page.locator('[data-testid="assignment-form"]')).toBeVisible();
    
    // Step 2: Attempt to assign task to inactive employee
    await page.click('[data-testid="employee-dropdown"]');
    
    // Verify inactive employee not listed in dropdown
    const inactiveEmployeeOption = page.locator('[data-testid="employee-option"][data-employee-name="Jane Doe"]');
    await expect(inactiveEmployeeOption).not.toBeVisible();
    
    // Alternative: If inactive employee somehow appears, verify error on selection
    const allEmployeeOptions = await page.locator('[data-testid="employee-option"]').allTextContents();
    expect(allEmployeeOptions).not.toContain('Jane Doe');
    
    // Step 3: Attempt to submit without valid selection or with inactive employee
    // Close dropdown and try to submit empty
    await page.keyboard.press('Escape');
    await page.click('[data-testid="submit-assignment-button"]');
    
    // Verify submission blocked with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/employee|invalid|required/i);
    
    // Verify no confirmation message displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
  });

  test('Verify assignment processing time within SLA', async ({ page }) => {
    // Step 1: Assign task to valid employee and measure response time
    await page.goto('/tasks');
    await page.click('[data-testid="task-item"]:first-child');
    
    // Get task ID for verification
    const taskId = await page.locator('[data-testid="task-id"]').textContent();
    
    await page.click('[data-testid="assign-task-button"]');
    await expect(page.locator('[data-testid="assignment-form"]')).toBeVisible();
    
    // Start timer
    const startTime = Date.now();
    
    // Select active employee and submit
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option"][data-employee-name="Michael Johnson"]');
    await page.click('[data-testid="submit-assignment-button"]');
    
    // Wait for confirmation message
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    
    // Calculate processing time
    const endTime = Date.now();
    const processingTime = (endTime - startTime) / 1000;
    
    // Verify response received within 2 seconds
    expect(processingTime).toBeLessThanOrEqual(2);
    
    // Step 2: Check database for assignment record
    // Navigate to task details to verify assignment saved
    await page.goto('/tasks');
    await page.click(`[data-testid="task-item"][data-task-id="${taskId}"]`);
    
    // Verify assignment saved correctly
    await expect(page.locator('[data-testid="assigned-employee"]')).toBeVisible();
    await expect(page.locator('[data-testid="assigned-employee"]')).toContainText('Michael Johnson');
    const assignmentStatus = await page.locator('[data-testid="task-status"]').textContent();
    expect(assignmentStatus).toContain('Assigned');
    
    // Step 3: Confirm confirmation message was displayed
    // Navigate back to verify the assignment flow completed successfully
    await page.goto('/tasks');
    const assignedTask = page.locator(`[data-testid="task-item"][data-task-id="${taskId}"]`);
    await expect(assignedTask.locator('[data-testid="task-assignee"]')).toContainText('Michael Johnson');
  });
});