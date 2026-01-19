import { test, expect } from '@playwright/test';

test.describe('Task Assignment Validation - Story 19', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate rejection of task assignment to non-existent employee', async ({ page }) => {
    // Navigate to the task assignment form (create new task)
    await page.click('[data-testid="create-task-button"]');
    await expect(page.locator('[data-testid="task-form"]')).toBeVisible();

    // Fill in valid data for task title, description, deadline, and priority fields
    await page.fill('[data-testid="task-title-input"]', 'Test Task for Validation');
    await page.fill('[data-testid="task-description-input"]', 'This is a test task to validate employee assignment');
    
    // Set a valid future deadline
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const futureDateString = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', futureDateString);
    
    await page.selectOption('[data-testid="task-priority-select"]', 'High');

    // Enter a non-existent employee ID
    await page.fill('[data-testid="employee-assignment-input"]', 'EMP99999');
    
    // Verify that validation error appears
    const validationError = page.locator('[data-testid="employee-validation-error"]');
    await expect(validationError).toBeVisible({ timeout: 1000 });
    await expect(validationError).toContainText(/employee does not exist/i);
    
    // Verify that the validation error message is clear and descriptive
    const errorText = await validationError.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText?.length).toBeGreaterThan(10);

    // Attempt to submit the form
    await page.click('[data-testid="submit-task-button"]');
    
    // Verify submission is blocked - form should still be visible
    await expect(page.locator('[data-testid="task-form"]')).toBeVisible();
    await expect(validationError).toBeVisible();
    
    // Verify that no task record is created by checking for success message absence
    await expect(page.locator('[data-testid="task-success-message"]')).not.toBeVisible();

    // Clear the invalid employee ID and select a valid existing employee
    await page.fill('[data-testid="employee-assignment-input"]', '');
    await page.fill('[data-testid="employee-assignment-input"]', 'EMP001');
    
    // Verify validation error is cleared
    await expect(validationError).not.toBeVisible();
    
    // Submit with valid employee assignment
    await page.click('[data-testid="submit-task-button"]');
    
    // Verify successful submission
    await expect(page.locator('[data-testid="task-success-message"]')).toBeVisible({ timeout: 3000 });
  });

  test('Validate rejection of past deadline input', async ({ page }) => {
    // Navigate to the task assignment form (create new task)
    await page.click('[data-testid="create-task-button"]');
    await expect(page.locator('[data-testid="task-form"]')).toBeVisible();

    // Fill in valid data for task title, description, priority, and employee assignment
    await page.fill('[data-testid="task-title-input"]', 'Task with Past Deadline Test');
    await page.fill('[data-testid="task-description-input"]', 'Testing past deadline validation');
    await page.selectOption('[data-testid="task-priority-select"]', 'Medium');
    await page.fill('[data-testid="employee-assignment-input"]', 'EMP001');

    // Enter a past date for task deadline
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 1);
    const pastDateString = pastDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', pastDateString);
    
    // Verify that validation error appears
    const deadlineValidationError = page.locator('[data-testid="deadline-validation-error"]');
    await expect(deadlineValidationError).toBeVisible({ timeout: 1000 });
    await expect(deadlineValidationError).toContainText(/invalid deadline|past date|future date/i);
    
    // Verify that the validation error message is clear and descriptive
    const errorText = await deadlineValidationError.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText?.length).toBeGreaterThan(10);

    // Attempt to submit the form
    await page.click('[data-testid="submit-task-button"]');
    
    // Verify submission is blocked
    await expect(page.locator('[data-testid="task-form"]')).toBeVisible();
    await expect(deadlineValidationError).toBeVisible();
    
    // Verify that no task record is created
    await expect(page.locator('[data-testid="task-success-message"]')).not.toBeVisible();

    // Test with today's date
    const todayDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', todayDate);
    
    // Check if today's date is accepted or rejected based on business rules
    // Assuming today's date might show validation error or be accepted
    await page.waitForTimeout(500);

    // Update with a valid future date
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 5);
    const futureDateString = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', futureDateString);
    
    // Verify validation error is cleared
    await expect(deadlineValidationError).not.toBeVisible();
    
    // Submit with valid future deadline
    await page.click('[data-testid="submit-task-button"]');
    
    // Verify successful submission
    await expect(page.locator('[data-testid="task-success-message"]')).toBeVisible({ timeout: 3000 });
  });

  test('Ensure real-time validation feedback is delivered promptly', async ({ page }) => {
    // Navigate to the task assignment form
    await page.click('[data-testid="create-task-button"]');
    await expect(page.locator('[data-testid="task-form"]')).toBeVisible();

    // Test 1: Non-existent employee ID validation timing
    const startTime1 = Date.now();
    await page.fill('[data-testid="employee-assignment-input"]', 'EMP99999');
    
    const employeeError = page.locator('[data-testid="employee-validation-error"]');
    await expect(employeeError).toBeVisible({ timeout: 1000 });
    const endTime1 = Date.now();
    const responseTime1 = endTime1 - startTime1;
    
    // Verify response time is under 1 second (1000ms)
    expect(responseTime1).toBeLessThan(1000);
    console.log(`Employee validation response time: ${responseTime1}ms`);

    // Clear the employee field
    await page.fill('[data-testid="employee-assignment-input"]', '');
    await expect(employeeError).not.toBeVisible();

    // Test 2: Past date deadline validation timing
    const startTime2 = Date.now();
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 2);
    const pastDateString = pastDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', pastDateString);
    
    const deadlineError = page.locator('[data-testid="deadline-validation-error"]');
    await expect(deadlineError).toBeVisible({ timeout: 1000 });
    const endTime2 = Date.now();
    const responseTime2 = endTime2 - startTime2;
    
    // Verify response time is under 1 second
    expect(responseTime2).toBeLessThan(1000);
    console.log(`Deadline validation response time: ${responseTime2}ms`);

    // Clear the deadline field
    await page.fill('[data-testid="task-deadline-input"]', '');
    await expect(deadlineError).not.toBeVisible();

    // Test 3: Invalid priority value validation timing
    const startTime3 = Date.now();
    await page.fill('[data-testid="task-priority-select"]', 'InvalidPriority');
    
    const priorityError = page.locator('[data-testid="priority-validation-error"]');
    await expect(priorityError).toBeVisible({ timeout: 1000 });
    const endTime3 = Date.now();
    const responseTime3 = endTime3 - startTime3;
    
    // Verify response time is under 1 second
    expect(responseTime3).toBeLessThan(1000);
    console.log(`Priority validation response time: ${responseTime3}ms`);

    // Clear the priority field
    await page.selectOption('[data-testid="task-priority-select"]', '');
    await expect(priorityError).not.toBeVisible();

    // Test 4: Empty required field (task title) validation timing
    const startTime4 = Date.now();
    await page.fill('[data-testid="task-title-input"]', '');
    await page.click('[data-testid="task-description-input"]'); // Trigger blur event
    
    const titleError = page.locator('[data-testid="title-validation-error"]');
    await expect(titleError).toBeVisible({ timeout: 1000 });
    const endTime4 = Date.now();
    const responseTime4 = endTime4 - startTime4;
    
    // Verify response time is under 1 second
    expect(responseTime4).toBeLessThan(1000);
    console.log(`Title validation response time: ${responseTime4}ms`);

    // Test 5: Multiple invalid inputs simultaneously
    await page.fill('[data-testid="task-title-input"]', 'Multiple Validation Test');
    
    const startTime5 = Date.now();
    
    // Enter multiple invalid inputs at once
    await page.fill('[data-testid="employee-assignment-input"]', 'EMP99999');
    await page.fill('[data-testid="task-deadline-input"]', pastDateString);
    await page.fill('[data-testid="task-priority-select"]', 'InvalidPriority');
    
    // Wait for all validation errors to appear
    await Promise.all([
      expect(employeeError).toBeVisible({ timeout: 1000 }),
      expect(deadlineError).toBeVisible({ timeout: 1000 }),
      expect(priorityError).toBeVisible({ timeout: 1000 })
    ]);
    
    const endTime5 = Date.now();
    const responseTime5 = endTime5 - startTime5;
    
    // Verify all validation errors appear within 1 second
    expect(responseTime5).toBeLessThan(1000);
    console.log(`Multiple validation response time: ${responseTime5}ms`);
    
    // Verify all measured response times are consistent and under 1 second
    const allResponseTimes = [responseTime1, responseTime2, responseTime3, responseTime4, responseTime5];
    allResponseTimes.forEach((time, index) => {
      expect(time).toBeLessThan(1000);
      console.log(`Test ${index + 1} validation response time: ${time}ms - PASS`);
    });
  });
});