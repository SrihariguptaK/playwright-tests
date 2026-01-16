import { test, expect } from '@playwright/test';

test.describe('Task Priority Assignment - Story 4', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const PRIORITY_PAGE_URL = `${BASE_URL}/tasks/priority`;
  const VALID_PRIORITIES = ['Low', 'Medium', 'High'];

  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'managerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Assign valid priority level successfully', async ({ page }) => {
    // Step 1: Navigate to task priority setting page
    await page.goto(PRIORITY_PAGE_URL);
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Priority selection form displayed
    await expect(page.locator('[data-testid="priority-selection-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="priority-dropdown"]')).toBeVisible();

    // Step 2: Select a valid priority level (e.g., High)
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-option-High"]');
    
    // Expected Result: Selection accepted without errors
    await expect(page.locator('[data-testid="priority-dropdown"]')).toContainText('High');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 3: Submit priority
    await page.click('[data-testid="submit-priority-button"]');
    
    // Expected Result: Priority saved and confirmation displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Priority assigned successfully');
    
    // Verify priority is stored correctly
    const savedPriority = await page.locator('[data-testid="current-priority-value"]').textContent();
    expect(savedPriority).toBe('High');
  });

  test('Reject invalid priority values', async ({ page }) => {
    // Step 1: Navigate to priority setting page
    await page.goto(PRIORITY_PAGE_URL);
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Priority selection form displayed
    await expect(page.locator('[data-testid="priority-selection-form"]')).toBeVisible();

    // Step 2: Attempt to enter invalid priority value
    // Try to manually input invalid text if input field is editable
    const priorityInput = page.locator('[data-testid="priority-input"]');
    if (await priorityInput.isVisible()) {
      await priorityInput.fill('Critical');
      
      // Expected Result: Validation error displayed
      await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
      await expect(page.locator('[data-testid="validation-error"]')).toContainText(/invalid priority/i);
    }

    // Step 3: Attempt to submit invalid priority
    await page.click('[data-testid="submit-priority-button"]');
    
    // Expected Result: Submission blocked with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/priority must be one of/i);
    
    // Verify no confirmation message is shown
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
  });

  test('Verify priority update processing time', async ({ page }) => {
    // Step 1: Update priority with valid level
    await page.goto(PRIORITY_PAGE_URL);
    await page.waitForLoadState('networkidle');
    
    // Record start time
    const startTime = Date.now();
    
    // Select and submit priority
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-option-High"]');
    await page.click('[data-testid="submit-priority-button"]');
    
    // Wait for response
    await page.waitForResponse(response => 
      response.url().includes('/api/tasks/priority') && response.status() === 200
    );
    
    const endTime = Date.now();
    const processingTime = endTime - startTime;
    
    // Expected Result: Response received within 2 seconds
    expect(processingTime).toBeLessThan(2000);

    // Step 2: Check database for updated priority
    await page.waitForLoadState('networkidle');
    const updatedPriority = await page.locator('[data-testid="current-priority-value"]').textContent();
    
    // Expected Result: Priority updated correctly
    expect(updatedPriority).toBe('High');

    // Step 3: Confirm confirmation message display
    // Expected Result: Message shown to manager
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText(/priority.*successfully/i);
  });

  test('Assign valid priority level successfully - happy path with all validations', async ({ page }) => {
    // Navigate to task priority setting page
    await page.goto(PRIORITY_PAGE_URL);
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="priority-selection-form"]')).toBeVisible();

    // Select a valid priority level (e.g., High) from the available options
    await page.click('[data-testid="priority-dropdown"]');
    await expect(page.locator('[data-testid="priority-option-Low"]')).toBeVisible();
    await expect(page.locator('[data-testid="priority-option-Medium"]')).toBeVisible();
    await expect(page.locator('[data-testid="priority-option-High"]')).toBeVisible();
    await page.click('[data-testid="priority-option-High"]');

    // Submit priority by clicking the submit button
    await page.click('[data-testid="submit-priority-button"]');

    // Verify the priority is stored correctly in the database
    await page.waitForResponse(response => 
      response.url().includes('/api/tasks/priority') && response.status() === 200
    );
    const storedPriority = await page.locator('[data-testid="current-priority-value"]').textContent();
    expect(storedPriority).toBe('High');

    // Check that notification is triggered for the assigned employee
    await expect(page.locator('[data-testid="notification-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText(/notification sent/i);
  });

  test('Reject invalid priority values - error case with comprehensive checks', async ({ page }) => {
    // Navigate to priority setting page
    await page.goto(PRIORITY_PAGE_URL);
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="priority-selection-form"]')).toBeVisible();

    // Attempt to enter an invalid priority value (e.g., 'Critical' or 'Urgent')
    const priorityInput = page.locator('[data-testid="priority-input"]');
    if (await priorityInput.isVisible()) {
      await priorityInput.fill('Critical');
      await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
      
      await priorityInput.fill('Urgent');
      await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    }

    // Attempt to submit the invalid priority by clicking the submit button
    await page.click('[data-testid="submit-priority-button"]');

    // Verify that no priority is saved in the database
    const errorResponse = page.waitForResponse(response => 
      response.url().includes('/api/tasks/priority') && response.status() >= 400
    );
    await expect(errorResponse).resolves.toBeTruthy();

    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/invalid priority/i);

    // Verify that no notification is triggered
    await expect(page.locator('[data-testid="notification-indicator"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
  });

  test('Verify priority update processing time - boundary test with full workflow', async ({ page }) => {
    // Navigate to the task with existing priority and open priority update interface
    await page.goto(`${BASE_URL}/tasks/1`);
    await page.waitForLoadState('networkidle');
    await page.click('[data-testid="edit-priority-button"]');
    await expect(page.locator('[data-testid="priority-update-form"]')).toBeVisible();

    // Verify current priority is displayed
    const currentPriority = await page.locator('[data-testid="current-priority-value"]').textContent();
    expect(VALID_PRIORITIES).toContain(currentPriority || '');

    // Update priority with a valid level (e.g., change from Medium to High) and note the timestamp
    const timestampBeforeSubmission = Date.now();
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-option-High"]');

    // Submit the updated priority and measure response time
    const responsePromise = page.waitForResponse(response => 
      response.url().includes('/api/tasks/priority') && response.status() === 200
    );
    await page.click('[data-testid="submit-priority-button"]');
    const response = await responsePromise;
    const timestampAfterResponse = Date.now();
    const responseTime = timestampAfterResponse - timestampBeforeSubmission;

    // Verify response time is within 2 seconds
    expect(responseTime).toBeLessThan(2000);

    // Check database for updated priority immediately after submission
    await page.waitForLoadState('networkidle');
    const updatedPriority = await page.locator('[data-testid="current-priority-value"]').textContent();
    expect(updatedPriority).toBe('High');

    // Confirm confirmation message display to manager
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText(/priority updated successfully/i);

    // Verify notification trigger for the employee
    await expect(page.locator('[data-testid="notification-indicator"]')).toBeVisible();
  });
});