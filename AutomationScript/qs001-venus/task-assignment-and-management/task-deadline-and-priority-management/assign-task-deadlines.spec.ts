import { test, expect } from '@playwright/test';

test.describe('Story-12: Assign Deadlines to Tasks', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful deadline assignment with future date', async ({ page }) => {
    // Navigate to the task management page and select an existing task
    await page.goto(`${BASE_URL}/tasks`);
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Select an existing task
    await page.click('[data-testid="task-item"]:first-child');
    await expect(page.locator('[data-testid="task-details"]')).toBeVisible();
    
    // Click on the deadline update or edit button
    await page.click('[data-testid="edit-deadline-button"]');
    
    // Deadline input form is displayed
    await expect(page.locator('[data-testid="deadline-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="deadline-date-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="deadline-time-input"]')).toBeVisible();
    
    // Enter a valid future date (7 days from current date)
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    const formattedTime = '14:30';
    
    await page.fill('[data-testid="deadline-date-input"]', formattedDate);
    
    // Input accepted without validation errors
    await expect(page.locator('[data-testid="deadline-error"]')).not.toBeVisible();
    
    // Enter a valid future time
    await page.fill('[data-testid="deadline-time-input"]', formattedTime);
    await expect(page.locator('[data-testid="deadline-error"]')).not.toBeVisible();
    
    // Click the Submit or Save button to save the deadline update
    await page.click('[data-testid="submit-deadline-button"]');
    
    // Deadline is saved, confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Deadline updated successfully');
    
    // Verify the task details page shows the updated deadline
    await expect(page.locator('[data-testid="task-deadline"]')).toContainText(formattedDate);
    
    // Verify notifications sent indicator
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible();
  });

  test('Verify rejection of past date deadline assignment', async ({ page }) => {
    // Navigate to the task management page and select an existing task
    await page.goto(`${BASE_URL}/tasks`);
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Select an existing task
    await page.click('[data-testid="task-item"]:first-child');
    await expect(page.locator('[data-testid="task-details"]')).toBeVisible();
    
    // Click on the deadline update or edit button
    await page.click('[data-testid="edit-deadline-button"]');
    
    // Deadline input form is displayed
    await expect(page.locator('[data-testid="deadline-form"]')).toBeVisible();
    
    // Enter a past date (yesterday's date)
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 1);
    const formattedPastDate = pastDate.toISOString().split('T')[0];
    const pastTime = '10:00';
    
    await page.fill('[data-testid="deadline-date-input"]', formattedPastDate);
    await page.fill('[data-testid="deadline-time-input"]', pastTime);
    
    // Validation error displayed indicating invalid deadline
    await expect(page.locator('[data-testid="deadline-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="deadline-error"]')).toContainText(/past date|invalid deadline|future date/i);
    
    // Attempt to click the Submit or Save button
    await page.click('[data-testid="submit-deadline-button"]');
    
    // Submission blocked - error message persists
    await expect(page.locator('[data-testid="deadline-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Clear the past date and enter a valid future date and time
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 5);
    const formattedFutureDate = futureDate.toISOString().split('T')[0];
    const futureTime = '15:00';
    
    await page.fill('[data-testid="deadline-date-input"]', formattedFutureDate);
    await page.fill('[data-testid="deadline-time-input"]', futureTime);
    
    // Error should disappear with valid future date
    await expect(page.locator('[data-testid="deadline-error"]')).not.toBeVisible();
    
    // Click the Submit or Save button with valid future date
    await page.click('[data-testid="submit-deadline-button"]');
    
    // Verify successful submission
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
  });

  test('Ensure notifications are sent upon deadline update', async ({ page }) => {
    // Navigate to the task management page and select a task that has employees assigned
    await page.goto(`${BASE_URL}/tasks`);
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Select a task with assigned employees
    await page.click('[data-testid="task-item-with-assignees"]');
    await expect(page.locator('[data-testid="task-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="assigned-employees"]')).toBeVisible();
    
    // Click on the deadline update or edit button
    await page.click('[data-testid="edit-deadline-button"]');
    await expect(page.locator('[data-testid="deadline-form"]')).toBeVisible();
    
    // Enter a valid future date and time for the deadline
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 10);
    const formattedDate = futureDate.toISOString().split('T')[0];
    const formattedTime = '16:00';
    
    await page.fill('[data-testid="deadline-date-input"]', formattedDate);
    await page.fill('[data-testid="deadline-time-input"]', formattedTime);
    
    // Click the Submit or Save button to update the deadline
    await page.click('[data-testid="submit-deadline-button"]');
    
    // Deadline update is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Observe the confirmation message displayed to the manager
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/deadline updated|successfully updated/i);
    
    // Verify the manager sees the confirmation message on the task page
    await expect(page.locator('[data-testid="task-deadline"]')).toContainText(formattedDate);
    
    // Access the notification system or notification logs
    await page.click('[data-testid="notifications-menu"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    
    // Verify that all assigned employees received the deadline update notification
    await expect(page.locator('[data-testid="notification-sent-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-sent-status"]')).toContainText(/sent|delivered/i);
    
    // Check the notification content for accuracy
    const notificationCount = await page.locator('[data-testid="notification-recipient"]').count();
    expect(notificationCount).toBeGreaterThan(0);
    
    // Verify notification contains deadline information
    await expect(page.locator('[data-testid="notification-content"]').first()).toContainText(/deadline/i);
  });
});