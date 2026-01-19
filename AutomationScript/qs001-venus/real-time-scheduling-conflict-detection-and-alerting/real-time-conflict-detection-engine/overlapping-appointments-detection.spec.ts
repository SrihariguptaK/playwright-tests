import { test, expect } from '@playwright/test';

test.describe('Overlapping Appointments Detection', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application base URL
    await page.goto('/');
    // Assume user is already logged in or perform login here if needed
  });

  test('Validate detection of overlapping appointments (happy-path)', async ({ page }) => {
    // Step 1: Navigate to scheduling interface by clicking on 'Schedule' menu option
    await page.click('[data-testid="menu-schedule"]', { timeout: 5000 });
    
    // Expected Result: Scheduling form is displayed
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible({ timeout: 5000 });
    
    // Step 2: Enter appointment details that overlap with existing appointment
    // Select Resource A
    await page.click('[data-testid="resource-select"]');
    await page.click('[data-testid="resource-option-a"]');
    
    // Set date to current date
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date"]', currentDate);
    
    // Set start time to 10:30 AM
    await page.fill('[data-testid="appointment-start-time"]', '10:30');
    await page.selectOption('[data-testid="appointment-start-period"]', 'AM');
    
    // Set end time to 11:30 AM
    await page.fill('[data-testid="appointment-end-time"]', '11:30');
    await page.selectOption('[data-testid="appointment-end-period"]', 'AM');
    
    // Enter client name
    await page.fill('[data-testid="client-name"]', 'John Doe');
    
    // Expected Result: System detects conflict within 1 second
    // Step 3: Observe conflict alert on UI
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible({ timeout: 1000 });
    
    // Expected Result: Conflict alert is displayed clearly
    await expect(conflictAlert).toContainText('conflict', { ignoreCase: true });
    await expect(conflictAlert).toContainText('overlap', { ignoreCase: true });
  });

  test('Verify prevention of saving overlapping schedules without override (error-case)', async ({ page }) => {
    // Step 1: Navigate to scheduling interface and enter overlapping appointment details
    await page.click('[data-testid="menu-schedule"]');
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();
    
    // Select Resource B
    await page.click('[data-testid="resource-select"]');
    await page.click('[data-testid="resource-option-b"]');
    
    // Set date to current date
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date"]', currentDate);
    
    // Set start time to 2:30 PM
    await page.fill('[data-testid="appointment-start-time"]', '2:30');
    await page.selectOption('[data-testid="appointment-start-period"]', 'PM');
    
    // Set end time to 3:30 PM
    await page.fill('[data-testid="appointment-end-time"]', '3:30');
    await page.selectOption('[data-testid="appointment-end-period"]', 'PM');
    
    await page.fill('[data-testid="client-name"]', 'Jane Smith');
    
    // Step 2: Click 'Save' button to attempt saving without override
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Expected Result: System blocks save and displays error message
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 2000 });
    await expect(errorMessage).toContainText('cannot save', { ignoreCase: true });
    
    // Verify the form is still displayed (save was blocked)
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();
    
    // Step 3: Modify appointment to resolve conflict
    // Change start time to 3:00 PM
    await page.fill('[data-testid="appointment-start-time"]', '3:00');
    
    // Change end time to 4:00 PM
    await page.fill('[data-testid="appointment-end-time"]', '4:00');
    
    // Step 4: Click 'Save' button to save modified schedule
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Expected Result: Schedule saves successfully
    const successMessage = page.locator('[data-testid="success-message"]');
    await expect(successMessage).toBeVisible({ timeout: 2000 });
    await expect(successMessage).toContainText('saved successfully', { ignoreCase: true });
  });

  test('Check logging of detected conflicts (happy-path)', async ({ page }) => {
    // Step 1: Navigate to scheduling interface and create overlapping appointment
    await page.click('[data-testid="menu-schedule"]');
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();
    
    // Select Resource C
    await page.click('[data-testid="resource-select"]');
    await page.click('[data-testid="resource-option-c"]');
    
    // Set date to current date
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date"]', currentDate);
    
    // Set start time to 9:30 AM
    await page.fill('[data-testid="appointment-start-time"]', '9:30');
    await page.selectOption('[data-testid="appointment-start-period"]', 'AM');
    
    // Set end time to 10:30 AM
    await page.fill('[data-testid="appointment-end-time"]', '10:30');
    await page.selectOption('[data-testid="appointment-end-period"]', 'AM');
    
    // Enter client details
    await page.fill('[data-testid="client-name"]', 'Robert Johnson');
    await page.fill('[data-testid="client-email"]', 'robert.johnson@example.com');
    
    // Expected Result: Conflict is logged with user and timestamp
    // Wait for conflict detection
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 1000 });
    
    // Step 2: Navigate to admin interface
    await page.click('[data-testid="menu-admin"]');
    
    // Select 'Conflict Logs' or 'Audit Logs' section
    await page.click('text=Conflict Logs');
    await expect(page.locator('[data-testid="conflict-logs-table"]')).toBeVisible({ timeout: 3000 });
    
    // Step 3: Search or filter logs for recently created conflict
    // Filter by date
    await page.fill('[data-testid="log-filter-date"]', currentDate);
    
    // Filter by resource (Resource C)
    await page.click('[data-testid="log-filter-resource"]');
    await page.click('[data-testid="log-filter-resource-c"]');
    
    // Apply filters
    await page.click('[data-testid="apply-filters-btn"]');
    
    // Step 4: Verify accuracy of logged information
    const logEntry = page.locator('[data-testid="conflict-log-entry"]').first();
    await expect(logEntry).toBeVisible({ timeout: 2000 });
    
    // Expected Result: Logged conflict details are accurate and complete
    await expect(logEntry).toContainText('Resource C');
    await expect(logEntry).toContainText('9:30');
    await expect(logEntry).toContainText('10:30');
    await expect(logEntry).toContainText(currentDate);
    
    // Verify timestamp is present
    const timestamp = logEntry.locator('[data-testid="log-timestamp"]');
    await expect(timestamp).toBeVisible();
    
    // Verify user information is logged
    const userInfo = logEntry.locator('[data-testid="log-user"]');
    await expect(userInfo).toBeVisible();
    await expect(userInfo).not.toBeEmpty();
  });
});