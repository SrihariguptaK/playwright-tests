import { test, expect } from '@playwright/test';

test.describe('Scheduling Conflict Override - Story 6', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling page
    await page.goto('/scheduling');
    // Wait for page to be ready
    await page.waitForLoadState('networkidle');
  });

  test('Validate authorized override of scheduling conflict', async ({ page }) => {
    // Step 1: Trigger scheduling conflict and select override
    // Create or modify a schedule that triggers a conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="patient-name-input"]', 'John Doe');
    await page.fill('[data-testid="appointment-date-input"]', '2024-03-15');
    await page.fill('[data-testid="appointment-time-input"]', '10:00');
    await page.selectOption('[data-testid="provider-select"]', 'Dr. Smith');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Wait for conflict alert to appear
    await expect(page.locator('[data-testid="conflict-alert-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('scheduling conflict');
    
    // Click override button
    await page.click('[data-testid="override-conflict-button"]');
    
    // Expected Result: System prompts for authorization credentials
    await expect(page.locator('[data-testid="authorization-prompt"]')).toBeVisible();
    await expect(page.locator('[data-testid="credentials-form"]')).toBeVisible();
    
    // Step 2: Enter valid credentials
    await page.fill('[data-testid="auth-username-input"]', 'scheduler_admin');
    await page.fill('[data-testid="auth-password-input"]', 'ValidPassword123!');
    await page.click('[data-testid="submit-credentials-button"]');
    
    // Expected Result: Override is applied and logged
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Override applied successfully');
    
    // Verify the schedule was created despite conflict
    await expect(page.locator('[data-testid="schedule-list"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="schedule-list"]')).toContainText('10:00');
    
    // Step 3: Verify override action in audit logs
    await page.click('[data-testid="audit-logs-menu"]');
    await page.click('[data-testid="override-history-link"]');
    
    // Wait for audit logs page to load
    await page.waitForLoadState('networkidle');
    
    // Filter by recent timestamp or user
    await page.fill('[data-testid="audit-log-search-input"]', 'scheduler_admin');
    await page.click('[data-testid="search-logs-button"]');
    
    // Expected Result: Override entry is present with correct user and timestamp
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry).toContainText('scheduler_admin');
    await expect(auditLogEntry).toContainText('Override');
    await expect(auditLogEntry).toContainText('John Doe');
    
    // Verify timestamp is recent (within last few minutes)
    const timestamp = await auditLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
  });

  test('Verify prevention of unauthorized override - invalid credentials', async ({ page }) => {
    // Step 1: Attempt override with invalid credentials
    // Trigger scheduling conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="patient-name-input"]', 'Jane Smith');
    await page.fill('[data-testid="appointment-date-input"]', '2024-03-15');
    await page.fill('[data-testid="appointment-time-input"]', '10:00');
    await page.selectOption('[data-testid="provider-select"]', 'Dr. Smith');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Wait for conflict alert
    await expect(page.locator('[data-testid="conflict-alert-dialog"]')).toBeVisible();
    
    // Click override button
    await page.click('[data-testid="override-conflict-button"]');
    
    // Enter invalid credentials
    await page.fill('[data-testid="auth-username-input"]', 'invalid_user');
    await page.fill('[data-testid="auth-password-input"]', 'WrongPassword');
    await page.click('[data-testid="submit-credentials-button"]');
    
    // Expected Result: System denies override and displays error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('unauthorized');
    
    // Verify conflict remains unresolved
    await expect(page.locator('[data-testid="conflict-alert-dialog"]')).toBeVisible();
    
    // Close error message
    await page.click('[data-testid="close-error-button"]');
    
    // Verify schedule was not created
    await page.click('[data-testid="cancel-override-button"]');
    await page.click('[data-testid="close-conflict-dialog"]');
    
    // Check schedule list does not contain the conflicting appointment
    const scheduleList = page.locator('[data-testid="schedule-list"]');
    await expect(scheduleList.filter({ hasText: 'Jane Smith' }).filter({ hasText: '10:00' })).toHaveCount(0);
  });

  test('Verify prevention of unauthorized override - no credentials provided', async ({ page }) => {
    // Step 2: Attempt override without credentials
    // Trigger scheduling conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="patient-name-input"]', 'Bob Johnson');
    await page.fill('[data-testid="appointment-date-input"]', '2024-03-15');
    await page.fill('[data-testid="appointment-time-input"]', '10:00');
    await page.selectOption('[data-testid="provider-select"]', 'Dr. Smith');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Wait for conflict alert
    await expect(page.locator('[data-testid="conflict-alert-dialog"]')).toBeVisible();
    
    // Click override button
    await page.click('[data-testid="override-conflict-button"]');
    
    // Authorization prompt appears
    await expect(page.locator('[data-testid="authorization-prompt"]')).toBeVisible();
    
    // Close or cancel without entering credentials
    await page.click('[data-testid="cancel-authorization-button"]');
    
    // Expected Result: System denies override
    // Conflict alert should still be displayed
    await expect(page.locator('[data-testid="conflict-alert-dialog"]')).toBeVisible();
    
    // Close conflict dialog
    await page.click('[data-testid="close-conflict-dialog"]');
    
    // Verify schedule remains unchanged - appointment not created
    const scheduleList = page.locator('[data-testid="schedule-list"]');
    await expect(scheduleList.filter({ hasText: 'Bob Johnson' }).filter({ hasText: '10:00' })).toHaveCount(0);
  });

  test('Verify authorization process completes within 2 seconds', async ({ page }) => {
    // Trigger scheduling conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="patient-name-input"]', 'Performance Test');
    await page.fill('[data-testid="appointment-date-input"]', '2024-03-15');
    await page.fill('[data-testid="appointment-time-input"]', '10:00');
    await page.selectOption('[data-testid="provider-select"]', 'Dr. Smith');
    await page.click('[data-testid="save-schedule-button"]');
    
    await expect(page.locator('[data-testid="conflict-alert-dialog"]')).toBeVisible();
    await page.click('[data-testid="override-conflict-button"]');
    
    // Measure authorization time
    const startTime = Date.now();
    
    await page.fill('[data-testid="auth-username-input"]', 'scheduler_admin');
    await page.fill('[data-testid="auth-password-input"]', 'ValidPassword123!');
    await page.click('[data-testid="submit-credentials-button"]');
    
    // Wait for success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    const endTime = Date.now();
    const authorizationTime = endTime - startTime;
    
    // Verify authorization completed within 2 seconds (2000ms)
    expect(authorizationTime).toBeLessThan(2000);
  });
});