import { test, expect } from '@playwright/test';

test.describe('Shift Template Creation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as HR Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful shift template creation with valid input', async ({ page }) => {
    // Step 1: Navigate to shift template creation page
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template-button"]');
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();

    // Step 2: Enter valid start time, end time, breaks, and assign roles
    await page.fill('[data-testid="template-name-input"]', 'Morning Shift - Weekday');
    await page.selectOption('[data-testid="category-dropdown"]', 'Standard Shifts');
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.fill('[data-testid="end-time-input"]', '17:00');
    
    // Add first break period
    await page.click('[data-testid="add-break-button"]');
    await page.fill('[data-testid="break-start-time-0"]', '12:00');
    await page.fill('[data-testid="break-end-time-0"]', '12:30');
    await page.selectOption('[data-testid="break-type-0"]', 'Lunch');
    
    // Add second break period
    await page.click('[data-testid="add-break-button"]');
    await page.fill('[data-testid="break-start-time-1"]', '15:00');
    await page.fill('[data-testid="break-end-time-1"]', '15:15');
    await page.selectOption('[data-testid="break-type-1"]', 'Rest');
    
    // Assign roles
    await page.click('[data-testid="roles-dropdown"]');
    await page.click('[data-testid="role-option-customer-service-representative"]');
    await page.click('[data-testid="role-option-team-lead"]');
    await page.click('[data-testid="roles-dropdown"]'); // Close dropdown
    
    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Step 3: Submit the form
    await page.click('[data-testid="save-template-button"]');
    
    // Verify confirmation message is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift template created successfully');
    
    // Verify template appears in the list
    await page.click('[data-testid="view-templates-button"]');
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Morning Shift - Weekday');
  });

  test('Reject shift template creation with overlapping breaks', async ({ page }) => {
    // Step 1: Navigate to shift template creation page
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template-button"]');
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();

    // Step 2: Enter breaks with overlapping time periods
    await page.fill('[data-testid="template-name-input"]', 'Test Overlapping Breaks');
    await page.fill('[data-testid="start-time-input"]', '08:00');
    await page.fill('[data-testid="end-time-input"]', '16:00');
    
    // Add first break period
    await page.click('[data-testid="add-break-button"]');
    await page.fill('[data-testid="break-start-time-0"]', '11:00');
    await page.fill('[data-testid="break-end-time-0"]', '11:30');
    
    // Add second break period with overlapping time
    await page.click('[data-testid="add-break-button"]');
    await page.fill('[data-testid="break-start-time-1"]', '11:15');
    await page.fill('[data-testid="break-end-time-1"]', '11:45');
    
    // Add third break period with complete overlap
    await page.click('[data-testid="add-break-button"]');
    await page.fill('[data-testid="break-start-time-2"]', '11:00');
    await page.fill('[data-testid="break-end-time-2"]', '11:30');
    
    // Assign role
    await page.click('[data-testid="roles-dropdown"]');
    await page.click('[data-testid="role-option-supervisor"]');
    await page.click('[data-testid="roles-dropdown"]');
    
    // Verify validation error messages are displayed
    await expect(page.locator('[data-testid="validation-error-overlapping-breaks"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-overlapping-breaks"]')).toContainText('Break periods cannot overlap');
    
    // Step 3: Attempt to submit the form
    const saveButton = page.locator('[data-testid="save-template-button"]');
    await expect(saveButton).toBeDisabled();
    
    // Monitor network requests to ensure no API call is made
    let apiCallMade = false;
    page.on('request', request => {
      if (request.url().includes('/api/shifttemplates') && request.method() === 'POST') {
        apiCallMade = true;
      }
    });
    
    await saveButton.click({ force: true }).catch(() => {});
    await page.waitForTimeout(1000);
    
    // Verify no API call was made
    expect(apiCallMade).toBe(false);
  });

  test('Ensure audit trail records template creation', async ({ page }) => {
    // Step 1: Create a new shift template
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template-button"]');
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    
    await page.fill('[data-testid="template-name-input"]', 'Evening Shift - Audit Test');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '22:00');
    
    // Add break period
    await page.click('[data-testid="add-break-button"]');
    await page.fill('[data-testid="break-start-time-0"]', '17:00');
    await page.fill('[data-testid="break-end-time-0"]', '17:30');
    
    // Assign role
    await page.click('[data-testid="roles-dropdown"]');
    await page.click('[data-testid="role-option-sales-associate"]');
    await page.click('[data-testid="roles-dropdown"]');
    
    // Select category
    await page.selectOption('[data-testid="category-dropdown"]', 'Evening Shifts');
    
    // Note timestamp before submission
    const timestampBeforeSubmission = new Date();
    
    // Submit the form
    await page.click('[data-testid="save-template-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 2: Query audit trail logs
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-trail-link"]');
    await expect(page.locator('[data-testid="audit-trail-page"]')).toBeVisible();
    
    // Filter audit logs by action type
    await page.selectOption('[data-testid="action-type-filter"]', 'Template Creation');
    await page.selectOption('[data-testid="entity-type-filter"]', 'ShiftTemplate');
    
    // Search for the specific template
    await page.fill('[data-testid="audit-search-input"]', 'Evening Shift - Audit Test');
    await page.click('[data-testid="audit-search-button"]');
    
    // Verify audit entry exists
    const auditEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(auditEntry).toBeVisible();
    
    // Verify audit entry contains template name
    await expect(auditEntry.locator('[data-testid="audit-entity-name"]')).toContainText('Evening Shift - Audit Test');
    
    // Verify audit entry contains user identity
    await expect(auditEntry.locator('[data-testid="audit-user"]')).toContainText('hr.manager@company.com');
    
    // Verify audit entry contains timestamp
    const auditTimestamp = await auditEntry.locator('[data-testid="audit-timestamp"]').textContent();
    expect(auditTimestamp).toBeTruthy();
    
    // Verify audit entry contains action type
    await expect(auditEntry.locator('[data-testid="audit-action"]')).toContainText('Template Creation');
    
    // Verify audit entry contains complete information
    await expect(auditEntry.locator('[data-testid="audit-details"]')).toBeVisible();
  });
});