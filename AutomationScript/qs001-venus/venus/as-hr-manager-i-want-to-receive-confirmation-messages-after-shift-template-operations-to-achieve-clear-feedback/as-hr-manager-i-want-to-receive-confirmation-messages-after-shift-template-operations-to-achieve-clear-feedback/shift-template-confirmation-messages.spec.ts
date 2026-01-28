import { test, expect } from '@playwright/test';

test.describe('Shift Template Confirmation Messages', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as HR Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'hr.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
  });

  test('Verify success message displays after shift template creation (happy-path)', async ({ page }) => {
    // Navigate to the shift template creation page
    await page.goto(`${baseURL}/shift-templates`);
    await page.click('[data-testid="create-template-button"]');
    await page.waitForSelector('[data-testid="shift-template-form"]');

    // Fill in all required fields
    await page.fill('[data-testid="template-name-input"]', 'Morning Shift Template');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.fill('[data-testid="break-duration"]', '60');

    // Click the Create or Save button
    await page.click('[data-testid="save-template-button"]');

    // Observe the notification area for confirmation message
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible({ timeout: 5000 });

    // Verify the message content and visibility
    await expect(notification).toContainText('Shift template created successfully');
    await expect(notification).toHaveClass(/success/);
  });

  test('Verify success message displays after shift template update (happy-path)', async ({ page }) => {
    // Navigate to shift templates list
    await page.goto(`${baseURL}/shift-templates`);
    await page.waitForSelector('[data-testid="shift-templates-list"]');

    // Select an existing shift template from the list
    const firstTemplate = page.locator('[data-testid="template-item"]').first();
    await firstTemplate.click();

    // Click the Edit button
    await page.click('[data-testid="edit-template-button"]');
    await page.waitForSelector('[data-testid="shift-template-form"]');

    // Modify one or more fields
    await page.fill('[data-testid="template-name-input"]', 'Updated Morning Shift');
    await page.fill('[data-testid="shift-end-time"]', '18:00');

    // Click the Update or Save Changes button
    await page.click('[data-testid="save-template-button"]');

    // Observe the notification area for confirmation message
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible({ timeout: 5000 });
    await expect(notification).toContainText('Shift template updated successfully');

    // Verify the updated template reflects the changes
    await expect(page.locator('[data-testid="template-name"]')).toContainText('Updated Morning Shift');
  });

  test('Verify success message displays after shift template deletion (happy-path)', async ({ page }) => {
    // Navigate to shift templates list
    await page.goto(`${baseURL}/shift-templates`);
    await page.waitForSelector('[data-testid="shift-templates-list"]');

    // Locate a shift template to delete
    const templateToDelete = page.locator('[data-testid="template-item"]').first();
    const templateName = await templateToDelete.locator('[data-testid="template-name"]').textContent();

    // Click the Delete button
    await templateToDelete.locator('[data-testid="delete-template-button"]').click();

    // Click Confirm in the confirmation dialog
    await page.click('[data-testid="confirm-delete-button"]');

    // Observe the notification area for confirmation message
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible({ timeout: 5000 });
    await expect(notification).toContainText('Shift template deleted successfully');

    // Verify the template is removed from the list
    await expect(page.locator(`[data-testid="template-item"]:has-text("${templateName}")`)).not.toBeVisible();
  });

  test('Verify descriptive error message displays when shift template creation fails due to missing required fields (error-case)', async ({ page }) => {
    // Navigate to the shift template creation form
    await page.goto(`${baseURL}/shift-templates`);
    await page.click('[data-testid="create-template-button"]');
    await page.waitForSelector('[data-testid="shift-template-form"]');

    // Leave template name empty and fill other fields
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');

    // Click the Create or Save button
    await page.click('[data-testid="save-template-button"]');

    // Observe the notification area and form validation
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible({ timeout: 5000 });

    // Verify the error message provides actionable guidance
    await expect(notification).toContainText('Template name is required');
    await expect(notification).toHaveClass(/error/);
    const fieldError = page.locator('[data-testid="template-name-error"]');
    await expect(fieldError).toBeVisible();
  });

  test('Verify descriptive error message displays when shift template update fails due to validation errors (error-case)', async ({ page }) => {
    // Navigate to shift templates and open for editing
    await page.goto(`${baseURL}/shift-templates`);
    await page.waitForSelector('[data-testid="shift-templates-list"]');
    await page.locator('[data-testid="template-item"]').first().click();
    await page.click('[data-testid="edit-template-button"]');

    // Enter invalid data
    await page.fill('[data-testid="shift-start-time"]', '25:00'); // Invalid time format
    await page.fill('[data-testid="break-duration"]', '-30'); // Negative value

    // Click the Update button
    await page.click('[data-testid="save-template-button"]');

    // Observe the notification area for error message
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible({ timeout: 5000 });

    // Verify the error message provides specific details
    await expect(notification).toContainText('Invalid time format');
    await expect(notification).toHaveClass(/error/);
  });

  test('Verify descriptive error message displays when shift template deletion fails due to dependencies (error-case)', async ({ page }) => {
    // Navigate to shift templates list
    await page.goto(`${baseURL}/shift-templates`);
    await page.waitForSelector('[data-testid="shift-templates-list"]');

    // Locate a shift template with active dependencies
    const templateWithDependencies = page.locator('[data-testid="template-item"][data-has-dependencies="true"]').first();
    await templateWithDependencies.locator('[data-testid="delete-template-button"]').click();

    // Confirm the deletion action
    await page.click('[data-testid="confirm-delete-button"]');

    // Observe the notification area for error message
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible({ timeout: 5000 });

    // Verify the error message provides actionable guidance
    await expect(notification).toContainText('Cannot delete template with active assignments');
    await expect(notification).toHaveClass(/error/);
  });

  test('Verify error message displays when network or server error occurs during shift template operation (error-case)', async ({ page }) => {
    // Simulate server error by intercepting the request
    await page.route('**/api/shift-templates', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Internal server error' })
      });
    });

    // Navigate to shift template creation
    await page.goto(`${baseURL}/shift-templates`);
    await page.click('[data-testid="create-template-button"]');

    // Fill in fields and submit
    await page.fill('[data-testid="template-name-input"]', 'Test Template');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.click('[data-testid="save-template-button"]');

    // Observe the notification area for error message
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible({ timeout: 5000 });

    // Verify the error message provides helpful guidance
    await expect(notification).toContainText('server error');
    await expect(notification).toHaveClass(/error/);
  });

  test('Verify confirmation messages are accessible and comply with WCAG standards (happy-path)', async ({ page }) => {
    // Navigate to shift template creation
    await page.goto(`${baseURL}/shift-templates`);
    await page.click('[data-testid="create-template-button"]');

    // Fill in all required fields
    await page.fill('[data-testid="template-name-input"]', 'Accessibility Test Template');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.fill('[data-testid="break-duration"]', '60');
    await page.click('[data-testid="save-template-button"]');

    // Verify the message has proper ARIA attributes
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible();
    await expect(notification).toHaveAttribute('role', /alert|status/);
    await expect(notification).toHaveAttribute('aria-live');

    // Verify message is keyboard accessible
    await page.keyboard.press('Tab');
    const focusedElement = await page.evaluate(() => document.activeElement?.getAttribute('data-testid'));
    
    // Verify message remains visible for adequate time
    await expect(notification).toBeVisible();
    await page.waitForTimeout(1000);
    await expect(notification).toBeVisible();
  });

  test('Verify error messages are accessible and comply with WCAG standards (error-case)', async ({ page }) => {
    // Navigate to shift template creation
    await page.goto(`${baseURL}/shift-templates`);
    await page.click('[data-testid="create-template-button"]');

    // Trigger an error condition by leaving required fields empty
    await page.click('[data-testid="save-template-button"]');

    // Verify error message has proper ARIA attributes
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible();
    await expect(notification).toHaveAttribute('role', 'alert');
    await expect(notification).toHaveAttribute('aria-live', 'assertive');

    // Verify error message is associated with form field
    const fieldError = page.locator('[data-testid="template-name-error"]');
    await expect(fieldError).toBeVisible();
    const inputField = page.locator('[data-testid="template-name-input"]');
    const ariaDescribedBy = await inputField.getAttribute('aria-describedby');
    expect(ariaDescribedBy).toBeTruthy();

    // Verify keyboard navigation
    await page.keyboard.press('Tab');
    const focusedElement = await page.locator(':focus');
    await expect(focusedElement).toBeVisible();
  });

  test('Verify notifications are displayed promptly after shift template creation (happy-path)', async ({ page }) => {
    // Navigate to shift template creation
    await page.goto(`${baseURL}/shift-templates`);
    await page.click('[data-testid="create-template-button"]');

    // Fill in all required fields
    await page.fill('[data-testid="template-name-input"]', 'Prompt Test Template');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.fill('[data-testid="break-duration"]', '60');

    // Measure time until notification appears
    const startTime = Date.now();
    await page.click('[data-testid="save-template-button"]');
    
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible({ timeout: 3000 });
    const endTime = Date.now();
    const responseTime = endTime - startTime;

    // Verify notification appears promptly (within 3 seconds)
    expect(responseTime).toBeLessThan(3000);

    // Verify no page refresh required
    const currentURL = page.url();
    expect(currentURL).toContain('shift-templates');
  });

  test('Verify notifications are displayed promptly after shift template update (happy-path)', async ({ page }) => {
    // Navigate to shift templates and open for editing
    await page.goto(`${baseURL}/shift-templates`);
    await page.waitForSelector('[data-testid="shift-templates-list"]');
    await page.locator('[data-testid="template-item"]').first().click();
    await page.click('[data-testid="edit-template-button"]');

    // Make changes
    await page.fill('[data-testid="template-name-input"]', 'Prompt Update Test');

    // Measure time until notification appears
    const startTime = Date.now();
    await page.click('[data-testid="save-template-button"]');
    
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible({ timeout: 3000 });
    const endTime = Date.now();
    const responseTime = endTime - startTime;

    // Verify notification appears immediately
    expect(responseTime).toBeLessThan(3000);
  });

  test('Verify notifications are displayed promptly after shift template deletion (happy-path)', async ({ page }) => {
    // Navigate to shift templates list
    await page.goto(`${baseURL}/shift-templates`);
    await page.waitForSelector('[data-testid="shift-templates-list"]');

    // Select a template to delete
    const templateToDelete = page.locator('[data-testid="template-item"]').first();
    await templateToDelete.locator('[data-testid="delete-template-button"]').click();

    // Measure time until notification appears
    const startTime = Date.now();
    await page.click('[data-testid="confirm-delete-button"]');
    
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible({ timeout: 3000 });
    const endTime = Date.now();
    const responseTime = endTime - startTime;

    // Verify notification appears immediately
    expect(responseTime).toBeLessThan(3000);

    // Verify template is removed from list
    await expect(templateToDelete).not.toBeVisible();
  });

  test('Verify notification messages comply with UI design standards and consistency (happy-path)', async ({ page }) => {
    // Perform shift template creation and observe success notification
    await page.goto(`${baseURL}/shift-templates`);
    await page.click('[data-testid="create-template-button"]');
    await page.fill('[data-testid="template-name-input"]', 'UI Standards Test');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.click('[data-testid="save-template-button"]');

    // Verify notification uses standard success color and icon
    const successNotification = page.locator('[data-testid="notification-message"]');
    await expect(successNotification).toBeVisible();
    await expect(successNotification).toHaveClass(/success/);
    const successIcon = successNotification.locator('[data-testid="notification-icon"]');
    await expect(successIcon).toBeVisible();

    // Get notification position for consistency check
    const successPosition = await successNotification.boundingBox();

    // Trigger an error condition
    await page.click('[data-testid="create-template-button"]');
    await page.click('[data-testid="save-template-button"]');

    // Verify error notification styling
    const errorNotification = page.locator('[data-testid="notification-message"]');
    await expect(errorNotification).toBeVisible();
    await expect(errorNotification).toHaveClass(/error/);

    // Verify notification positioning is consistent
    const errorPosition = await errorNotification.boundingBox();
    expect(errorPosition?.x).toBe(successPosition?.x);
    expect(errorPosition?.y).toBe(successPosition?.y);

    // Verify dismiss behavior
    const closeButton = errorNotification.locator('[data-testid="notification-close"]');
    if (await closeButton.isVisible()) {
      await closeButton.click();
      await expect(errorNotification).not.toBeVisible();
    }
  });

  test('Verify notification messages use modal dialogs appropriately for critical operations (happy-path)', async ({ page }) => {
    // Navigate to shift templates list
    await page.goto(`${baseURL}/shift-templates`);
    await page.waitForSelector('[data-testid="shift-templates-list"]');

    // Initiate deletion operation
    const templateToDelete = page.locator('[data-testid="template-item"]').first();
    await templateToDelete.locator('[data-testid="delete-template-button"]').click();

    // Verify modal dialog appears for confirmation
    const modal = page.locator('[data-testid="confirmation-modal"]');
    await expect(modal).toBeVisible();

    // Verify modal contains clear messaging
    await expect(modal).toContainText('Are you sure');
    await expect(modal).toContainText('delete');

    // Confirm deletion
    await page.click('[data-testid="confirm-delete-button"]');
    await expect(modal).not.toBeVisible();

    // Perform non-critical operation (creation)
    await page.click('[data-testid="create-template-button"]');
    await page.fill('[data-testid="template-name-input"]', 'Modal Test Template');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.click('[data-testid="save-template-button"]');

    // Verify modal is not used for creation
    await expect(modal).not.toBeVisible();
    const inlineNotification = page.locator('[data-testid="notification-message"]');
    await expect(inlineNotification).toBeVisible();
  });

  test('Verify notification messages use inline notifications appropriately for standard operations (happy-path)', async ({ page }) => {
    // Create a new shift template
    await page.goto(`${baseURL}/shift-templates`);
    await page.click('[data-testid="create-template-button"]');
    await page.fill('[data-testid="template-name-input"]', 'Inline Notification Test');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.click('[data-testid="save-template-button"]');

    // Observe the type of notification displayed
    const notification = page.locator('[data-testid="notification-message"]');
    await expect(notification).toBeVisible();

    // Verify inline notification does not block user interaction
    const createButton = page.locator('[data-testid="create-template-button"]');
    await expect(createButton).toBeEnabled();
    
    // Verify notification is positioned inline (not modal)
    const notificationBox = await notification.boundingBox();
    expect(notificationBox).toBeTruthy();

    // Update an existing template
    await page.locator('[data-testid="template-item"]').first().click();
    await page.click('[data-testid="edit-template-button"]');
    await page.fill('[data-testid="template-name-input"]', 'Updated Inline Test');
    await page.click('[data-testid="save-template-button"]');

    // Verify notification type for update operation
    await expect(notification).toBeVisible();

    // Check for auto-dismiss or close button
    const closeButton = notification.locator('[data-testid="notification-close"]');
    const hasCloseButton = await closeButton.isVisible();
    
    if (hasCloseButton) {
      await closeButton.click();
      await expect(notification).not.toBeVisible();
    } else {
      // Wait for auto-dismiss
      await page.waitForTimeout(5000);
      await expect(notification).not.toBeVisible();
    }

    // Verify notification appears in consistent location
    await page.click('[data-testid="create-template-button"]');
    await page.fill('[data-testid="template-name-input"]', 'Location Test');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.click('[data-testid="save-template-button"]');
    
    const newNotificationBox = await notification.boundingBox();
    expect(newNotificationBox?.x).toBe(notificationBox?.x);
    expect(newNotificationBox?.y).toBe(notificationBox?.y);
  });
});