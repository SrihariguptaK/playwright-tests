import { test, expect } from '@playwright/test';

test.describe('Shift Template Deletion Protection', () => {
  let baseURL: string;

  test.beforeEach(async ({ page }) => {
    baseURL = process.env.BASE_URL || 'http://localhost:3000';
    // Login as HR Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'HRManager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify system blocks deletion of shift template assigned to active schedules', async ({ page }) => {
    // Navigate to the Shift Templates management page
    await page.goto(`${baseURL}/shift-templates`);
    await expect(page.locator('[data-testid="shift-templates-page"]')).toBeVisible();

    // Identify a shift template that is assigned to active schedules
    const assignedTemplate = page.locator('[data-testid="template-row"]').filter({ has: page.locator('[data-testid="status-assigned"]') }).first();
    await expect(assignedTemplate).toBeVisible();

    // Click on the delete button/icon for the selected shift template
    await assignedTemplate.locator('[data-testid="delete-template-button"]').click();

    // Observe the system response and verify the deletion is blocked
    const warningDialog = page.locator('[data-testid="deletion-blocked-dialog"]');
    await expect(warningDialog).toBeVisible();
    await expect(warningDialog.locator('[data-testid="warning-message"]')).toContainText('cannot be deleted');
    await expect(warningDialog.locator('[data-testid="warning-message"]')).toContainText('assigned to active schedules');

    // Click OK or Close on the warning message
    await warningDialog.locator('[data-testid="close-dialog-button"]').click();
    await expect(warningDialog).not.toBeVisible();

    // Verify template still exists in the list
    await expect(assignedTemplate).toBeVisible();
  });

  test('Verify system allows deletion of shift template not assigned to any schedules', async ({ page }) => {
    // Navigate to the Shift Templates management page
    await page.goto(`${baseURL}/shift-templates`);
    await expect(page.locator('[data-testid="shift-templates-page"]')).toBeVisible();

    // Identify a shift template that is not assigned to any schedules
    const unassignedTemplate = page.locator('[data-testid="template-row"]').filter({ has: page.locator('[data-testid="status-unassigned"]') }).first();
    await expect(unassignedTemplate).toBeVisible();
    const templateName = await unassignedTemplate.locator('[data-testid="template-name"]').textContent();

    // Click on the delete button/icon for the unassigned shift template
    await unassignedTemplate.locator('[data-testid="delete-template-button"]').click();

    // Observe the system response
    const confirmDialog = page.locator('[data-testid="confirm-deletion-dialog"]');
    await expect(confirmDialog).toBeVisible();

    // Click 'Confirm' or 'Yes' on the confirmation dialog
    await confirmDialog.locator('[data-testid="confirm-button"]').click();

    // Observe the deletion result
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('successfully deleted');

    // Verify the template is no longer in the list
    await expect(page.locator('[data-testid="template-row"]').filter({ hasText: templateName || '' })).not.toBeVisible();
  });

  test('Verify system logs deletion attempts for templates assigned to active schedules', async ({ page }) => {
    // Navigate to the Shift Templates management page
    await page.goto(`${baseURL}/shift-templates`);
    await expect(page.locator('[data-testid="shift-templates-page"]')).toBeVisible();

    // Note the current timestamp and the shift template ID to be deleted
    const timestamp = new Date();
    const assignedTemplate = page.locator('[data-testid="template-row"]').filter({ has: page.locator('[data-testid="status-assigned"]') }).first();
    const templateId = await assignedTemplate.getAttribute('data-template-id');

    // Attempt to delete a shift template that is assigned to active schedules
    await assignedTemplate.locator('[data-testid="delete-template-button"]').click();
    const warningDialog = page.locator('[data-testid="deletion-blocked-dialog"]');
    await expect(warningDialog).toBeVisible();

    // Close the warning message
    await warningDialog.locator('[data-testid="close-dialog-button"]').click();

    // Navigate to the audit logs or system logs section
    await page.goto(`${baseURL}/audit-logs`);
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Search for the deletion attempt using the template ID and timestamp
    await page.fill('[data-testid="search-template-id"]', templateId || '');
    await page.click('[data-testid="search-button"]');

    // Verify the log entry contains required information
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-user-id"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-template-id"]')).toContainText(templateId || '');
    await expect(logEntry.locator('[data-testid="log-action"]')).toContainText('DELETE');
    await expect(logEntry.locator('[data-testid="log-outcome"]')).toContainText('BLOCKED');
    await expect(logEntry.locator('[data-testid="log-reason"]')).toContainText('assigned to active schedules');
  });

  test('Verify system logs successful deletion of unassigned templates', async ({ page }) => {
    // Navigate to the Shift Templates management page
    await page.goto(`${baseURL}/shift-templates`);
    await expect(page.locator('[data-testid="shift-templates-page"]')).toBeVisible();

    // Note the current timestamp and the shift template ID to be deleted
    const timestamp = new Date();
    const unassignedTemplate = page.locator('[data-testid="template-row"]').filter({ has: page.locator('[data-testid="status-unassigned"]') }).first();
    const templateId = await unassignedTemplate.getAttribute('data-template-id');

    // Delete a shift template that is not assigned to any schedules
    await unassignedTemplate.locator('[data-testid="delete-template-button"]').click();
    const confirmDialog = page.locator('[data-testid="confirm-deletion-dialog"]');
    await confirmDialog.locator('[data-testid="confirm-button"]').click();
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate to the audit logs or system logs section
    await page.goto(`${baseURL}/audit-logs`);
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Search for the deletion event using the template ID and timestamp
    await page.fill('[data-testid="search-template-id"]', templateId || '');
    await page.click('[data-testid="search-button"]');

    // Verify the log entry contains required information
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-user-id"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-template-id"]')).toContainText(templateId || '');
    await expect(logEntry.locator('[data-testid="log-action"]')).toContainText('DELETE');
    await expect(logEntry.locator('[data-testid="log-outcome"]')).toContainText('SUCCESS');
  });

  test('Verify warning message clarity when attempting to delete assigned template', async ({ page }) => {
    // Navigate to the Shift Templates management page
    await page.goto(`${baseURL}/shift-templates`);
    await expect(page.locator('[data-testid="shift-templates-page"]')).toBeVisible();

    // Attempt to delete a shift template assigned to active schedules
    const assignedTemplate = page.locator('[data-testid="template-row"]').filter({ has: page.locator('[data-testid="status-assigned"]') }).first();
    await assignedTemplate.locator('[data-testid="delete-template-button"]').click();

    // Read and verify the warning message content
    const warningDialog = page.locator('[data-testid="deletion-blocked-dialog"]');
    await expect(warningDialog).toBeVisible();
    const warningMessage = warningDialog.locator('[data-testid="warning-message"]');
    await expect(warningMessage).toContainText('cannot be deleted');
    await expect(warningMessage).toContainText('assigned to active schedules');

    // Verify the warning dialog has appropriate buttons
    const closeButton = warningDialog.locator('[data-testid="close-dialog-button"]');
    await expect(closeButton).toBeVisible();
    await expect(closeButton).toHaveText(/OK|Close|Cancel/i);

    // Check if the warning message includes the number of active schedules
    await expect(warningMessage).toMatch(/\d+\s+(schedule|schedules)/i);

    await closeButton.click();
  });

  test('Verify real-time usage check performance when deleting template', async ({ page }) => {
    // Navigate to the Shift Templates management page
    await page.goto(`${baseURL}/shift-templates`);
    await expect(page.locator('[data-testid="shift-templates-page"]')).toBeVisible();

    // Test assigned template deletion performance
    const assignedTemplate = page.locator('[data-testid="template-row"]').filter({ has: page.locator('[data-testid="status-assigned"]') }).first();
    const startTime1 = Date.now();
    await assignedTemplate.locator('[data-testid="delete-template-button"]').click();
    await expect(page.locator('[data-testid="deletion-blocked-dialog"]')).toBeVisible();
    const endTime1 = Date.now();
    const responseTime1 = endTime1 - startTime1;

    // Close the warning dialog
    await page.locator('[data-testid="close-dialog-button"]').click();

    // Test unassigned template deletion performance
    const unassignedTemplate = page.locator('[data-testid="template-row"]').filter({ has: page.locator('[data-testid="status-unassigned"]') }).first();
    const startTime2 = Date.now();
    await unassignedTemplate.locator('[data-testid="delete-template-button"]').click();
    await expect(page.locator('[data-testid="confirm-deletion-dialog"]')).toBeVisible();
    const endTime2 = Date.now();
    const responseTime2 = endTime2 - startTime2;

    // Verify response times are within acceptable range (< 2000ms)
    expect(responseTime1).toBeLessThan(2000);
    expect(responseTime2).toBeLessThan(2000);

    await page.locator('[data-testid="cancel-button"]').click();
  });

  test('Verify role-based access control for template deletion', async ({ page }) => {
    // Logout current user
    await page.goto(`${baseURL}/logout`);

    // Login with a user account that does not have HR Manager role
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'regular.employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to the Shift Templates management page
    const response = await page.goto(`${baseURL}/shift-templates`);

    // Verify access is restricted
    if (response?.status() === 403 || response?.status() === 401) {
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    } else {
      // If page is accessible, verify that delete buttons are not present or disabled
      const deleteButtons = page.locator('[data-testid="delete-template-button"]');
      const count = await deleteButtons.count();
      if (count > 0) {
        await expect(deleteButtons.first()).toBeDisabled();
      } else {
        expect(count).toBe(0);
      }
    }
  });

  test('Verify system behavior when template becomes assigned between check and deletion', async ({ page, context }) => {
    // Navigate to the Shift Templates management page
    await page.goto(`${baseURL}/shift-templates`);
    await expect(page.locator('[data-testid="shift-templates-page"]')).toBeVisible();

    // Identify an unassigned shift template and initiate deletion
    const unassignedTemplate = page.locator('[data-testid="template-row"]').filter({ has: page.locator('[data-testid="status-unassigned"]') }).first();
    const templateId = await unassignedTemplate.getAttribute('data-template-id');
    await unassignedTemplate.locator('[data-testid="delete-template-button"]').click();
    const confirmDialog = page.locator('[data-testid="confirm-deletion-dialog"]');
    await expect(confirmDialog).toBeVisible();

    // Simulate another user assigning this template to an active schedule
    const newPage = await context.newPage();
    await newPage.goto(`${baseURL}/login`);
    await newPage.fill('[data-testid="email-input"]', 'hr.manager2@company.com');
    await newPage.fill('[data-testid="password-input"]', 'HRManager123!');
    await newPage.click('[data-testid="login-button"]');
    await newPage.goto(`${baseURL}/schedules/create`);
    await newPage.selectOption('[data-testid="template-select"]', templateId || '');
    await newPage.click('[data-testid="save-schedule-button"]');
    await newPage.close();

    // Click 'Confirm' on the deletion dialog
    await confirmDialog.locator('[data-testid="confirm-button"]').click();

    // Observe the system response - should show error or warning
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText('cannot be deleted');

    // Verify the template remains in the system
    await page.reload();
    const templateRow = page.locator(`[data-testid="template-row"][data-template-id="${templateId}"]`);
    await expect(templateRow).toBeVisible();
  });

  test('Verify system behavior when attempting to delete multiple templates simultaneously', async ({ page }) => {
    // Navigate to the Shift Templates management page
    await page.goto(`${baseURL}/shift-templates`);
    await expect(page.locator('[data-testid="shift-templates-page"]')).toBeVisible();

    // Select multiple shift templates including both assigned and unassigned
    const assignedTemplate = page.locator('[data-testid="template-row"]').filter({ has: page.locator('[data-testid="status-assigned"]') }).first();
    const unassignedTemplate = page.locator('[data-testid="template-row"]').filter({ has: page.locator('[data-testid="status-unassigned"]') }).first();
    
    await assignedTemplate.locator('[data-testid="template-checkbox"]').check();
    await unassignedTemplate.locator('[data-testid="template-checkbox"]').check();

    // Click the bulk delete button
    await page.click('[data-testid="bulk-delete-button"]');

    // Observe the system response
    const bulkDeleteDialog = page.locator('[data-testid="bulk-delete-dialog"]');
    await expect(bulkDeleteDialog).toBeVisible();

    // Verify the message lists assigned templates that will be skipped
    const warningMessage = bulkDeleteDialog.locator('[data-testid="bulk-warning-message"]');
    await expect(warningMessage).toContainText('assigned');
    await expect(warningMessage).toContainText('skipped');

    // Confirm the bulk deletion
    await bulkDeleteDialog.locator('[data-testid="confirm-bulk-delete-button"]').click();

    // Verify the results
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(assignedTemplate).toBeVisible(); // Assigned template should remain
    await expect(unassignedTemplate).not.toBeVisible(); // Unassigned template should be deleted
  });

  test('Verify system behavior when template is assigned to inactive schedules', async ({ page }) => {
    // Navigate to the Shift Templates management page
    await page.goto(`${baseURL}/shift-templates`);
    await expect(page.locator('[data-testid="shift-templates-page"]')).toBeVisible();

    // Identify a shift template assigned only to inactive or past schedules
    const inactiveTemplate = page.locator('[data-testid="template-row"]').filter({ has: page.locator('[data-testid="status-inactive-only"]') }).first();
    await expect(inactiveTemplate).toBeVisible();
    const templateName = await inactiveTemplate.locator('[data-testid="template-name"]').textContent();

    // Click on the delete button for this template
    await inactiveTemplate.locator('[data-testid="delete-template-button"]').click();

    // Observe the system response - should allow deletion
    const confirmDialog = page.locator('[data-testid="confirm-deletion-dialog"]');
    await expect(confirmDialog).toBeVisible();

    // Confirm the deletion
    await confirmDialog.locator('[data-testid="confirm-button"]').click();

    // Verify the template is removed from the list
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-row"]').filter({ hasText: templateName || '' })).not.toBeVisible();
  });

  test('Verify API endpoint returns correct error code when deleting assigned template', async ({ request }) => {
    // Identify the ID of a shift template assigned to active schedules
    const templateId = 'assigned-template-123';

    // Send DELETE request with valid authentication token
    const response = await request.delete(`${baseURL}/api/shifttemplates/${templateId}`, {
      headers: {
        'Authorization': 'Bearer valid-hr-manager-token',
        'Content-Type': 'application/json'
      }
    });

    // Verify the HTTP response status code
    expect(response.status()).toBe(409); // Conflict or 400 Bad Request

    // Verify the response body contains error details
    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/cannot be deleted|assigned to active schedules/i);

    // Verify the response includes appropriate error code
    expect(responseBody).toHaveProperty('errorCode');
    expect(responseBody.errorCode).toMatch(/TEMPLATE_IN_USE|DELETION_BLOCKED/i);

    // Verify the template still exists
    const getResponse = await request.get(`${baseURL}/api/shifttemplates/${templateId}`, {
      headers: {
        'Authorization': 'Bearer valid-hr-manager-token'
      }
    });
    expect(getResponse.status()).toBe(200);
  });

  test('Verify API endpoint returns success when deleting unassigned template', async ({ request }) => {
    // Identify the ID of a shift template not assigned to any schedules
    const templateId = 'unassigned-template-456';

    // Send DELETE request with valid authentication token
    const response = await request.delete(`${baseURL}/api/shifttemplates/${templateId}`, {
      headers: {
        'Authorization': 'Bearer valid-hr-manager-token',
        'Content-Type': 'application/json'
      }
    });

    // Verify the HTTP response status code
    expect(response.status()).toBe(200);

    // Verify the response body contains success confirmation
    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('success');
    expect(responseBody.success).toBe(true);
    expect(responseBody).toHaveProperty('message');
    expect(responseBody.message).toMatch(/successfully deleted|deleted successfully/i);

    // Send GET request to verify the template is removed
    const getResponse = await request.get(`${baseURL}/api/shifttemplates/${templateId}`, {
      headers: {
        'Authorization': 'Bearer valid-hr-manager-token'
      }
    });
    expect(getResponse.status()).toBe(404);
  });
});