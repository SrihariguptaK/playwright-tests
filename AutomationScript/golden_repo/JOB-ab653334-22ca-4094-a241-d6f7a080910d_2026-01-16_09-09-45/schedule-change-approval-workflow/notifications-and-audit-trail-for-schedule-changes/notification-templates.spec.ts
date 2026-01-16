import { test, expect } from '@playwright/test';

test.describe('Notification Templates Management', () => {
  const adminCredentials = {
    username: 'admin@example.com',
    password: 'AdminPass123!'
  };

  const nonAdminCredentials = {
    username: 'coordinator@example.com',
    password: 'CoordPass123!'
  };

  test('Validate creation and editing of notification templates', async ({ page }) => {
    // Step 1: Log in as System Administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Notification templates management page is accessible
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="administration-menu"]');
    await page.click('[data-testid="notification-templates-menu-item"]');
    await expect(page).toHaveURL(/.*notification-templates/);
    await expect(page.locator('[data-testid="notification-templates-page"]')).toBeVisible();

    // Step 2: Create a new template with placeholders
    await page.click('[data-testid="create-new-template-button"]');
    await expect(page.locator('[data-testid="template-creation-form"]')).toBeVisible();
    
    await page.fill('[data-testid="template-name-input"]', 'Schedule Change Approved');
    await page.selectOption('[data-testid="template-type-select"]', 'Approval Notification');
    await page.fill('[data-testid="template-subject-input"]', 'Your Schedule Change Request {{requestId}} has been Approved');
    await page.fill('[data-testid="template-body-textarea"]', 'Dear {{coordinatorName}}, Your schedule change request {{requestId}} submitted on {{submissionDate}} has been approved by {{approverName}} on {{approvalDate}}. Comments: {{approverComments}}');
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Template is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template saved successfully');
    await expect(page.locator('[data-testid="templates-list"]')).toContainText('Schedule Change Approved');

    // Step 3: Edit the template and save changes
    await page.locator('[data-testid="template-row"]', { hasText: 'Schedule Change Approved' }).locator('[data-testid="edit-template-button"]').click();
    await expect(page.locator('[data-testid="template-edit-form"]')).toBeVisible();
    
    await page.fill('[data-testid="template-subject-input"]', 'Schedule Change Request {{requestId}} - Approved');
    const currentBodyContent = await page.inputValue('[data-testid="template-body-textarea"]');
    await page.fill('[data-testid="template-body-textarea"]', currentBodyContent + ' Please review the updated schedule at your earliest convenience.');
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Changes are saved and reflected
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template updated successfully');
    
    // Verify changes are reflected
    await page.locator('[data-testid="template-row"]', { hasText: 'Schedule Change Approved' }).locator('[data-testid="edit-template-button"]').click();
    await expect(page.locator('[data-testid="template-subject-input"]')).toHaveValue('Schedule Change Request {{requestId}} - Approved');
    await expect(page.locator('[data-testid="template-body-textarea"]')).toContainText('Please review the updated schedule at your earliest convenience.');
  });

  test('Verify template preview functionality', async ({ page }) => {
    // Login as System Administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Navigate to notification templates management page
    await page.click('[data-testid="administration-menu"]');
    await page.click('[data-testid="notification-templates-menu-item"]');
    await expect(page).toHaveURL(/.*notification-templates/);

    // Step 1: Open a notification template in edit mode
    await page.locator('[data-testid="template-row"]', { hasText: 'Schedule Change Approved' }).locator('[data-testid="edit-template-button"]').click();
    
    // Expected Result: Template content is displayed
    await expect(page.locator('[data-testid="template-edit-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-subject-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-body-textarea"]')).toBeVisible();
    const templateContent = await page.locator('[data-testid="template-body-textarea"]').inputValue();
    expect(templateContent).toContain('{{');
    expect(templateContent).toContain('}}');

    // Step 2: Click preview with sample data
    await page.click('[data-testid="preview-with-sample-data-button"]');
    
    // Expected Result: Rendered template with placeholders replaced is displayed
    await expect(page.locator('[data-testid="template-preview-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="preview-subject"]')).toBeVisible();
    await expect(page.locator('[data-testid="preview-body"]')).toBeVisible();
    
    // Verify placeholders are replaced with sample data
    const previewSubject = await page.locator('[data-testid="preview-subject"]').textContent();
    const previewBody = await page.locator('[data-testid="preview-body"]').textContent();
    
    expect(previewSubject).not.toContain('{{');
    expect(previewSubject).not.toContain('}}');
    expect(previewBody).not.toContain('{{');
    expect(previewBody).not.toContain('}}');
    
    // Verify sample data is present
    expect(previewBody).toMatch(/Dear [A-Za-z]+/);
    expect(previewBody).toMatch(/request [A-Z0-9-]+/);
  });

  test('Ensure unauthorized users cannot manage templates', async ({ page, request }) => {
    // Step 1: Log in as non-admin user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', nonAdminCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAdminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Expected Result: Notification template management page is not accessible
    await page.goto('/admin/notification-templates');
    
    // Verify access is denied - either redirected or error message shown
    const currentUrl = page.url();
    const isAccessDenied = currentUrl.includes('unauthorized') || 
                          currentUrl.includes('access-denied') || 
                          !currentUrl.includes('notification-templates');
    
    if (currentUrl.includes('notification-templates')) {
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|permission/i);
    } else {
      expect(isAccessDenied).toBeTruthy();
    }

    // Step 2: Attempt to access template management API endpoints
    const authToken = await page.evaluate(() => {
      return localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
    });

    // Expected Result: Access is denied with appropriate error
    
    // Test GET /api/notification-templates
    const getResponse = await request.get('/api/notification-templates', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    expect(getResponse.status()).toBe(403);
    const getBody = await getResponse.json();
    expect(getBody.error || getBody.message).toMatch(/forbidden|unauthorized|access denied|permission/i);

    // Test POST /api/notification-templates
    const postResponse = await request.post('/api/notification-templates', {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        name: 'Unauthorized Template',
        type: 'Test',
        subject: 'Test Subject',
        body: 'Test Body'
      }
    });
    expect(postResponse.status()).toBe(403);
    const postBody = await postResponse.json();
    expect(postBody.error || postBody.message).toMatch(/forbidden|unauthorized|access denied|permission/i);

    // Test PUT /api/notification-templates/{id}
    const putResponse = await request.put('/api/notification-templates/1', {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        name: 'Updated Template',
        subject: 'Updated Subject'
      }
    });
    expect(putResponse.status()).toBe(403);
    const putBody = await putResponse.json();
    expect(putBody.error || putBody.message).toMatch(/forbidden|unauthorized|access denied|permission/i);

    // Test DELETE /api/notification-templates/{id}
    const deleteResponse = await request.delete('/api/notification-templates/1', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    expect(deleteResponse.status()).toBe(403);
    const deleteBody = await deleteResponse.json();
    expect(deleteBody.error || deleteBody.message).toMatch(/forbidden|unauthorized|access denied|permission/i);
  });
});