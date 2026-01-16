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

  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('Validate creation and editing of notification templates', async ({ page }) => {
    // Step 1: Log in as System Administrator
    await page.fill('input[name="username"]', adminCredentials.username);
    await page.fill('input[name="password"]', adminCredentials.password);
    await page.click('button[type="submit"]');
    
    // Wait for navigation and verify login success
    await page.waitForURL('**/dashboard');
    
    // Navigate to Notification Templates management page
    await page.click('text=Admin');
    await page.click('text=Notification Templates');
    
    // Expected Result: Notification templates management page is accessible
    await expect(page.locator('h1')).toContainText('Notification Templates');
    await expect(page.locator('[data-testid="create-template-button"]')).toBeVisible();

    // Step 2: Create a new template with placeholders
    await page.click('[data-testid="create-template-button"]');
    
    await page.fill('[data-testid="template-name-input"]', 'Schedule Change Approved');
    await page.selectOption('[data-testid="template-type-select"]', 'Email');
    await page.fill('[data-testid="template-subject-input"]', 'Your schedule change request {{requestId}} has been approved');
    await page.fill('[data-testid="template-body-input"]', 'Dear {{userName}}, Your request for {{scheduleDate}} has been approved by {{approverName}} on {{approvalDate}}');
    
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Template is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template saved successfully');
    await expect(page.locator('text=Schedule Change Approved')).toBeVisible();

    // Step 3: Edit the template and save changes
    await page.click('text=Schedule Change Approved');
    
    // Verify template content is displayed in edit mode
    await expect(page.locator('[data-testid="template-name-input"]')).toHaveValue('Schedule Change Approved');
    
    // Modify the template
    await page.fill('[data-testid="template-subject-input"]', 'Schedule Change Request {{requestId}} - Approved');
    
    const currentBodyText = await page.inputValue('[data-testid="template-body-input"]');
    await page.fill('[data-testid="template-body-input"]', currentBodyText + ' Please review the updated schedule in your dashboard');
    
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Changes are saved and reflected
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template updated successfully');
    
    // Verify changes are reflected
    await page.click('text=Schedule Change Approved');
    await expect(page.locator('[data-testid="template-subject-input"]')).toHaveValue('Schedule Change Request {{requestId}} - Approved');
    await expect(page.locator('[data-testid="template-body-input"]')).toContainText('Please review the updated schedule in your dashboard');
  });

  test('Verify template preview functionality', async ({ page }) => {
    // Step 1: Log in as System Administrator
    await page.fill('input[name="username"]', adminCredentials.username);
    await page.fill('input[name="password"]', adminCredentials.password);
    await page.click('button[type="submit"]');
    
    await page.waitForURL('**/dashboard');
    
    // Navigate to Notification Templates management page
    await page.click('text=Admin');
    await page.click('text=Notification Templates');
    
    // Locate an existing template and open in edit mode
    await page.click('[data-testid="template-list-item"]:first-child');
    
    // Expected Result: Template content is displayed
    await expect(page.locator('[data-testid="template-name-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-subject-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-body-input"]')).toBeVisible();

    // Step 2: Click preview with sample data
    await page.click('[data-testid="preview-template-button"]');
    
    // Expected Result: Rendered template with placeholders replaced is displayed
    await expect(page.locator('[data-testid="template-preview-modal"]')).toBeVisible();
    
    // Verify placeholders are replaced with sample data
    const previewContent = page.locator('[data-testid="preview-content"]');
    await expect(previewContent).toBeVisible();
    
    // Verify no unreplaced placeholders remain (no {{}} patterns)
    const previewText = await previewContent.textContent();
    expect(previewText).not.toContain('{{');
    expect(previewText).not.toContain('}}');
    
    // Verify preview renders within performance requirement
    const startTime = Date.now();
    await page.click('[data-testid="preview-template-button"]');
    await page.waitForSelector('[data-testid="preview-content"]');
    const renderTime = Date.now() - startTime;
    expect(renderTime).toBeLessThan(1000);
  });

  test('Ensure unauthorized users cannot manage templates', async ({ page, request }) => {
    // Step 1: Log in as non-admin user
    await page.fill('input[name="username"]', nonAdminCredentials.username);
    await page.fill('input[name="password"]', nonAdminCredentials.password);
    await page.click('button[type="submit"]');
    
    await page.waitForURL('**/dashboard');
    
    // Expected Result: Notification template management page is not accessible
    // Attempt to navigate to template management page via URL
    await page.goto('/admin/notification-templates');
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('text=Access Denied')).toBeVisible();
    
    // Verify user is redirected or shown error
    const currentUrl = page.url();
    expect(currentUrl).not.toContain('/admin/notification-templates');

    // Step 2: Attempt to access template management API endpoints
    const authToken = await page.evaluate(() => localStorage.getItem('authToken'));
    
    // Test GET /api/notification-templates
    const getResponse = await request.get('/api/notification-templates', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    // Expected Result: Access is denied with appropriate error
    expect(getResponse.status()).toBe(403);
    const getBody = await getResponse.json();
    expect(getBody.error).toContain('Access denied');
    
    // Test POST /api/notification-templates
    const postResponse = await request.post('/api/notification-templates', {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        name: 'Unauthorized Template',
        type: 'Email',
        subject: 'Test Subject',
        body: 'Test Body'
      }
    });
    
    expect(postResponse.status()).toBe(403);
    const postBody = await postResponse.json();
    expect(postBody.error).toContain('Access denied');
    
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
    expect(putBody.error).toContain('Access denied');
    
    // Test DELETE /api/notification-templates/{id}
    const deleteResponse = await request.delete('/api/notification-templates/1', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    expect(deleteResponse.status()).toBe(403);
    const deleteBody = await deleteResponse.json();
    expect(deleteBody.error).toContain('Access denied');
  });
});