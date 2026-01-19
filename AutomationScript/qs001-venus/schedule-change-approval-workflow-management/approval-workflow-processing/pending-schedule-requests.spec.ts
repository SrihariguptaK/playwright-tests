import { test, expect } from '@playwright/test';

test.describe('Pending Schedule Change Requests Dashboard', () => {
  
  test('Verify pending requests dashboard displays correct data', async ({ page }) => {
    // Action: Login as approver
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard page loads successfully
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="pending-requests-dashboard"]')).toBeVisible();
    
    // Action: View list of pending schedule change requests
    const requestsList = page.locator('[data-testid="pending-requests-list"]');
    await expect(requestsList).toBeVisible();
    
    // Expected Result: All assigned pending requests are displayed
    const requestItems = page.locator('[data-testid="request-item"]');
    await expect(requestItems).toHaveCountGreaterThan(0);
    
    // Verify request contains expected information
    const firstRequest = requestItems.first();
    await expect(firstRequest.locator('[data-testid="employee-name"]')).toBeVisible();
    await expect(firstRequest.locator('[data-testid="request-date"]')).toBeVisible();
    await expect(firstRequest.locator('[data-testid="request-status"]')).toContainText('Pending');
    
    // Action: Select a request to view details
    await firstRequest.click();
    
    // Expected Result: Request details and attachments are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-details-employee"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-details-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-details-reason"]')).toBeVisible();
    
    const attachmentsSection = page.locator('[data-testid="request-attachments"]');
    if (await attachmentsSection.isVisible()) {
      await expect(attachmentsSection).toBeVisible();
    }
  });
  
  test('Test filtering functionality on dashboard', async ({ page }) => {
    // Login as approver
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Get initial count of requests
    const requestItems = page.locator('[data-testid="request-item"]');
    const initialCount = await requestItems.count();
    
    // Action: Apply filter by employee name
    await page.fill('[data-testid="filter-employee-name"]', 'John Smith');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Expected Result: Dashboard shows only requests matching the employee
    await page.waitForTimeout(500); // Wait for filter to apply
    const filteredByEmployee = page.locator('[data-testid="request-item"]');
    const filteredCount = await filteredByEmployee.count();
    
    if (filteredCount > 0) {
      const employeeNames = filteredByEmployee.locator('[data-testid="employee-name"]');
      for (let i = 0; i < await employeeNames.count(); i++) {
        await expect(employeeNames.nth(i)).toContainText('John Smith');
      }
    }
    
    // Action: Apply filter by date range
    await page.fill('[data-testid="filter-date-start"]', '2024-01-01');
    await page.fill('[data-testid="filter-date-end"]', '2024-12-31');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Expected Result: Dashboard shows requests within the specified dates
    await page.waitForTimeout(500); // Wait for filter to apply
    const filteredByDate = page.locator('[data-testid="request-item"]');
    await expect(filteredByDate.first()).toBeVisible();
    
    // Action: Clear filters
    await page.click('[data-testid="clear-filters-button"]');
    
    // Expected Result: Dashboard shows all pending requests
    await page.waitForTimeout(500); // Wait for filters to clear
    const allRequests = page.locator('[data-testid="request-item"]');
    const finalCount = await allRequests.count();
    expect(finalCount).toBeGreaterThanOrEqual(filteredCount);
    
    // Verify employee name filter is cleared
    await expect(page.locator('[data-testid="filter-employee-name"]')).toHaveValue('');
  });
  
  test('Ensure unauthorized users cannot access dashboard', async ({ page, request }) => {
    // Action: Login as non-approver user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access to dashboard is denied
    await page.goto('/dashboard/pending-requests');
    
    // Check for access denied message or redirect
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedMessage = page.locator('text=/unauthorized|access denied|forbidden/i');
    
    const isAccessDenied = await accessDeniedMessage.isVisible().catch(() => false);
    const isUnauthorized = await unauthorizedMessage.isVisible().catch(() => false);
    const isRedirected = !page.url().includes('pending-requests');
    
    expect(isAccessDenied || isUnauthorized || isRedirected).toBeTruthy();
    
    // Action: Attempt to access API endpoint directly
    const cookies = await page.context().cookies();
    const authToken = cookies.find(c => c.name === 'authToken' || c.name === 'token')?.value || '';
    
    const apiResponse = await request.get('/api/schedule-change-requests?status=pending&approverId=123', {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      failOnStatusCode: false
    });
    
    // Expected Result: API returns authorization error
    expect([401, 403]).toContain(apiResponse.status());
    
    const responseBody = await apiResponse.json().catch(() => ({}));
    expect(responseBody.error || responseBody.message).toMatch(/unauthorized|forbidden|access denied/i);
  });
  
});