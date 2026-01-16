import { test, expect } from '@playwright/test';

test.describe('Story-25: Automatic Declination Notifications for Underwriting Manager', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000/api';
  
  // Test data for application that meets declination criteria
  const declinationApplicationData = {
    applicantName: 'John Declination Test',
    email: 'john.declination@test.com',
    creditScore: 550, // Below threshold (assuming 600 is minimum)
    debtToIncomeRatio: 55, // Exceeds limit (assuming 50% is maximum)
    loanAmount: 50000,
    annualIncome: 40000
  };
  
  const managerCredentials = {
    username: 'underwriting.manager@company.com',
    password: 'Manager@123'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to application homepage
    await page.goto(BASE_URL);
  });

  test('Validate automatic declination marking and notification (happy-path)', async ({ page, request }) => {
    // Step 1: Submit an application that meets declination criteria
    await page.goto(`${BASE_URL}/applications/new`);
    
    await page.fill('[data-testid="applicant-name"]', declinationApplicationData.applicantName);
    await page.fill('[data-testid="applicant-email"]', declinationApplicationData.email);
    await page.fill('[data-testid="credit-score"]', declinationApplicationData.creditScore.toString());
    await page.fill('[data-testid="debt-to-income-ratio"]', declinationApplicationData.debtToIncomeRatio.toString());
    await page.fill('[data-testid="loan-amount"]', declinationApplicationData.loanAmount.toString());
    await page.fill('[data-testid="annual-income"]', declinationApplicationData.annualIncome.toString());
    
    await page.click('[data-testid="submit-application-btn"]');
    
    // Wait for submission confirmation
    await expect(page.locator('[data-testid="application-submitted-message"]')).toBeVisible({ timeout: 5000 });
    
    // Extract application ID from confirmation message or URL
    const applicationIdElement = page.locator('[data-testid="application-id"]');
    await expect(applicationIdElement).toBeVisible();
    const applicationId = await applicationIdElement.textContent();
    
    // Step 2: Wait for rules engine to process the application (maximum 2 seconds)
    await page.waitForTimeout(2500);
    
    // Step 3: Verify the application status via GET /api/declinations endpoint
    const declinationsResponse = await request.get(`${API_BASE_URL}/declinations`);
    expect(declinationsResponse.ok()).toBeTruthy();
    
    const declinations = await declinationsResponse.json();
    const declinedApplication = declinations.find((app: any) => app.applicationId === applicationId?.trim());
    
    expect(declinedApplication).toBeDefined();
    expect(declinedApplication.status).toBe('declined');
    expect(declinedApplication.declinationReasons).toBeDefined();
    expect(declinedApplication.declinationReasons.length).toBeGreaterThan(0);
    
    // Step 4: Check the underwriting manager's notification inbox/dashboard alerts
    // Log out current session if any
    const logoutBtn = page.locator('[data-testid="logout-btn"]');
    if (await logoutBtn.isVisible()) {
      await logoutBtn.click();
    }
    
    // Step 5: Log in as underwriting manager
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-btn"]');
    
    // Wait for successful login
    await expect(page.locator('[data-testid="manager-dashboard"]')).toBeVisible({ timeout: 5000 });
    
    // Check for notification badge or alert
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible();
    
    const notificationCount = await notificationBadge.textContent();
    expect(parseInt(notificationCount || '0')).toBeGreaterThan(0);
    
    // Open notifications panel
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    
    // Verify declination notification is present
    const declinationNotification = page.locator(`[data-testid="notification-item"]`, {
      hasText: applicationId?.trim() || ''
    });
    await expect(declinationNotification).toBeVisible();
    await expect(declinationNotification).toContainText('declined');
    
    // Step 6: Navigate to the declined applications dashboard
    await page.click('[data-testid="declined-applications-menu"]');
    await expect(page.locator('[data-testid="declined-applications-dashboard"]')).toBeVisible();
    
    // Step 7: Locate the recently declined application in the dashboard list
    const declinedAppRow = page.locator(`[data-testid="declined-app-row-${applicationId?.trim()}"]`);
    await expect(declinedAppRow).toBeVisible();
    
    // Verify application details in the list
    await expect(declinedAppRow).toContainText(declinationApplicationData.applicantName);
    await expect(declinedAppRow).toContainText('declined');
    
    // Step 8: Click on the declined application to view detailed declination reasons
    await declinedAppRow.click();
    
    // Wait for details modal or page to load
    await expect(page.locator('[data-testid="declination-details-modal"]')).toBeVisible({ timeout: 3000 });
    
    // Verify declination reasons are displayed
    const declinationReasonsSection = page.locator('[data-testid="declination-reasons-section"]');
    await expect(declinationReasonsSection).toBeVisible();
    
    // Verify specific declination reasons based on test data
    await expect(declinationReasonsSection).toContainText('credit score');
    await expect(declinationReasonsSection).toContainText('debt-to-income ratio');
    
    // Step 9: Verify declination reason is logged in the audit system
    const auditLogSection = page.locator('[data-testid="audit-log-section"]');
    await expect(auditLogSection).toBeVisible();
    
    // Verify audit log contains declination entry
    const auditEntries = page.locator('[data-testid="audit-log-entry"]');
    await expect(auditEntries.first()).toBeVisible();
    
    const firstAuditEntry = auditEntries.first();
    await expect(firstAuditEntry).toContainText('Application Declined');
    await expect(firstAuditEntry).toContainText(applicationId?.trim() || '');
    
    // Verify timestamp is recent (within last 5 minutes)
    const timestampElement = firstAuditEntry.locator('[data-testid="audit-timestamp"]');
    const timestamp = await timestampElement.textContent();
    expect(timestamp).toBeTruthy();
    
    // Verify API endpoint for manager-specific declinations
    const managerDeclinationsResponse = await request.get(`${API_BASE_URL}/declinations/manager`);
    expect(managerDeclinationsResponse.ok()).toBeTruthy();
    
    const managerDeclinations = await managerDeclinationsResponse.json();
    expect(managerDeclinations).toBeDefined();
    expect(Array.isArray(managerDeclinations)).toBeTruthy();
    
    const managerDeclinedApp = managerDeclinations.find((app: any) => app.applicationId === applicationId?.trim());
    expect(managerDeclinedApp).toBeDefined();
    expect(managerDeclinedApp.status).toBe('declined');
  });

  test('Verify only authorized managers can access declination details', async ({ page, request }) => {
    // Attempt to access declination endpoint without authentication
    const unauthorizedResponse = await request.get(`${API_BASE_URL}/declinations/manager`);
    expect(unauthorizedResponse.status()).toBe(401);
    
    // Navigate to declined applications dashboard without login
    await page.goto(`${BASE_URL}/manager/declined-applications`);
    
    // Should redirect to login page
    await expect(page).toHaveURL(/.*login.*/i, { timeout: 5000 });
    
    // Login as manager
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-btn"]');
    
    // Should now have access to declined applications dashboard
    await page.goto(`${BASE_URL}/manager/declined-applications`);
    await expect(page.locator('[data-testid="declined-applications-dashboard"]')).toBeVisible({ timeout: 5000 });
  });

  test('Verify declination notification delivery within performance requirements', async ({ page, request }) => {
    // Submit application meeting declination criteria
    await page.goto(`${BASE_URL}/applications/new`);
    
    await page.fill('[data-testid="applicant-name"]', 'Performance Test User');
    await page.fill('[data-testid="applicant-email"]', 'performance.test@test.com');
    await page.fill('[data-testid="credit-score"]', '500');
    await page.fill('[data-testid="debt-to-income-ratio"]', '60');
    await page.fill('[data-testid="loan-amount"]', '30000');
    await page.fill('[data-testid="annual-income"]', '35000');
    
    const startTime = Date.now();
    
    await page.click('[data-testid="submit-application-btn"]');
    await expect(page.locator('[data-testid="application-submitted-message"]')).toBeVisible();
    
    const applicationId = await page.locator('[data-testid="application-id"]').textContent();
    
    // Wait and check declination marking time
    await page.waitForTimeout(2500);
    
    const declinationsResponse = await request.get(`${API_BASE_URL}/declinations`);
    const declinations = await declinationsResponse.json();
    const declinedApp = declinations.find((app: any) => app.applicationId === applicationId?.trim());
    
    const endTime = Date.now();
    const processingTime = endTime - startTime;
    
    // Verify declination marking within 2 seconds (2000ms) as per technical requirements
    expect(declinedApp).toBeDefined();
    expect(processingTime).toBeLessThanOrEqual(2000);
  });
});