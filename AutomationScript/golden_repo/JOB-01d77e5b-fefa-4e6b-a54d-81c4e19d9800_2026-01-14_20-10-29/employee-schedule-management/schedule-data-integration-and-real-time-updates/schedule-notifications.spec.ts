import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications', () => {
  const ADMIN_EMAIL = 'admin@company.com';
  const ADMIN_PASSWORD = 'Admin123!';
  const EMPLOYEE_EMAIL = 'employee@company.com';
  const EMPLOYEE_PASSWORD = 'Employee123!';
  const EMPLOYEE_B_EMAIL = 'employeeb@company.com';
  const EMPLOYEE_B_PASSWORD = 'EmployeeB123!';
  const BASE_URL = 'http://localhost:3000';

  test('Validate schedule change notification delivery (happy-path)', async ({ page, context }) => {
    // Step 1: Administrator/Manager accesses the schedule management system and updates the employee's schedule
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule management
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-page"]')).toBeVisible();
    
    // Find and update employee's schedule
    await page.fill('[data-testid="employee-search-input"]', EMPLOYEE_EMAIL);
    await page.click('[data-testid="search-button"]');
    await page.click('[data-testid="edit-schedule-button"]');
    
    // Change shift time from 9:00 AM to 10:00 AM
    await page.selectOption('[data-testid="shift-start-time"]', '10:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Notification generated and queued
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');
    
    // Logout admin
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 2: Wait for notification processing (maximum 1 minute)
    await page.waitForTimeout(5000); // Wait 5 seconds for notification processing
    
    // Step 3: Employee logs into the web interface using valid credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Notification alert displayed
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="notification-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();
    
    // Step 4: Employee clicks on the notification alert to view details
    await page.click('[data-testid="notification-alert"]');
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-message"]')).toContainText('schedule');
    await expect(page.locator('[data-testid="notification-message"]')).toContainText('10:00');
    
    // Step 5: Employee clicks the 'Mark as Read' button on the notification
    await page.click('[data-testid="mark-as-read-button"]');
    
    // Expected Result: Notification marked read and archived
    await expect(page.locator('[data-testid="notification-read-status"]')).toContainText('Read');
    
    // Step 6: Employee navigates to the notification history section
    await page.click('[data-testid="notification-history-link"]');
    await expect(page.locator('[data-testid="notification-history-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-history-list"]')).toContainText('schedule');
    await expect(page.locator('[data-testid="archived-notification"]')).toBeVisible();
  });

  test('Verify notification access control (error-case)', async ({ page, request }) => {
    // Step 1: Employee B is logged in
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', EMPLOYEE_B_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_B_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Get Employee A's ID (simulated - in real scenario this would be obtained through unauthorized means)
    const employeeAId = 'employee-a-id-12345';
    
    // Step 2: Employee B attempts to access the notifications endpoint for Employee A by manipulating the URL or API request
    const response = await request.get(`${BASE_URL}/api/notifications/schedule-changes?employeeId=${employeeAId}`, {
      failOnStatusCode: false
    });
    
    // Expected Result: Access denied
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Access denied');
    
    // Attempt to access via URL manipulation
    await page.goto(`${BASE_URL}/notifications?employeeId=${employeeAId}`);
    
    // Expected Result: System processes the unauthorized access request and denies access
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Access denied');
    
    // Step 3: Verify that Employee B can only see their own notifications by navigating to their notification page
    await page.goto(`${BASE_URL}/notifications`);
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    
    // Verify only Employee B's notifications are visible
    const notifications = page.locator('[data-testid="notification-item"]');
    const notificationCount = await notifications.count();
    
    for (let i = 0; i < notificationCount; i++) {
      const notification = notifications.nth(i);
      const employeeId = await notification.getAttribute('data-employee-id');
      expect(employeeId).not.toBe(employeeAId);
    }
    
    // Step 4: Check system logs for the unauthorized access attempt (verify through admin panel or API)
    // Note: This would typically require admin access or a separate monitoring endpoint
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as admin to check logs
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="security-logs-link"]');
    
    // Verify unauthorized access attempt is logged
    await page.fill('[data-testid="log-search-input"]', EMPLOYEE_B_EMAIL);
    await page.click('[data-testid="search-logs-button"]');
    
    await expect(page.locator('[data-testid="log-entry"]').first()).toContainText('Unauthorized access attempt');
    await expect(page.locator('[data-testid="log-entry"]').first()).toContainText(employeeAId);
  });
});