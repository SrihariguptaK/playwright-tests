import { test, expect } from '@playwright/test';

test.describe('Attendance Anomaly Alerts - Story 7', () => {
  const supervisorEmail = 'supervisor@company.com';
  const supervisorPassword = 'SupervisorPass123';
  const nonSupervisorEmail = 'employee@company.com';
  const nonSupervisorPassword = 'EmployeePass123';
  const baseURL = 'https://attendance.company.com';

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Detect and alert missing attendance records (happy-path)', async ({ page }) => {
    // Step 1: Simulate missing attendance record for an employee
    // Ensure no check-in/check-out entry exists for a scheduled work day
    await page.goto(`${baseURL}/admin/test-data`);
    await page.fill('[data-testid="employee-id-input"]', 'EMP001');
    await page.fill('[data-testid="work-date-input"]', '2024-01-15');
    await page.click('[data-testid="remove-attendance-record-btn"]');
    
    // Wait for anomaly detection system to process (simulated)
    await page.waitForTimeout(2000);
    
    // Expected Result: System detects anomaly and generates alert
    const response = await page.request.get(`${baseURL}/api/attendance/anomalies`);
    expect(response.ok()).toBeTruthy();
    const anomalies = await response.json();
    expect(anomalies.some((a: any) => a.type === 'MISSING_RECORD' && a.employeeId === 'EMP001')).toBeTruthy();

    // Step 2: Login as Supervisor and check email inbox and system notification panel
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', supervisorEmail);
    await page.fill('[data-testid="password-input"]', supervisorPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Check system notification panel
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    const missingRecordAlert = page.locator('[data-testid="anomaly-alert"]').filter({ hasText: 'Missing attendance record' });
    await expect(missingRecordAlert).toBeVisible();
    
    // Expected Result: Alert contains detailed information about the missing record
    await expect(missingRecordAlert).toContainText('EMP001');
    await expect(missingRecordAlert).toContainText('2024-01-15');
    await expect(missingRecordAlert).toContainText('Missing attendance record');

    // Step 3: Navigate to the anomaly details page and click 'Mark as Resolved' button
    await missingRecordAlert.click();
    await expect(page.locator('[data-testid="anomaly-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="anomaly-type"]')).toContainText('MISSING_RECORD');
    await expect(page.locator('[data-testid="employee-id"]')).toContainText('EMP001');
    await expect(page.locator('[data-testid="suggested-action"]')).toBeVisible();
    
    await page.click('[data-testid="mark-resolved-button"]');
    
    // Expected Result: Anomaly status updated and alert cleared
    await expect(page.locator('[data-testid="anomaly-status"]')).toContainText('Resolved');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Anomaly marked as resolved');
    
    // Verify alert is cleared from notification panel
    await page.click('[data-testid="notifications-icon"]');
    const resolvedAlert = page.locator('[data-testid="anomaly-alert"]').filter({ hasText: 'EMP001' });
    await expect(resolvedAlert).toHaveCount(0);
  });

  test('Detect and alert duplicate attendance entries (happy-path)', async ({ page }) => {
    // Step 1: Create duplicate attendance entries for an employee
    // Submit two identical check-in/check-out records for the same date and time
    await page.goto(`${baseURL}/admin/test-data`);
    
    const attendanceData = {
      employeeId: 'EMP002',
      date: '2024-01-16',
      checkIn: '09:00',
      checkOut: '17:00'
    };
    
    // Create first entry
    await page.fill('[data-testid="employee-id-input"]', attendanceData.employeeId);
    await page.fill('[data-testid="attendance-date-input"]', attendanceData.date);
    await page.fill('[data-testid="check-in-time-input"]', attendanceData.checkIn);
    await page.fill('[data-testid="check-out-time-input"]', attendanceData.checkOut);
    await page.click('[data-testid="submit-attendance-btn"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record created');
    
    // Create duplicate entry
    await page.fill('[data-testid="employee-id-input"]', attendanceData.employeeId);
    await page.fill('[data-testid="attendance-date-input"]', attendanceData.date);
    await page.fill('[data-testid="check-in-time-input"]', attendanceData.checkIn);
    await page.fill('[data-testid="check-out-time-input"]', attendanceData.checkOut);
    await page.click('[data-testid="submit-attendance-btn"]');
    
    // Wait for anomaly detection
    await page.waitForTimeout(2000);
    
    // Expected Result: System detects duplicates and generates alert
    const response = await page.request.get(`${baseURL}/api/attendance/anomalies`);
    expect(response.ok()).toBeTruthy();
    const anomalies = await response.json();
    expect(anomalies.some((a: any) => a.type === 'DUPLICATE_ENTRY' && a.employeeId === 'EMP002')).toBeTruthy();

    // Step 2: Login as Supervisor and navigate to anomaly alerts section
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', supervisorEmail);
    await page.fill('[data-testid="password-input"]', supervisorPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to anomaly alerts section
    await page.click('[data-testid="anomaly-alerts-menu"]');
    await expect(page).toHaveURL(/.*anomalies/);
    
    // Review the duplicate entry alert details
    const duplicateAlert = page.locator('[data-testid="anomaly-row"]').filter({ hasText: 'Duplicate' });
    await expect(duplicateAlert).toBeVisible();
    
    // Expected Result: Alert provides information on duplicate entries
    await duplicateAlert.click();
    await expect(page.locator('[data-testid="anomaly-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="anomaly-type"]')).toContainText('DUPLICATE_ENTRY');
    await expect(page.locator('[data-testid="employee-id"]')).toContainText('EMP002');
    await expect(page.locator('[data-testid="duplicate-date"]')).toContainText('2024-01-16');
    await expect(page.locator('[data-testid="duplicate-time"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="duplicate-time"]')).toContainText('17:00');
    await expect(page.locator('[data-testid="suggested-action"]')).toContainText('Review and remove duplicate entry');
  });

  test('Restrict alert access to supervisors (error-case)', async ({ page }) => {
    // Step 1: Login to the attendance system using non-supervisor user credentials
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', nonSupervisorEmail);
    await page.fill('[data-testid="password-input"]', nonSupervisorPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Expected Result: Access to anomaly alerts denied
    // Attempt to directly access anomaly alerts page via URL
    await page.goto(`${baseURL}/anomalies`);
    
    // Should be redirected or see access denied message
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedMessage = page.locator('text=/Access Denied|Unauthorized|403/');
    
    await expect(accessDeniedMessage.or(unauthorizedMessage)).toBeVisible();
    
    // Verify anomaly alerts menu is not visible for non-supervisor
    await page.goto(`${baseURL}/dashboard`);
    const anomalyMenu = page.locator('[data-testid="anomaly-alerts-menu"]');
    await expect(anomalyMenu).not.toBeVisible();
    
    // Step 2: Attempt API call to GET /api/attendance/anomalies endpoint
    const apiResponse = await page.request.get(`${baseURL}/api/attendance/anomalies`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });
    
    // Expected Result: Authorization error returned
    expect(apiResponse.status()).toBe(403);
    const errorBody = await apiResponse.json();
    expect(errorBody.error).toMatch(/unauthorized|forbidden|access denied/i);
  });
});