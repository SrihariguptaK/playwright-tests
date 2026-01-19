import { test, expect } from '@playwright/test';

test.describe('HR Synchronization Conflict Detection', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const apiURL = process.env.API_URL || 'http://localhost:3000/api';

  test.beforeEach(async ({ page }) => {
    // Navigate to HR synchronization dashboard
    await page.goto(`${baseURL}/hr-sync`);
    await page.waitForLoadState('networkidle');
  });

  test('Verify detection and logging of data conflicts', async ({ page, request }) => {
    // Step 1: Simulate conflicting employee data during synchronization
    
    // Prepare conflicting employee data
    const conflictingEmployeeData = {
      employeeId: 'EMP001',
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@company.com',
      department: 'Engineering',
      position: 'Senior Developer',
      salary: 95000,
      lastModified: new Date().toISOString()
    };

    // Create existing record with different data to cause conflict
    await request.post(`${apiURL}/hr/employees`, {
      data: {
        employeeId: 'EMP001',
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@company.com',
        department: 'Marketing',
        position: 'Manager',
        salary: 85000,
        lastModified: new Date(Date.now() - 86400000).toISOString()
      }
    });

    // Trigger synchronization with conflicting data
    await page.click('[data-testid="sync-trigger-button"]');
    
    // Upload or input conflicting employee data
    await page.click('[data-testid="manual-sync-option"]');
    await page.fill('[data-testid="employee-id-input"]', conflictingEmployeeData.employeeId);
    await page.fill('[data-testid="department-input"]', conflictingEmployeeData.department);
    await page.fill('[data-testid="position-input"]', conflictingEmployeeData.position);
    await page.fill('[data-testid="salary-input"]', conflictingEmployeeData.salary.toString());
    
    await page.click('[data-testid="start-sync-button"]');

    // Expected Result: System detects conflict and logs details
    await page.waitForSelector('[data-testid="sync-status"]', { timeout: 10000 });
    
    const syncStatus = await page.locator('[data-testid="sync-status"]').textContent();
    expect(syncStatus).toContain('Conflict Detected');

    // Verify conflict is logged
    await page.click('[data-testid="view-logs-button"]');
    await page.waitForSelector('[data-testid="conflict-log-entry"]');
    
    const conflictLogEntry = page.locator('[data-testid="conflict-log-entry"]').first();
    await expect(conflictLogEntry).toBeVisible();
    
    const logDetails = await conflictLogEntry.textContent();
    expect(logDetails).toContain('EMP001');
    expect(logDetails).toContain('department');
    expect(logDetails).toContain('Engineering');
    expect(logDetails).toContain('Marketing');

    // Verify timestamp is present
    const timestamp = await conflictLogEntry.locator('[data-testid="conflict-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    expect(timestamp).toMatch(/\d{4}-\d{2}-\d{2}/);

    // Step 2: Check notification system for alert
    await page.click('[data-testid="notifications-icon"]');
    await page.waitForSelector('[data-testid="notification-panel"]');
    
    // Expected Result: Support team receives conflict notification
    const notificationPanel = page.locator('[data-testid="notification-panel"]');
    await expect(notificationPanel).toBeVisible();
    
    const conflictNotification = notificationPanel.locator('[data-testid="conflict-notification"]').first();
    await expect(conflictNotification).toBeVisible();
    
    const notificationText = await conflictNotification.textContent();
    expect(notificationText).toContain('Data Conflict Detected');
    expect(notificationText).toContain('EMP001');
    
    // Verify notification timestamp is within 5 minutes
    const notificationTime = await conflictNotification.locator('[data-testid="notification-time"]').textContent();
    expect(notificationTime).toMatch(/\d+ (second|minute)s? ago/);

    // Verify support team email notification via API
    const notificationResponse = await request.get(`${apiURL}/hr/sync/notifications/latest`);
    expect(notificationResponse.ok()).toBeTruthy();
    
    const notificationData = await notificationResponse.json();
    expect(notificationData.type).toBe('conflict');
    expect(notificationData.employeeId).toBe('EMP001');
    expect(notificationData.recipients).toContain('support@company.com');
  });

  test('Verify synchronization continues for non-conflicting data', async ({ page, request }) => {
    // Step 1: Run synchronization with mixed conflicting and non-conflicting records
    
    // Prepare mixed dataset
    const mixedEmployeeData = [
      {
        employeeId: 'EMP002',
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@company.com',
        department: 'Sales',
        position: 'Sales Manager',
        salary: 78000,
        conflicting: false
      },
      {
        employeeId: 'EMP003',
        firstName: 'Bob',
        lastName: 'Johnson',
        email: 'bob.johnson@company.com',
        department: 'Engineering',
        position: 'Developer',
        salary: 72000,
        conflicting: true // This will have conflicting data in target
      },
      {
        employeeId: 'EMP004',
        firstName: 'Alice',
        lastName: 'Williams',
        email: 'alice.williams@company.com',
        department: 'HR',
        position: 'HR Specialist',
        salary: 65000,
        conflicting: false
      }
    ];

    // Create existing conflicting record for EMP003
    await request.post(`${apiURL}/hr/employees`, {
      data: {
        employeeId: 'EMP003',
        firstName: 'Bob',
        lastName: 'Johnson',
        email: 'bob.johnson@company.com',
        department: 'Marketing',
        position: 'Marketing Specialist',
        salary: 68000,
        lastModified: new Date(Date.now() - 86400000).toISOString()
      }
    });

    // Trigger batch synchronization
    await page.click('[data-testid="sync-trigger-button"]');
    await page.click('[data-testid="batch-sync-option"]');
    
    // Upload batch file or use API to trigger sync
    await page.click('[data-testid="upload-batch-button"]');
    
    // Simulate file upload with mixed data
    const fileInput = page.locator('[data-testid="batch-file-input"]');
    await fileInput.setInputFiles({
      name: 'employees.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(mixedEmployeeData))
    });

    await page.click('[data-testid="start-batch-sync-button"]');

    // Wait for synchronization to complete
    await page.waitForSelector('[data-testid="sync-complete-status"]', { timeout: 60000 });

    // Expected Result: Non-conflicting records are updated successfully
    const syncSummary = page.locator('[data-testid="sync-summary"]');
    await expect(syncSummary).toBeVisible();

    // Verify sync summary shows successful updates for non-conflicting records
    const successCount = await syncSummary.locator('[data-testid="success-count"]').textContent();
    expect(parseInt(successCount || '0')).toBeGreaterThanOrEqual(2);

    const conflictCount = await syncSummary.locator('[data-testid="conflict-count"]').textContent();
    expect(parseInt(conflictCount || '0')).toBe(1);

    // Verify non-conflicting records were updated
    await page.click('[data-testid="view-sync-details-button"]');
    await page.waitForSelector('[data-testid="sync-details-table"]');

    // Check EMP002 was updated successfully
    const emp002Row = page.locator('[data-testid="employee-row-EMP002"]');
    await expect(emp002Row).toBeVisible();
    const emp002Status = await emp002Row.locator('[data-testid="sync-status"]').textContent();
    expect(emp002Status).toBe('Success');

    // Check EMP004 was updated successfully
    const emp004Row = page.locator('[data-testid="employee-row-EMP004"]');
    await expect(emp004Row).toBeVisible();
    const emp004Status = await emp004Row.locator('[data-testid="sync-status"]').textContent();
    expect(emp004Status).toBe('Success');

    // Check EMP003 has conflict status
    const emp003Row = page.locator('[data-testid="employee-row-EMP003"]');
    await expect(emp003Row).toBeVisible();
    const emp003Status = await emp003Row.locator('[data-testid="sync-status"]').textContent();
    expect(emp003Status).toBe('Conflict');

    // Verify via API that non-conflicting records were actually updated in database
    const emp002Response = await request.get(`${apiURL}/hr/employees/EMP002`);
    expect(emp002Response.ok()).toBeTruthy();
    const emp002Data = await emp002Response.json();
    expect(emp002Data.department).toBe('Sales');
    expect(emp002Data.position).toBe('Sales Manager');
    expect(emp002Data.salary).toBe(78000);

    const emp004Response = await request.get(`${apiURL}/hr/employees/EMP004`);
    expect(emp004Response.ok()).toBeTruthy();
    const emp004Data = await emp004Response.json();
    expect(emp004Data.department).toBe('HR');
    expect(emp004Data.position).toBe('HR Specialist');
    expect(emp004Data.salary).toBe(65000);

    // Verify conflicting record was NOT overwritten
    const emp003Response = await request.get(`${apiURL}/hr/employees/EMP003`);
    expect(emp003Response.ok()).toBeTruthy();
    const emp003Data = await emp003Response.json();
    expect(emp003Data.department).toBe('Marketing'); // Original value preserved
    expect(emp003Data.position).toBe('Marketing Specialist'); // Original value preserved
  });
});