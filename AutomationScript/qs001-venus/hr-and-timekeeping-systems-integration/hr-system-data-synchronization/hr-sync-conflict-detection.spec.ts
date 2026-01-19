import { test, expect } from '@playwright/test';

test.describe('HR Synchronization Conflict Detection', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000';
  const SYNC_ENDPOINT = `${API_BASE_URL}/api/hr/sync`;

  test.beforeEach(async ({ page }) => {
    // Navigate to HR synchronization dashboard
    await page.goto(`${API_BASE_URL}/hr/sync-dashboard`);
    await expect(page.locator('[data-testid="sync-dashboard"]')).toBeVisible();
  });

  test('Verify detection and logging of data conflicts', async ({ page, request }) => {
    // Step 1: Prepare conflicting employee data
    const conflictingEmployee = {
      employeeId: 'EMP001',
      name: 'John Doe',
      department: 'Finance',
      salary: 85000
    };

    // Prepare source HR system with conflicting data
    await request.post(`${API_BASE_URL}/api/hr/test-data/source`, {
      data: conflictingEmployee
    });

    // Prepare target database with original values
    await request.post(`${API_BASE_URL}/api/hr/test-data/target`, {
      data: {
        employeeId: 'EMP001',
        name: 'John Doe',
        department: 'IT',
        salary: 75000
      }
    });

    // Step 2: Trigger HR synchronization job
    await page.click('[data-testid="trigger-sync-button"]');
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Running', { timeout: 10000 });

    // Step 3: Monitor synchronization process
    await page.waitForSelector('[data-testid="sync-progress"]', { state: 'visible' });
    await expect(page.locator('[data-testid="sync-progress"]')).toBeVisible();

    // Step 4: Wait for conflict detection
    await page.waitForSelector('[data-testid="conflict-detected-alert"]', { timeout: 30000 });
    await expect(page.locator('[data-testid="conflict-detected-alert"]')).toBeVisible();

    // Step 5: Access conflict log and verify details
    await page.click('[data-testid="view-conflict-logs"]');
    await expect(page.locator('[data-testid="conflict-log-table"]')).toBeVisible();

    const conflictRow = page.locator('[data-testid="conflict-row-EMP001"]');
    await expect(conflictRow).toBeVisible();
    await expect(conflictRow.locator('[data-testid="employee-id"]')).toContainText('EMP001');
    await expect(conflictRow.locator('[data-testid="conflict-field"]')).toContainText('department');
    await expect(conflictRow.locator('[data-testid="source-value"]')).toContainText('Finance');
    await expect(conflictRow.locator('[data-testid="target-value"]')).toContainText('IT');

    // Verify salary conflict is also logged
    await expect(conflictRow.locator('[data-testid="conflict-field"]').nth(1)).toContainText('salary');
    await expect(conflictRow.locator('[data-testid="source-value"]').nth(1)).toContainText('85000');
    await expect(conflictRow.locator('[data-testid="target-value"]').nth(1)).toContainText('75000');

    // Step 6: Verify timestamp in conflict log
    const timestamp = await conflictRow.locator('[data-testid="conflict-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    const logTime = new Date(timestamp!);
    const currentTime = new Date();
    const timeDifference = Math.abs(currentTime.getTime() - logTime.getTime()) / 60000;
    expect(timeDifference).toBeLessThan(10); // Within 10 minutes

    // Step 7: Check notification system for alert
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    const conflictNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Conflict detected for employee EMP001' });
    await expect(conflictNotification).toBeVisible();
    await expect(conflictNotification).toContainText('Support team');

    // Step 8: Verify conflicting record was not overwritten
    const targetDataResponse = await request.get(`${API_BASE_URL}/api/hr/employees/EMP001`);
    expect(targetDataResponse.ok()).toBeTruthy();
    const targetData = await targetDataResponse.json();
    expect(targetData.department).toBe('IT'); // Original value preserved
    expect(targetData.salary).toBe(75000); // Original value preserved
  });

  test('Verify synchronization continues for non-conflicting data', async ({ page, request }) => {
    // Step 1: Prepare test dataset with mixed records
    const testDataset = [
      {
        employeeId: 'EMP001',
        name: 'John Doe',
        department: 'Finance', // Conflicting - target has 'IT'
        salary: 75000,
        phone: '555-0001',
        address: '123 Main St'
      },
      {
        employeeId: 'EMP002',
        name: 'Jane Smith',
        department: 'HR',
        salary: 85000, // Conflicting - target has 65000
        phone: '555-0002',
        address: '456 Oak Ave'
      },
      {
        employeeId: 'EMP003',
        name: 'Bob Johnson',
        department: 'IT',
        salary: 70000,
        phone: '555-9999', // Non-conflicting update
        address: '789 Pine Rd'
      },
      {
        employeeId: 'EMP004',
        name: 'Alice Williams',
        department: 'Sales',
        salary: 60000,
        phone: '555-0004',
        address: '321 Elm St' // New employee - non-conflicting
      },
      {
        employeeId: 'EMP005',
        name: 'Charlie Brown',
        department: 'Marketing',
        salary: 72000,
        phone: '555-0005',
        address: '654 Maple Dr' // Non-conflicting address update
      }
    ];

    // Prepare source data
    await request.post(`${API_BASE_URL}/api/hr/test-data/source/bulk`, {
      data: { employees: testDataset }
    });

    // Prepare target data with conflicts
    const targetDataset = [
      { employeeId: 'EMP001', name: 'John Doe', department: 'IT', salary: 75000, phone: '555-0001', address: '123 Main St' },
      { employeeId: 'EMP002', name: 'Jane Smith', department: 'HR', salary: 65000, phone: '555-0002', address: '456 Oak Ave' },
      { employeeId: 'EMP003', name: 'Bob Johnson', department: 'IT', salary: 70000, phone: '555-0003', address: '789 Pine Rd' },
      { employeeId: 'EMP005', name: 'Charlie Brown', department: 'Marketing', salary: 72000, phone: '555-0005', address: '999 Old Address' }
    ];

    await request.post(`${API_BASE_URL}/api/hr/test-data/target/bulk`, {
      data: { employees: targetDataset }
    });

    // Step 2: Initiate HR synchronization job
    await page.click('[data-testid="trigger-sync-button"]');
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Running', { timeout: 10000 });

    // Step 3-8: Monitor synchronization progress for each record
    await page.waitForSelector('[data-testid="sync-progress-details"]', { state: 'visible' });
    
    // Wait for processing of all records
    await page.waitForSelector('[data-testid="sync-status"]', { timeout: 60000 });
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: 60000 });

    // Step 9: Verify completion status
    const syncSummary = page.locator('[data-testid="sync-summary"]');
    await expect(syncSummary).toBeVisible();
    await expect(syncSummary.locator('[data-testid="total-records"]')).toContainText('5');
    await expect(syncSummary.locator('[data-testid="conflicts-detected"]')).toContainText('2');
    await expect(syncSummary.locator('[data-testid="successful-updates"]')).toContainText('3');

    // Step 10: Query target database to verify non-conflicting records were updated
    const emp003Response = await request.get(`${API_BASE_URL}/api/hr/employees/EMP003`);
    expect(emp003Response.ok()).toBeTruthy();
    const emp003Data = await emp003Response.json();
    expect(emp003Data.phone).toBe('555-9999'); // Updated successfully

    const emp004Response = await request.get(`${API_BASE_URL}/api/hr/employees/EMP004`);
    expect(emp004Response.ok()).toBeTruthy();
    const emp004Data = await emp004Response.json();
    expect(emp004Data.name).toBe('Alice Williams'); // New employee inserted
    expect(emp004Data.department).toBe('Sales');

    const emp005Response = await request.get(`${API_BASE_URL}/api/hr/employees/EMP005`);
    expect(emp005Response.ok()).toBeTruthy();
    const emp005Data = await emp005Response.json();
    expect(emp005Data.address).toBe('654 Maple Dr'); // Address updated successfully

    // Step 11: Verify conflicting records were not overwritten
    const emp001Response = await request.get(`${API_BASE_URL}/api/hr/employees/EMP001`);
    expect(emp001Response.ok()).toBeTruthy();
    const emp001Data = await emp001Response.json();
    expect(emp001Data.department).toBe('IT'); // Original value preserved

    const emp002Response = await request.get(`${API_BASE_URL}/api/hr/employees/EMP002`);
    expect(emp002Response.ok()).toBeTruthy();
    const emp002Data = await emp002Response.json();
    expect(emp002Data.salary).toBe(65000); // Original value preserved

    // Step 12: Review conflict logs to confirm both conflicts were logged
    await page.click('[data-testid="view-conflict-logs"]');
    await expect(page.locator('[data-testid="conflict-log-table"]')).toBeVisible();

    const conflictRows = page.locator('[data-testid^="conflict-row-"]');
    await expect(conflictRows).toHaveCount(2);

    await expect(page.locator('[data-testid="conflict-row-EMP001"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-row-EMP002"]')).toBeVisible();

    // Step 13: Check notification system for alerts
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();

    const notifications = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Conflict detected' });
    await expect(notifications).toHaveCount(2);

    await expect(notifications.nth(0)).toContainText('EMP001');
    await expect(notifications.nth(1)).toContainText('EMP002');
  });
});