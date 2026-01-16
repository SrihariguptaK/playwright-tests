import { test, expect } from '@playwright/test';

test.describe('API Version Compatibility - Story 21', () => {
  const baseURL = process.env.API_BASE_URL || 'https://api.example.com';
  const adminDashboardURL = process.env.ADMIN_DASHBOARD_URL || 'https://admin.example.com';

  test.describe('TC#1: Validate detection and routing of multiple API versions', () => {
    test('should route v1 API request to v1 handler', async ({ page, request }) => {
      // Action: Send API request with version header v1
      const response = await request.get(`${baseURL}/employees`, {
        headers: {
          'API-Version': 'v1',
          'Content-Type': 'application/json'
        }
      });

      // Expected Result: Request routed to v1 handler
      expect(response.ok()).toBeTruthy();
      const responseHeaders = response.headers();
      expect(responseHeaders['x-api-version-handler']).toBe('v1');
      
      const responseBody = await response.json();
      expect(responseBody).toHaveProperty('version', 'v1');
    });

    test('should route v2 API request to v2 handler', async ({ page, request }) => {
      // Action: Send API request with version header v2
      const response = await request.get(`${baseURL}/employees`, {
        headers: {
          'API-Version': 'v2',
          'Content-Type': 'application/json'
        }
      });

      // Expected Result: Request routed to v2 handler
      expect(response.ok()).toBeTruthy();
      const responseHeaders = response.headers();
      expect(responseHeaders['x-api-version-handler']).toBe('v2');
      
      const responseBody = await response.json();
      expect(responseBody).toHaveProperty('version', 'v2');
    });

    test('should verify logs for version usage with timestamps', async ({ page }) => {
      // Navigate to admin dashboard logs page
      await page.goto(`${adminDashboardURL}/logs`);
      await page.waitForLoadState('networkidle');

      // Login if required
      const loginButton = page.locator('[data-testid="login-button"]');
      if (await loginButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await page.fill('[data-testid="username-input"]', process.env.ADMIN_USERNAME || 'admin');
        await page.fill('[data-testid="password-input"]', process.env.ADMIN_PASSWORD || 'password');
        await loginButton.click();
        await page.waitForURL('**/logs');
      }

      // Filter logs for API version usage
      await page.click('[data-testid="filter-dropdown"]');
      await page.click('[data-testid="filter-api-version"]');
      await page.waitForTimeout(1000);

      // Expected Result: Logs show correct version and timestamp
      const logEntries = page.locator('[data-testid="log-entry"]');
      await expect(logEntries.first()).toBeVisible();

      const firstLogEntry = logEntries.first();
      await expect(firstLogEntry.locator('[data-testid="log-version"]')).toContainText(/v[12]/);
      await expect(firstLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
      
      const timestampText = await firstLogEntry.locator('[data-testid="log-timestamp"]').textContent();
      expect(timestampText).toMatch(/\d{4}-\d{2}-\d{2}/);
    });
  });

  test.describe('TC#2: Test data mapping correctness per API version', () => {
    test('should map data according to v1 schema', async ({ request }) => {
      // Action: Send sample data via v1 API
      const sampleDataV1 = {
        emp_id: '12345',
        first_name: 'John',
        last_name: 'Doe',
        dept_code: 'ENG',
        hire_date: '2023-01-15'
      };

      const response = await request.post(`${baseURL}/v1/employees`, {
        headers: {
          'API-Version': 'v1',
          'Content-Type': 'application/json'
        },
        data: sampleDataV1
      });

      // Expected Result: Data mapped according to v1 schema
      expect(response.ok()).toBeTruthy();
      const responseBody = await response.json();
      
      expect(responseBody).toHaveProperty('emp_id', sampleDataV1.emp_id);
      expect(responseBody).toHaveProperty('first_name', sampleDataV1.first_name);
      expect(responseBody).toHaveProperty('last_name', sampleDataV1.last_name);
      expect(responseBody).toHaveProperty('dept_code', sampleDataV1.dept_code);
      expect(responseBody.schema_version).toBe('v1');
    });

    test('should map data according to v2 schema', async ({ request }) => {
      // Action: Send sample data via v2 API
      const sampleDataV2 = {
        employeeId: '12345',
        personalInfo: {
          firstName: 'John',
          lastName: 'Doe'
        },
        department: {
          code: 'ENG',
          name: 'Engineering'
        },
        hireDate: '2023-01-15T00:00:00Z'
      };

      const response = await request.post(`${baseURL}/v2/employees`, {
        headers: {
          'API-Version': 'v2',
          'Content-Type': 'application/json'
        },
        data: sampleDataV2
      });

      // Expected Result: Data mapped according to v2 schema
      expect(response.ok()).toBeTruthy();
      const responseBody = await response.json();
      
      expect(responseBody).toHaveProperty('employeeId', sampleDataV2.employeeId);
      expect(responseBody).toHaveProperty('personalInfo');
      expect(responseBody.personalInfo).toHaveProperty('firstName', sampleDataV2.personalInfo.firstName);
      expect(responseBody.personalInfo).toHaveProperty('lastName', sampleDataV2.personalInfo.lastName);
      expect(responseBody).toHaveProperty('department');
      expect(responseBody.schema_version).toBe('v2');
    });

    test('should compare transformed data outputs conform to respective schemas', async ({ request }) => {
      // Send same logical data through both versions
      const employeeDataV1 = {
        emp_id: '67890',
        first_name: 'Jane',
        last_name: 'Smith',
        dept_code: 'HR'
      };

      const employeeDataV2 = {
        employeeId: '67890',
        personalInfo: {
          firstName: 'Jane',
          lastName: 'Smith'
        },
        department: {
          code: 'HR'
        }
      };

      const responseV1 = await request.post(`${baseURL}/v1/employees`, {
        headers: { 'API-Version': 'v1', 'Content-Type': 'application/json' },
        data: employeeDataV1
      });

      const responseV2 = await request.post(`${baseURL}/v2/employees`, {
        headers: { 'API-Version': 'v2', 'Content-Type': 'application/json' },
        data: employeeDataV2
      });

      // Expected Result: Data conforms to respective version schemas
      expect(responseV1.ok()).toBeTruthy();
      expect(responseV2.ok()).toBeTruthy();

      const bodyV1 = await responseV1.json();
      const bodyV2 = await responseV2.json();

      // Verify v1 schema structure
      expect(bodyV1).toHaveProperty('emp_id');
      expect(bodyV1).toHaveProperty('first_name');
      expect(bodyV1).toHaveProperty('last_name');
      expect(bodyV1.schema_version).toBe('v1');

      // Verify v2 schema structure
      expect(bodyV2).toHaveProperty('employeeId');
      expect(bodyV2).toHaveProperty('personalInfo');
      expect(bodyV2.personalInfo).toHaveProperty('firstName');
      expect(bodyV2.personalInfo).toHaveProperty('lastName');
      expect(bodyV2.schema_version).toBe('v2');

      // Verify logical data equivalence
      expect(bodyV1.emp_id).toBe(bodyV2.employeeId);
      expect(bodyV1.first_name).toBe(bodyV2.personalInfo.firstName);
      expect(bodyV1.last_name).toBe(bodyV2.personalInfo.lastName);
    });
  });

  test.describe('TC#3: Verify alerting on deprecated API version usage', () => {
    test('should process request and log usage for deprecated API version', async ({ request }) => {
      // Action: Send API request using deprecated version
      const response = await request.get(`${baseURL}/employees`, {
        headers: {
          'API-Version': 'v0.9',
          'Content-Type': 'application/json'
        }
      });

      // Expected Result: System processes request and logs usage
      expect(response.ok()).toBeTruthy();
      const responseHeaders = response.headers();
      expect(responseHeaders['x-deprecated-version']).toBe('true');
      expect(responseHeaders['x-deprecation-warning']).toContain('deprecated');
    });

    test('should generate alert notification to administrators', async ({ page }) => {
      // Navigate to admin dashboard alerts page
      await page.goto(`${adminDashboardURL}/alerts`);
      await page.waitForLoadState('networkidle');

      // Login if required
      const loginButton = page.locator('[data-testid="login-button"]');
      if (await loginButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await page.fill('[data-testid="username-input"]', process.env.ADMIN_USERNAME || 'admin');
        await page.fill('[data-testid="password-input"]', process.env.ADMIN_PASSWORD || 'password');
        await loginButton.click();
        await page.waitForURL('**/alerts');
      }

      // Filter for deprecated version alerts
      await page.click('[data-testid="alert-filter"]');
      await page.click('[data-testid="filter-deprecated-version"]');
      await page.waitForTimeout(1000);

      // Expected Result: Alert is generated and sent
      const alertItems = page.locator('[data-testid="alert-item"]');
      await expect(alertItems.first()).toBeVisible({ timeout: 10000 });
      
      const firstAlert = alertItems.first();
      await expect(firstAlert.locator('[data-testid="alert-type"]')).toContainText('Deprecated API Version');
      await expect(firstAlert.locator('[data-testid="alert-status"]')).toContainText(/active|sent/i);
    });

    test('should display alert with version and usage information', async ({ page }) => {
      // Navigate to admin dashboard alerts page
      await page.goto(`${adminDashboardURL}/alerts`);
      await page.waitForLoadState('networkidle');

      // Login if required
      const loginButton = page.locator('[data-testid="login-button"]');
      if (await loginButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await page.fill('[data-testid="username-input"]', process.env.ADMIN_USERNAME || 'admin');
        await page.fill('[data-testid="password-input"]', process.env.ADMIN_PASSWORD || 'password');
        await loginButton.click();
        await page.waitForURL('**/alerts');
      }

      // Filter and open deprecated version alert
      await page.click('[data-testid="alert-filter"]');
      await page.click('[data-testid="filter-deprecated-version"]');
      await page.waitForTimeout(1000);

      const alertItems = page.locator('[data-testid="alert-item"]');
      await alertItems.first().click();
      await page.waitForSelector('[data-testid="alert-details"]');

      // Expected Result: Alert contains version and usage information
      const alertDetails = page.locator('[data-testid="alert-details"]');
      await expect(alertDetails).toBeVisible();
      
      await expect(alertDetails.locator('[data-testid="deprecated-version"]')).toContainText(/v0\.\d+/);
      await expect(alertDetails.locator('[data-testid="usage-count"]')).toBeVisible();
      await expect(alertDetails.locator('[data-testid="last-used-timestamp"]')).toBeVisible();
      await expect(alertDetails.locator('[data-testid="alert-message"]')).toContainText(/deprecated/i);
      
      const usageCountText = await alertDetails.locator('[data-testid="usage-count"]').textContent();
      expect(parseInt(usageCountText || '0')).toBeGreaterThan(0);
    });
  });
});