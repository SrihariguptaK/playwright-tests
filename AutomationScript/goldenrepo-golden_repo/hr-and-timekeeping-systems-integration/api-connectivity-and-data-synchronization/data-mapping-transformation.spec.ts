import { test, expect } from '@playwright/test';

interface SourceData {
  [key: string]: any;
}

interface TransformedData {
  [key: string]: any;
}

interface TransformationLog {
  timestamp: string;
  level: string;
  message: string;
  recordId?: string;
}

test.describe('Data Mapping and Transformation Rules', () => {
  let apiContext: any;

  test.beforeEach(async ({ page }) => {
    // Navigate to the data transformation configuration page
    await page.goto('/integration/data-transformation');
    await page.waitForLoadState('networkidle');
  });

  test('Validate data mapping and transformation accuracy', async ({ page, request }) => {
    // Step 1: Provide sample source data with various formats
    const sampleSourceData: SourceData = {
      emp_id: '12345',
      first_name: 'John',
      last_name: 'Doe',
      hire_date: '2023-01-15',
      salary: '75000.50',
      department_code: 'ENG',
      is_active: 'true'
    };

    // Upload or input source data
    await page.click('[data-testid="upload-source-data-btn"]');
    await page.fill('[data-testid="source-data-input"]', JSON.stringify(sampleSourceData));
    await page.click('[data-testid="apply-transformation-btn"]');

    // Wait for transformation to complete
    await page.waitForSelector('[data-testid="transformation-complete-indicator"]', { timeout: 10000 });

    // Expected Result: Data is transformed according to mapping rules
    const transformedDataElement = await page.locator('[data-testid="transformed-data-output"]');
    const transformedDataText = await transformedDataElement.textContent();
    const transformedData: TransformedData = JSON.parse(transformedDataText || '{}');

    expect(transformedData).toHaveProperty('employeeId');
    expect(transformedData.employeeId).toBe('12345');
    expect(transformedData).toHaveProperty('firstName', 'John');
    expect(transformedData).toHaveProperty('lastName', 'Doe');
    expect(transformedData).toHaveProperty('hireDate');
    expect(transformedData).toHaveProperty('salary');
    expect(typeof transformedData.salary).toBe('number');
    expect(transformedData).toHaveProperty('departmentCode', 'ENG');
    expect(transformedData).toHaveProperty('isActive');
    expect(typeof transformedData.isActive).toBe('boolean');

    // Step 2: Validate transformed data against target schema
    await page.click('[data-testid="validate-schema-btn"]');
    await page.waitForSelector('[data-testid="validation-result"]', { timeout: 5000 });

    // Expected Result: Data passes schema validation
    const validationResult = await page.locator('[data-testid="validation-result"]');
    const validationStatus = await validationResult.getAttribute('data-status');
    expect(validationStatus).toBe('passed');

    const validationMessage = await validationResult.textContent();
    expect(validationMessage).toContain('Schema validation passed');

    // Step 3: Check logs for transformation errors
    await page.click('[data-testid="view-logs-btn"]');
    await page.waitForSelector('[data-testid="transformation-logs"]', { timeout: 5000 });

    // Expected Result: No errors are logged for valid data
    const logsContainer = await page.locator('[data-testid="transformation-logs"]');
    const errorLogs = await logsContainer.locator('[data-log-level="error"]').count();
    expect(errorLogs).toBe(0);

    const infoLogs = await logsContainer.locator('[data-log-level="info"]').count();
    expect(infoLogs).toBeGreaterThan(0);
  });

  test('Test handling of missing and extra fields', async ({ page }) => {
    // Step 1: Provide source data with missing optional fields
    const sourceDataMissingFields: SourceData = {
      emp_id: '67890',
      first_name: 'Jane',
      last_name: 'Smith',
      hire_date: '2023-03-20'
      // Missing optional fields: department_code, middle_name
    };

    await page.click('[data-testid="upload-source-data-btn"]');
    await page.fill('[data-testid="source-data-input"]', JSON.stringify(sourceDataMissingFields));
    await page.click('[data-testid="apply-transformation-btn"]');

    await page.waitForSelector('[data-testid="transformation-complete-indicator"]', { timeout: 10000 });

    // Expected Result: Transformation completes without data loss
    const transformationStatus = await page.locator('[data-testid="transformation-status"]');
    const statusText = await transformationStatus.textContent();
    expect(statusText).toContain('completed');

    const transformedDataElement = await page.locator('[data-testid="transformed-data-output"]');
    const transformedDataText = await transformedDataElement.textContent();
    const transformedData: TransformedData = JSON.parse(transformedDataText || '{}');

    expect(transformedData.employeeId).toBe('67890');
    expect(transformedData.firstName).toBe('Jane');
    expect(transformedData.lastName).toBe('Smith');

    // Step 2: Provide source data with extra unexpected fields
    await page.click('[data-testid="clear-data-btn"]');

    const sourceDataExtraFields: SourceData = {
      emp_id: '11111',
      first_name: 'Bob',
      last_name: 'Johnson',
      hire_date: '2023-05-10',
      unexpected_field_1: 'extra data',
      unexpected_field_2: 12345,
      legacy_system_id: 'OLD-999'
    };

    await page.click('[data-testid="upload-source-data-btn"]');
    await page.fill('[data-testid="source-data-input"]', JSON.stringify(sourceDataExtraFields));
    await page.click('[data-testid="apply-transformation-btn"]');

    await page.waitForSelector('[data-testid="transformation-complete-indicator"]', { timeout: 10000 });

    // Expected Result: Extra fields are ignored or logged without failure
    const statusAfterExtra = await page.locator('[data-testid="transformation-status"]');
    const statusTextAfterExtra = await statusAfterExtra.textContent();
    expect(statusTextAfterExtra).toContain('completed');

    await page.click('[data-testid="view-logs-btn"]');
    await page.waitForSelector('[data-testid="transformation-logs"]', { timeout: 5000 });

    const logsContainer = await page.locator('[data-testid="transformation-logs"]');
    const warningLogs = await logsContainer.locator('[data-log-level="warning"]');
    const warningCount = await warningLogs.count();

    // Extra fields should be logged as warnings or info, not errors
    if (warningCount > 0) {
      const warningText = await warningLogs.first().textContent();
      expect(warningText).toMatch(/extra|unexpected|ignored/i);
    }

    // Step 3: Verify transformed data integrity
    const finalTransformedElement = await page.locator('[data-testid="transformed-data-output"]');
    const finalTransformedText = await finalTransformedElement.textContent();
    const finalTransformedData: TransformedData = JSON.parse(finalTransformedText || '{}');

    // Expected Result: Data conforms to target schema
    await page.click('[data-testid="validate-schema-btn"]');
    await page.waitForSelector('[data-testid="validation-result"]', { timeout: 5000 });

    const validationResult = await page.locator('[data-testid="validation-result"]');
    const validationStatus = await validationResult.getAttribute('data-status');
    expect(validationStatus).toBe('passed');

    // Verify only expected fields are present in transformed data
    expect(finalTransformedData).toHaveProperty('employeeId');
    expect(finalTransformedData).toHaveProperty('firstName');
    expect(finalTransformedData).toHaveProperty('lastName');
    expect(finalTransformedData).not.toHaveProperty('unexpected_field_1');
    expect(finalTransformedData).not.toHaveProperty('unexpected_field_2');
  });

  test('Measure transformation processing time', async ({ page }) => {
    // Step 1: Process batch of 1000 records through transformation engine
    const batchSize = 1000;
    const batchData: SourceData[] = [];

    // Generate 1000 sample records
    for (let i = 0; i < batchSize; i++) {
      batchData.push({
        emp_id: `EMP${10000 + i}`,
        first_name: `FirstName${i}`,
        last_name: `LastName${i}`,
        hire_date: '2023-01-01',
        salary: `${50000 + (i * 100)}`,
        department_code: i % 2 === 0 ? 'ENG' : 'HR',
        is_active: 'true'
      });
    }

    await page.click('[data-testid="batch-processing-tab"]');
    await page.waitForSelector('[data-testid="batch-upload-section"]', { timeout: 5000 });

    await page.click('[data-testid="upload-batch-data-btn"]');
    await page.fill('[data-testid="batch-data-input"]', JSON.stringify(batchData));

    // Record start time
    const startTime = Date.now();

    await page.click('[data-testid="process-batch-btn"]');
    await page.waitForSelector('[data-testid="batch-processing-complete"]', { timeout: 600000 });

    // Record end time
    const endTime = Date.now();
    const totalProcessingTime = endTime - startTime;

    // Expected Result: Average processing time per record is under 500ms
    const averageTimePerRecord = totalProcessingTime / batchSize;
    expect(averageTimePerRecord).toBeLessThan(500);

    // Verify processing metrics displayed on UI
    const metricsElement = await page.locator('[data-testid="processing-metrics"]');
    const metricsText = await metricsElement.textContent();
    expect(metricsText).toContain('1000');
    expect(metricsText).toMatch(/completed|success/i);

    const avgTimeElement = await page.locator('[data-testid="avg-processing-time"]');
    const avgTimeText = await avgTimeElement.textContent();
    const displayedAvgTime = parseFloat(avgTimeText?.match(/[0-9.]+/)?.[0] || '0');
    expect(displayedAvgTime).toBeLessThan(500);

    // Step 2: Monitor system resource usage during processing
    await page.click('[data-testid="view-resource-metrics-btn"]');
    await page.waitForSelector('[data-testid="resource-metrics-panel"]', { timeout: 5000 });

    // Expected Result: System operates within acceptable resource limits
    const cpuUsageElement = await page.locator('[data-testid="cpu-usage"]');
    const cpuUsageText = await cpuUsageElement.textContent();
    const cpuUsage = parseFloat(cpuUsageText?.match(/[0-9.]+/)?.[0] || '0');
    expect(cpuUsage).toBeLessThan(90); // CPU usage should be under 90%

    const memoryUsageElement = await page.locator('[data-testid="memory-usage"]');
    const memoryUsageText = await memoryUsageElement.textContent();
    const memoryUsage = parseFloat(memoryUsageText?.match(/[0-9.]+/)?.[0] || '0');
    expect(memoryUsage).toBeLessThan(85); // Memory usage should be under 85%

    // Step 3: Review logs for any performance-related errors
    await page.click('[data-testid="view-logs-btn"]');
    await page.waitForSelector('[data-testid="transformation-logs"]', { timeout: 5000 });

    // Expected Result: No performance errors detected
    const logsContainer = await page.locator('[data-testid="transformation-logs"]');
    const performanceErrors = await logsContainer.locator('[data-log-level="error"]').filter({
      hasText: /performance|timeout|slow|latency/i
    }).count();
    expect(performanceErrors).toBe(0);

    const errorLogs = await logsContainer.locator('[data-log-level="error"]').count();
    expect(errorLogs).toBe(0);

    // Verify success rate
    const successRateElement = await page.locator('[data-testid="success-rate"]');
    const successRateText = await successRateElement.textContent();
    const successRate = parseFloat(successRateText?.match(/[0-9.]+/)?.[0] || '0');
    expect(successRate).toBeGreaterThanOrEqual(99); // 99% or higher success rate
  });
});