import { test, expect } from '@playwright/test';

interface RatingRequest {
  productType: string;
  ratingFactors: Record<string, any>;
}

interface RatingResponse {
  productType: string;
  calculatedRate: number;
  ratingFactors: Record<string, any>;
  timestamp: string;
}

interface ActuarialBenchmark {
  productType: string;
  expectedRate: number;
  tolerance: number;
}

test.describe('Rating Engine Integration Tests', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000';
  const RATING_ENDPOINT = '/api/rate';
  
  const testDataSets: RatingRequest[] = [
    {
      productType: 'Auto Insurance',
      ratingFactors: {
        driverAge: 35,
        vehicleYear: 2020,
        vehicleMake: 'Toyota',
        vehicleModel: 'Camry',
        coverageType: 'Comprehensive',
        annualMileage: 12000,
        zipCode: '90210'
      }
    },
    {
      productType: 'Home Insurance',
      ratingFactors: {
        propertyValue: 350000,
        constructionType: 'Frame',
        yearBuilt: 2015,
        squareFootage: 2500,
        coverageAmount: 350000,
        deductible: 1000,
        zipCode: '90210'
      }
    },
    {
      productType: 'Life Insurance',
      ratingFactors: {
        age: 40,
        gender: 'Male',
        smoker: false,
        coverageAmount: 500000,
        term: 20,
        healthClass: 'Preferred'
      }
    }
  ];

  const actuarialBenchmarks: ActuarialBenchmark[] = [
    { productType: 'Auto Insurance', expectedRate: 1250.00, tolerance: 50 },
    { productType: 'Home Insurance', expectedRate: 1800.00, tolerance: 75 },
    { productType: 'Life Insurance', expectedRate: 850.00, tolerance: 40 }
  ];

  test('Validate rating accuracy for multiple products', async ({ request, page }) => {
    const testResults: any[] = [];
    
    // Navigate to test results page for logging
    await page.goto(`${API_BASE_URL}/test-results`);
    
    for (const testData of testDataSets) {
      // Step 1: Send rating request with predefined inputs
      const response = await request.post(`${API_BASE_URL}${RATING_ENDPOINT}`, {
        data: testData,
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      // Expected Result: Received ratings match expected outputs
      expect(response.ok()).toBeTruthy();
      expect(response.status()).toBe(200);
      
      const ratingResponse: RatingResponse = await response.json();
      expect(ratingResponse).toHaveProperty('calculatedRate');
      expect(ratingResponse.productType).toBe(testData.productType);
      
      // Step 2: Compare results against actuarial benchmarks
      const benchmark = actuarialBenchmarks.find(b => b.productType === testData.productType);
      expect(benchmark).toBeDefined();
      
      if (benchmark) {
        const rateDifference = Math.abs(ratingResponse.calculatedRate - benchmark.expectedRate);
        
        // Expected Result: No discrepancies found
        expect(rateDifference).toBeLessThanOrEqual(benchmark.tolerance);
        
        testResults.push({
          productType: testData.productType,
          inputData: testData.ratingFactors,
          receivedRate: ratingResponse.calculatedRate,
          expectedRate: benchmark.expectedRate,
          difference: rateDifference,
          status: rateDifference <= benchmark.tolerance ? 'PASS' : 'FAIL'
        });
      }
    }
    
    // Step 3: Log test results
    await page.goto(`${API_BASE_URL}/test-management`);
    await page.waitForSelector('[data-testid="test-results-form"]');
    
    // Document results for review
    await page.fill('[data-testid="test-name-input"]', 'Rating Accuracy Validation - Multiple Products');
    await page.fill('[data-testid="test-results-textarea"]', JSON.stringify(testResults, null, 2));
    await page.selectOption('[data-testid="test-status-select"]', 'PASS');
    await page.click('[data-testid="submit-results-button"]');
    
    // Expected Result: Results documented for review
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Test results saved successfully');
    
    // Verify all products passed
    const failedTests = testResults.filter(r => r.status === 'FAIL');
    expect(failedTests.length).toBe(0);
  });

  test('Test system behavior under API timeout', async ({ request, page, context }) => {
    const TIMEOUT_THRESHOLD = 30000; // 30 seconds
    
    // Step 1: Simulate API timeout during rating request
    const validTestData: RatingRequest = {
      productType: 'Auto Insurance',
      ratingFactors: {
        driverAge: 30,
        vehicleYear: 2021,
        vehicleMake: 'Honda',
        vehicleModel: 'Accord',
        coverageType: 'Full Coverage',
        annualMileage: 15000,
        zipCode: '10001'
      }
    };
    
    // Configure mock to simulate timeout
    await page.goto(`${API_BASE_URL}/admin/test-config`);
    await page.waitForSelector('[data-testid="timeout-config-section"]');
    await page.check('[data-testid="simulate-timeout-checkbox"]');
    await page.fill('[data-testid="timeout-delay-input"]', String(TIMEOUT_THRESHOLD + 5000));
    await page.click('[data-testid="save-config-button"]');
    await expect(page.locator('[data-testid="config-saved-message"]')).toBeVisible();
    
    // Navigate to quote processing page
    await page.goto(`${API_BASE_URL}/quotes/new`);
    await page.waitForSelector('[data-testid="quote-form"]');
    
    // Fill in quote form with test data
    await page.selectOption('[data-testid="product-type-select"]', validTestData.productType);
    await page.fill('[data-testid="driver-age-input"]', String(validTestData.ratingFactors.driverAge));
    await page.fill('[data-testid="vehicle-year-input"]', String(validTestData.ratingFactors.vehicleYear));
    await page.fill('[data-testid="vehicle-make-input"]', validTestData.ratingFactors.vehicleMake);
    await page.fill('[data-testid="vehicle-model-input"]', validTestData.ratingFactors.vehicleModel);
    await page.selectOption('[data-testid="coverage-type-select"]', validTestData.ratingFactors.coverageType);
    await page.fill('[data-testid="annual-mileage-input"]', String(validTestData.ratingFactors.annualMileage));
    await page.fill('[data-testid="zip-code-input"]', validTestData.ratingFactors.zipCode);
    
    // Submit rating request
    await page.click('[data-testid="submit-quote-button"]');
    
    // Monitor system behavior during timeout
    await page.waitForSelector('[data-testid="processing-indicator"]', { timeout: 5000 });
    
    // Expected Result: System triggers retry mechanism
    await expect(page.locator('[data-testid="retry-indicator"]')).toBeVisible({ timeout: TIMEOUT_THRESHOLD + 10000 });
    await expect(page.locator('[data-testid="retry-attempt-count"]')).toContainText(/Retry attempt [1-3]/i);
    
    // Step 2: Verify error message displayed to user
    await page.waitForSelector('[data-testid="error-notification"]', { timeout: 45000 });
    
    // Expected Result: Appropriate error notification shown
    const errorMessage = await page.locator('[data-testid="error-notification"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/rating service.*temporarily unavailable/i);
    await expect(errorMessage).toContainText(/please try again/i);
    
    // Verify no technical details exposed
    const errorText = await errorMessage.textContent();
    expect(errorText).not.toMatch(/timeout|exception|stack trace|error code/i);
    
    // Step 3: Check system logs for timeout event
    await page.goto(`${API_BASE_URL}/admin/logs`);
    await page.waitForSelector('[data-testid="logs-container"]');
    
    // Filter logs for timeout events
    await page.fill('[data-testid="log-search-input"]', 'timeout');
    await page.click('[data-testid="search-logs-button"]');
    await page.waitForSelector('[data-testid="log-entry"]');
    
    // Expected Result: Timeout logged with details
    const logEntries = page.locator('[data-testid="log-entry"]');
    await expect(logEntries.first()).toBeVisible();
    
    const firstLogEntry = await logEntries.first().textContent();
    expect(firstLogEntry).toMatch(/timeout/i);
    expect(firstLogEntry).toContain('POST /api/rate');
    expect(firstLogEntry).toMatch(/\d{4}-\d{2}-\d{2}.*\d{2}:\d{2}:\d{2}/); // Timestamp pattern
    
    // Verify retry attempts logged
    await page.fill('[data-testid="log-search-input"]', 'retry');
    await page.click('[data-testid="search-logs-button"]');
    await page.waitForSelector('[data-testid="log-entry"]');
    
    const retryLogEntries = page.locator('[data-testid="log-entry"]');
    const retryCount = await retryLogEntries.count();
    expect(retryCount).toBeGreaterThan(0);
    
    // Verify no sensitive data in logs
    const allLogText = await page.locator('[data-testid="logs-container"]').textContent();
    expect(allLogText).not.toMatch(/password|ssn|credit.*card|api.*key|secret/i);
    
    // Verify log contains troubleshooting information
    const detailedLog = await logEntries.first().getAttribute('data-log-details');
    if (detailedLog) {
      const logDetails = JSON.parse(detailedLog);
      expect(logDetails).toHaveProperty('timestamp');
      expect(logDetails).toHaveProperty('requestId');
      expect(logDetails).toHaveProperty('retryAttempts');
      expect(logDetails).toHaveProperty('errorType');
    }
  });
});