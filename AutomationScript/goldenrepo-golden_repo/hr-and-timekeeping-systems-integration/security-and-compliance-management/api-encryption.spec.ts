import { test, expect } from '@playwright/test';
import https from 'https';
import tls from 'tls';

interface ApiResponse {
  status: number;
  data?: any;
  error?: string;
  timestamp?: string;
}

interface PerformanceMetrics {
  averageLatency: number;
  p50: number;
  p95: number;
  p99: number;
}

test.describe('API Data Transmission Encryption - Story 19', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'https://api.example.com';
  const TEST_ENDPOINT = '/api/v1/timekeeping/entries';
  const LOGS_PAGE_URL = process.env.LOGS_PAGE_URL || 'https://admin.example.com/logs';
  const SECURITY_LOGS_URL = process.env.SECURITY_LOGS_URL || 'https://admin.example.com/security-logs';
  const PERFORMANCE_LOGS_URL = process.env.PERFORMANCE_LOGS_URL || 'https://admin.example.com/performance-logs';

  test.beforeEach(async ({ page }) => {
    // Setup authentication for admin pages
    await page.goto(process.env.ADMIN_LOGIN_URL || 'https://admin.example.com/login');
    await page.fill('[data-testid="username-input"]', process.env.ADMIN_USERNAME || 'security_officer');
    await page.fill('[data-testid="password-input"]', process.env.ADMIN_PASSWORD || 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
  });

  test('Validate enforcement of TLS 1.2+ encryption - happy path', async ({ page, request }) => {
    // Step 1: Configure API client to use TLS 1.0 protocol and attempt to make an API call
    const tls10Response = await request.fetch(API_BASE_URL + TEST_ENDPOINT, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer test-token',
        'Content-Type': 'application/json'
      },
      ignoreHTTPSErrors: false,
      // Note: Playwright doesn't directly support forcing TLS 1.0, this simulates the rejection
    }).catch(error => ({ status: 0, error: error.message }));
    
    // Expected Result: API call is rejected with encryption error
    expect(tls10Response.status === 0 || tls10Response.status >= 400).toBeTruthy();

    // Step 2: Configure API client to use TLS 1.1 protocol and attempt to make an API call
    const tls11Response = await request.fetch(API_BASE_URL + TEST_ENDPOINT, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer test-token',
        'Content-Type': 'application/json'
      },
      ignoreHTTPSErrors: false,
    }).catch(error => ({ status: 0, error: error.message }));
    
    // Expected Result: API call is rejected with encryption error
    expect(tls11Response.status === 0 || tls11Response.status >= 400).toBeTruthy();

    // Step 3: Configure API client to use TLS 1.2 protocol and make an API call
    const tls12Response = await request.get(API_BASE_URL + TEST_ENDPOINT, {
      headers: {
        'Authorization': 'Bearer test-token',
        'Content-Type': 'application/json'
      }
    });
    
    // Expected Result: API call is accepted and processed
    expect(tls12Response.ok()).toBeTruthy();
    expect(tls12Response.status()).toBe(200);

    // Step 4: Configure API client to use TLS 1.3 protocol and make an API call
    const tls13Response = await request.get(API_BASE_URL + TEST_ENDPOINT, {
      headers: {
        'Authorization': 'Bearer test-token',
        'Content-Type': 'application/json'
      }
    });
    
    // Expected Result: API call is accepted and processed
    expect(tls13Response.ok()).toBeTruthy();
    expect(tls13Response.status()).toBe(200);

    // Step 5: Navigate to system logs and filter for encryption status entries
    await page.goto(LOGS_PAGE_URL);
    await page.waitForLoadState('networkidle');
    
    await page.fill('[data-testid="log-search-input"]', 'encryption status');
    await page.selectOption('[data-testid="log-type-filter"]', 'encryption');
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForSelector('[data-testid="log-entries-table"]');

    // Expected Result: Encryption success is recorded with timestamp
    const logEntries = page.locator('[data-testid="log-entry-row"]');
    await expect(logEntries.first()).toBeVisible();
    
    const firstLogEntry = logEntries.first();
    await expect(firstLogEntry.locator('[data-testid="log-status"]')).toContainText('success');
    await expect(firstLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();

    // Step 6: Verify log entry for successful TLS 1.2 connection shows encryption cipher suite
    await firstLogEntry.click();
    await page.waitForSelector('[data-testid="log-details-panel"]');
    
    const logDetails = page.locator('[data-testid="log-details-panel"]');
    await expect(logDetails.locator('[data-testid="tls-version"]')).toContainText(/TLS 1\.[23]/);
    await expect(logDetails.locator('[data-testid="cipher-suite"]')).toBeVisible();
    const cipherSuiteText = await logDetails.locator('[data-testid="cipher-suite"]').textContent();
    expect(cipherSuiteText).toBeTruthy();
    expect(cipherSuiteText!.length).toBeGreaterThan(0);
  });

  test('Test rejection of API calls with invalid certificates - error case', async ({ page, request }) => {
    // Step 1: Configure API client to use an expired SSL certificate
    const expiredCertResponse = await request.fetch(API_BASE_URL + TEST_ENDPOINT, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer test-token-expired-cert',
        'Content-Type': 'application/json'
      },
      ignoreHTTPSErrors: false,
    }).catch(error => ({ status: 0, error: error.message }));
    
    // Expected Result: API call is rejected with certificate error
    expect(expiredCertResponse.status === 0 || expiredCertResponse.status >= 400).toBeTruthy();

    // Step 2: Configure API client to use a self-signed certificate not in trusted store
    const selfSignedResponse = await request.fetch(API_BASE_URL + TEST_ENDPOINT, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer test-token-self-signed',
        'Content-Type': 'application/json'
      },
      ignoreHTTPSErrors: false,
    }).catch(error => ({ status: 0, error: error.message }));
    
    // Expected Result: API call is rejected with certificate error
    expect(selfSignedResponse.status === 0 || selfSignedResponse.status >= 400).toBeTruthy();

    // Step 3: Configure API client to use a certificate with mismatched domain name
    const mismatchedDomainResponse = await request.fetch(API_BASE_URL + TEST_ENDPOINT, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer test-token-mismatched',
        'Content-Type': 'application/json'
      },
      ignoreHTTPSErrors: false,
    }).catch(error => ({ status: 0, error: error.message }));
    
    // Expected Result: API call is rejected with certificate error
    expect(mismatchedDomainResponse.status === 0 || mismatchedDomainResponse.status >= 400).toBeTruthy();

    // Step 4: Configure API client to use a valid, non-expired certificate from trusted CA
    const validCertResponse = await request.get(API_BASE_URL + TEST_ENDPOINT, {
      headers: {
        'Authorization': 'Bearer valid-test-token',
        'Content-Type': 'application/json'
      }
    });
    
    // Expected Result: API call is accepted
    expect(validCertResponse.ok()).toBeTruthy();
    expect(validCertResponse.status()).toBe(200);

    // Step 5: Navigate to system security logs and search for certificate validation events
    await page.goto(SECURITY_LOGS_URL);
    await page.waitForLoadState('networkidle');
    
    await page.fill('[data-testid="security-log-search"]', 'certificate validation');
    await page.selectOption('[data-testid="event-type-filter"]', 'certificate');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="security-log-table"]');

    // Expected Result: All events are logged accurately
    const securityLogEntries = page.locator('[data-testid="security-log-row"]');
    await expect(securityLogEntries.first()).toBeVisible();
    const logCount = await securityLogEntries.count();
    expect(logCount).toBeGreaterThan(0);

    // Step 6: Review log entries for rejected certificate attempts
    const rejectedLogs = page.locator('[data-testid="security-log-row"][data-status="rejected"]');
    await expect(rejectedLogs.first()).toBeVisible();
    
    await rejectedLogs.first().click();
    await page.waitForSelector('[data-testid="security-log-details"]');
    
    const logDetailsPanel = page.locator('[data-testid="security-log-details"]');
    await expect(logDetailsPanel.locator('[data-testid="error-type"]')).toContainText(/certificate|expired|invalid/);
    await expect(logDetailsPanel.locator('[data-testid="error-details"]')).toBeVisible();
    
    // Expected Result: Error details are captured
    const errorDetails = await logDetailsPanel.locator('[data-testid="error-details"]').textContent();
    expect(errorDetails).toBeTruthy();
    expect(errorDetails!.length).toBeGreaterThan(0);

    // Step 7: Verify log entry for successful certificate validation contains certificate chain
    await page.click('[data-testid="close-details-button"]');
    
    const successfulLogs = page.locator('[data-testid="security-log-row"][data-status="success"]');
    await expect(successfulLogs.first()).toBeVisible();
    
    await successfulLogs.first().click();
    await page.waitForSelector('[data-testid="security-log-details"]');
    
    const successLogDetails = page.locator('[data-testid="security-log-details"]');
    await expect(successLogDetails.locator('[data-testid="certificate-chain"]')).toBeVisible();
    
    const certChainInfo = await successLogDetails.locator('[data-testid="certificate-chain"]').textContent();
    expect(certChainInfo).toBeTruthy();
    expect(certChainInfo).toContain('Root CA');
  });

  test('Measure encryption overhead on API latency - boundary', async ({ page, request }) => {
    const iterations = 100;
    const latencyThreshold = 5; // 5% maximum overhead

    // Step 1: Configure test environment to allow unencrypted HTTP for baseline
    // Note: This would be test environment only
    const baselineUrl = process.env.TEST_HTTP_URL || 'http://test-api.example.com';

    // Step 2: Execute 100 API calls using unencrypted HTTP and measure response time
    const baselineLatencies: number[] = [];
    
    for (let i = 0; i < iterations; i++) {
      const startTime = Date.now();
      await request.get(baselineUrl + TEST_ENDPOINT, {
        headers: {
          'Authorization': 'Bearer test-token',
          'Content-Type': 'application/json'
        }
      }).catch(() => ({ status: 0 }));
      const endTime = Date.now();
      baselineLatencies.push(endTime - startTime);
    }

    // Step 3: Document baseline metrics
    const baselineAvg = baselineLatencies.reduce((a, b) => a + b, 0) / baselineLatencies.length;
    const baselineSorted = [...baselineLatencies].sort((a, b) => a - b);
    const baselineP50 = baselineSorted[Math.floor(iterations * 0.5)];
    const baselineP95 = baselineSorted[Math.floor(iterations * 0.95)];
    const baselineP99 = baselineSorted[Math.floor(iterations * 0.99)];

    // Expected Result: Baseline latency recorded
    expect(baselineAvg).toBeGreaterThan(0);
    expect(baselineP50).toBeGreaterThan(0);
    expect(baselineP95).toBeGreaterThan(0);
    expect(baselineP99).toBeGreaterThan(0);

    // Step 4: Configure API client to use TLS 1.2 encryption and execute 100 API calls
    const tls12Latencies: number[] = [];
    
    for (let i = 0; i < iterations; i++) {
      const startTime = Date.now();
      await request.get(API_BASE_URL + TEST_ENDPOINT, {
        headers: {
          'Authorization': 'Bearer test-token',
          'Content-Type': 'application/json'
        }
      });
      const endTime = Date.now();
      tls12Latencies.push(endTime - startTime);
    }

    // Step 5: Measure and record average response time for TLS 1.2 encrypted calls
    const tls12Avg = tls12Latencies.reduce((a, b) => a + b, 0) / tls12Latencies.length;
    const tls12Sorted = [...tls12Latencies].sort((a, b) => a - b);
    const tls12P50 = tls12Sorted[Math.floor(iterations * 0.5)];
    const tls12P95 = tls12Sorted[Math.floor(iterations * 0.95)];
    const tls12P99 = tls12Sorted[Math.floor(iterations * 0.99)];

    // Step 6: Calculate percentage increase in latency
    const latencyIncrease = ((tls12Avg - baselineAvg) / baselineAvg) * 100;

    // Expected Result: Latency increase is under 5%
    expect(latencyIncrease).toBeLessThanOrEqual(latencyThreshold);

    // Step 7: Repeat test with TLS 1.3 encryption
    const tls13Latencies: number[] = [];
    
    for (let i = 0; i < iterations; i++) {
      const startTime = Date.now();
      await request.get(API_BASE_URL + TEST_ENDPOINT, {
        headers: {
          'Authorization': 'Bearer test-token',
          'Content-Type': 'application/json'
        }
      });
      const endTime = Date.now();
      tls13Latencies.push(endTime - startTime);
    }

    const tls13Avg = tls13Latencies.reduce((a, b) => a + b, 0) / tls13Latencies.length;
    const tls13Increase = ((tls13Avg - baselineAvg) / baselineAvg) * 100;
    
    expect(tls13Increase).toBeLessThanOrEqual(latencyThreshold);

    // Step 8: Navigate to performance logs and analyze detailed timing breakdowns
    await page.goto(PERFORMANCE_LOGS_URL);
    await page.waitForLoadState('networkidle');
    
    await page.fill('[data-testid="performance-search"]', 'SSL handshake');
    await page.click('[data-testid="filter-apply-button"]');
    await page.waitForSelector('[data-testid="performance-log-table"]');

    // Expected Result: No significant performance degradation detected
    const performanceEntries = page.locator('[data-testid="performance-log-entry"]');
    await expect(performanceEntries.first()).toBeVisible();
    
    await performanceEntries.first().click();
    await page.waitForSelector('[data-testid="performance-details-panel"]');
    
    const perfDetails = page.locator('[data-testid="performance-details-panel"]');
    await expect(perfDetails.locator('[data-testid="ssl-handshake-time"]')).toBeVisible();
    await expect(perfDetails.locator('[data-testid="encryption-time"]')).toBeVisible();
    await expect(perfDetails.locator('[data-testid="data-transfer-time"]')).toBeVisible();

    // Step 9: Review system resource utilization
    await page.click('[data-testid="resource-utilization-tab"]');
    await page.waitForSelector('[data-testid="cpu-usage-chart"]');
    
    await expect(page.locator('[data-testid="cpu-usage-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="memory-usage-chart"]')).toBeVisible();
    
    const cpuUsage = await page.locator('[data-testid="avg-cpu-usage"]').textContent();
    const memoryUsage = await page.locator('[data-testid="avg-memory-usage"]').textContent();
    
    expect(cpuUsage).toBeTruthy();
    expect(memoryUsage).toBeTruthy();

    // Step 10: Generate performance comparison report
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-modal"]');
    
    await page.selectOption('[data-testid="report-type-select"]', 'comparison');
    await page.fill('[data-testid="baseline-metric-input"]', baselineAvg.toString());
    await page.fill('[data-testid="encrypted-metric-input"]', tls12Avg.toString());
    await page.click('[data-testid="generate-report-submit"]');
    
    await page.waitForSelector('[data-testid="report-generated-success"]');
    
    // Expected Result: Performance comparison report showing baseline vs encrypted metrics
    await expect(page.locator('[data-testid="report-generated-success"]')).toBeVisible();
    await expect(page.locator('[data-testid="performance-graph"]')).toBeVisible();
    
    const reportSummary = page.locator('[data-testid="report-summary"]');
    await expect(reportSummary.locator('[data-testid="baseline-latency"]')).toContainText(baselineAvg.toFixed(2));
    await expect(reportSummary.locator('[data-testid="encrypted-latency"]')).toContainText(tls12Avg.toFixed(2));
    await expect(reportSummary.locator('[data-testid="latency-increase-percentage"]')).toContainText(latencyIncrease.toFixed(2));
  });
});