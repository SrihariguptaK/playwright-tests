import { test, expect } from '@playwright/test';

interface QuoteRequest {
  productId: string;
  coverageAmount: number;
  term: number;
}

interface QuoteResponse {
  quoteId: string;
  premium: number;
  algorithmUsed: string;
  processingTime: number;
}

test.describe('Dynamic Rating Algorithm System', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000';
  const ADMIN_URL = process.env.ADMIN_URL || 'http://localhost:3001';

  test.describe('TC#1: Validate dynamic algorithm selection based on product', () => {
    test('should select algorithm module A for product identifier A', async ({ request, page }) => {
      // Step 1: Send quote request with product identifier A
      const quoteRequestA: QuoteRequest = {
        productId: 'PRODUCT_A',
        coverageAmount: 100000,
        term: 12
      };

      const responseA = await request.post(`${API_BASE_URL}/api/quotes`, {
        data: quoteRequestA
      });

      expect(responseA.ok()).toBeTruthy();
      const quoteDataA: QuoteResponse = await responseA.json();
      
      // Expected Result: System selects algorithm module A
      expect(quoteDataA.algorithmUsed).toBe('ALGORITHM_MODULE_A');
      expect(quoteDataA.quoteId).toBeDefined();
      expect(quoteDataA.premium).toBeGreaterThan(0);
    });

    test('should select algorithm module B for product identifier B', async ({ request, page }) => {
      // Step 2: Send quote request with product identifier B
      const quoteRequestB: QuoteRequest = {
        productId: 'PRODUCT_B',
        coverageAmount: 150000,
        term: 24
      };

      const responseB = await request.post(`${API_BASE_URL}/api/quotes`, {
        data: quoteRequestB
      });

      expect(responseB.ok()).toBeTruthy();
      const quoteDataB: QuoteResponse = await responseB.json();
      
      // Expected Result: System selects algorithm module B
      expect(quoteDataB.algorithmUsed).toBe('ALGORITHM_MODULE_B');
      expect(quoteDataB.quoteId).toBeDefined();
      expect(quoteDataB.premium).toBeGreaterThan(0);
    });

    test('should log correct algorithm selection for each request', async ({ request, page }) => {
      // Step 3: Verify logs for algorithm selection
      await page.goto(`${ADMIN_URL}/admin/logs`);
      await page.waitForLoadState('networkidle');

      // Login to admin panel if required
      const loginButton = page.locator('[data-testid="admin-login-button"]');
      if (await loginButton.isVisible()) {
        await page.fill('[data-testid="username-input"]', 'admin');
        await page.fill('[data-testid="password-input"]', 'admin123');
        await loginButton.click();
        await page.waitForURL('**/admin/logs');
      }

      // Send test requests
      const quoteRequestA: QuoteRequest = {
        productId: 'PRODUCT_A',
        coverageAmount: 100000,
        term: 12
      };

      const quoteRequestB: QuoteRequest = {
        productId: 'PRODUCT_B',
        coverageAmount: 150000,
        term: 24
      };

      await request.post(`${API_BASE_URL}/api/quotes`, { data: quoteRequestA });
      await request.post(`${API_BASE_URL}/api/quotes`, { data: quoteRequestB });

      // Refresh logs page
      await page.click('[data-testid="refresh-logs-button"]');
      await page.waitForTimeout(1000);

      // Filter for algorithm selection logs
      await page.fill('[data-testid="log-filter-input"]', 'algorithm selection');
      await page.click('[data-testid="apply-filter-button"]');
      await page.waitForLoadState('networkidle');

      // Expected Result: Correct module selection logged for each request
      const logEntries = page.locator('[data-testid="log-entry"]');
      const logCount = await logEntries.count();
      expect(logCount).toBeGreaterThanOrEqual(2);

      // Verify Product A log entry
      const productALog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'PRODUCT_A' }).first();
      await expect(productALog).toContainText('ALGORITHM_MODULE_A');
      await expect(productALog).toContainText('selected');

      // Verify Product B log entry
      const productBLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'PRODUCT_B' }).first();
      await expect(productBLog).toContainText('ALGORITHM_MODULE_B');
      await expect(productBLog).toContainText('selected');
    });
  });

  test.describe('TC#2: Ensure rating calculation latency under 500ms', () => {
    test('should complete each rating calculation within 500ms under load', async ({ request }) => {
      // Step 1: Send multiple quote requests under load
      const numberOfRequests = 20;
      const quoteRequests: Promise<any>[] = [];
      const latencies: number[] = [];

      for (let i = 0; i < numberOfRequests; i++) {
        const quoteRequest: QuoteRequest = {
          productId: i % 2 === 0 ? 'PRODUCT_A' : 'PRODUCT_B',
          coverageAmount: 100000 + (i * 10000),
          term: 12 + (i % 12)
        };

        const startTime = Date.now();
        const requestPromise = request.post(`${API_BASE_URL}/api/quotes`, {
          data: quoteRequest
        }).then(async (response) => {
          const endTime = Date.now();
          const latency = endTime - startTime;
          latencies.push(latency);

          expect(response.ok()).toBeTruthy();
          const quoteData: QuoteResponse = await response.json();
          
          // Expected Result: Each rating calculation completes within 500ms
          expect(latency).toBeLessThanOrEqual(500);
          expect(quoteData.processingTime).toBeLessThanOrEqual(500);
          
          return quoteData;
        });

        quoteRequests.push(requestPromise);
      }

      // Wait for all requests to complete
      const results = await Promise.all(quoteRequests);
      
      // Verify all requests completed successfully
      expect(results.length).toBe(numberOfRequests);
      
      // Calculate average latency
      const averageLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
      console.log(`Average latency: ${averageLatency}ms`);
      expect(averageLatency).toBeLessThanOrEqual(500);
    });

    test('should show no latency spikes in performance metrics', async ({ request, page }) => {
      // Step 2: Monitor system performance metrics
      await page.goto(`${ADMIN_URL}/admin/performance`);
      await page.waitForLoadState('networkidle');

      // Login to admin panel if required
      const loginButton = page.locator('[data-testid="admin-login-button"]');
      if (await loginButton.isVisible()) {
        await page.fill('[data-testid="username-input"]', 'admin');
        await page.fill('[data-testid="password-input"]', 'admin123');
        await loginButton.click();
        await page.waitForURL('**/admin/performance');
      }

      // Set time range for monitoring
      await page.click('[data-testid="time-range-selector"]');
      await page.click('[data-testid="last-5-minutes-option"]');

      // Filter for rating calculation metrics
      await page.click('[data-testid="metric-type-selector"]');
      await page.click('[data-testid="rating-calculation-option"]');
      await page.click('[data-testid="apply-metrics-filter"]');
      await page.waitForLoadState('networkidle');

      // Generate load
      const loadRequests: Promise<any>[] = [];
      for (let i = 0; i < 15; i++) {
        const quoteRequest: QuoteRequest = {
          productId: i % 3 === 0 ? 'PRODUCT_A' : 'PRODUCT_B',
          coverageAmount: 100000,
          term: 12
        };
        loadRequests.push(request.post(`${API_BASE_URL}/api/quotes`, { data: quoteRequest }));
      }

      await Promise.all(loadRequests);

      // Refresh metrics
      await page.click('[data-testid="refresh-metrics-button"]');
      await page.waitForTimeout(2000);

      // Expected Result: No latency spikes observed
      const maxLatencyElement = page.locator('[data-testid="max-latency-value"]');
      const maxLatencyText = await maxLatencyElement.textContent();
      const maxLatency = parseInt(maxLatencyText?.replace('ms', '') || '0');
      expect(maxLatency).toBeLessThanOrEqual(500);

      const p95LatencyElement = page.locator('[data-testid="p95-latency-value"]');
      const p95LatencyText = await p95LatencyElement.textContent();
      const p95Latency = parseInt(p95LatencyText?.replace('ms', '') || '0');
      expect(p95Latency).toBeLessThanOrEqual(500);

      const p99LatencyElement = page.locator('[data-testid="p99-latency-value"]');
      const p99LatencyText = await p99LatencyElement.textContent();
      const p99Latency = parseInt(p99LatencyText?.replace('ms', '') || '0');
      expect(p99Latency).toBeLessThanOrEqual(500);

      // Check for spike indicators
      const spikeWarning = page.locator('[data-testid="latency-spike-warning"]');
      await expect(spikeWarning).not.toBeVisible();
    });
  });
});