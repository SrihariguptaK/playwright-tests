import { test, expect } from '@playwright/test';

const API_BASE_URL = process.env.API_BASE_URL || 'https://api.example.com';
const PROTECTED_ENDPOINT = '/api/v1/protected-resource';
const VALID_API_KEY = process.env.VALID_API_KEY || 'valid_api_key_token_12345';
const INVALID_API_KEY = 'invalid_key_12345';

test.describe('Story-17: Reject unauthorized API requests for secure access control', () => {
  
  test.describe('Test Case #1: Verify rejection of API requests with invalid credentials', () => {
    
    test('should reject API request with invalid API key and return 401 Unauthorized', async ({ request }) => {
      // Action: Send API request with invalid API key
      const response = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${INVALID_API_KEY}`
        }
      });
      
      // Expected Result: Request rejected with 401 Unauthorized
      expect(response.status()).toBe(401);
      
      const responseBody = await response.json();
      expect(responseBody).toHaveProperty('error');
      
      // Verify no sensitive data is returned
      expect(responseBody).not.toHaveProperty('data');
      expect(responseBody).not.toHaveProperty('resource');
    });
    
    test('should reject API request without credentials and return 401 Unauthorized', async ({ request }) => {
      // Action: Send API request without credentials
      const response = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`);
      
      // Expected Result: Request rejected with 401 Unauthorized
      expect(response.status()).toBe(401);
      
      const responseBody = await response.json();
      expect(responseBody).toHaveProperty('error');
    });
    
    test('should reject API request with malformed Authorization header', async ({ request }) => {
      // Action: Send API request with malformed Authorization header
      const response = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': 'InvalidFormat'
        }
      });
      
      // Expected Result: Request rejected with 401 Unauthorized
      expect(response.status()).toBe(401);
    });
    
    test('should log all unauthorized access attempts with IP and timestamp', async ({ request, page }) => {
      // Send unauthorized request to generate log entry
      await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${INVALID_API_KEY}`
        }
      });
      
      // Navigate to system logs interface
      await page.goto(`${API_BASE_URL.replace('/api', '')}/admin/logs`);
      
      // Wait for logs to load
      await page.waitForSelector('[data-testid="logs-table"]', { timeout: 5000 });
      
      // Expected Result: All unauthorized attempts logged with details
      const logEntries = await page.locator('[data-testid="log-entry"]').all();
      expect(logEntries.length).toBeGreaterThan(0);
      
      // Verify log entry contains IP address
      const firstLogEntry = logEntries[0];
      await expect(firstLogEntry.locator('[data-testid="log-ip-address"]')).toBeVisible();
      
      // Verify log entry contains timestamp
      await expect(firstLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
      
      // Verify log entry contains attempted credential info
      await expect(firstLogEntry.locator('[data-testid="log-credentials"]')).toBeVisible();
    });
    
    test('should process authorized requests without delay after unauthorized attempts', async ({ request }) => {
      // Send unauthorized request first
      await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${INVALID_API_KEY}`
        }
      });
      
      // Action: Send valid request with correct API key
      const startTime = Date.now();
      const response = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${VALID_API_KEY}`
        }
      });
      const endTime = Date.now();
      
      // Expected Result: Authorized request processed normally
      expect(response.status()).toBe(200);
      
      const responseBody = await response.json();
      expect(responseBody).toHaveProperty('data');
      
      // Verify minimal latency (less than 2 seconds)
      const responseTime = endTime - startTime;
      expect(responseTime).toBeLessThan(2000);
    });
  });
  
  test.describe('Test Case #2: Test rate limiting on repeated unauthorized requests', () => {
    
    test('should block requests after threshold exceeded from same IP', async ({ request }) => {
      const sourceIP = '192.168.1.100';
      const threshold = 10;
      const totalRequests = 15;
      
      // Action: Send multiple unauthorized requests rapidly from same IP
      const responses = [];
      
      for (let i = 0; i < totalRequests; i++) {
        const response = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
          headers: {
            'Authorization': `Bearer ${INVALID_API_KEY}`,
            'X-Forwarded-For': sourceIP
          }
        });
        responses.push(response);
      }
      
      // Expected Result: First 10 requests return 401, subsequent requests blocked
      for (let i = 0; i < threshold; i++) {
        expect(responses[i].status()).toBe(401);
      }
      
      // Expected Result: System blocks requests after threshold exceeded
      for (let i = threshold; i < totalRequests; i++) {
        expect(responses[i].status()).toBe(429); // Too Many Requests
        
        // Verify rate limit headers
        const headers = responses[i].headers();
        expect(headers).toHaveProperty('x-ratelimit-limit');
        expect(headers).toHaveProperty('x-ratelimit-remaining');
        expect(headers).toHaveProperty('retry-after');
      }
      
      // Verify error message indicates rate limiting
      const blockedResponse = await responses[threshold].json();
      expect(blockedResponse.error).toContain('rate limit');
    });
    
    test('should process authorized request normally from rate-limited IP', async ({ request }) => {
      const sourceIP = '192.168.1.101';
      
      // Trigger rate limiting with unauthorized requests
      for (let i = 0; i < 12; i++) {
        await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
          headers: {
            'Authorization': `Bearer ${INVALID_API_KEY}`,
            'X-Forwarded-For': sourceIP
          }
        });
      }
      
      // Action: Attempt authorized request from same IP
      const authorizedResponse = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${VALID_API_KEY}`,
          'X-Forwarded-For': sourceIP
        }
      });
      
      // Expected Result: Authorized request processed normally
      expect(authorizedResponse.status()).toBe(200);
      
      const responseBody = await authorizedResponse.json();
      expect(responseBody).toHaveProperty('data');
    });
    
    test('should handle unauthorized requests independently from different IP addresses', async ({ request }) => {
      const ipAddress1 = '192.168.1.102';
      const ipAddress2 = '192.168.1.103';
      
      // Trigger rate limiting from first IP
      for (let i = 0; i < 12; i++) {
        await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
          headers: {
            'Authorization': `Bearer ${INVALID_API_KEY}`,
            'X-Forwarded-For': ipAddress1
          }
        });
      }
      
      // Action: Send unauthorized request from different IP
      const responseFromIP2 = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${INVALID_API_KEY}`,
          'X-Forwarded-For': ipAddress2
        }
      });
      
      // Expected Result: Request from different IP handled independently (401, not 429)
      expect(responseFromIP2.status()).toBe(401);
    });
    
    test('should reset rate limit after time window expires', async ({ request }) => {
      const sourceIP = '192.168.1.104';
      
      // Trigger rate limiting
      for (let i = 0; i < 12; i++) {
        await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
          headers: {
            'Authorization': `Bearer ${INVALID_API_KEY}`,
            'X-Forwarded-For': sourceIP
          }
        });
      }
      
      // Wait for rate limit window to reset (1 minute)
      await new Promise(resolve => setTimeout(resolve, 61000));
      
      // Action: Send another unauthorized request after window reset
      const response = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${INVALID_API_KEY}`,
          'X-Forwarded-For': sourceIP
        }
      });
      
      // Expected Result: Request returns 401 (not 429), indicating rate limit reset
      expect(response.status()).toBe(401);
    });
  });
  
  test.describe('Test Case #3: Validate error message content for unauthorized requests', () => {
    
    test('should return clear error message stating Unauthorized access', async ({ request }) => {
      // Action: Send unauthorized API request
      const response = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${INVALID_API_KEY}`
        }
      });
      
      expect(response.status()).toBe(401);
      
      // Verify response follows JSON format
      const contentType = response.headers()['content-type'];
      expect(contentType).toContain('application/json');
      
      const responseBody = await response.json();
      
      // Expected Result: Error message clearly states 'Unauthorized access'
      expect(responseBody).toHaveProperty('error');
      expect(responseBody.error.toLowerCase()).toContain('unauthorized');
      
      // Verify standard error fields
      expect(responseBody).toHaveProperty('message');
      expect(responseBody.message.toLowerCase()).toMatch(/unauthorized access|invalid credentials|authentication required/);
    });
    
    test('should not expose sensitive system information in error messages', async ({ request }) => {
      const response = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${INVALID_API_KEY}`
        }
      });
      
      const responseBody = await response.json();
      const responseText = JSON.stringify(responseBody).toLowerCase();
      
      // Verify no sensitive information exposed
      expect(responseText).not.toContain('database');
      expect(responseText).not.toContain('sql');
      expect(responseText).not.toContain('stack trace');
      expect(responseText).not.toContain('internal path');
      expect(responseText).not.toContain('/var/');
      expect(responseText).not.toContain('c:\\');
    });
    
    test('should provide actionable guidance in error messages', async ({ request }) => {
      const response = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${INVALID_API_KEY}`
        }
      });
      
      const responseBody = await response.json();
      const messageText = (responseBody.message || responseBody.error || '').toLowerCase();
      
      // Verify actionable guidance is provided
      const hasActionableGuidance = 
        messageText.includes('provide valid') ||
        messageText.includes('contact administrator') ||
        messageText.includes('check credentials') ||
        messageText.includes('authentication required');
      
      expect(hasActionableGuidance).toBeTruthy();
    });
    
    test('should return consistent error messages across different endpoints', async ({ request }) => {
      const endpoints = [
        '/api/v1/users',
        '/api/v1/reports',
        '/api/v1/settings',
        '/api/v1/secure-data'
      ];
      
      const responses = [];
      
      // Send unauthorized requests to different endpoints
      for (const endpoint of endpoints) {
        const response = await request.get(`${API_BASE_URL}${endpoint}`, {
          headers: {
            'Authorization': `Bearer ${INVALID_API_KEY}`
          }
        });
        
        expect(response.status()).toBe(401);
        const body = await response.json();
        responses.push(body);
      }
      
      // Compare error messages for consistency
      const firstErrorStructure = Object.keys(responses[0]).sort();
      
      for (let i = 1; i < responses.length; i++) {
        const currentErrorStructure = Object.keys(responses[i]).sort();
        expect(currentErrorStructure).toEqual(firstErrorStructure);
      }
      
      // Verify all contain similar error message patterns
      for (const response of responses) {
        expect(response.error.toLowerCase()).toContain('unauthorized');
      }
    });
    
    test('should return consistent error messages across different HTTP methods', async ({ request }) => {
      const methods = ['GET', 'POST', 'PUT', 'DELETE'];
      const responses = [];
      
      // Test with different HTTP methods
      for (const method of methods) {
        let response;
        
        if (method === 'GET') {
          response = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
            headers: { 'Authorization': `Bearer ${INVALID_API_KEY}` }
          });
        } else if (method === 'POST') {
          response = await request.post(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
            headers: { 'Authorization': `Bearer ${INVALID_API_KEY}` },
            data: { test: 'data' }
          });
        } else if (method === 'PUT') {
          response = await request.put(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
            headers: { 'Authorization': `Bearer ${INVALID_API_KEY}` },
            data: { test: 'data' }
          });
        } else if (method === 'DELETE') {
          response = await request.delete(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
            headers: { 'Authorization': `Bearer ${INVALID_API_KEY}` }
          });
        }
        
        expect(response.status()).toBe(401);
        const body = await response.json();
        responses.push(body);
      }
      
      // Verify consistency across methods
      for (const response of responses) {
        expect(response).toHaveProperty('error');
        expect(response.error.toLowerCase()).toContain('unauthorized');
      }
    });
    
    test('should include appropriate CORS headers in error responses', async ({ request }) => {
      const response = await request.get(`${API_BASE_URL}${PROTECTED_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${INVALID_API_KEY}`,
          'Origin': 'https://example-client.com'
        }
      });
      
      expect(response.status()).toBe(401);
      
      // Verify CORS headers if applicable
      const headers = response.headers();
      
      if (headers['access-control-allow-origin']) {
        expect(headers).toHaveProperty('access-control-allow-origin');
        expect(headers).toHaveProperty('access-control-allow-methods');
      }
    });
  });
});