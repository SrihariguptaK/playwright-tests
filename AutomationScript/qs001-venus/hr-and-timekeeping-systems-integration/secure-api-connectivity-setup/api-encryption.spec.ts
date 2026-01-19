import { test, expect } from '@playwright/test';
import https from 'https';
import http from 'http';

const API_BASE_URL = process.env.API_BASE_URL || 'https://localhost:3000';
const API_ENDPOINT = '/api/employees';

test.describe('API Data Transmission Encryption - Story 14', () => {
  test.describe('Verify API endpoints accept HTTPS connections only', () => {
    test('should accept and process HTTPS API requests', async ({ request }) => {
      // Action: Send API request over HTTPS
      const response = await request.get(`${API_BASE_URL}${API_ENDPOINT}`, {
        ignoreHTTPSErrors: false,
        headers: {
          'Content-Type': 'application/json'
        }
      });

      // Expected Result: Request is accepted and processed
      expect(response.status()).toBeLessThan(400);
      expect(response.ok() || response.status() === 401 || response.status() === 403).toBeTruthy();
    });

    test('should reject HTTP API requests with error indicating HTTPS required', async ({ request }) => {
      const httpUrl = API_BASE_URL.replace('https://', 'http://');
      
      try {
        // Action: Send API request over HTTP
        const response = await request.get(`${httpUrl}${API_ENDPOINT}`, {
          maxRedirects: 0,
          headers: {
            'Content-Type': 'application/json'
          }
        });

        // Expected Result: Request is rejected with error indicating HTTPS required
        // Should either be rejected (400-level error) or redirected to HTTPS (300-level)
        const status = response.status();
        const isRejected = status >= 400;
        const isRedirectedToHttps = status >= 300 && status < 400;
        
        expect(isRejected || isRedirectedToHttps).toBeTruthy();
        
        if (isRejected) {
          const body = await response.text();
          expect(body.toLowerCase()).toMatch(/https|secure|ssl|tls/);
        }
      } catch (error) {
        // Connection refused or protocol error is also acceptable
        expect(error.message).toMatch(/ECONNREFUSED|protocol|HTTPS|SSL/);
      }
    });
  });

  test.describe('Verify TLS version enforcement', () => {
    test('should reject connection attempts with TLS 1.1 or lower', async () => {
      const url = new URL(API_BASE_URL + API_ENDPOINT);
      
      // Action: Attempt connection with TLS 1.1 or lower
      const tlsOptions = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'GET',
        minVersion: 'TLSv1',
        maxVersion: 'TLSv1.1',
        rejectUnauthorized: false
      };

      let connectionRejected = false;
      let errorMessage = '';

      try {
        await new Promise((resolve, reject) => {
          const req = https.request(tlsOptions, (res) => {
            // If we get a response, connection was not properly rejected
            resolve(res.statusCode);
          });

          req.on('error', (error) => {
            connectionRejected = true;
            errorMessage = error.message;
            reject(error);
          });

          req.end();
        });
      } catch (error) {
        connectionRejected = true;
        errorMessage = error.message;
      }

      // Expected Result: Connection is rejected
      expect(connectionRejected).toBeTruthy();
      expect(errorMessage).toMatch(/handshake|protocol|version|alert|SSL|TLS/);
    });

    test('should accept connection attempts with TLS 1.2 or higher', async () => {
      const url = new URL(API_BASE_URL + API_ENDPOINT);
      
      // Action: Attempt connection with TLS 1.2 or higher
      const tlsOptions = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'GET',
        minVersion: 'TLSv1.2',
        rejectUnauthorized: false
      };

      let connectionAccepted = false;
      let statusCode = 0;

      try {
        statusCode = await new Promise((resolve, reject) => {
          const req = https.request(tlsOptions, (res) => {
            connectionAccepted = true;
            resolve(res.statusCode);
          });

          req.on('error', (error) => {
            reject(error);
          });

          req.setTimeout(5000, () => {
            req.destroy();
            reject(new Error('Connection timeout'));
          });

          req.end();
        });
      } catch (error) {
        connectionAccepted = false;
      }

      // Expected Result: Connection is accepted
      expect(connectionAccepted).toBeTruthy();
      expect(statusCode).toBeGreaterThan(0);
    });
  });

  test.describe('Additional Security Validation', () => {
    test('should verify HTTPS endpoint responds with valid TLS certificate', async ({ request }) => {
      const response = await request.get(`${API_BASE_URL}${API_ENDPOINT}`, {
        ignoreHTTPSErrors: false
      });

      // Verify the connection was established (certificate validation passed)
      expect(response.status()).toBeDefined();
    });

    test('should verify API endpoint URL uses HTTPS protocol', () => {
      const url = new URL(API_BASE_URL);
      
      // Verify protocol is HTTPS
      expect(url.protocol).toBe('https:');
    });
  });
});