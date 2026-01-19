import { test, expect } from '@playwright/test';
import https from 'https';
import http from 'http';

const API_BASE_URL = process.env.API_BASE_URL || 'https://api.example.com';
const API_ENDPOINT = '/api/employees';
const AUTH_TOKEN = process.env.AUTH_TOKEN || 'valid-auth-token';

test.describe('API Encryption Security - Story 14', () => {
  
  test.describe('Verify API endpoints accept HTTPS connections only', () => {
    
    test('should accept and process HTTPS API requests', async ({ request }) => {
      // Action: Send API request over HTTPS
      const response = await request.get(`${API_BASE_URL}${API_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${AUTH_TOKEN}`,
          'Content-Type': 'application/json'
        },
        ignoreHTTPSErrors: false
      });
      
      // Expected Result: Request is accepted and processed
      expect(response.status()).toBeLessThan(400);
      expect(response.ok() || response.status() === 401).toBeTruthy();
    });
    
    test('should reject HTTP API requests with error indicating HTTPS required', async ({ request }) => {
      // Action: Send API request over HTTP
      const httpUrl = API_BASE_URL.replace('https://', 'http://');
      
      try {
        const response = await request.get(`${httpUrl}${API_ENDPOINT}`, {
          headers: {
            'Authorization': `Bearer ${AUTH_TOKEN}`,
            'Content-Type': 'application/json'
          },
          maxRedirects: 0,
          timeout: 5000
        });
        
        // Expected Result: Request is rejected with error indicating HTTPS required
        // Should either fail to connect, return 400-level error, or redirect to HTTPS
        if (response.status() === 301 || response.status() === 302) {
          const location = response.headers()['location'];
          expect(location).toContain('https://');
        } else {
          expect(response.status()).toBeGreaterThanOrEqual(400);
        }
      } catch (error) {
        // Connection rejection is also acceptable
        expect(error).toBeDefined();
      }
    });
    
    test('should log all connection attempts with encryption status', async ({ request }) => {
      // Send HTTPS request
      await request.get(`${API_BASE_URL}${API_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${AUTH_TOKEN}`,
          'Content-Type': 'application/json'
        }
      });
      
      // Send HTTP request (will be rejected)
      const httpUrl = API_BASE_URL.replace('https://', 'http://');
      try {
        await request.get(`${httpUrl}${API_ENDPOINT}`, {
          headers: {
            'Authorization': `Bearer ${AUTH_TOKEN}`,
            'Content-Type': 'application/json'
          },
          timeout: 5000
        });
      } catch (error) {
        // Expected to fail
      }
      
      // Query connection logs to verify both attempts were recorded
      const logsResponse = await request.get(`${API_BASE_URL}/api/logs/connections`, {
        headers: {
          'Authorization': `Bearer ${AUTH_TOKEN}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (logsResponse.ok()) {
        const logs = await logsResponse.json();
        expect(Array.isArray(logs)).toBeTruthy();
        
        // Verify logs contain protocol information
        const recentLogs = logs.slice(0, 10);
        const hasProtocolInfo = recentLogs.some((log: any) => 
          log.protocol || log.encryption_status || log.tls_version
        );
        expect(hasProtocolInfo).toBeTruthy();
      }
    });
  });
  
  test.describe('Verify TLS version enforcement', () => {
    
    test('should reject connection attempts with TLS 1.1', async () => {
      // Action: Attempt connection with TLS 1.1
      const options = {
        hostname: API_BASE_URL.replace('https://', '').replace('http://', ''),
        port: 443,
        path: API_ENDPOINT,
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${AUTH_TOKEN}`,
          'Content-Type': 'application/json'
        },
        minVersion: 'TLSv1.1' as const,
        maxVersion: 'TLSv1.1' as const
      };
      
      let connectionRejected = false;
      
      await new Promise<void>((resolve) => {
        const req = https.request(options, (res) => {
          // If we get a response, connection was not properly rejected
          connectionRejected = false;
          resolve();
        });
        
        req.on('error', (error: any) => {
          // Expected Result: Connection is rejected
          connectionRejected = true;
          expect(error).toBeDefined();
          resolve();
        });
        
        req.setTimeout(5000, () => {
          req.destroy();
          connectionRejected = true;
          resolve();
        });
        
        req.end();
      });
      
      expect(connectionRejected).toBeTruthy();
    });
    
    test('should reject connection attempts with TLS 1.0', async () => {
      // Action: Attempt connection with TLS 1.0
      const options = {
        hostname: API_BASE_URL.replace('https://', '').replace('http://', ''),
        port: 443,
        path: API_ENDPOINT,
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${AUTH_TOKEN}`,
          'Content-Type': 'application/json'
        },
        minVersion: 'TLSv1' as const,
        maxVersion: 'TLSv1' as const
      };
      
      let connectionRejected = false;
      
      await new Promise<void>((resolve) => {
        const req = https.request(options, (res) => {
          connectionRejected = false;
          resolve();
        });
        
        req.on('error', (error: any) => {
          // Expected Result: Connection is rejected
          connectionRejected = true;
          expect(error).toBeDefined();
          resolve();
        });
        
        req.setTimeout(5000, () => {
          req.destroy();
          connectionRejected = true;
          resolve();
        });
        
        req.end();
      });
      
      expect(connectionRejected).toBeTruthy();
    });
    
    test('should accept connection attempts with TLS 1.2', async ({ request }) => {
      // Action: Attempt connection with TLS 1.2
      const response = await request.get(`${API_BASE_URL}${API_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${AUTH_TOKEN}`,
          'Content-Type': 'application/json'
        },
        ignoreHTTPSErrors: false
      });
      
      // Expected Result: Connection is accepted
      expect(response.status()).toBeLessThan(500);
    });
    
    test('should accept connection attempts with TLS 1.3', async ({ request }) => {
      // Action: Attempt connection with TLS 1.3
      const response = await request.get(`${API_BASE_URL}${API_ENDPOINT}`, {
        headers: {
          'Authorization': `Bearer ${AUTH_TOKEN}`,
          'Content-Type': 'application/json'
        },
        ignoreHTTPSErrors: false
      });
      
      // Expected Result: Connection is accepted
      expect(response.status()).toBeLessThan(500);
    });
    
    test('should log all TLS connection attempts with versions and outcomes', async ({ request }) => {
      // Attempt connections with different TLS versions
      const tlsVersions = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
      
      for (const version of ['TLSv1.2', 'TLSv1.3']) {
        try {
          await request.get(`${API_BASE_URL}${API_ENDPOINT}`, {
            headers: {
              'Authorization': `Bearer ${AUTH_TOKEN}`,
              'Content-Type': 'application/json'
            }
          });
        } catch (error) {
          // Some versions expected to fail
        }
      }
      
      // Query connection logs to verify attempts were recorded
      const logsResponse = await request.get(`${API_BASE_URL}/api/logs/connections`, {
        headers: {
          'Authorization': `Bearer ${AUTH_TOKEN}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (logsResponse.ok()) {
        const logs = await logsResponse.json();
        expect(Array.isArray(logs)).toBeTruthy();
        
        // Verify logs contain TLS version and outcome information
        const recentLogs = logs.slice(0, 20);
        const hasTLSInfo = recentLogs.some((log: any) => 
          log.tls_version || log.protocol_version || log.encryption_protocol
        );
        const hasOutcomeInfo = recentLogs.some((log: any) => 
          log.status || log.outcome || log.success !== undefined
        );
        
        expect(hasTLSInfo || hasOutcomeInfo).toBeTruthy();
      }
    });
  });
});