import { test, expect } from '@playwright/test';

test.describe('Attendance Data Validation', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000';
  const VALIDATION_ENDPOINT = '/attendance/validate';
  const MAX_VALIDATION_TIME = 500;

  test('Validate acceptance of correct attendance data', async ({ request }) => {
    // Prepare a valid attendance event JSON payload with all required fields
    const validAttendanceEvent = {
      employeeId: 'EMP001',
      timestamp: new Date().toISOString(),
      eventType: 'check-in',
      location: 'Main Office'
    };

    const startTime = Date.now();

    // Send POST request to /attendance/validate endpoint with the valid attendance event payload
    const response = await request.post(`${API_BASE_URL}${VALIDATION_ENDPOINT}`, {
      data: validAttendanceEvent
    });

    const endTime = Date.now();
    const responseTime = endTime - startTime;

    // Review the API response body for validation confirmation
    expect(response.ok()).toBeTruthy();
    expect(response.status()).toBe(200);

    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('success', true);
    expect(responseBody).toHaveProperty('message');
    expect(responseBody.message).toContain('accepted');

    // Measure and record the response time from request submission to response receipt
    expect(responseTime).toBeLessThan(MAX_VALIDATION_TIME);

    // Verify the event was stored (checking response confirmation)
    expect(responseBody).toHaveProperty('eventId');
    expect(responseBody.eventId).toBeTruthy();
  });

  test('Verify rejection of invalid attendance data', async ({ request }) => {
    // Prepare an invalid attendance event JSON payload with missing employee ID field
    const invalidAttendanceEvent = {
      timestamp: new Date().toISOString(),
      eventType: 'check-out',
      location: 'Main Office'
      // Missing employeeId field
    };

    const startTime = Date.now();

    // Send POST request to /attendance/validate endpoint with the invalid attendance event payload
    const response = await request.post(`${API_BASE_URL}${VALIDATION_ENDPOINT}`, {
      data: invalidAttendanceEvent
    });

    const endTime = Date.now();
    const responseTime = endTime - startTime;

    // Review the API response status code
    expect(response.status()).toBe(400);

    // Examine the API response body for error details
    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('success', false);
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toContain('employeeId');
    expect(responseBody).toHaveProperty('validationErrors');

    // Verify error was logged (checking response includes log reference)
    expect(responseBody).toHaveProperty('errorLogId');
    expect(responseBody.errorLogId).toBeTruthy();

    // Measure the validation response time
    expect(responseTime).toBeLessThan(MAX_VALIDATION_TIME);
  });

  test('Test duplicate event detection', async ({ request }) => {
    // Prepare a valid attendance event JSON payload with all required fields
    const attendanceEvent = {
      employeeId: 'EMP002',
      timestamp: new Date().toISOString(),
      eventType: 'check-in',
      location: 'Branch Office'
    };

    // Send POST request to /attendance/validate endpoint with the attendance event payload for the first time
    const firstResponse = await request.post(`${API_BASE_URL}${VALIDATION_ENDPOINT}`, {
      data: attendanceEvent
    });

    // Verify the first event is stored
    expect(firstResponse.ok()).toBeTruthy();
    expect(firstResponse.status()).toBe(200);

    const firstResponseBody = await firstResponse.json();
    expect(firstResponseBody).toHaveProperty('success', true);
    expect(firstResponseBody).toHaveProperty('eventId');
    const firstEventId = firstResponseBody.eventId;

    const startTime = Date.now();

    // Immediately send another POST request with the exact same attendance event payload (duplicate)
    const duplicateResponse = await request.post(`${API_BASE_URL}${VALIDATION_ENDPOINT}`, {
      data: attendanceEvent
    });

    const endTime = Date.now();
    const responseTime = endTime - startTime;

    // Review the API response status code for the duplicate submission
    expect(duplicateResponse.status()).toBe(409);

    // Examine the API response body for duplicate detection details
    const duplicateResponseBody = await duplicateResponse.json();
    expect(duplicateResponseBody).toHaveProperty('success', false);
    expect(duplicateResponseBody).toHaveProperty('error');
    expect(duplicateResponseBody.error).toContain('duplicate');
    expect(duplicateResponseBody).toHaveProperty('duplicateDetected', true);
    expect(duplicateResponseBody).toHaveProperty('originalEventId', firstEventId);

    // Measure the duplicate detection response time
    expect(responseTime).toBeLessThan(MAX_VALIDATION_TIME);
  });
});