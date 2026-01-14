import { test, expect } from '@playwright/test';

test.describe('Concurrent Scheduling - Data Integrity', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_URL = process.env.API_URL || 'http://localhost:3000/api';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/scheduler/dashboard`);
    await page.waitForLoadState('networkidle');
  });

  test('Ensure conflict detection under concurrent booking submissions', async ({ page, request }) => {
    // Prepare 100 booking requests with intentionally overlapping time slots for the same resources
    const overlappingBookings = [];
    const resourceId = 'resource-001';
    const startTime = '2024-02-01T10:00:00Z';
    const endTime = '2024-02-01T12:00:00Z';

    for (let i = 0; i < 100; i++) {
      overlappingBookings.push({
        resourceId: resourceId,
        startTime: startTime,
        endTime: endTime,
        schedulerId: `scheduler-${i}`,
        bookingType: 'meeting'
      });
    }

    // Initiate concurrent submission of all 100 booking requests simultaneously
    const submissionPromises = overlappingBookings.map(async (booking) => {
      return request.post(`${API_URL}/schedule/book`, {
        data: booking,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-token'
        }
      });
    });

    // Monitor system response for each booking submission request
    const responses = await Promise.allSettled(submissionPromises);

    let successfulBookings = 0;
    let conflictDetections = 0;
    const bookingIds = [];

    // Analyze responses to verify conflict detection
    for (const response of responses) {
      if (response.status === 'fulfilled') {
        const responseData = await response.value.json();
        if (response.value.status() === 201 || response.value.status() === 200) {
          successfulBookings++;
          if (responseData.bookingId) {
            bookingIds.push(responseData.bookingId);
          }
        } else if (response.value.status() === 409 || responseData.conflict) {
          conflictDetections++;
        }
      }
    }

    // System detects all conflicts accurately
    expect(conflictDetections).toBeGreaterThan(0);
    expect(successfulBookings + conflictDetections).toBe(100);
    expect(successfulBookings).toBeLessThanOrEqual(1);

    // Query the database to retrieve all bookings created during the concurrent submission test
    const dbBookingsResponse = await request.get(`${API_URL}/schedule/bookings`, {
      params: {
        resourceId: resourceId,
        startTime: startTime,
        endTime: endTime
      }
    });

    expect(dbBookingsResponse.ok()).toBeTruthy();
    const dbBookings = await dbBookingsResponse.json();

    // Verify no bookings created with unresolved conflicts
    expect(dbBookings.length).toBeLessThanOrEqual(1);

    // Verify no conflicting bookings persisted
    if (dbBookings.length > 1) {
      for (let i = 0; i < dbBookings.length; i++) {
        for (let j = i + 1; j < dbBookings.length; j++) {
          const booking1Start = new Date(dbBookings[i].startTime);
          const booking1End = new Date(dbBookings[i].endTime);
          const booking2Start = new Date(dbBookings[j].startTime);
          const booking2End = new Date(dbBookings[j].endTime);

          const hasOverlap = booking1Start < booking2End && booking2Start < booking1End;
          expect(hasOverlap).toBeFalsy();
        }
      }
    }

    // Review system logs for race conditions or deadlock errors
    const logsResponse = await request.get(`${API_URL}/system/logs`, {
      params: {
        level: 'error',
        search: 'race condition|deadlock'
      }
    });

    if (logsResponse.ok()) {
      const logs = await logsResponse.json();
      expect(logs.filter((log: any) => log.message.includes('race condition') || log.message.includes('deadlock')).length).toBe(0);
    }
  });

  test('Verify data consistency during concurrent operations', async ({ page, request }) => {
    // Create initial set of 25 confirmed bookings across various resources and time slots
    const initialBookings = [];
    for (let i = 0; i < 25; i++) {
      const bookingResponse = await request.post(`${API_URL}/schedule/book`, {
        data: {
          resourceId: `resource-${i % 5}`,
          startTime: `2024-02-${String(i + 1).padStart(2, '0')}T09:00:00Z`,
          endTime: `2024-02-${String(i + 1).padStart(2, '0')}T10:00:00Z`,
          schedulerId: `scheduler-initial-${i}`,
          bookingType: 'meeting'
        }
      });

      expect(bookingResponse.ok()).toBeTruthy();
      const bookingData = await bookingResponse.json();
      initialBookings.push(bookingData);
    }

    // Take a snapshot of the current database state
    const snapshotResponse = await request.get(`${API_URL}/schedule/bookings/all`);
    expect(snapshotResponse.ok()).toBeTruthy();
    const initialSnapshot = await snapshotResponse.json();
    const initialBookingCount = initialSnapshot.length;

    // Prepare concurrent operations: 25 new booking requests and 15 cancellation requests
    const newBookingRequests = [];
    for (let i = 0; i < 25; i++) {
      newBookingRequests.push(
        request.post(`${API_URL}/schedule/book`, {
          data: {
            resourceId: `resource-${i % 5}`,
            startTime: `2024-03-${String(i + 1).padStart(2, '0')}T14:00:00Z`,
            endTime: `2024-03-${String(i + 1).padStart(2, '0')}T15:00:00Z`,
            schedulerId: `scheduler-concurrent-${i}`,
            bookingType: 'meeting'
          }
        })
      );
    }

    const cancellationRequests = [];
    for (let i = 0; i < 15 && i < initialBookings.length; i++) {
      cancellationRequests.push(
        request.delete(`${API_URL}/schedule/book/${initialBookings[i].bookingId || initialBookings[i].id}`)
      );
    }

    // Execute all 40 operations concurrently
    const allOperations = [...newBookingRequests, ...cancellationRequests];
    const operationResults = await Promise.allSettled(allOperations);

    // Monitor and collect responses from all concurrent operations
    let successfulNewBookings = 0;
    let successfulCancellations = 0;
    let failedOperations = 0;

    for (let i = 0; i < operationResults.length; i++) {
      const result = operationResults[i];
      if (result.status === 'fulfilled') {
        const response = result.value;
        if (response.ok()) {
          if (i < 25) {
            successfulNewBookings++;
          } else {
            successfulCancellations++;
          }
        } else {
          failedOperations++;
        }
      } else {
        failedOperations++;
      }
    }

    // Query the database to retrieve current state after concurrent operations
    await page.waitForTimeout(1000); // Allow for database consistency
    const finalStateResponse = await request.get(`${API_URL}/schedule/bookings/all`);
    expect(finalStateResponse.ok()).toBeTruthy();
    const finalBookings = await finalStateResponse.json();

    // Verify data consistency
    // (a) All successful cancellations are reflected in database
    const expectedFinalCount = initialBookingCount - successfulCancellations + successfulNewBookings;
    expect(finalBookings.length).toBe(expectedFinalCount);

    // (b) All successful new bookings are persisted
    const newBookingsInDb = finalBookings.filter((booking: any) => 
      booking.schedulerId && booking.schedulerId.startsWith('scheduler-concurrent-')
    );
    expect(newBookingsInDb.length).toBe(successfulNewBookings);

    // (c) No phantom bookings exist
    const cancelledBookingIds = initialBookings.slice(0, 15).map(b => b.bookingId || b.id);
    const phantomBookings = finalBookings.filter((booking: any) => 
      cancelledBookingIds.includes(booking.bookingId || booking.id)
    );
    expect(phantomBookings.length).toBe(15 - successfulCancellations);

    // (d) Resource availability is correctly updated
    for (let i = 0; i < 5; i++) {
      const availabilityResponse = await request.get(`${API_URL}/resources/resource-${i}/availability`);
      expect(availabilityResponse.ok()).toBeTruthy();
      const availability = await availabilityResponse.json();
      expect(availability).toBeDefined();
    }

    // Perform referential integrity check
    const integrityResponse = await request.get(`${API_URL}/system/integrity-check`);
    if (integrityResponse.ok()) {
      const integrityResult = await integrityResponse.json();
      expect(integrityResult.valid).toBeTruthy();
      expect(integrityResult.orphanedRecords).toBe(0);
    }

    // Review transaction logs for rollback operations, deadlocks, or consistency violations
    const transactionLogsResponse = await request.get(`${API_URL}/system/transaction-logs`, {
      params: {
        timeRange: '5m',
        types: 'rollback,deadlock,consistency_violation'
      }
    });

    if (transactionLogsResponse.ok()) {
      const transactionLogs = await transactionLogsResponse.json();
      const criticalIssues = transactionLogs.filter((log: any) => 
        log.type === 'deadlock' || log.type === 'consistency_violation'
      );
      expect(criticalIssues.length).toBe(0);
    }

    // Verify audit trail completeness for all operations performed
    const auditResponse = await request.get(`${API_URL}/audit/trail`, {
      params: {
        operations: 'create,delete',
        timeRange: '5m'
      }
    });

    expect(auditResponse.ok()).toBeTruthy();
    const auditTrail = await auditResponse.json();
    expect(auditTrail.length).toBeGreaterThanOrEqual(successfulNewBookings + successfulCancellations);

    // Data remains consistent with no anomalies
    expect(finalBookings.every((booking: any) => booking.resourceId && booking.startTime && booking.endTime)).toBeTruthy();
  });
});