import { test, expect } from '@playwright/test';

test.describe('Concurrent Scheduling - Conflict Detection and Data Integrity', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000';
  const SCHEDULER_CREDENTIALS = [
    { username: 'scheduler1@test.com', password: 'Test123!' },
    { username: 'scheduler2@test.com', password: 'Test123!' },
    { username: 'scheduler3@test.com', password: 'Test123!' },
    { username: 'scheduler4@test.com', password: 'Test123!' },
    { username: 'scheduler5@test.com', password: 'Test123!' }
  ];

  let authTokens: string[] = [];

  test.beforeAll(async ({ request }) => {
    // Authenticate all scheduler users and collect tokens
    for (const cred of SCHEDULER_CREDENTIALS) {
      const response = await request.post(`${API_BASE_URL}/api/auth/login`, {
        data: cred
      });
      const body = await response.json();
      authTokens.push(body.token);
    }
  });

  test('Validate conflict detection under concurrent booking submissions', async ({ request }) => {
    const bookingRequests = [];
    const roomId = 'room-a-101';
    const baseDate = new Date();
    baseDate.setHours(10, 0, 0, 0);
    
    // Prepare 50 bookings for Room A from 10:00-11:00
    for (let i = 0; i < 50; i++) {
      bookingRequests.push({
        resourceId: roomId,
        startTime: new Date(baseDate.getTime()).toISOString(),
        endTime: new Date(baseDate.getTime() + 60 * 60 * 1000).toISOString(),
        schedulerId: `scheduler-${i % 5}`,
        title: `Booking ${i} - Slot 1`,
        token: authTokens[i % authTokens.length]
      });
    }

    // Prepare 50 bookings for Room A from 10:30-11:30 (overlapping)
    const overlappingStart = new Date(baseDate.getTime() + 30 * 60 * 1000);
    for (let i = 50; i < 100; i++) {
      bookingRequests.push({
        resourceId: roomId,
        startTime: overlappingStart.toISOString(),
        endTime: new Date(overlappingStart.getTime() + 60 * 60 * 1000).toISOString(),
        schedulerId: `scheduler-${i % 5}`,
        title: `Booking ${i} - Slot 2`,
        token: authTokens[i % authTokens.length]
      });
    }

    // Action: Simulate 100 concurrent booking submissions with overlapping times
    const submissionPromises = bookingRequests.map(booking =>
      request.post(`${API_BASE_URL}/api/bookings`, {
        data: {
          resourceId: booking.resourceId,
          startTime: booking.startTime,
          endTime: booking.endTime,
          schedulerId: booking.schedulerId,
          title: booking.title
        },
        headers: {
          'Authorization': `Bearer ${booking.token}`,
          'Content-Type': 'application/json'
        }
      }).catch(err => ({ error: true, message: err.message }))
    );

    const responses = await Promise.all(submissionPromises);

    // Expected Result: System detects all conflicts accurately
    let successCount = 0;
    let conflictCount = 0;
    let errorResponses = [];

    for (const response of responses) {
      if (response.error) {
        errorResponses.push(response);
        continue;
      }
      
      const status = response.status();
      if (status === 201) {
        successCount++;
      } else if (status === 409 || status === 400) {
        const body = await response.json();
        if (body.message && (body.message.includes('conflict') || body.message.includes('overlap'))) {
          conflictCount++;
        }
      }
    }

    // Verify that conflicts were detected (should be at least 99 conflicts since only 1 booking can succeed per time slot)
    expect(conflictCount).toBeGreaterThanOrEqual(98);
    expect(successCount).toBeLessThanOrEqual(2);

    // Action: Verify no conflicting bookings are saved
    const dbQueryResponse = await request.get(`${API_BASE_URL}/api/bookings`, {
      params: {
        resourceId: roomId,
        startDate: baseDate.toISOString(),
        endDate: new Date(baseDate.getTime() + 2 * 60 * 60 * 1000).toISOString()
      },
      headers: {
        'Authorization': `Bearer ${authTokens[0]}`
      }
    });

    expect(dbQueryResponse.ok()).toBeTruthy();
    const savedBookings = await dbQueryResponse.json();

    // Expected Result: Database contains only conflict-free bookings
    // Verify no time overlaps exist in saved bookings
    for (let i = 0; i < savedBookings.length; i++) {
      for (let j = i + 1; j < savedBookings.length; j++) {
        const booking1Start = new Date(savedBookings[i].startTime).getTime();
        const booking1End = new Date(savedBookings[i].endTime).getTime();
        const booking2Start = new Date(savedBookings[j].startTime).getTime();
        const booking2End = new Date(savedBookings[j].endTime).getTime();

        // Check for overlap
        const hasOverlap = (booking1Start < booking2End && booking1End > booking2Start);
        expect(hasOverlap).toBeFalsy();
      }
    }

    // Verify total saved bookings is minimal (should be 1 or 2 max for same resource)
    expect(savedBookings.length).toBeLessThanOrEqual(2);
  });

  test('Ensure no data loss or errors during concurrent submissions', async ({ request }) => {
    // Record the current count of bookings in the database as baseline
    const baselineResponse = await request.get(`${API_BASE_URL}/api/bookings/count`, {
      headers: {
        'Authorization': `Bearer ${authTokens[0]}`
      }
    });
    const baselineData = await baselineResponse.json();
    const baselineCount = baselineData.count || 0;

    // Prepare 100 valid booking submissions with non-overlapping time slots across different resources
    const validBookings = [];
    const baseDate = new Date();
    baseDate.setDate(baseDate.getDate() + 1); // Tomorrow
    baseDate.setHours(8, 0, 0, 0);

    for (let i = 0; i < 100; i++) {
      const resourceId = `room-${Math.floor(i / 10)}`; // 10 bookings per resource
      const slotIndex = i % 10;
      const startTime = new Date(baseDate.getTime() + slotIndex * 60 * 60 * 1000);
      const endTime = new Date(startTime.getTime() + 60 * 60 * 1000);

      validBookings.push({
        resourceId: resourceId,
        startTime: startTime.toISOString(),
        endTime: endTime.toISOString(),
        schedulerId: `scheduler-${i % 5}`,
        title: `Valid Booking ${i}`,
        description: `Concurrent test booking ${i}`,
        token: authTokens[i % authTokens.length]
      });
    }

    // Action: Execute concurrent submission of all 100 valid bookings
    const submissionPromises = validBookings.map(booking =>
      request.post(`${API_BASE_URL}/api/bookings`, {
        data: {
          resourceId: booking.resourceId,
          startTime: booking.startTime,
          endTime: booking.endTime,
          schedulerId: booking.schedulerId,
          title: booking.title,
          description: booking.description
        },
        headers: {
          'Authorization': `Bearer ${booking.token}`,
          'Content-Type': 'application/json'
        }
      })
    );

    const responses = await Promise.all(submissionPromises);

    // Expected Result: All valid bookings receive success responses (HTTP 201 Created) without errors
    let successResponses = 0;
    let failedResponses = 0;
    const responseDetails = [];

    for (let i = 0; i < responses.length; i++) {
      const response = responses[i];
      const status = response.status();
      const body = await response.json();

      responseDetails.push({
        index: i,
        status: status,
        body: body
      });

      if (status === 201) {
        successResponses++;
      } else {
        failedResponses++;
      }
    }

    // Expected Result: All valid bookings are saved without errors
    expect(successResponses).toBe(100);
    expect(failedResponses).toBe(0);

    // Query the database and count total bookings after concurrent submission
    const afterSubmissionResponse = await request.get(`${API_BASE_URL}/api/bookings/count`, {
      headers: {
        'Authorization': `Bearer ${authTokens[0]}`
      }
    });
    const afterSubmissionData = await afterSubmissionResponse.json();
    const afterSubmissionCount = afterSubmissionData.count || 0;

    // Verify that exactly 100 new bookings were added
    expect(afterSubmissionCount - baselineCount).toBe(100);

    // Verify data integrity by checking that all submitted booking details match database records
    const verificationPromises = validBookings.map(booking =>
      request.get(`${API_BASE_URL}/api/bookings`, {
        params: {
          resourceId: booking.resourceId,
          startTime: booking.startTime,
          endTime: booking.endTime
        },
        headers: {
          'Authorization': `Bearer ${authTokens[0]}`
        }
      })
    );

    const verificationResponses = await Promise.all(verificationPromises);
    let verifiedBookings = 0;

    for (let i = 0; i < verificationResponses.length; i++) {
      const response = verificationResponses[i];
      expect(response.ok()).toBeTruthy();
      
      const bookings = await response.json();
      const matchingBooking = bookings.find(b => 
        b.resourceId === validBookings[i].resourceId &&
        b.startTime === validBookings[i].startTime &&
        b.endTime === validBookings[i].endTime &&
        b.title === validBookings[i].title
      );

      if (matchingBooking) {
        verifiedBookings++;
      }
    }

    // All 100 bookings should be verifiable in the database
    expect(verifiedBookings).toBe(100);

    // Check for duplicate bookings
    const allBookingsResponse = await request.get(`${API_BASE_URL}/api/bookings`, {
      params: {
        startDate: baseDate.toISOString(),
        endDate: new Date(baseDate.getTime() + 24 * 60 * 60 * 1000).toISOString()
      },
      headers: {
        'Authorization': `Bearer ${authTokens[0]}`
      }
    });

    const allBookings = await allBookingsResponse.json();
    const bookingKeys = new Set();
    let duplicateCount = 0;

    for (const booking of allBookings) {
      const key = `${booking.resourceId}-${booking.startTime}-${booking.endTime}`;
      if (bookingKeys.has(key)) {
        duplicateCount++;
      }
      bookingKeys.add(key);
    }

    // Verify no duplicate bookings exist
    expect(duplicateCount).toBe(0);
  });
});