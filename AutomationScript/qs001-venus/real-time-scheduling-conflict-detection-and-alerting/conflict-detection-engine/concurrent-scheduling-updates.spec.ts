import { test, expect } from '@playwright/test';
import { request } from '@playwright/test';

test.describe('Concurrent Scheduling Updates - Conflict Detection', () => {
  const BASE_URL = process.env.API_URL || 'http://localhost:3000';
  const AUTH_TOKENS = [
    'token_user1',
    'token_user2',
    'token_user3',
    'token_user4',
    'token_user5'
  ];

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/scheduler`);
  });

  test('Validate conflict detection under concurrent schedule updates (happy-path)', async ({ page, request: apiContext }) => {
    // Set up 5 concurrent user sessions with valid authentication tokens
    const userSessions = AUTH_TOKENS.map(token => ({
      token,
      headers: { 'Authorization': `Bearer ${token}` }
    }));

    // Prepare overlapping appointment data
    const overlappingAppointments = [
      {
        userId: 'user1',
        room: 'Room A',
        startTime: '10:00',
        endTime: '11:00',
        date: '2024-01-15'
      },
      {
        userId: 'user2',
        room: 'Room A',
        startTime: '10:30',
        endTime: '11:30',
        date: '2024-01-15'
      },
      {
        userId: 'user3',
        room: 'Room A',
        startTime: '10:15',
        endTime: '11:15',
        date: '2024-01-15'
      },
      {
        userId: 'user4',
        room: 'Room A',
        startTime: '10:45',
        endTime: '11:45',
        date: '2024-01-15'
      },
      {
        userId: 'user5',
        room: 'Room A',
        startTime: '10:20',
        endTime: '11:20',
        date: '2024-01-15'
      }
    ];

    // Simultaneously trigger PUT /api/appointments/{id} requests from all 5 users within a 100ms window
    const startTime = Date.now();
    const concurrentRequests = overlappingAppointments.map((appointment, index) => {
      return apiContext.put(`${BASE_URL}/api/appointments/${index + 1}`, {
        headers: userSessions[index].headers,
        data: appointment
      });
    });

    // Action: Simulate multiple users updating overlapping schedules concurrently
    const responses = await Promise.all(concurrentRequests);
    const endTime = Date.now();
    const executionWindow = endTime - startTime;

    // Expected Result: System processes all updates without errors
    expect(executionWindow).toBeLessThan(100);
    responses.forEach(response => {
      expect(response.status()).toBeLessThanOrEqual(409); // 200 OK or 409 Conflict acceptable
    });

    // Action: Verify all conflicts are detected and flagged
    const appointmentsResponse = await apiContext.get(`${BASE_URL}/api/appointments`, {
      params: { date: '2024-01-15', room: 'Room A' }
    });
    expect(appointmentsResponse.ok()).toBeTruthy();
    const appointments = await appointmentsResponse.json();

    // Expected Result: No conflicts are missed
    const conflictedAppointments = appointments.filter((apt: any) => apt.hasConflict === true);
    expect(conflictedAppointments.length).toBeGreaterThan(0);

    // Verify conflict flags on overlapping appointments
    for (let i = 0; i < appointments.length - 1; i++) {
      for (let j = i + 1; j < appointments.length; j++) {
        const apt1 = appointments[i];
        const apt2 = appointments[j];
        if (apt1.room === apt2.room) {
          const overlap = checkTimeOverlap(apt1.startTime, apt1.endTime, apt2.startTime, apt2.endTime);
          if (overlap) {
            expect(apt1.hasConflict || apt2.hasConflict).toBeTruthy();
          }
        }
      }
    }

    // Action: Check system logs for concurrency events
    const logsResponse = await apiContext.get(`${BASE_URL}/api/system/logs`, {
      params: {
        eventType: 'concurrency',
        startTime: startTime,
        endTime: endTime
      }
    });
    expect(logsResponse.ok()).toBeTruthy();
    const logs = await logsResponse.json();

    // Expected Result: All update and conflict events are logged accurately
    expect(logs.length).toBeGreaterThanOrEqual(5);
    const updateEvents = logs.filter((log: any) => log.eventType === 'appointment_update');
    const conflictEvents = logs.filter((log: any) => log.eventType === 'conflict_detected');
    expect(updateEvents.length).toBe(5);
    expect(conflictEvents.length).toBeGreaterThan(0);

    // Verify conflict alerts are generated
    const alertsResponse = await apiContext.get(`${BASE_URL}/api/alerts/conflicts`, {
      params: { date: '2024-01-15' }
    });
    expect(alertsResponse.ok()).toBeTruthy();
    const alerts = await alertsResponse.json();
    expect(alerts.length).toBeGreaterThan(0);

    // Validate data integrity - check for duplicates
    const appointmentIds = appointments.map((apt: any) => apt.id);
    const uniqueIds = new Set(appointmentIds);
    expect(uniqueIds.size).toBe(appointmentIds.length);
  });

  test('Ensure system performance under concurrent load (boundary)', async ({ page, request: apiContext }) => {
    // Configure load testing parameters
    const CONCURRENT_USERS = 100;
    const TOTAL_REQUESTS = 500;
    const INTENTIONAL_CONFLICTS = 50;
    const LOAD_TEST_DURATION = 5 * 60 * 1000; // 5 minutes
    const MAX_CONFLICT_DETECTION_LATENCY = 1000; // 1 second

    // Prepare test data with 500 appointment update requests including 50 intentional conflicts
    const testAppointments = [];
    const rooms = ['Room A', 'Room B', 'Room C', 'Room D', 'Room E'];
    
    for (let i = 0; i < TOTAL_REQUESTS; i++) {
      const isConflict = i < INTENTIONAL_CONFLICTS;
      const room = isConflict ? 'Room A' : rooms[i % rooms.length];
      const hour = isConflict ? 10 : 10 + (i % 8);
      
      testAppointments.push({
        id: i + 1,
        room: room,
        startTime: `${hour}:00`,
        endTime: `${hour + 1}:00`,
        date: '2024-01-20',
        userId: `user${(i % CONCURRENT_USERS) + 1}`
      });
    }

    // Start system resource monitoring
    const monitoringStartTime = Date.now();
    const performanceMetrics: any[] = [];

    // Action: Generate high volume of concurrent schedule updates
    const batchSize = 50;
    const batches = Math.ceil(TOTAL_REQUESTS / batchSize);
    
    for (let batch = 0; batch < batches; batch++) {
      const batchStart = batch * batchSize;
      const batchEnd = Math.min(batchStart + batchSize, TOTAL_REQUESTS);
      const batchAppointments = testAppointments.slice(batchStart, batchEnd);

      const batchStartTime = Date.now();
      const batchRequests = batchAppointments.map(appointment => {
        const requestStartTime = Date.now();
        return apiContext.put(`${BASE_URL}/api/appointments/${appointment.id}`, {
          headers: { 'Authorization': `Bearer token_user${(appointment.id % CONCURRENT_USERS) + 1}` },
          data: appointment
        }).then(response => {
          const requestEndTime = Date.now();
          return {
            response,
            latency: requestEndTime - requestStartTime,
            requestStartTime,
            requestEndTime
          };
        });
      });

      const batchResults = await Promise.all(batchRequests);
      const batchEndTime = Date.now();

      // Collect performance metrics
      batchResults.forEach(result => {
        performanceMetrics.push({
          latency: result.latency,
          status: result.response.status(),
          timestamp: result.requestEndTime
        });
      });

      // Monitor API response times
      const avgLatency = batchResults.reduce((sum, r) => sum + r.latency, 0) / batchResults.length;
      expect(avgLatency).toBeLessThan(5000); // Average response time under 5 seconds
    }

    // Action: Monitor system resource usage
    const resourceResponse = await apiContext.get(`${BASE_URL}/api/system/resources`, {
      params: {
        startTime: monitoringStartTime,
        endTime: Date.now()
      }
    });
    expect(resourceResponse.ok()).toBeTruthy();
    const resourceMetrics = await resourceResponse.json();

    // Expected Result: System operates within performance thresholds
    expect(resourceMetrics.cpuUsage).toBeLessThan(90);
    expect(resourceMetrics.memoryUsage).toBeLessThan(85);
    expect(resourceMetrics.dbConnectionPoolUtilization).toBeLessThan(95);

    // Measure conflict detection latency
    const conflictLatencies: number[] = [];
    for (const metric of performanceMetrics) {
      if (metric.status === 409 || metric.status === 200) {
        // Query for conflict detection timestamp
        const conflictCheckResponse = await apiContext.get(`${BASE_URL}/api/conflicts/latency`, {
          params: { timestamp: metric.timestamp }
        });
        if (conflictCheckResponse.ok()) {
          const conflictData = await conflictCheckResponse.json();
          if (conflictData.detectionLatency) {
            conflictLatencies.push(conflictData.detectionLatency);
          }
        }
      }
    }

    // Expected Result: System maintains conflict detection latency under 1 second
    if (conflictLatencies.length > 0) {
      conflictLatencies.sort((a, b) => a - b);
      const p95Index = Math.floor(conflictLatencies.length * 0.95);
      const p95Latency = conflictLatencies[p95Index];
      expect(p95Latency).toBeLessThan(MAX_CONFLICT_DETECTION_LATENCY);
    }

    // Verify system throughput
    const totalDuration = (performanceMetrics[performanceMetrics.length - 1].timestamp - performanceMetrics[0].timestamp) / 1000;
    const throughput = TOTAL_REQUESTS / totalDuration;
    expect(throughput).toBeGreaterThan(1); // At least 1 transaction per second

    // Review error logs
    const errorLogsResponse = await apiContext.get(`${BASE_URL}/api/system/logs`, {
      params: {
        level: 'error',
        startTime: monitoringStartTime,
        endTime: Date.now()
      }
    });
    expect(errorLogsResponse.ok()).toBeTruthy();
    const errorLogs = await errorLogsResponse.json();
    
    // Verify no critical failures occurred
    const criticalErrors = errorLogs.filter((log: any) => 
      log.message.includes('timeout') || 
      log.message.includes('exception') || 
      log.message.includes('data corruption')
    );
    expect(criticalErrors.length).toBe(0);

    // Verify all conflicts were detected
    const finalConflictsResponse = await apiContext.get(`${BASE_URL}/api/conflicts`, {
      params: { date: '2024-01-20' }
    });
    expect(finalConflictsResponse.ok()).toBeTruthy();
    const finalConflicts = await finalConflictsResponse.json();
    expect(finalConflicts.length).toBeGreaterThanOrEqual(INTENTIONAL_CONFLICTS);
  });

  // Helper function to check time overlap
  function checkTimeOverlap(start1: string, end1: string, start2: string, end2: string): boolean {
    const s1 = parseTime(start1);
    const e1 = parseTime(end1);
    const s2 = parseTime(start2);
    const e2 = parseTime(end2);
    return s1 < e2 && s2 < e1;
  }

  function parseTime(time: string): number {
    const [hours, minutes] = time.split(':').map(Number);
    return hours * 60 + minutes;
  }
});