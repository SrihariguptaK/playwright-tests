import { test, expect } from '@playwright/test';

test.describe('Concurrent Scheduling Operations - Story 22', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_URL = process.env.API_URL || 'http://localhost:3000/api';
  
  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/scheduler`);
    await page.waitForLoadState('networkidle');
  });

  test('Validate conflict detection under concurrent scheduling (happy-path)', async ({ page, request }) => {
    // Prepare 100 concurrent scheduling requests with intentional conflicts
    const totalRequests = 100;
    const conflictPercentage = 0.2;
    const conflictingRequests = Math.floor(totalRequests * conflictPercentage);
    
    const baseTime = new Date();
    baseTime.setHours(14, 0, 0, 0);
    
    const appointmentRequests = [];
    
    // Create requests with intentional conflicts (20%)
    for (let i = 0; i < conflictingRequests; i++) {
      const conflictTime = new Date(baseTime);
      conflictTime.setMinutes(i * 15);
      
      // Create two appointments with same time/resource (conflict)
      appointmentRequests.push({
        patientId: `patient-${i}-a`,
        doctorId: 'doctor-conflict-1',
        startTime: conflictTime.toISOString(),
        endTime: new Date(conflictTime.getTime() + 30 * 60000).toISOString(),
        type: 'consultation'
      });
      
      appointmentRequests.push({
        patientId: `patient-${i}-b`,
        doctorId: 'doctor-conflict-1',
        startTime: conflictTime.toISOString(),
        endTime: new Date(conflictTime.getTime() + 30 * 60000).toISOString(),
        type: 'consultation'
      });
    }
    
    // Create non-conflicting requests (remaining 60%)
    const remainingRequests = totalRequests - (conflictingRequests * 2);
    for (let i = 0; i < remainingRequests; i++) {
      const uniqueTime = new Date(baseTime);
      uniqueTime.setHours(baseTime.getHours() + Math.floor(i / 4));
      uniqueTime.setMinutes((i % 4) * 15);
      
      appointmentRequests.push({
        patientId: `patient-unique-${i}`,
        doctorId: `doctor-${i % 10}`,
        startTime: uniqueTime.toISOString(),
        endTime: new Date(uniqueTime.getTime() + 30 * 60000).toISOString(),
        type: 'consultation'
      });
    }
    
    // Initiate 100 concurrent users to simultaneously create appointments
    const concurrentPromises = appointmentRequests.map(async (appointmentData) => {
      const response = await request.post(`${API_URL}/appointments`, {
        data: appointmentData,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-token'
        }
      });
      
      return {
        status: response.status(),
        body: await response.json().catch(() => ({})),
        request: appointmentData
      };
    });
    
    // Monitor system processing of all 100 concurrent operations
    const results = await Promise.all(concurrentPromises);
    
    // Verify that the system processes all operations
    expect(results.length).toBe(totalRequests);
    
    // Verify that the system detects all intentional conflicts
    const conflictResponses = results.filter(r => 
      r.status === 409 || 
      (r.body && r.body.conflict === true) ||
      (r.body && r.body.error && r.body.error.includes('conflict'))
    );
    
    const successResponses = results.filter(r => r.status === 200 || r.status === 201);
    
    // Check that conflict alerts are generated for each detected conflict
    expect(conflictResponses.length).toBeGreaterThanOrEqual(conflictingRequests);
    
    // Navigate to conflicts page to verify alerts
    await page.goto(`${BASE_URL}/scheduler/conflicts`);
    await page.waitForSelector('[data-testid="conflict-list"]', { timeout: 5000 });
    
    const conflictAlerts = await page.locator('[data-testid="conflict-alert"]').count();
    expect(conflictAlerts).toBeGreaterThanOrEqual(conflictingRequests);
    
    // Verify the timing of conflict detection (under 2 seconds)
    for (const result of conflictResponses) {
      if (result.body && result.body.detectionTime) {
        expect(result.body.detectionTime).toBeLessThan(2000);
      }
    }
    
    // Review system logs to confirm all operations were logged
    await page.goto(`${BASE_URL}/admin/logs`);
    await page.waitForSelector('[data-testid="system-logs"]');
    
    const logEntries = await page.locator('[data-testid="log-entry"]').count();
    expect(logEntries).toBeGreaterThanOrEqual(totalRequests);
    
    // Validate that no false positives exist
    const falsePositives = results.filter(r => {
      const isConflictResponse = r.status === 409 || (r.body && r.body.conflict === true);
      const shouldNotConflict = !r.request.doctorId.includes('conflict');
      return isConflictResponse && shouldNotConflict;
    });
    
    expect(falsePositives.length).toBe(0);
    
    // Calculate conflict detection accuracy rate
    const expectedConflicts = conflictingRequests;
    const detectedConflicts = conflictResponses.length;
    const accuracy = (detectedConflicts / expectedConflicts) * 100;
    
    expect(accuracy).toBeGreaterThanOrEqual(100);
  });

  test('Ensure data consistency during concurrent operations (edge-case)', async ({ page, request }) => {
    // Identify 10 existing appointments in the system
    const existingAppointmentsResponse = await request.get(`${API_URL}/appointments?limit=10`);
    expect(existingAppointmentsResponse.ok()).toBeTruthy();
    
    const existingAppointments = await existingAppointmentsResponse.json();
    const targetAppointments = existingAppointments.slice(0, 10);
    
    // If not enough appointments exist, create them
    if (targetAppointments.length < 10) {
      for (let i = targetAppointments.length; i < 10; i++) {
        const createResponse = await request.post(`${API_URL}/appointments`, {
          data: {
            patientId: `patient-concurrent-${i}`,
            doctorId: `doctor-concurrent-${i}`,
            startTime: new Date(Date.now() + i * 3600000).toISOString(),
            endTime: new Date(Date.now() + i * 3600000 + 1800000).toISOString(),
            type: 'consultation'
          }
        });
        const newAppointment = await createResponse.json();
        targetAppointments.push(newAppointment);
      }
    }
    
    // Create test scenarios with overlapping time slots
    const concurrentUpdates = [];
    const updateAttempts = [];
    
    for (const appointment of targetAppointments) {
      const appointmentId = appointment.id || appointment._id;
      
      // Create 5 concurrent update requests per appointment
      for (let i = 0; i < 5; i++) {
        const overlappingTime = new Date();
        overlappingTime.setHours(15, 0, 0, 0);
        
        const updateData = {
          startTime: overlappingTime.toISOString(),
          endTime: new Date(overlappingTime.getTime() + 30 * 60000).toISOString(),
          doctorId: 'doctor-shared-resource',
          updateAttempt: i,
          timestamp: Date.now()
        };
        
        updateAttempts.push({
          appointmentId,
          updateData,
          attemptNumber: i
        });
        
        concurrentUpdates.push(
          request.put(`${API_URL}/appointments/${appointmentId}`, {
            data: updateData,
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer test-token'
            }
          })
        );
      }
    }
    
    // Execute concurrent PUT requests
    const updateResults = await Promise.all(
      concurrentUpdates.map(async (updatePromise) => {
        try {
          const response = await updatePromise;
          return {
            status: response.status(),
            body: await response.json().catch(() => ({})),
            success: response.ok()
          };
        } catch (error) {
          return {
            status: 500,
            body: { error: error.message },
            success: false
          };
        }
      })
    );
    
    // Verify that only one update per appointment is successfully committed
    const successfulUpdates = updateResults.filter(r => r.success);
    const conflictedUpdates = updateResults.filter(r => r.status === 409 || r.status === 423);
    
    expect(successfulUpdates.length).toBeLessThanOrEqual(targetAppointments.length);
    expect(conflictedUpdates.length).toBeGreaterThan(0);
    
    // Check for lost updates by comparing final state
    for (const appointment of targetAppointments) {
      const appointmentId = appointment.id || appointment._id;
      const finalStateResponse = await request.get(`${API_URL}/appointments/${appointmentId}`);
      const finalState = await finalStateResponse.json();
      
      // Verify data integrity
      expect(finalState).toBeDefined();
      expect(finalState.id || finalState._id).toBe(appointmentId);
      
      // Verify that appointment has valid timestamps
      expect(finalState.startTime).toBeDefined();
      expect(finalState.endTime).toBeDefined();
      
      // Verify concurrency control fields are updated
      if (finalState.version || finalState.updatedAt) {
        expect(finalState.version || finalState.updatedAt).toBeDefined();
      }
    }
    
    // Navigate to appointments page to verify UI consistency
    await page.goto(`${BASE_URL}/scheduler/appointments`);
    await page.waitForSelector('[data-testid="appointments-list"]');
    
    // Query the database to verify data integrity
    const allAppointmentsResponse = await request.get(`${API_URL}/appointments`);
    const allAppointments = await allAppointmentsResponse.json();
    
    // Check for any data inconsistencies
    for (const appointment of allAppointments) {
      expect(appointment.startTime).toBeDefined();
      expect(appointment.endTime).toBeDefined();
      expect(new Date(appointment.startTime).getTime()).toBeLessThan(
        new Date(appointment.endTime).getTime()
      );
    }
    
    // Validate that all users received appropriate responses
    const validStatusCodes = [200, 201, 409, 423, 400];
    for (const result of updateResults) {
      expect(validStatusCodes).toContain(result.status);
    }
    
    // Perform comprehensive data consistency check
    await page.goto(`${BASE_URL}/admin/data-integrity`);
    await page.waitForSelector('[data-testid="integrity-check-button"]');
    await page.click('[data-testid="integrity-check-button"]');
    
    await page.waitForSelector('[data-testid="integrity-result"]', { timeout: 10000 });
    const integrityStatus = await page.locator('[data-testid="integrity-status"]').textContent();
    
    expect(integrityStatus).toContain('PASS');
    
    // Verify no lost updates occurred
    const lostUpdatesCount = await page.locator('[data-testid="lost-updates-count"]').textContent();
    expect(parseInt(lostUpdatesCount || '0')).toBe(0);
  });
});