import { test, expect, Page } from '@playwright/test';

// Test Data Fixtures
const validSchedulingData = {
  patientName: 'John Doe',
  patientId: 'PAT-12345',
  doctorId: 'DOC-67890',
  roomId: 'ROOM-101',
  date: '2024-12-31',
  time: '14:30',
  duration: '30',
  appointmentType: 'Consultation',
  notes: 'Regular checkup appointment'
};

const invalidSchedulingData = {
  invalidDate: {
    past: '2020-01-01',
    wrongFormat: '31/12/2024',
    invalid: '2024-13-45',
    empty: ''
  },
  invalidTime: {
    wrongFormat: '2:30 PM',
    invalid: '25:70',
    empty: ''
  },
  invalidResourceIds: {
    doctorId: 'INVALID-ID-123!@#',
    roomId: '<script>alert("xss")</script>',
    patientId: 'DROP TABLE patients;'
  },
  missingFields: {
    noPatientName: '',
    noDoctorId: '',
    noDate: '',
    noTime: ''
  }
};

// Page Object Model
class SchedulingPage {
  readonly page: Page;
  
  // Selectors
  readonly patientNameInput = '[data-testid="patient-name-input"]';
  readonly patientIdInput = '[data-testid="patient-id-input"]';
  readonly doctorIdInput = '[data-testid="doctor-id-input"]';
  readonly roomIdInput = '[data-testid="room-id-input"]';
  readonly dateInput = '[data-testid="appointment-date-input"]';
  readonly timeInput = '[data-testid="appointment-time-input"]';
  readonly durationInput = '[data-testid="appointment-duration-input"]';
  readonly appointmentTypeSelect = '[data-testid="appointment-type-select"]';
  readonly notesTextarea = '[data-testid="appointment-notes-textarea"]';
  readonly submitButton = '[data-testid="submit-appointment-button"]';
  readonly cancelButton = '[data-testid="cancel-appointment-button"]';
  
  // Validation error selectors
  readonly patientNameError = '[data-testid="patient-name-error"]';
  readonly patientIdError = '[data-testid="patient-id-error"]';
  readonly doctorIdError = '[data-testid="doctor-id-error"]';
  readonly roomIdError = '[data-testid="room-id-error"]';
  readonly dateError = '[data-testid="appointment-date-error"]';
  readonly timeError = '[data-testid="appointment-time-error"]';
  readonly durationError = '[data-testid="appointment-duration-error"]';
  readonly generalError = '[data-testid="general-error-message"]';
  readonly successMessage = '[data-testid="success-message"]';

  constructor(page: Page) {
    this.page = page;
  }

  async navigate(): Promise<void> {
    await this.page.goto('/scheduling/new-appointment');
    await this.page.waitForLoadState('networkidle');
  }

  async fillPatientName(name: string): Promise<void> {
    await this.page.fill(this.patientNameInput, name);
    await this.page.waitForTimeout(100);
  }

  async fillPatientId(id: string): Promise<void> {
    await this.page.fill(this.patientIdInput, id);
    await this.page.waitForTimeout(100);
  }

  async fillDoctorId(id: string): Promise<void> {
    await this.page.fill(this.doctorIdInput, id);
    await this.page.waitForTimeout(100);
  }

  async fillRoomId(id: string): Promise<void> {
    await this.page.fill(this.roomIdInput, id);
    await this.page.waitForTimeout(100);
  }

  async fillDate(date: string): Promise<void> {
    await this.page.fill(this.dateInput, date);
    await this.page.waitForTimeout(100);
  }

  async fillTime(time: string): Promise<void> {
    await this.page.fill(this.timeInput, time);
    await this.page.waitForTimeout(100);
  }

  async fillDuration(duration: string): Promise<void> {
    await this.page.fill(this.durationInput, duration);
    await this.page.waitForTimeout(100);
  }

  async selectAppointmentType(type: string): Promise<void> {
    await this.page.selectOption(this.appointmentTypeSelect, type);
    await this.page.waitForTimeout(100);
  }

  async fillNotes(notes: string): Promise<void> {
    await this.page.fill(this.notesTextarea, notes);
    await this.page.waitForTimeout(100);
  }

  async clickSubmit(): Promise<void> {
    await this.page.click(this.submitButton);
  }

  async isSubmitButtonDisabled(): Promise<boolean> {
    return await this.page.isDisabled(this.submitButton);
  }

  async getValidationError(selector: string): Promise<string | null> {
    try {
      await this.page.waitForSelector(selector, { timeout: 1000 });
      return await this.page.textContent(selector);
    } catch {
      return null;
    }
  }

  async waitForValidationError(selector: string, timeout: number = 1000): Promise<void> {
    await this.page.waitForSelector(selector, { state: 'visible', timeout });
  }

  async isValidationErrorVisible(selector: string): Promise<boolean> {
    try {
      await this.page.waitForSelector(selector, { state: 'visible', timeout: 1000 });
      return true;
    } catch {
      return false;
    }
  }

  async fillCompleteForm(data: typeof validSchedulingData): Promise<void> {
    await this.fillPatientName(data.patientName);
    await this.fillPatientId(data.patientId);
    await this.fillDoctorId(data.doctorId);
    await this.fillRoomId(data.roomId);
    await this.fillDate(data.date);
    await this.fillTime(data.time);
    await this.fillDuration(data.duration);
    await this.selectAppointmentType(data.appointmentType);
    await this.fillNotes(data.notes);
  }

  async clearAllFields(): Promise<void> {
    await this.page.fill(this.patientNameInput, '');
    await this.page.fill(this.patientIdInput, '');
    await this.page.fill(this.doctorIdInput, '');
    await this.page.fill(this.roomIdInput, '');
    await this.page.fill(this.dateInput, '');
    await this.page.fill(this.timeInput, '');
    await this.page.fill(this.durationInput, '');
    await this.page.fill(this.notesTextarea, '');
  }
}

test.describe('Story-23: As Scheduler, I want the system to validate scheduling inputs to prevent invalid data causing conflicts', () => {
  let schedulingPage: SchedulingPage;

  test.beforeEach(async ({ page }) => {
    schedulingPage = new SchedulingPage(page);
    await schedulingPage.navigate();
  });

  test.describe('Date and Time Format Validation', () => {
    test('should validate date format and reject invalid date formats', async ({ page }) => {
      // Test with wrong date format (DD/MM/YYYY instead of YYYY-MM-DD)
      await schedulingPage.fillDate(invalidSchedulingData.invalidDate.wrongFormat);
      await schedulingPage.fillPatientName(validSchedulingData.patientName);
      
      // Trigger validation by moving focus
      await page.click(schedulingPage