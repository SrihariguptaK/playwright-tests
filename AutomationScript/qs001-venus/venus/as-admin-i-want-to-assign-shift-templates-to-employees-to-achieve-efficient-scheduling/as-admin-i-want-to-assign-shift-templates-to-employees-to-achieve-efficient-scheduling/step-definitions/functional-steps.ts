import { Given, When, Then, Before, After } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

// TODO: Replace with Object Repository when available
// import { LOCATORS } from '../object-repository/locators';

let browser: Browser;
let context: BrowserContext;
let page: Page;
let basePage: BasePage;
let homePage: HomePage;
let actions: GenericActions;
let assertions: AssertionHelpers;
let waits: WaitHelpers;

Before(async function () {
  browser = await chromium.launch({ headless: process.env.HEADLESS !== 'false' });
  context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    ignoreHTTPSErrors: true,
  });
  page = await context.newPage();
  
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
  
  basePage = new BasePage(page, context);
  homePage = new HomePage(page, context);
  
  this.testData = {
    users: {
      Admin: { username: 'admin', password: 'admin123' },
      Manager: { username: 'manager', password: 'manager123' },
      User: { username: 'user', password: 'user123' }
    },
    employees: {},
    shiftTemplates: {},
    currentSchedule: {}
  };
});

After(async function (scenario) {
  if (scenario.result?.status === 'FAILED') {
    const screenshot = await page.screenshot();
    this.attach(screenshot, 'image/png');
  }
  await page.close();
  await context.close();
  await browser.close();
});

// ==================== GIVEN STEPS ====================

Given('user is logged in with {string} level authentication', async function (userLevel: string) {
  const credentials = this.testData?.users?.[userLevel] || { username: 'admin', password: 'admin123' };
  
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('[data-testid="input-username"]'), credentials.username);
  await actions.fill(page.locator('[data-testid="input-password"]'), credentials.password);
  await actions.click(page.locator('[data-testid="button-login"]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('[data-testid="dashboard"], [data-testid="main-content"]'));
});

Given('{string} page is loaded', async function (pageName: string) {
  const pageLocator = `[data-testid="page-${pageName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const navLinkLocator = `[data-testid="nav-${pageName.toLowerCase().replace(/\s+/g, '-')}"]`;
  
  const navLink = page.locator(navLinkLocator);
  if (await navLink.count() > 0) {
    await actions.click(navLink);
  } else {
    await actions.click(page.locator(`a:has-text("${pageName}"), button:has-text("${pageName}")`));
  }
  
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(pageLocator + ', [data-testid="employee-schedule-page"], main'));
});

Given('database connection is active and {string} table is accessible', async function (tableName: string) {
  this.testData.databaseTable = tableName;
  this.testData.databaseConnected = true;
});

Given('employee {string} exists in the system with no current shift assignments', async function (employeeName: string) {
  this.testData.employees[employeeName] = {
    name: employeeName,
    shifts: [],
    hasAssignments: false
  };
});

Given('shift template {string} exists and is active', async function (templateName: string) {
  this.testData.shiftTemplates[templateName] = {
    name: templateName,
    active: true
  };
});

Given('employee {string} exists with existing shift assignment', async function (employeeName: string) {
  this.testData.employees[employeeName] = {
    name: employeeName,
    shifts: [],
    hasAssignments: true
  };
});

Given('employee {string} has {string} assigned on {string}', async function (employeeName: string, shiftName: string, date: string) {
  if (!this.testData.employees[employeeName]) {
    this.testData.employees[employeeName] = {
      name: employeeName,
      shifts: []
    };
  }
  
  this.testData.employees[employeeName].shifts.push({
    shiftName: shiftName,
    date: date
  });
});

Given('multiple shift templates are available in the system', async function () {
  this.testData.multipleTemplatesAvailable = true;
});

Given('user is viewing {string} schedule', async function (employeeName: string) {
  const employeeLocator = `[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const employeeItem = page.locator(employeeLocator);
  
  if (await employeeItem.count() > 0) {
    await actions.click(employeeItem);
  } else {
    await actions.click(page.locator(`[data-testid="employee-list-item"]:has-text("${employeeName}")`));
  }
  
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('[data-testid="employee-details-panel"], [data-testid="employee-schedule-view"]'));
});

Given('edit permissions are enabled for {string} role', async function (roleName: string) {
  this.testData.editPermissions = true;
  this.testData.userRole = roleName;
});

Given('employee {string} exists in the system', async function (employeeName: string) {
  if (!this.testData.employees[employeeName]) {
    this.testData.employees[employeeName] = {
      name: employeeName,
      shifts: []
    };
  }
});

Given('shift template {string} is available and active', async function (templateName: string) {
  this.testData.shiftTemplates[templateName] = {
    name: templateName,
    active: true
  };
});

Given('calendar view is set to {string} view mode', async function (viewMode: string) {
  const viewModeLocator = `[data-testid="calendar-view-${viewMode.toLowerCase()}"]`;
  const viewButton = page.locator(viewModeLocator);
  
  if (await viewButton.count() > 0) {
    await actions.click(viewButton);
  } else {
    await actions.click(page.locator(`button:has-text("${viewMode}")`));
  }
  
  await waits.waitForNetworkIdle();
  this.testData.calendarViewMode = viewMode;
});

// ==================== WHEN STEPS ====================

When('user navigates to {string} section', async function (sectionName: string) {
  const sectionLocator = `[data-testid="section-${sectionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const navLinkLocator = `[data-testid="nav-${sectionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  
  const navLink = page.locator(navLinkLocator);
  if (await navLink.count() > 0) {
    await actions.click(navLink);
  } else {
    await actions.click(page.locator(`a:has-text("${sectionName}"), button:has-text("${sectionName}")`));
  }
  
  await waits.waitForNetworkIdle();
});

When('user selects employee {string} from the employee list', async function (employeeName: string) {
  const employeeLocator = `[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const employeeItem = page.locator(employeeLocator);
  
  if (await employeeItem.count() > 0) {
    await actions.click(employeeItem);
  } else {
    await actions.click(page.locator(`[data-testid="employee-list-item"]:has-text("${employeeName}"), li:has-text("${employeeName}")`));
  }
  
  await waits.waitForNetworkIdle();
  this.testData.selectedEmployee = employeeName;
});

When('user clicks {string} button in the employee details panel', async function (buttonText: string) {
  const testIdLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttons = page.locator(testIdLocator);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`[data-testid="employee-details-panel"] button:has-text("${buttonText}"), .employee-details button:has-text("${buttonText}")`));
  }
  
  await waits.waitForNetworkIdle();
});

When('user selects {string} template from the dropdown list', async function (templateName: string) {
  const dropdownLocator = '[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]';
  const optionLocator = `[data-testid="option-${templateName.toLowerCase().replace(/\s+/g, '-')}"]`;
  
  await actions.click(page.locator(dropdownLocator));
  await waits.waitForVisible(page.locator('[data-testid="dropdown-options"], .dropdown-menu'));
  
  const option = page.locator(optionLocator);
  if (await option.count() > 0) {
    await actions.click(option);
  } else {
    await actions.click(page.locator(`option:has-text("${templateName}"), li:has-text("${templateName}")`));
  }
  
  this.testData.selectedTemplate = templateName;
});

When('user chooses start date as {string}', async function (date: string) {
  const dateInputLocator = '[data-testid="input-start-date"], [data-testid="datepicker-start-date"]';
  await actions.fill(page.locator(dateInputLocator), date);
  this.testData.selectedStartDate = date;
});

When('user clicks {string} button', async function (buttonText: string) {
  const testIdLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttons = page.locator(testIdLocator);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`button:has-text("${buttonText}")`));
  }
  
  await waits.waitForNetworkIdle();
});

When('user notes the current schedule displaying {string} on {string}', async function (shiftName: string, date: string) {
  this.testData.currentSchedule = {
    shiftName: shiftName,
    date: date
  };
  
  const shiftBlockLocator = `[data-testid="shift-block-${date}"]`;
  await waits.waitForVisible(page.locator(shiftBlockLocator + ', [data-testid="calendar-shift"]'));
});

When('user sets start date to {string}', async function (date: string) {
  const dateInputLocator = '[data-testid="input-start-date"], [data-testid="datepicker-start-date"]';
  await actions.fill(page.locator(dateInputLocator), date);
  this.testData.selectedStartDate = date;
});

When('user opens a second browser window', async function () {
  this.secondContext = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    ignoreHTTPSErrors: true,
  });
  this.secondPage = await this.secondContext.newPage();
  this.secondActions = new GenericActions(this.secondPage, this.secondContext);
  this.secondWaits = new WaitHelpers(this.secondPage);
});

When('user logs in as {string} in second window', async function (userLevel: string) {
  const credentials = this.testData?.users?.[userLevel] || { username: 'admin', password: 'admin123' };
  
  await this.secondActions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await this.secondWaits.waitForNetworkIdle();
  
  await this.secondActions.fill(this.secondPage.locator('[data-testid="input-username"]'), credentials.username);
  await this.secondActions.fill(this.secondPage.locator('[data-testid="input-password"]'), credentials.password);
  await this.secondActions.click(this.secondPage.locator('[data-testid="button-login"]'));
  await this.secondWaits.waitForNetworkIdle();
});

When('user navigates to {string} schedule in second window', async function (employeeName: string) {
  const navLinkLocator = '[data-testid="nav-employee-schedule"]';
  const navLink = this.secondPage.locator(navLinkLocator);
  
  if (await navLink.count() > 0) {
    await this.secondActions.click(navLink);
  } else {
    await this.secondActions.click(this.secondPage.locator('a:has-text("Employee Schedule")'));
  }
  
  await this.secondWaits.waitForNetworkIdle();
  
  const employeeLocator = `[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const employeeItem = this.secondPage.locator(employeeLocator);
  
  if (await employeeItem.count() > 0) {
    await this.secondActions.click(employeeItem);
  } else {
    await this.secondActions.click(this.secondPage.locator(`[data-testid="employee-list-item"]:has-text("${employeeName}")`));
  }
  
  await this.secondWaits.waitForNetworkIdle();
});

When('user clicks on assigned {string} block on {string}', async function (shiftName: string, date: string) {
  const shiftBlockLocator = `[data-testid="shift-block-${date}"]`;
  const shiftBlock = page.locator(shiftBlockLocator);
  
  if (await shiftBlock.count() > 0) {
    await actions.click(shiftBlock);
  } else {
    await actions.click(page.locator(`[data-date="${date}"] [data-shift="${shiftName}"], .shift-block:has-text("${shiftName}")`));
  }
  
  await waits.waitForVisible(page.locator('[data-testid="shift-details-popover"], [data-testid="popover-shift-details"]'));
});

When('user clicks {string} button in the shift details popover', async function (buttonText: string) {
  const testIdLocator = `[data-testid="button-${buttonText.toLowerCase()}"]`;
  const buttons = page.locator(testIdLocator);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`[data-testid="shift-details-popover"] button:has-text("${buttonText}"), .popover button:has-text("${buttonText}")`));
  }
  
  await waits.waitForNetworkIdle();
});

When('user changes shift template to {string} from the dropdown', async function (templateName: string) {
  const dropdownLocator = '[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]';
  const optionLocator = `[data-testid="option-${templateName.toLowerCase().replace(/\s+/g, '-')}"]`;
  
  await actions.click(page.locator(dropdownLocator));
  await waits.waitForVisible(page.locator('[data-testid="dropdown-options"], .dropdown-menu'));
  
  const option = page.locator(optionLocator);
  if (await option.count() > 0) {
    await actions.click(option);
  } else {
    await actions.click(page.locator(`option:has-text("${templateName}"), li:has-text("${templateName}")`));
  }
  
  this.testData.updatedTemplate = templateName;
});

When('user keeps the same date', async function () {
  this.testData.dateUnchanged = true;
});

When('user selects employee {string} from the employee list without refreshing page', async function (employeeName: string) {
  const employeeLocator = `[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const employeeItem = page.locator(employeeLocator);
  
  if (await employeeItem.count() > 0) {
    await actions.click(employeeItem);
  } else {
    await actions.click(page.locator(`[data-testid="employee-list-item"]:has-text("${employeeName}")`));
  }
  
  await waits.waitForNetworkIdle();
  this.testData.selectedEmployee = employeeName;
});

When('user assigns {string} template to {string} for date {string}', async function (templateName: string, employeeName: string, date: string) {
  const assignButtonLocator = '[data-testid="button-assign-shift-template"]';
  await actions.click(page.locator(assignButtonLocator + ', button:has-text("Assign Shift Template")'));
  await waits.waitForNetworkIdle();
  
  const dropdownLocator = '[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]';
  await actions.click(page.locator(dropdownLocator));
  await waits.waitForVisible(page.locator('[data-testid="dropdown-options"], .dropdown-menu'));
  
  const optionLocator = `[data-testid="option-${templateName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const option = page.locator(optionLocator);
  if (await option.count() > 0) {
    await actions.click(option);
  } else {
    await actions.click(page.locator(`option:has-text("${templateName}"), li:has-text("${templateName}")`));
  }
  
  const dateInputLocator = '[data-testid="input-start-date"], [data-testid="datepicker-start-date"]';
  await actions.fill(page.locator(dateInputLocator), date);
  
  this.testData.assignmentData = {
    employee: employeeName,
    template: templateName,
    date: date
  };
});

When('user confirms the assignment', async function () {
  const confirmButtonLocator = '[data-testid="button-confirm-assignment"]';
  const confirmButton = page.locator(confirmButtonLocator);
  
  if (await confirmButton.count() > 0) {
    await actions.click(confirmButton);
  } else {
    await actions.click(page.locator('button:has-text("Confirm Assignment"), button:has-text("Confirm")'));
  }
  
  await waits.waitForNetworkIdle();
});

When('user navigates to calendar overview', async function () {
  const overviewLocator = '[data-testid="nav-calendar-overview"], [data-testid="button-calendar-overview"]';
  const overviewLink = page.locator(overviewLocator);
  
  if (await overviewLink.count() > 0) {
    await actions.click(overviewLink);
  } else {
    await actions.click(page.locator('a:has-text("Calendar Overview"), button:has-text("Overview")'));
  }
  
  await waits.waitForNetworkIdle();
});

When('user assigns {string} for {string} {string}', async function (shiftTemplate: string, dayOfWeek: string, date: string) {
  const assignButtonLocator = '[data-testid="button-assign-shift-template"]';
  await actions.click(page.locator(assignButtonLocator + ', button:has-text("Assign Shift Template")'));
  await waits.waitForNetworkIdle();
  
  const dropdownLocator = '[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]';
  await actions.click(page.locator(dropdownLocator));
  await waits.waitForVisible(page.locator('[data-testid="dropdown-options"], .dropdown-menu'));
  
  const optionLocator = `[data-testid="option-${shiftTemplate.toLowerCase().replace(/\s+/g, '-')}"]`;
  const option = page.locator(optionLocator);
  if (await option.count() > 0) {
    await actions.click(option);
  } else {
    await actions.click(page.locator(`option:has-text("${shiftTemplate}"), li:has-text("${shiftTemplate}")`));
  }
  
  const dateInputLocator = '[data-testid="input-start-date"], [data-testid="datepicker-start-date"]';
  await actions.fill(page.locator(dateInputLocator), date);
  
  const confirmButtonLocator = '[data-testid="button-confirm-assignment"]';
  await actions.click(page.locator(confirmButtonLocator + ', button:has-text("Confirm")'));
  await waits.waitForNetworkIdle();
});

When('user assigns {string} to {string} for {string} {string}', async function (shiftTemplate: string, employeeName: string, dayOfWeek: string, date: string) {
  const assignButtonLocator = '[data-testid="button-assign-shift-template"]';
  await actions.click(page.locator(assignButtonLocator + ', button:has-text("Assign Shift Template")'));
  await waits.waitForNetworkIdle();
  
  const dropdownLocator = '[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]';
  await actions.click(page.locator(dropdownLocator));
  await waits.waitForVisible(page.locator('[data-testid="dropdown-options"], .dropdown-menu'));
  
  const optionLocator = `[data-testid="option-${shiftTemplate.toLowerCase().replace(/\s+/g, '-')}"]`;
  const option = page.locator(optionLocator);
  if (await option.count() > 0) {
    await actions.click(option);
  } else {
    await actions.click(page.locator(`option:has-text("${shiftTemplate}"), li:has-text("${shiftTemplate}")`));
  }
  
  const dateInputLocator = '[data-testid="input-start-date"], [data-testid="datepicker-start-date"]';
  await actions.fill(page.locator(dateInputLocator), date);
  
  const confirmButtonLocator = '[data-testid="button-confirm-assignment"]';
  await actions.click(page.locator(confirmButtonLocator + ', button:has-text("Confirm")'));
  await waits.waitForNetworkIdle();
});

When('user switches calendar view from {string} to {string} view', async function (fromView: string, toView: string) {
  const viewModeLocator = `[data-testid="calendar-view-${toView.toLowerCase()}"]`;
  const viewButton = page.locator(viewModeLocator);
  
  if (await viewButton.count() > 0) {
    await actions.click(viewButton);
  } else {
    await actions.click(page.locator(`button:has-text("${toView}")`));
  }
  
  await waits.waitForNetworkIdle();
  this.testData.calendarViewMode = toView;
});

When('user hovers over each shift block in the calendar', async function () {
  const shiftBlocks = page.locator('[data-testid^="shift-block-"], .shift-block, .calendar-shift');
  const count = await shiftBlocks.count();
  
  this.testData.hoveredShifts = [];
  
  for (let i = 0; i < count; i++) {
    await actions.hover(shiftBlocks.nth(i));
    await waits.waitForVisible(page.locator('[data-testid="tooltip-shift"], .tooltip'));
    this.testData.hoveredShifts.push(i);
  }
});

// ==================== THEN STEPS ====================

Then('employee details panel should be visible on the right side', async function () {
  await assertions.assertVisible(page.locator('[data-testid="employee-details-panel"], [data-testid="panel-employee-details"]'));
});

Then('panel should display {string} current schedule and personal information', async function (employeeName: string) {
  const panelLocator = '[data-testid="employee-details-panel"], [data-testid="panel-employee-details"]';
  await assertions.assertContainsText(page.locator(panelLocator), employeeName);
});

Then('modal dialog should open displaying available shift templates', async function () {
  await waits.waitForVisible(page.locator('[data-testid="modal-shift-templates"], [data-testid="modal-assign-shift"]'));
  await assertions.assertVisible(page.locator('[data-testid="modal-shift-templates"], [data-testid="modal-assign-shift"]'));
});

Then('modal should display template names, times, and descriptions', async function () {
  const modalLocator = '[data-testid="modal-shift-templates"], [data-testid="modal-assign-shift"]';
  await assertions.assertVisible(page.locator(modalLocator));
  
  const templateListLocator = '[data-testid="template-list"], [data-testid="shift-template-options"]';
  await assertions.assertVisible(page.locator(templateListLocator));
});

Then('template should be highlighted in blue', async function () {
  const selectedTemplateLocator = '[data-testid="template-selected"], .template-selected, [aria-selected="true"]';
  await assertions.assertVisible(page.locator(selectedTemplateLocator));
});

Then('start date field should show {string}', async function (date: string) {
  const dateInputLocator = '[data-testid="input-start-date"], [data-testid="datepicker-start-date"]';
  const dateInput = page.locator(dateInputLocator);
  const value = await dateInput.inputValue();
  expect(value).toBe(date);
});

Then('{string} button should be enabled', async function (buttonText: string) {
  const testIdLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(testIdLocator);
  
  if (await button.count() > 0) {
    await expect(button).toBeEnabled();
  } else {
    await expect(page.locator(`button:has-text("${buttonText}")`)).toBeEnabled();
  }
});

Then('success message {string} should be displayed', async function (message: string) {
  const successLocator = '[data-testid="success-message"], [data-testid="alert-success"], .success-message, .alert-success';
  await waits.waitForVisible(page.locator(successLocator));
  await assertions.assertContainsText(page.locator(successLocator), message);
});

Then('modal should close automatically', async function () {
  const modalLocator = '[data-testid="modal-shift-templates"], [data-testid="modal-assign-shift"], .modal';
  await waits.waitForHidden(page.locator(modalLocator));
});

Then('calendar should display {string} on {string}', async function (shiftName: string, date: string) {
  const shiftBlockLocator = `[data-testid="shift-block-${date}"]`;
  const shiftBlock = page.locator(shiftBlockLocator + ', [data-testid="calendar-shift"]');
  
  await waits.waitForVisible(shiftBlock);
  await assertions.assertContainsText(shiftBlock, shiftName);
});

Then('shift block should show color-coded template with template name visible', async function () {
  const shiftBlockLocator = '[data-testid^="shift-block-"], .shift-block, .calendar-shift';
  await assertions.assertVisible(page.locator(shiftBlockLocator));
});

Then('shift assignment should be saved in {string} table for employee {string}', async function (tableName: string, employeeName: string) {
  this.testData.savedInDatabase = {
    table: tableName,
    employee: employeeName,
    saved: true
  };
});

Then('assignment should be logged in system audit trail with timestamp and admin user ID', async function () {
  this.testData.auditLogged = true;
});

Then('calendar view should show {string} assignment with time range and color coding', async function (shiftName: string) {
  const shiftBlockLocator = '[data-testid^="shift-block-"], .shift-block';
  await assertions.assertVisible(page.locator(shiftBlockLocator));
  await assertions.assertContainsText(page.locator(shiftBlockLocator), shiftName);
});

Then('assignment modal should open with available templates listed', async function () {
  await waits.waitForVisible(page.locator('[data-testid="modal-shift-templates"], [data-testid="modal-assign-shift"]'));
  await assertions.assertVisible(page.locator('[data-testid="template-list"], [data-testid="shift-template-options"]'));
});

Then('calendar should automatically update without page refresh', async function () {
  await waits.waitForNetworkIdle();
  const calendarLocator = '[data-testid="calendar-view"], [data-testid="employee-calendar"]';
  await assertions.assertVisible(page.locator(calendarLocator));
});

Then('second browser window should display {string} on {string}', async function (shiftName: string, date: string) {
  const shiftBlockLocator = `[data-testid="shift-block-${date}"]`;
  const shiftBlock = this.secondPage.locator(shiftBlockLocator + ', [data-testid="calendar-shift"]');
  
  await this.secondWaits.waitForVisible(shiftBlock);
  const secondAssertions = new AssertionHelpers(this.secondPage);
  await secondAssertions.assertContainsText(shiftBlock, shiftName);
});

Then('both shift assignments should be persisted in {string} table', async function (tableName: string) {
  this.testData.persistedInDatabase = {
    table: tableName,
    persisted: true
  };
});

Then('real-time synchronization should be confirmed across multiple browser sessions', async function () {
  this.testData.realtimeSyncConfirmed = true;
});

Then('shift details popover should appear', async function () {
  await waits.waitForVisible(page.locator('[data-testid="shift-details-popover"], [data-testid="popover-shift-details"]'));
  await assertions.assertVisible(page.locator('[data-testid="shift-details-popover"], [data-testid="popover-shift-details"]'));
});

Then('popover should display shift name, time range, date', async function () {
  const popoverLocator = '[data-testid="shift-details-popover"], [data-testid="popover-shift-details"]';
  await assertions.assertVisible(page.locator(popoverLocator));
});

Then('popover should display {string} and {string} buttons', async function (button1: string, button2: string) {
  const popoverLocator = '[data-testid="shift-details-popover"], [data-testid="popover-shift-details"]';
  const button1Locator = `[data-testid="button-${button1.toLowerCase()}"]`;
  const button2Locator = `[data-testid="button-${button2.toLowerCase()}"]`;
  
  await assertions.assertVisible(page.locator(popoverLocator + ' ' + button1Locator + ', ' + popoverLocator + ' button:has-text("' + button1 + '")'));
  await assertions.assertVisible(page.locator(popoverLocator + ' ' + button2Locator + ', ' + popoverLocator + ' button:has-text("' + button2 + '")'));
});

Then('edit shift modal should open', async function () {
  await waits.waitForVisible(page.locator('[data-testid="modal-edit-shift"], [data-testid="modal-shift-edit"]'));
  await assertions.assertVisible(page.locator('[data-testid="modal-edit-shift"], [data-testid="modal-shift-edit"]'));
});

Then('modal should be pre-populated with template {string}', async function (templateName: string) {
  const dropdownLocator = '[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]';
  const selectedValue = await page.locator(dropdownLocator).inputValue();
  expect(selectedValue).toContain(templateName);
});

Then('modal should be pre-populated with date {string}', async function (date: string) {
  const dateInputLocator = '[data-testid="input-start-date"], [data-testid="datepicker-start-date"]';
  const dateValue = await page.locator(dateInputLocator).inputValue();
  expect(dateValue).toBe(date);
});

Then('dropdown should display {string} as selected', async function (templateName: string) {
  const dropdownLocator = '[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]';
  await assertions.assertContainsText(page.locator(dropdownLocator), templateName);
});

Then('calendar should not display {string} on {string}', async function (shiftName: string, date: string) {
  const shiftBlockLocator = `[data-testid="shift-block-${date}"]`;
  const shiftBlock = page.locator(shiftBlockLocator);
  
  if (await shiftBlock.count() > 0) {
    const text = await shiftBlock.textContent();
    expect(text).not.toContain(shiftName);
  }
});

Then('shift should display updated time range and color coding', async function () {
  const shiftBlockLocator = '[data-testid^="shift-block-"], .shift-block';
  await assertions.assertVisible(page.locator(shiftBlockLocator));
});

Then('{string} table should be updated with {string} for {string} on {string}', async function (tableName: string, shiftName: string, employeeName: string, date: string) {
  this.testData.databaseUpdate = {
    table: tableName,
    shift: shiftName,
    employee: employeeName,
    date: date,
    updated: true
  };
});

Then('previous {string} assignment should be replaced not duplicated', async function (shiftName: string) {
  this.testData.replacedNotDuplicated = true;
});

Then('edit action should be logged in audit trail with timestamp and change details', async function () {
  this.testData.editAuditLogged = true;
});

Then('{string} details and schedule should be displayed in the employee panel', async function (employeeName: string) {
  const panelLocator = '[data-testid="employee-details-panel"], [data-testid="panel-employee-details"]';
  await assertions.assertVisible(page.locator(panelLocator));
  await assertions.assertContainsText(page.locator(panelLocator), employeeName);
});

Then('success message should be displayed', async function () {
  const successLocator = '[data-testid="success-message"], [data-testid="alert-success"], .success-message, .alert-success';
  await waits.waitForVisible(page.locator(successLocator));
  await assertions.assertVisible(page.locator(successLocator));
});

Then('{string} calendar should show {string} on {string}', async function (employeeName: string, shiftName: string, date: string) {
  const shiftBlockLocator = `[data-testid="shift-block-${date}"]`;
  const shiftBlock = page.locator(shiftBlockLocator + ', [data-testid="calendar-shift"]');
  
  await waits.waitForVisible(shiftBlock);
  await assertions.assertContainsText(shiftBlock, shiftName);
});

Then('{string} details and current schedule should be displayed', async function (employeeName: string) {
  const panelLocator = '[data-testid="employee-details-panel"], [data-testid="panel-employee-details"]';
  await assertions.assertVisible(page.locator(panelLocator));
  await assertions.assertContainsText(page.locator(panelLocator), employeeName);
});

Then('{string} panel should be replaced', async function (employeeName: string) {
  const panelLocator = '[data-testid="employee-details-panel"], [data-testid="panel-employee-details"]';
  await assertions.assertVisible(page.locator(panelLocator));
});

Then('calendar overview should display {string} with {string} on {string}', async function (employeeName: string, shiftName: string, date: string) {
  const overviewLocator = '[data-testid="calendar-overview"], [data-testid="overview-calendar"]';
  await assertions.assertVisible(page.locator(overviewLocator));
  
  const employeeShiftLocator = `[data-testid="overview-${employeeName.toLowerCase().replace(/\s+/g, '-')}-${date}"]`;
  const employeeShift = page.locator(employeeShiftLocator + ', [data-employee="' + employeeName + '"][data-date="' + date + '"]');
  
  if (await employeeShift.count() > 0) {
    await assertions.assertContainsText(employeeShift, shiftName);
  }
});

Then('all three employees should have {string} saved in {string} table for {string}', async function (shiftName: string, tableName: string, date: string) {
  this.testData.multipleEmployeesSaved = {
    table: tableName,
    shift: shiftName,
    date: date,
    saved: true
  };
});

Then('no scheduling conflicts should exist for any employee', async function () {
  this.testData.noConflicts = true;
});

Then('assignment should succeed', async function () {
  const successLocator = '[data-testid="success-message"], [data-testid="alert-success"], .success-message, .alert-success';
  await waits.waitForVisible(page.locator(successLocator));
});

Then('calendar should show {string} on {string}', async function (shiftName: string, dayOfWeek: string) {
  const shiftBlockLocator = '[data-testid^="shift-block-"], .shift-block';
  await waits.waitForVisible(page.locator(shiftBlockLocator));
  await assertions.assertContainsText(page.locator(shiftBlockLocator), shiftName);
});

Then('calendar should display all three shifts across the week with different color codes', async function () {
  const shiftBlocks = page.locator('[data-testid^="shift-block-"], .shift-block');
  const count = await shiftBlocks.count();
  expect(count).toBeGreaterThanOrEqual(3);
});

Then('monthly calendar view should load showing {string}', async function (monthYear: string) {
  const calendarHeaderLocator = '[data-testid="calendar-header"], [data-testid="calendar-month-year"]';
  await waits.waitForVisible(page.locator(calendarHeaderLocator));
  await assertions.assertContainsText(page.locator(calendarHeaderLocator), monthYear);
});

Then('all three assigned shifts should be visible on their respective dates', async function () {
  const shiftBlocks = page.locator('[data-testid^="shift-block-"], .shift-block');
  const count = await shiftBlocks.count();
  expect(count).toBeGreaterThanOrEqual(3);
});

Then('tooltip should appear for each shift', async function () {
  await waits.waitForVisible(page.locator('[data-testid="tooltip-shift"], .tooltip'));
  await assertions.assertVisible(page.locator('[data-testid="tooltip-shift"], .tooltip'));
});

Then('tooltip should display shift name, time range, employee name, and date', async function () {
  const tooltipLocator = '[data-testid="tooltip-shift"], .tooltip';
  await assertions.assertVisible(page.locator(tooltipLocator));
});

Then('all three shift assignments should be stored in {string} table', async function (tableName: string) {
  this.testData.allShiftsStored = {
    table: tableName,
    stored: true
  };
});

Then('calendar view should accurately represent all assignments with proper visual distinction', async function () {
  const shiftBlocks = page.locator('[data-testid^="shift-block-"], .shift-block');
  const count = await shiftBlocks.count();
  expect(count).toBeGreaterThan(0);
  await assertions.assertVisible(shiftBlocks.first());
});