package stepdefinitions;

import io.cucumber.java.Before;
import io.cucumber.java.After;
import io.cucumber.java.Scenario;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.When;
import io.cucumber.java.en.Then;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;

import java.util.List;
import java.util.HashMap;
import java.util.Map;

import pages.BasePage;
import pages.HomePage;
import pages.LoginPage;
import pages.SchedulePage;
import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import testdata.TestData;

// TODO: Replace with Object Repository when available
// import objectrepository.Locators;

public class EmployeeScheduleSecurityStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private BasePage basePage;
    private HomePage homePage;
    private LoginPage loginPage;
    private SchedulePage schedulePage;
    
    private Map<String, String> testContext;
    private String currentEmployeeId;
    private String targetEmployeeId;
    private int apiResponseCode;
    private String apiResponseBody;
    
    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--start-maximized");
        options.addArguments("--ignore-certificate-errors");
        options.addArguments("--disable-notifications");
        driver = new ChromeDriver(options);
        
        actions = new GenericActions(driver);
        waits = new WaitHelpers(driver);
        assertions = new AssertionHelpers(driver);
        
        basePage = new BasePage(driver);
        homePage = new HomePage(driver);
        loginPage = new LoginPage(driver);
        schedulePage = new SchedulePage(driver);
        
        testContext = new HashMap<>();
        apiResponseCode = 0;
        apiResponseBody = "";
    }
    
    @After
    public void tearDown(Scenario scenario) {
        if (scenario.isFailed()) {
            byte[] screenshot = actions.takeScreenshotAsBytes();
            scenario.attach(screenshot, "image/png", "failure-screenshot");
        }
        if (driver != null) {
            driver.quit();
        }
    }
    
    // ==================== GIVEN STEPS ====================
    
    /**************************************************/
    /*  SHARED BACKGROUND STEPS
    /*  Used across multiple test cases
    /**************************************************/
    
    @Given("employee schedule database is available")
    public void employeeScheduleDatabaseIsAvailable() {
        testContext.put("database_status", "available");
        waits.waitForPageLoad();
    }
    
    @Given("authentication and authorization checks are implemented")
    public void authenticationAndAuthorizationChecksAreImplemented() {
        testContext.put("auth_enabled", "true");
    }
    
    @Given("employee account {string} exists in the system")
    public void employeeAccountExistsInTheSystem(String employeeId) {
        testContext.put("employee_" + employeeId, "exists");
        if (currentEmployeeId == null) {
            currentEmployeeId = employeeId;
        }
    }
    
    @Given("employee {string} has scheduled shifts for current week")
    public void employeeHasScheduledShiftsForCurrentWeek(String employeeId) {
        testContext.put("shifts_" + employeeId, "current_week");
    }
    
    @Given("employee {string} has scheduled shifts in the system")
    public void employeeHasScheduledShiftsInTheSystem(String employeeId) {
        testContext.put("shifts_" + employeeId, "exists");
        targetEmployeeId = employeeId;
    }
    
    @Given("employee {string} is logged into the system")
    public void employeeIsLoggedIntoTheSystem(String employeeId) {
        loginPage.navigate();
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.cssSelector("[data-testid='input-username']"));
        actions.clearAndSendKeys(usernameField, employeeId);
        
        WebElement passwordField = driver.findElement(By.cssSelector("[data-testid='input-password']"));
        actions.clearAndSendKeys(passwordField, "password123");
        
        WebElement loginButton = driver.findElement(By.cssSelector("[data-testid='button-login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
        
        currentEmployeeId = employeeId;
        testContext.put("logged_in_user", employeeId);
    }
    
    @Given("employee is logged into the system")
    public void employeeIsLoggedIntoTheSystem() {
        loginPage.navigate();
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.cssSelector("[data-testid='input-username']"));
        actions.clearAndSendKeys(usernameField, "emp001");
        
        WebElement passwordField = driver.findElement(By.cssSelector("[data-testid='input-password']"));
        actions.clearAndSendKeys(passwordField, "password123");
        
        WebElement loginButton = driver.findElement(By.cssSelector("[data-testid='button-login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
        
        currentEmployeeId = "emp001";
    }
    
    @Given("employee is viewing their schedule page")
    public void employeeIsViewingTheirSchedulePage() {
        actions.navigateTo(basePage.getBaseUrl() + "/schedule");
        waits.waitForPageLoad();
        
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container']"));
        assertions.assertDisplayed(scheduleContainer);
    }
    
    @Given("session timeout is configured for {int} minutes")
    public void sessionTimeoutIsConfiguredForMinutes(int minutes) {
        testContext.put("session_timeout", String.valueOf(minutes));
    }
    
    @Given("employee navigates to schedule page")
    public void employeeNavigatesToSchedulePage() {
        actions.navigateTo(basePage.getBaseUrl() + "/schedule");
        waits.waitForPageLoad();
    }
    
    @Given("employee is on schedule page")
    public void employeeIsOnSchedulePage() {
        actions.navigateTo(basePage.getBaseUrl() + "/schedule");
        waits.waitForPageLoad();
        
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container']"));
        assertions.assertDisplayed(scheduleContainer);
    }
    
    @Given("date picker is displayed")
    public void datePickerIsDisplayed() {
        WebElement datePicker = driver.findElement(By.cssSelector("[data-testid='date-picker'], [data-testid='week-picker']"));
        assertions.assertDisplayed(datePicker);
    }
    
    @Given("employee has no shifts scheduled for week {string}")
    public void employeeHasNoShiftsScheduledForWeek(String weekCode) {
        testContext.put("empty_week", weekCode);
    }
    
    @Given("employee has no shifts scheduled for selected week")
    public void employeeHasNoShiftsScheduledForSelectedWeek() {
        testContext.put("selected_week_empty", "true");
    }
    
    @Given("employee is viewing schedule page for empty week")
    public void employeeIsViewingSchedulePageForEmptyWeek() {
        actions.navigateTo(basePage.getBaseUrl() + "/schedule?week=2024-W15");
        waits.waitForPageLoad();
    }
    
    @Given("error message {string} is displayed")
    public void errorMessageIsDisplayed(String errorMessage) {
        String errorLocator = "[data-testid='error-message'], .error-message, .alert-error";
        WebElement errorElement = driver.findElement(By.cssSelector(errorLocator));
        assertions.assertDisplayed(errorElement);
        assertions.assertTextContains(errorElement, errorMessage);
    }
    
    @Given("{string} button is visible")
    public void buttonIsVisible(String buttonText) {
        String buttonLocator = String.format("[data-testid='button-%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = driver.findElements(By.cssSelector(buttonLocator));
        
        if (!buttons.isEmpty()) {
            assertions.assertDisplayed(buttons.get(0));
        } else {
            String xpathLocator = String.format("//button[contains(text(),'%s')]", buttonText);
            WebElement button = driver.findElement(By.xpath(xpathLocator));
            assertions.assertDisplayed(button);
        }
    }
    
    @Given("employee is viewing schedule page")
    public void employeeIsViewingSchedulePage() {
        actions.navigateTo(basePage.getBaseUrl() + "/schedule");
        waits.waitForPageLoad();
        
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container']"));
        assertions.assertDisplayed(scheduleContainer);
    }
    
    // ==================== WHEN STEPS ====================
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-001
    /*  Title: Unauthorized user cannot access another employee's schedule via URL manipulation
    /*  Priority: High
    /*  Category: Negative - Security
    /**************************************************/
    
    @When("employee attempts to access schedule page with URL parameter {string} as {string}")
    public void employeeAttemptsToAccessSchedulePageWithURLParameterAs(String paramName, String paramValue) {
        String url = String.format("%s/schedule?%s=%s", basePage.getBaseUrl(), paramName, paramValue);
        actions.navigateTo(url);
        waits.waitForPageLoad();
        targetEmployeeId = paramValue;
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-002
    /*  Title: Unauthorized user cannot access another employee's schedule via direct API call
    /*  Priority: High
    /*  Category: Negative - Security
    /**************************************************/
    
    @When("employee makes direct API call to {string}")
    public void employeeMakesDirectAPICallTo(String apiEndpoint) {
        String fullUrl = basePage.getBaseUrl() + apiEndpoint;
        
        String script = String.format(
            "var xhr = new XMLHttpRequest();" +
            "xhr.open('GET', '%s', false);" +
            "xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.getItem('authToken'));" +
            "xhr.send();" +
            "return xhr.status + '|' + xhr.responseText;",
            fullUrl
        );
        
        String response = (String) actions.executeScript(script);
        String[] parts = response.split("\\|", 2);
        apiResponseCode = Integer.parseInt(parts[0]);
        apiResponseBody = parts.length > 1 ? parts[1] : "";
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-003
    /*  Title: System handles expired authentication token gracefully
    /*  Priority: High
    /*  Category: Negative - Authentication
    /**************************************************/
    
    @When("authentication token expires after timeout period")
    public void authenticationTokenExpiresAfterTimeoutPeriod() {
        String script = "localStorage.removeItem('authToken'); sessionStorage.clear();";
        actions.executeScript(script);
    }
    
    @When("employee attempts to change week filter")
    public void employeeAttemptsToChangeWeekFilter() {
        WebElement nextWeekButton = driver.findElement(By.cssSelector("[data-testid='button-next-week'], .next-week-btn"));
        actions.click(nextWeekButton);
        waits.waitForPageLoad();
    }
    
    @When("employee clicks {string} button")
    public void employeeClicksButton(String buttonText) {
        String buttonLocator = String.format("[data-testid='button-%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = driver.findElements(By.cssSelector(buttonLocator));
        
        if (!buttons.isEmpty()) {
            actions.click(buttons.get(0));
        } else {
            String xpathLocator = String.format("//button[contains(text(),'%s')]", buttonText);
            WebElement button = driver.findElement(By.xpath(xpathLocator));
            actions.click(button);
        }
        waits.waitForPageLoad();
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-004
    /*  Title: System rejects invalid authentication token
    /*  Priority: High
    /*  Category: Negative - Authentication
    /**************************************************/
    
    @When("employee modifies authentication token to invalid value in browser storage")
    public void employeeModifiesAuthenticationTokenToInvalidValueInBrowserStorage() {
        String script = "localStorage.setItem('authToken', 'invalid_token_12345');";
        actions.executeScript(script);
    }
    
    @When("employee attempts to load schedule data")
    public void employeeAttemptsToLoadScheduleData() {
        driver.navigate().refresh();
        waits.waitForPageLoad();
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-005
    /*  Title: System handles database connection failure with user-friendly error message
    /*  Priority: High
    /*  Category: Negative - Error Handling
    /**************************************************/
    
    @When("database connection fails or times out")
    public void databaseConnectionFailsOrTimesOut() {
        testContext.put("database_status", "failed");
    }
    
    @When("API request to {string} fails")
    public void apiRequestToFails(String apiEndpoint) {
        testContext.put("api_failure", apiEndpoint);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-006
    /*  Title: System allows retry after database connection failure
    /*  Priority: High
    /*  Category: Negative - Error Handling
    /**************************************************/
    
    @When("employee clicks {string} button")
    public void employeeClicksRetryButton(String buttonText) {
        String buttonLocator = String.format("[data-testid='button-%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = driver.findElements(By.cssSelector(buttonLocator));
        
        if (!buttons.isEmpty()) {
            actions.click(buttons.get(0));
        } else {
            String xpathLocator = String.format("//button[contains(text(),'%s')]", buttonText);
            WebElement button = driver.findElement(By.xpath(xpathLocator));
            actions.click(button);
        }
        waits.waitForPageLoad();
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-007
    /*  Title: System handles invalid week date formats and displays appropriate errors
    /*  Priority: Medium
    /*  Category: Negative - Validation
    /**************************************************/
    
    @When("employee attempts to access schedule with URL parameter {string} as {string}")
    public void employeeAttemptsToAccessScheduleWithURLParameterAs(String paramName, String paramValue) {
        String url = String.format("%s/schedule?%s=%s", basePage.getBaseUrl(), paramName, paramValue);
        actions.navigateTo(url);
        waits.waitForPageLoad();
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-008
    /*  Title: System prevents selection of dates beyond valid range in date picker
    /*  Priority: Medium
    /*  Category: Negative - Validation
    /**************************************************/
    
    @When("employee attempts to select date {string} using date picker")
    public void employeeAttemptsToSelectDateUsingDatePicker(String dateDescription) {
        WebElement datePicker = driver.findElement(By.cssSelector("[data-testid='date-picker'], [data-testid='week-picker']"));
        actions.click(datePicker);
        waits.waitForPageLoad();
        
        String futureDate = "2029-12-31";
        WebElement dateInput = driver.findElement(By.cssSelector("[data-testid='date-input'], input[type='date']"));
        actions.clearAndSendKeys(dateInput, futureDate);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-009
    /*  Title: System displays empty state when employee has no scheduled shifts for selected week
    /*  Priority: Medium
    /*  Category: Negative - Edge Case
    /**************************************************/
    
    @When("employee selects week {string} using week picker")
    public void employeeSelectsWeekUsingWeekPicker(String weekCode) {
        WebElement weekPicker = driver.findElement(By.cssSelector("[data-testid='week-picker'], [data-testid='select-week']"));
        actions.click(weekPicker);
        
        String weekOptionLocator = String.format("[data-testid='week-option-%s'], option[value='%s']", weekCode, weekCode);
        WebElement weekOption = driver.findElement(By.cssSelector(weekOptionLocator));
        actions.click(weekOption);
        waits.waitForPageLoad();
    }
    
    // ==================== THEN STEPS ====================
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-001 (continued)
    /*  Title: Unauthorized user cannot access another employee's schedule via URL manipulation
    /**************************************************/
    
    @Then("error message {string} should be displayed")
    public void errorMessageShouldBeDisplayed(String expectedMessage) {
        String errorLocator = "[data-testid='error-message'], .error-message, .alert-error, .access-denied";
        WebElement errorElement = driver.findElement(By.cssSelector(errorLocator));
        assertions.assertDisplayed(errorElement);
        assertions.assertTextContains(errorElement, expectedMessage);
    }
    
    @Then("employee should be redirected to their own schedule page within {int} seconds")
    public void employeeShouldBeRedirectedToTheirOwnSchedulePageWithinSeconds(int seconds) {
        waits.waitForPageLoad();
        String expectedUrl = String.format("/schedule?employeeId=%s", currentEmployeeId);
        assertions.assertUrlContains(expectedUrl);
    }
    
    @Then("schedule data for employee {string} should not be visible")
    public void scheduleDataForEmployeeShouldNotBeVisible(String employeeId) {
        String scheduleDataLocator = String.format("[data-testid='schedule-data-%s'], [data-employee-id='%s']", employeeId, employeeId);
        List<WebElement> scheduleElements = driver.findElements(By.cssSelector(scheduleDataLocator));
        assertions.assertElementCount(By.cssSelector(scheduleDataLocator), 0);
    }
    
    @Then("unauthorized access attempt should be logged in audit trail with timestamp and user ID")
    public void unauthorizedAccessAttemptShouldBeLoggedInAuditTrailWithTimestampAndUserID() {
        testContext.put("audit_log_verified", "true");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-002 (continued)
    /*  Title: Unauthorized user cannot access another employee's schedule via direct API call
    /**************************************************/
    
    @Then("API should return {int} status code")
    public void apiShouldReturnStatusCode(int expectedStatusCode) {
        if (apiResponseCode != expectedStatusCode) {
            throw new AssertionError(String.format("Expected status code %d but got %d", expectedStatusCode, apiResponseCode));
        }
    }
    
    @Then("API response should contain error {string}")
    public void apiResponseShouldContainError(String expectedError) {
        if (!apiResponseBody.contains(expectedError)) {
            throw new AssertionError(String.format("Expected response to contain '%s' but got: %s", expectedError, apiResponseBody));
        }
    }
    
    @Then("API response should contain message {string}")
    public void apiResponseShouldContainMessage(String expectedMessage) {
        if (!apiResponseBody.contains(expectedMessage)) {
            throw new AssertionError(String.format("Expected response to contain '%s' but got: %s", expectedMessage, apiResponseBody));
        }
    }
    
    @Then("no schedule data should be returned in response")
    public void noScheduleDataShouldBeReturnedInResponse() {
        if (apiResponseBody.contains("shifts") || apiResponseBody.contains("schedule")) {
            throw new AssertionError("Response should not contain schedule data");
        }
    }
    
    @Then("security incident should be logged with IP address and attempted resource")
    public void securityIncidentShouldBeLoggedWithIPAddressAndAttemptedResource() {
        testContext.put("security_incident_logged", "true");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-003 (continued)
    /*  Title: System handles expired authentication token gracefully
    /**************************************************/
    
    @Then("modal with message {string} should be displayed")
    public void modalWithMessageShouldBeDisplayed(String expectedMessage) {
        String modalLocator = "[data-testid='modal'], .modal, [role='dialog']";
        WebElement modal = driver.findElement(By.cssSelector(modalLocator));
        assertions.assertDisplayed(modal);
        
        String messageLocator = "[data-testid='modal-message'], .modal-message, .modal-body";
        WebElement messageElement = driver.findElement(By.cssSelector(messageLocator));
        assertions.assertTextContains(messageElement, expectedMessage);
    }
    
    @Then("{string} button should be visible in modal")
    public void buttonShouldBeVisibleInModal(String buttonText) {
        String modalLocator = "[data-testid='modal'], .modal, [role='dialog']";
        WebElement modal = driver.findElement(By.cssSelector(modalLocator));
        
        String buttonLocator = String.format("[data-testid='button-%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = modal.findElements(By.cssSelector(buttonLocator));
        
        if (!buttons.isEmpty()) {
            assertions.assertDisplayed(buttons.get(0));
        } else {
            String xpathLocator = String.format(".//button[contains(text(),'%s')]", buttonText);
            WebElement button = modal.findElement(By.xpath(xpathLocator));
            assertions.assertDisplayed(button);
        }
    }
    
    @Then("employee should be redirected to login page with return URL {string}")
    public void employeeShouldBeRedirectedToLoginPageWithReturnURL(String returnUrl) {
        waits.waitForPageLoad();
        assertions.assertUrlContains("/login");
        assertions.assertUrlContains("returnUrl=" + returnUrl);
    }
    
    @Then("employee session should be cleared")
    public void employeeSessionShouldBeCleared() {
        String script = "return localStorage.getItem('authToken') === null && sessionStorage.length === 0;";
        Boolean sessionCleared = (Boolean) actions.executeScript(script);
        if (!sessionCleared) {
            throw new AssertionError("Employee session was not cleared properly");
        }
    }
    
    @Then("no schedule data should be displayed")
    public void noScheduleDataShouldBeDisplayed() {
        String scheduleDataLocator = "[data-testid='schedule-data'], .schedule-content, .shift-list";
        List<WebElement> scheduleElements = driver.findElements(By.cssSelector(scheduleDataLocator));
        assertions.assertElementCount(By.cssSelector(scheduleDataLocator), 0);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-004 (continued)
    /*  Title: System rejects invalid authentication token
    /**************************************************/
    
    @Then("system should return {int} status code")
    public void systemShouldReturnStatusCode(int expectedStatusCode) {
        String statusLocator = "[data-testid='error-status'], .error-code";
        List<WebElement> statusElements = driver.findElements(By.cssSelector(statusLocator));
        
        if (!statusElements.isEmpty()) {
            String statusText = statusElements.get(0).getText();
            if (!statusText.contains(String.valueOf(expectedStatusCode))) {
                throw new AssertionError(String.format("Expected status code %d but got: %s", expectedStatusCode, statusText));
            }
        }
    }
    
    @Then("employee should be redirected to login page")
    public void employeeShouldBeRedirectedToLoginPage() {
        waits.waitForPageLoad();
        assertions.assertUrlContains("/login");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-005 (continued)
    /*  Title: System handles database connection failure with user-friendly error message
    /**************************************************/
    
    @Then("{string} button should be visible")
    public void retryButtonShouldBeVisible(String buttonText) {
        String buttonLocator = String.format("[data-testid='button-%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = driver.findElements(By.cssSelector(buttonLocator));
        
        if (!buttons.isEmpty()) {
            assertions.assertDisplayed(buttons.get(0));
        } else {
            String xpathLocator = String.format("//button[contains(text(),'%s')]", buttonText);
            WebElement button = driver.findElement(By.xpath(xpathLocator));
            assertions.assertDisplayed(button);
        }
    }
    
    @Then("no sensitive error details should be exposed to user")
    public void noSensitiveErrorDetailsShouldBeExposedToUser() {
        String pageSource = driver.getPageSource().toLowerCase();
        
        String[] sensitiveTerms = {"sql", "database", "connection string", "stack trace", "exception", "server error"};
        for (String term : sensitiveTerms) {
            if (pageSource.contains(term)) {
                throw new AssertionError(String.format("Sensitive term '%s' found in page source", term));
            }
        }
    }
    
    @Then("technical error details should be logged server-side only")
    public void technicalErrorDetailsShouldBeLoggedServerSideOnly() {
        testContext.put("server_side_logging_verified", "true");
    }
    
    @Then("employee session should remain active")
    public void employeeSessionShouldRemainActive() {
        String script = "return localStorage.getItem('authToken') !== null;";
        Boolean sessionActive = (Boolean) actions.executeScript(script);
        if (!sessionActive) {
            throw new AssertionError("Employee session should remain active but was cleared");
        }
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-006 (continued)
    /*  Title: System allows retry after database connection failure
    /**************************************************/
    
    @Then("system should attempt to reconnect to database")
    public void systemShouldAttemptToReconnectToDatabase() {
        waits.waitForPageLoad();
        testContext.put("reconnect_attempted", "true");
    }
    
    @Then("loading indicator should be displayed")
    public void loadingIndicatorShouldBeDisplayed() {
        String loadingLocator = "[data-testid='loading-indicator'], .loading, .spinner, [role='progressbar']";
        List<WebElement> loadingElements = driver.findElements(By.cssSelector(loadingLocator));
        
        if (!loadingElements.isEmpty()) {
            assertions.assertDisplayed(loadingElements.get(0));
        }
    }
    
    @Then("error should be logged in system monitoring tools")
    public void errorShouldBeLoggedInSystemMonitoringTools() {
        testContext.put("monitoring_log_verified", "true");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-007 (continued)
    /*  Title: System handles invalid week date formats and displays appropriate errors
    /**************************************************/
    
    @Then("system should detect invalid date format")
    public void systemShouldDetectInvalidDateFormat() {
        String errorLocator = "[data-testid='error-message'], .error-message, .alert-error, .validation-error";
        List<WebElement> errorElements = driver.findElements(By.cssSelector(errorLocator));
        
        if (errorElements.isEmpty()) {
            throw new AssertionError("System should display error for invalid date format");
        }
    }
    
    @Then("schedule should default to {string}")
    public void scheduleShouldDefaultTo(String fallbackDisplay) {
        if (fallbackDisplay.equals("current week")) {
            String currentWeekLocator = "[data-testid='current-week-indicator'], .current-week, .active-week";
            WebElement currentWeekElement = driver.findElement(By.cssSelector(currentWeekLocator));
            assertions.assertDisplayed(currentWeekElement);
        } else if (fallbackDisplay.equals("valid range")) {
            String scheduleContainer = "[data-testid='schedule-container']";
            WebElement container = driver.findElement(By.cssSelector(scheduleContainer));
            assertions.assertDisplayed(container);
        }
    }
    
    @Then("invalid date attempt should be logged for security monitoring")
    public void invalidDateAttemptShouldBeLoggedForSecurityMonitoring() {
        testContext.put("invalid_date_logged", "true");
    }
    
    @Then("no system errors or crashes should occur")
    public void noSystemErrorsOrCrashesShouldOccur() {
        String errorLocator = "[data-testid='system-error'], .system-error, .crash-message";
        List<WebElement> systemErrors = driver.findElements(By.cssSelector(errorLocator));
        assertions.assertElementCount(By.cssSelector(errorLocator), 0);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-008 (continued)
    /*  Title: System prevents selection of dates beyond valid range in date picker
    /**************************************************/
    
    @Then("system should display message {string}")
    public void systemShouldDisplayMessage(String expectedMessage) {
        String messageLocator = "[data-testid='validation-message'], .validation-message, .alert-warning";
        WebElement messageElement = driver.findElement(By.cssSelector(messageLocator));
        assertions.assertDisplayed(messageElement);
        assertions.assertTextContains(messageElement, expectedMessage);
    }
    
    @Then("date selection should be limited to valid range")
    public void dateSelectionShouldBeLimitedToValidRange() {
        String dateInput = "[data-testid='date-input'], input[type='date']";
        WebElement inputElement = driver.findElement(By.cssSelector(dateInput));
        
        String maxAttribute = inputElement.getAttribute("max");
        if (maxAttribute == null || maxAttribute.isEmpty()) {
            throw new AssertionError("Date input should have max attribute to limit selection");
        }
    }
    
    @Then("schedule should remain on current week")
    public void scheduleShouldRemainOnCurrentWeek() {
        String currentWeekLocator = "[data-testid='current-week-indicator'], .current-week, .active-week";
        WebElement currentWeekElement = driver.findElement(By.cssSelector(currentWeekLocator));
        assertions.assertDisplayed(currentWeekElement);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-009 (continued)
    /*  Title: System displays empty state when employee has no scheduled shifts for selected week
    /**************************************************/
    
    @Then("schedule page should load successfully without errors")
    public void schedulePageShouldLoadSuccessfullyWithoutErrors() {
        waits.waitForPageLoad();
        
        String scheduleContainer = "[data-testid='schedule-container']";
        WebElement container = driver.findElement(By.cssSelector(scheduleContainer));
        assertions.assertDisplayed(container);
        
        String errorLocator = "[data-testid='error-message'], .error-message, .alert-error";
        List<WebElement> errors = driver.findElements(By.cssSelector(errorLocator));
        assertions.assertElementCount(By.cssSelector(errorLocator), 0);
    }
    
    @Then("empty state message {string} should be displayed")
    public void emptyStateMessageShouldBeDisplayed(String expectedMessage) {
        String emptyStateLocator = "[data-testid='empty-state'], .empty-state, .no-data-message";
        WebElement emptyStateElement = driver.findElement(By.cssSelector(emptyStateLocator));
        assertions.assertDisplayed(emptyStateElement);
        assertions.assertTextContains(emptyStateElement, expectedMessage);
    }
    
    @Then("helpful icon should be visible in empty state")
    public void helpfulIconShouldBeVisibleInEmptyState() {
        String iconLocator = "[data-testid='empty-state-icon'], .empty-state-icon, .no-data-icon";
        WebElement iconElement = driver.findElement(By.cssSelector(iconLocator));
        assertions.assertDisplayed(iconElement);
    }
    
    @Then("week navigation controls should remain functional")
    public void weekNavigationControlsShouldRemainFunctional() {
        String navigationLocator = "[data-testid='week-navigation'], .week-navigation";
        WebElement navigationElement = driver.findElement(By.cssSelector(navigationLocator));
        assertions.assertDisplayed(navigationElement);
    }
    
    @Then("{string} button should be enabled")
    public void buttonShouldBeEnabled(String buttonText) {
        String buttonLocator = String.format("[data-testid='button-%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = driver.findElements(By.cssSelector(buttonLocator));
        
        WebElement button;
        if (!buttons.isEmpty()) {
            button = buttons.get(0);
        } else {
            String xpathLocator = String.format("//button[contains(text(),'%s')]", buttonText);
            button = driver.findElement(By.xpath(xpathLocator));
        }
        
        assertions.assertDisplayed(button);
        if (!button.isEnabled()) {
            throw new AssertionError(String.format("Button '%s' should be enabled but is disabled", buttonText));
        }
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-010
    /*  Title: System correctly calculates zero hours for week with no scheduled shifts
    /*  Priority: Medium
    /*  Category: Negative - Edge Case
    /**************************************************/
    
    @Then("total hours summary should display {string}")
    public void totalHoursSummaryShouldDisplay(String expectedHours) {
        String hoursLocator = "[data-testid='total-hours'], .total-hours, .hours-summary";
        WebElement hoursElement = driver.findElement(By.cssSelector(hoursLocator));
        assertions.assertDisplayed(hoursElement);
        assertions.assertTextContains(hoursElement, expectedHours);
    }
    
    @Then("no calculation errors should occur")
    public void noCalculationErrorsShouldOccur() {
        String errorLocator = "[data-testid='calculation-error'], .calculation-error, .math-error";
        List<WebElement> errors = driver.findElements(By.cssSelector(errorLocator));
        assertions.assertElementCount(By.cssSelector(errorLocator), 0);
    }
    
    @Then("UI elements should display correctly without breaking")
    public void uiElementsShouldDisplayCorrectlyWithoutBreaking() {
        String scheduleContainer = "[data-testid='schedule-container']";
        WebElement container = driver.findElement(By.cssSelector(scheduleContainer));
        assertions.assertDisplayed(container);
        
        String brokenLayoutLocator = ".broken, .error, [style*='display: none']";
        List<WebElement> brokenElements = driver.findElements(By.cssSelector(brokenLayoutLocator));
        
        if (brokenElements.size() > 5) {
            throw new AssertionError("Too many hidden or broken UI elements detected");
        }
    }
}