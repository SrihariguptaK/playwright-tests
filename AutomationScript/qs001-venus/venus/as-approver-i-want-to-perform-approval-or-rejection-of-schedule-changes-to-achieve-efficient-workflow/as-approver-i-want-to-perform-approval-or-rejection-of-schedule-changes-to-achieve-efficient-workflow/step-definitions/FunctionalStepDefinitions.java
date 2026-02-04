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

import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import config.ConfigReader;
import testdata.TestData;

public class ScheduleChangeRequestApprovalStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private static final String APP_URL = ConfigReader.getProperty("app.url", "http://localhost:3000");
    private static final int TIMEOUT = Integer.parseInt(ConfigReader.getProperty("timeout", "30"));
    
    private static final String BTN_LOGIN = "//button[@type='submit' or contains(text(),'Login') or contains(text(),'Sign In')]";
    private static final String INPUT_USERNAME = "//input[@placeholder='Username' or @name='username' or @id='username']";
    private static final String INPUT_PASSWORD = "//input[@type='password' or @placeholder='Password' or @name='password']";
    private static final String DASHBOARD = "//div[contains(@class,'dashboard')] | //h1[contains(text(),'Dashboard')]";
    private static final String PENDING_REQUESTS_TAB = "//button[contains(text(),'Pending Requests')] | //a[contains(text(),'Pending Requests')] | //div[contains(text(),'Pending Requests')]";
    private static final String PENDING_REQUESTS_MENU = "//nav//a[contains(text(),'Pending Requests')] | //aside//a[contains(text(),'Pending Requests')] | //ul[contains(@class,'sidebar')]//a[contains(text(),'Pending Requests')]";
    private static final String PENDING_REQUESTS_TABLE = "//table[contains(@class,'requests')] | //table//thead//th[contains(text(),'Request ID')] | //div[contains(@class,'requests-table')]//table";
    private static final String TABLE_ROWS = "//table//tbody//tr";
    private static final String BTN_APPROVE = "//button[contains(text(),'Approve') or contains(@class,'approve')]";
    private static final String BTN_REJECT = "//button[contains(text(),'Reject') or contains(@class,'reject')]";
    private static final String BTN_CONFIRM_APPROVAL = "//button[contains(text(),'Confirm Approval') or contains(text(),'Confirm')]";
    private static final String BTN_CONFIRM_REJECTION = "//button[contains(text(),'Confirm Rejection') or contains(text(),'Confirm')]";
    private static final String TEXTAREA_APPROVAL_COMMENTS = "//textarea[contains(@placeholder,'approval comments') or contains(@name,'approvalComments')] | //label[contains(text(),'approval comments')]/..//textarea";
    private static final String TEXTAREA_REJECTION_REASON = "//textarea[contains(@placeholder,'Rejection reason') or contains(@name,'rejectionReason')] | //label[contains(text(),'Rejection reason')]/..//textarea";
    private static final String SUCCESS_MESSAGE = "//div[contains(@class,'success') or contains(@class,'alert-success')] | //div[@role='alert'][contains(.,'success')]";
    private static final String REQUEST_DETAILS_MODAL = "//div[@role='dialog'] | //div[contains(@class,'modal') and contains(@class,'show')]";
    private static final String OVERVIEW_PENDING_COUNT = "//div[contains(@class,'overview')]//span[contains(text(),'pending')] | //div[contains(@class,'pending-count')]";
    private static final String WELCOME_MESSAGE = "//div[contains(text(),'Welcome')] | //h1[contains(text(),'Welcome')] | //span[contains(text(),'Welcome')]";
    private static final String REQUEST_HISTORY_NAV = "//nav//a[contains(text(),'Request History')] | //a[contains(@href,'history')]";
    private static final String STATUS_FILTER_DROPDOWN = "//select[contains(@name,'status')] | //div[contains(@class,'status-filter')]";
    private static final String SEARCH_INPUT = "//input[@type='search' or contains(@placeholder,'Search') or contains(@name,'search')]";
    private static final String SUBMISSION_DATE_HEADER = "//th[contains(text(),'Submission Date')] | //th[contains(text(),'Date Submitted')]";
    private static final String CHARACTER_COUNT = "//span[contains(@class,'char-count')] | //div[contains(text(),'characters')]";
    private static final String NOTIFICATION_LINK = "//a[contains(@href,'request') or contains(@href,'details')]";
    
    private String requestId;
    private long performanceStartTime;
    
    private String buttonByText(String text) {
        return String.format("//button[contains(text(),'%s') or contains(.,'%s')]", text, text);
    }
    
    private String inputByPlaceholder(String placeholder) {
        return String.format("//input[contains(@placeholder,'%s')]", placeholder);
    }
    
    private String inputByLabel(String label) {
        return String.format("//label[contains(text(),'%s')]/..//input | //label[contains(text(),'%s')]/following-sibling::input", label, label);
    }
    
    private String textareaByLabel(String label) {
        return String.format("//label[contains(text(),'%s')]/..//textarea | //textarea[contains(@placeholder,'%s')]", label, label);
    }
    
    private String linkByText(String text) {
        return String.format("//a[contains(text(),'%s')]", text);
    }
    
    private String elementContainingText(String text) {
        return String.format("//*[contains(text(),'%s')]", text);
    }
    
    private String tableColumnHeader(String columnName) {
        return String.format("//th[contains(text(),'%s')]", columnName);
    }
    
    private String requestRowById(String id) {
        return String.format("//table//tbody//tr[contains(.,'%s')]", id);
    }
    
    private String statusBadge(String status) {
        return String.format("//span[contains(@class,'badge') and contains(text(),'%s')] | //div[contains(@class,'status') and contains(text(),'%s')]", status, status);
    }
    
    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        if (Boolean.parseBoolean(ConfigReader.getProperty("headless", "false"))) {
            options.addArguments("--headless");
        }
        options.addArguments("--disable-notifications");
        options.addArguments("--start-maximized");
        driver = new ChromeDriver(options);
        driver.manage().window().maximize();
        
        actions = new GenericActions(driver, TIMEOUT);
        waits = new WaitHelpers(driver, TIMEOUT);
        assertions = new AssertionHelpers(driver);
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
    
    @Given("user is logged in with {string} role")
    public void userIsLoggedInWithRole(String role) {
        actions.navigateTo(APP_URL + "/login");
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.xpath(INPUT_USERNAME));
        actions.clearAndSendKeys(usernameField, TestData.getUsername(role));
        
        WebElement passwordField = driver.findElement(By.xpath(INPUT_PASSWORD));
        actions.clearAndSendKeys(passwordField, TestData.getPassword(role));
        
        WebElement loginButton = driver.findElement(By.xpath(BTN_LOGIN));
        actions.click(loginButton);
        
        waits.waitForElementVisible(By.xpath(DASHBOARD));
        waits.waitForPageLoad();
    }
    
    @Given("user has valid session token")
    public void userHasValidSessionToken() {
        String sessionToken = actions.getAttribute(driver.findElement(By.xpath("//body")), "data-session-token");
        if (sessionToken == null || sessionToken.isEmpty()) {
            String cookieValue = driver.manage().getCookieNamed("session_token").getValue();
            assertions.assertNotNull(cookieValue);
        }
    }
    
    @Given("database connection is active")
    public void databaseConnectionIsActive() {
        WebElement dbStatusIndicator = driver.findElement(By.xpath("//div[contains(@class,'db-status')] | //span[contains(@class,'connection-status')]"));
        String statusText = actions.getText(dbStatusIndicator);
        assertions.assertTextContains(dbStatusIndicator, "connected");
    }
    
    @Given("{string} table is accessible")
    public void tableIsAccessible(String tableName) {
        actions.navigateTo(APP_URL + "/admin/database-status");
        waits.waitForPageLoad();
        String xpath = String.format("//div[contains(@class,'table-status')]//span[contains(text(),'%s')]", tableName);
        WebElement tableStatus = driver.findElement(By.xpath(xpath));
        assertions.assertDisplayed(tableStatus);
    }
    
    @Given("at least one pending schedule change request exists in the system")
    public void atLeastOnePendingScheduleChangeRequestExistsInTheSystem() {
        actions.navigateTo(APP_URL + "/api/scheduleChangeRequests/seed");
        waits.waitForPageLoad();
        waits.waitForSeconds(1);
    }
    
    @Given("approver has permission to access the pending requests section")
    public void approverHasPermissionToAccessThePendingRequestsSection() {
        WebElement pendingRequestsNav = driver.findElement(By.xpath(PENDING_REQUESTS_MENU));
        assertions.assertDisplayed(pendingRequestsNav);
        assertions.assertEnabled(pendingRequestsNav);
    }
    
    @Given("approver has necessary permissions to reject requests")
    public void approverHasNecessaryPermissionsToRejectRequests() {
        actions.navigateTo(APP_URL + "/dashboard");
        waits.waitForPageLoad();
        WebElement rejectButton = driver.findElement(By.xpath(BTN_REJECT));
        assertions.assertEnabled(rejectButton);
    }
    
    @Given("system is connected to notification service")
    public void systemIsConnectedToNotificationService() {
        WebElement notificationStatus = driver.findElement(By.xpath("//div[contains(@class,'notification-service')] | //span[contains(text(),'Notification')]"));
        assertions.assertDisplayed(notificationStatus);
    }
    
    @Given("multiple pending schedule change requests exist in the system")
    public void multiplePendingScheduleChangeRequestsExistInTheSystem() {
        actions.navigateTo(APP_URL + "/api/scheduleChangeRequests/seed?count=10");
        waits.waitForPageLoad();
        waits.waitForSeconds(1);
    }
    
    @Given("at least {int} requests exist with different submission dates and requesters")
    public void atLeastRequestsExistWithDifferentSubmissionDatesAndRequesters(int count) {
        actions.navigateTo(APP_URL + "/api/scheduleChangeRequests/seed?count=" + count);
        waits.waitForPageLoad();
        waits.waitForSeconds(1);
    }
    
    @Given("browser cache is cleared")
    public void browserCacheIsCleared() {
        driver.manage().deleteAllCookies();
        actions.navigateTo("chrome://settings/clearBrowserData");
        waits.waitForSeconds(1);
    }
    
    @Given("at least one schedule change request has been previously approved or rejected")
    public void atLeastOneScheduleChangeRequestHasBeenPreviouslyApprovedOrRejected() {
        actions.navigateTo(APP_URL + "/api/scheduleChangeRequests/seedHistory");
        waits.waitForPageLoad();
        waits.waitForSeconds(1);
    }
    
    @Given("request history feature is enabled in the system")
    public void requestHistoryFeatureIsEnabledInTheSystem() {
        WebElement historyNav = driver.findElement(By.xpath(REQUEST_HISTORY_NAV));
        assertions.assertDisplayed(historyNav);
    }
    
    @Given("user has permission to view historical decisions")
    public void userHasPermissionToViewHistoricalDecisions() {
        WebElement historyNav = driver.findElement(By.xpath(REQUEST_HISTORY_NAV));
        assertions.assertEnabled(historyNav);
    }
    
    @Given("a pending schedule change request exists submitted by a valid requester")
    public void aPendingScheduleChangeRequestExistsSubmittedByAValidRequester() {
        actions.navigateTo(APP_URL + "/api/scheduleChangeRequests/seed?requester=valid");
        waits.waitForPageLoad();
        waits.waitForSeconds(1);
    }
    
    @Given("notification service is running and configured correctly")
    public void notificationServiceIsRunningAndConfiguredCorrectly() {
        actions.navigateTo(APP_URL + "/admin/services");
        waits.waitForPageLoad();
        WebElement notificationService = driver.findElement(By.xpath("//div[contains(text(),'Notification Service')]//span[contains(@class,'running') or contains(text(),'Active')]"));
        assertions.assertDisplayed(notificationService);
    }
    
    @Given("requester has valid email address")
    public void requesterHasValidEmailAddress() {
        actions.navigateTo(APP_URL + "/pending-requests");
        waits.waitForPageLoad();
        WebElement firstRow = driver.findElement(By.xpath("(//table//tbody//tr)[1]"));
        actions.click(firstRow);
        waits.waitForElementVisible(By.xpath(REQUEST_DETAILS_MODAL));
        WebElement emailField = driver.findElement(By.xpath("//div[contains(@class,'requester-email')] | //span[contains(text(),'@')]"));
        assertions.assertDisplayed(emailField);
    }
    
    @Given("requester has notification preferences enabled")
    public void requesterHasNotificationPreferencesEnabled() {
        WebElement notificationPreference = driver.findElement(By.xpath("//div[contains(@class,'notification-enabled')] | //span[contains(text(),'Notifications: Enabled')]"));
        assertions.assertDisplayed(notificationPreference);
    }
    
    @Given("system is under normal load conditions")
    public void systemIsUnderNormalLoadConditions() {
        actions.navigateTo(APP_URL + "/admin/system-health");
        waits.waitForPageLoad();
        WebElement loadIndicator = driver.findElement(By.xpath("//div[contains(@class,'load')]//span[contains(text(),'Normal') or contains(text(),'Low')]"));
        assertions.assertDisplayed(loadIndicator);
    }
    
    @Given("at least one pending request exists")
    public void atLeastOnePendingRequestExists() {
        actions.navigateTo(APP_URL + "/api/scheduleChangeRequests/seed?count=1");
        waits.waitForPageLoad();
        waits.waitForSeconds(1);
    }
    
    @Given("performance monitoring tools are available")
    public void performanceMonitoringToolsAreAvailable() {
        actions.pressKey(org.openqa.selenium.Keys.F12);
        waits.waitForSeconds(1);
    }
    
    @Given("pending schedule change request with ID {string} exists")
    public void pendingScheduleChangeRequestWithIDExists(String requestId) {
        this.requestId = requestId;
        actions.navigateTo(APP_URL + "/api/scheduleChangeRequests/seed?id=" + requestId);
        waits.waitForPageLoad();
        waits.waitForSeconds(1);
    }
    
    @When("user navigates to {string} page")
    public void userNavigatesToPage(String pageName) {
        String url = APP_URL + "/" + pageName.toLowerCase().replace(" ", "-");
        actions.navigateTo(url);
        waits.waitForPageLoad();
    }
    
    @When("user clicks {string} tab")
    public void userClicksTab(String tabName) {
        String xpath = String.format("//button[contains(text(),'%s')] | //a[contains(text(),'%s')] | //div[@role='tab' and contains(text(),'%s')]", tabName, tabName, tabName);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement tab = driver.findElement(By.xpath(xpath));
        actions.click(tab);
        waits.waitForPageLoad();
    }
    
    @When("user clicks on a specific pending request row")
    public void userClicksOnASpecificPendingRequestRow() {
        waits.waitForElementVisible(By.xpath(TABLE_ROWS));
        WebElement firstRow = driver.findElement(By.xpath("(//table//tbody//tr)[1]"));
        actions.click(firstRow);
        waits.waitForSeconds(1);
    }
    
    @When("user clicks {string} button")
    public void userClicksButton(String buttonName) {
        String xpath = String.format("//button[contains(text(),'%s') or contains(.,'%s')]", buttonName, buttonName);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement button = driver.findElement(By.xpath(xpath));
        actions.click(button);
        waits.waitForSeconds(1);
    }
    
    @When("user enters {string} in {string} field")
    public void userEntersInField(String value, String fieldName) {
        String byLabel = String.format("//label[contains(text(),'%s')]/..//input | //label[contains(text(),'%s')]/..//textarea", fieldName, fieldName);
        String byPlaceholder = String.format("//input[contains(@placeholder,'%s')] | //textarea[contains(@placeholder,'%s')]", fieldName, fieldName);
        
        WebElement inputField = null;
        if (!driver.findElements(By.xpath(byLabel)).isEmpty()) {
            inputField = driver.findElement(By.xpath(byLabel));
        } else if (!driver.findElements(By.xpath(byPlaceholder)).isEmpty()) {
            inputField = driver.findElement(By.xpath(byPlaceholder));
        } else {
            String byName = String.format("//input[@name='%s'] | //textarea[@name='%s']", fieldName.toLowerCase().replace(" ", ""), fieldName.toLowerCase().replace(" ", ""));
            inputField = driver.findElement(By.xpath(byName));
        }
        
        actions.clearAndSendKeys(inputField, value);
    }
    
    @When("user enters {string} in {string} field")
    public void userEntersValueInNamedField(String value, String fieldName) {
        String xpath = textareaByLabel(fieldName);
        if (driver.findElements(By.xpath(xpath)).isEmpty()) {
            xpath = inputByLabel(fieldName);
        }
        if (driver.findElements(By.xpath(xpath)).isEmpty()) {
            xpath = inputByPlaceholder(fieldName);
        }
        waits.waitForElementVisible(By.xpath(xpath));
        WebElement field = driver.findElement(By.xpath(xpath));
        actions.clearAndSendKeys(field, value);
    }
    
    @When("user clicks {string} menu item in left sidebar")
    public void userClicksMenuItemInLeftSidebar(String menuItem) {
        String xpath = String.format("//aside//a[contains(text(),'%s')] | //nav[contains(@class,'sidebar')]//a[contains(text(),'%s')]", menuItem, menuItem);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement menuLink = driver.findElement(By.xpath(xpath));
        actions.click(menuLink);
        waits.waitForPageLoad();
    }
    
    @When("user clicks on a specific request row")
    public void userClicksOnASpecificRequestRow() {
        waits.waitForElementVisible(By.xpath(TABLE_ROWS));
        WebElement firstRow = driver.findElement(By.xpath("(//table//tbody//tr)[1]"));
        actions.click(firstRow);
        waits.waitForSeconds(1);
    }
    
    @When("user clicks {string} column header")
    public void userClicksColumnHeader(String columnName) {
        String xpath = tableColumnHeader(columnName);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement header = driver.findElement(By.xpath(xpath));
        actions.click(header);
        waits.waitForSeconds(1);
    }
    
    @When("user uses search functionality to filter by requester name")
    public void userUsesSearchFunctionalityToFilterByRequesterName() {
        waits.waitForElementVisible(By.xpath(SEARCH_INPUT));
        WebElement searchInput = driver.findElement(By.xpath(SEARCH_INPUT));
        actions.clearAndSendKeys(searchInput, "John");
        waits.waitForSeconds(1);
    }
    
    @When("user navigates to {string} section from main navigation menu")
    public void userNavigatesToSectionFromMainNavigationMenu(String sectionName) {
        String xpath = String.format("//nav//a[contains(text(),'%s')] | //a[contains(@href,'%s')]", sectionName, sectionName.toLowerCase().replace(" ", "-"));
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement navLink = driver.findElement(By.xpath(xpath));
        actions.click(navLink);
        waits.waitForPageLoad();
    }
    
    @When("user selects {string} from status filter dropdown")
    public void userSelectsFromStatusFilterDropdown(String status) {
        waits.waitForElementVisible(By.xpath(STATUS_FILTER_DROPDOWN));
        WebElement dropdown = driver.findElement(By.xpath(STATUS_FILTER_DROPDOWN));
        actions.selectByVisibleText(dropdown, status);
        waits.waitForSeconds(1);
    }
    
    @When("user clicks on a previously approved request")
    public void userClicksOnAPreviouslyApprovedRequest() {
        String xpath = "//table//tbody//tr[contains(.,'Approved')][1]";
        waits.waitForElementVisible(By.xpath(xpath));
        WebElement approvedRow = driver.findElement(By.xpath(xpath));
        actions.click(approvedRow);
        waits.waitForSeconds(1);
    }
    
    @When("user navigates to pending requests section")
    public void userNavigatesToPendingRequestsSection() {
        actions.navigateTo(APP_URL + "/pending-requests");
        waits.waitForPageLoad();
    }
    
    @When("user selects a request submitted by a specific requester")
    public void userSelectsARequestSubmittedByASpecificRequester() {
        waits.waitForElementVisible(By.xpath(TABLE_ROWS));
        WebElement firstRow = driver.findElement(By.xpath("(//table//tbody//tr)[1]"));
        actions.click(firstRow);
        waits.waitForSeconds(1);
    }
    
    @When("user checks requester email inbox within {int} seconds")
    public void userChecksRequesterEmailInboxWithinSeconds(int seconds) {
        waits.waitForSeconds(seconds);
        actions.navigateTo(APP_URL + "/test/email-inbox");
        waits.waitForPageLoad();
    }
    
    @When("user clicks link in notification")
    public void userClicksLinkInNotification() {
        waits.waitForElementVisible(By.xpath(NOTIFICATION_LINK));
        WebElement link = driver.findElement(By.xpath(NOTIFICATION_LINK));
        actions.click(link);
        waits.waitForPageLoad();
    }
    
    @When("user starts performance timer and navigates to pending requests section")
    public void userStartsPerformanceTimerAndNavigatesToPendingRequestsSection() {
        performanceStartTime = System.currentTimeMillis();
        actions.navigateTo(APP_URL + "/pending-requests");
        waits.waitForPageLoad();
    }
    
    @When("user selects a pending request")
    public void userSelectsAPendingRequest() {
        waits.waitForElementVisible(By.xpath(TABLE_ROWS));
        WebElement firstRow = driver.findElement(By.xpath("(//table//tbody//tr)[1]"));
        actions.click(firstRow);
        waits.waitForSeconds(1);
    }
    
    @When("user measures time from click to success message")
    public void userMeasuresTimeFromClickToSuccessMessage() {
        performanceStartTime = System.currentTimeMillis();
    }
    
    @When("user checks network tab in browser developer tools")
    public void userChecksNetworkTabInBrowserDeveloperTools() {
        actions.pressKey(org.openqa.selenium.Keys.F12);
        waits.waitForSeconds(1);
    }
    
    @When("user repeats approval action for {int} different requests")
    public void userRepeatsApprovalActionForDifferentRequests(int count) {
        for (int i = 0; i < count; i++) {
            actions.navigateTo(APP_URL + "/pending-requests");
            waits.waitForPageLoad();
            WebElement row = driver.findElement(By.xpath("(//table//tbody//tr)[1]"));
            actions.click(row);
            waits.waitForSeconds(1);
            WebElement approveBtn = driver.findElement(By.xpath(BTN_APPROVE));
            actions.click(approveBtn);
            waits.waitForSeconds(1);
            WebElement confirmBtn = driver.findElement(By.xpath(BTN_CONFIRM_APPROVAL));
            actions.click(confirmBtn);
            waits.waitForElementVisible(By.xpath(SUCCESS_MESSAGE));
            waits.waitForSeconds(1);
        }
    }
    
    @When("user navigates to {string} section")
    public void userNavigatesToSection(String sectionName) {
        String url = APP_URL + "/" + sectionName.toLowerCase().replace(" ", "-");
        actions.navigateTo(url);
        waits.waitForPageLoad();
    }
    
    @When("user clicks on request with ID {string}")
    public void userClicksOnRequestWithID(String requestId) {
        String xpath = requestRowById(requestId);
        waits.waitForElementVisible(By.xpath(xpath));
        WebElement row = driver.findElement(By.xpath(xpath));
        actions.click(row);
        waits.waitForSeconds(1);
    }
    
    @When("user clicks {string} button")
    public void userClicksActionButton(String action) {
        String xpath = String.format("//button[contains(text(),'%s')]", action);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement button = driver.findElement(By.xpath(xpath));
        actions.click(button);
        waits.waitForSeconds(1);
    }
    
    @When("user enters {string} in comments field")
    public void userEntersInCommentsField(String comments) {
        String xpath = "//textarea[contains(@placeholder,'comment') or contains(@name,'comment')] | //textarea";
        waits.waitForElementVisible(By.xpath(xpath));
        WebElement textarea = driver.findElement(By.xpath(xpath));
        actions.clearAndSendKeys(textarea, comments);
    }
    
    @When("user clicks {string} button")
    public void userClicksConfirmButton(String buttonText) {
        String xpath = String.format("//button[contains(text(),'%s')]", buttonText);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement button = driver.findElement(By.xpath(xpath));
        actions.click(button);
        waits.waitForSeconds(1);
    }
    
    @When("user attempts to click {string} button without entering comments")
    public void userAttemptsToClickButtonWithoutEnteringComments(String buttonName) {
        String xpath = String.format("//button[contains(text(),'%s')]", buttonName);
        WebElement button = driver.findElement(By.xpath(xpath));
        boolean isEnabled = actions.isEnabled(button);
        if (!isEnabled) {
            waits.waitForSeconds(1);
        }
    }
    
    @When("user navigates to pending requests section from approver dashboard")
    public void userNavigatesToPendingRequestsSectionFromApproverDashboard() {
        WebElement pendingRequestsLink = driver.findElement(By.xpath(PENDING_REQUESTS_MENU));
        actions.click(pendingRequestsLink);
        waits.waitForPageLoad();
    }
    
    @When("user enters valid password in {string} field")
    public void userEntersValidPasswordInField(String fieldName) {
        WebElement passwordField = driver.findElement(By.xpath(INPUT_PASSWORD));
        actions.clearAndSendKeys(passwordField, TestData.getPassword("Approver"));
    }
    
    @Then("{string} page should load within {int} seconds")
    public void pageShouldLoadWithinSeconds(String pageName, int seconds) {
        long startTime = System.currentTimeMillis();
        waits.waitForPageLoad();
        long endTime = System.currentTimeMillis();
        long loadTime = (endTime - startTime) / 1000;
        if (loadTime > seconds) {
            throw new AssertionError("Page load time exceeded " + seconds + " seconds. Actual: " + loadTime);
        }
    }
    
    @Then("overview of pending requests count should be visible")
    public void overviewOfPendingRequestsCountShouldBeVisible() {
        waits.waitForElementVisible(By.xpath(OVERVIEW_PENDING_COUNT));
        WebElement countElement = driver.findElement(By.xpath(OVERVIEW_PENDING_COUNT));
        assertions.assertDisplayed(countElement);
    }
    
    @Then("list of all pending schedule change requests should be displayed")
    public void listOfAllPendingScheduleChangeRequestsShouldBeDisplayed() {
        waits.waitForElementVisible(By.xpath(PENDING_REQUESTS_TABLE));
        WebElement table = driver.findElement(By.xpath(PENDING_REQUESTS_TABLE));
        assertions.assertDisplayed(table);
    }
    
    @Then("table should display columns {string}")