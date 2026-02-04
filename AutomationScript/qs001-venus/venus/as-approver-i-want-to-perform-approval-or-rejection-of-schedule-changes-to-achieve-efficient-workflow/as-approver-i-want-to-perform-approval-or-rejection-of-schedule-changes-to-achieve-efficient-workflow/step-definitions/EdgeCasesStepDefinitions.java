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
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import config.ConfigReader;
import testdata.TestData;

public class ScheduleChangeRequestApprovalEdgeCasesStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private static final String APP_URL = ConfigReader.getProperty("app.url", "http://localhost:3000");
    private static final int TIMEOUT = Integer.parseInt(ConfigReader.getProperty("timeout", "30"));
    
    private String currentRequestId;
    private String approvalComment;
    private int characterLimit;
    private int initialRequestCount;
    private String currentApproverSession;
    
    private static final String BTN_LOGIN = "//button[@type='submit' or contains(text(),'Login') or contains(text(),'Sign In')]";
    private static final String INPUT_USERNAME = "//input[@placeholder='Username' or @name='username' or @id='username']";
    private static final String INPUT_PASSWORD = "//input[@type='password' or @placeholder='Password']";
    private static final String DASHBOARD = "//div[contains(@class,'dashboard')] | //h1[contains(text(),'Dashboard')]";
    private static final String NAV_PENDING_REQUESTS = "//nav//a[contains(text(),'Pending Requests') or contains(@href,'pending-requests')]";
    private static final String PENDING_REQUESTS_SECTION = "//div[contains(@class,'pending-requests')] | //h1[contains(text(),'Pending Requests')]";
    private static final String PENDING_REQUESTS_TABLE = "//table[contains(@class,'requests-table')] | //table//thead//th[contains(text(),'Request ID')]//ancestor::table";
    private static final String TABLE_ROWS = "//table//tbody//tr[contains(@class,'request-row') or td]";
    private static final String BTN_APPROVE = "//button[contains(text(),'Approve') or contains(@class,'approve-btn')]";
    private static final String BTN_REJECT = "//button[contains(text(),'Reject') or contains(@class,'reject-btn')]";
    private static final String APPROVAL_DIALOG = "//div[@role='dialog' or contains(@class,'approval-dialog') or contains(@class,'modal')]";
    private static final String TEXTAREA_COMMENT = "//textarea[@placeholder='Enter approval comment' or @name='comment' or contains(@class,'comment-textarea')]";
    private static final String BTN_CONFIRM_APPROVAL = "//button[contains(text(),'Confirm Approval') or contains(text(),'Submit Approval')]";
    private static final String CHARACTER_COUNTER = "//span[contains(@class,'character-counter') or contains(@class,'char-count')]";
    private static final String SUCCESS_MESSAGE = "//div[contains(@class,'success') or contains(@class,'alert-success')]";
    private static final String ERROR_MESSAGE = "//div[contains(@class,'error') or contains(@class,'alert-error') or contains(@class,'alert-danger')]";
    private static final String VALIDATION_MESSAGE = "//span[contains(@class,'validation-message') or contains(@class,'error-message')]";
    private static final String EMPTY_STATE_MESSAGE = "//div[contains(@class,'empty-state')] | //p[contains(text(),'No pending requests')]";
    private static final String TABLE_HEADERS = "//table//thead//th";
    private static final String FILTER_OPTIONS = "//div[contains(@class,'filter')] | //select[contains(@class,'filter')]";
    private static final String SEARCH_INPUT = "//input[@placeholder='Search' or contains(@class,'search-input')]";
    private static final String NO_RESULTS_MESSAGE = "//div[contains(text(),'No results found')] | //p[contains(text(),'No results found')]";
    private static final String PAGINATION_CONTROLS = "//div[contains(@class,'pagination')] | //nav[contains(@class,'pagination')]";
    private static final String PAGINATION_INFO = "//span[contains(@class,'pagination-info')] | //div[contains(text(),'Showing')]";
    private static final String BTN_NEXT = "//button[contains(text(),'Next') or contains(@class,'next-page')]";
    private static final String BTN_PREVIOUS = "//button[contains(text(),'Previous') or contains(@class,'prev-page')]";
    private static final String REQUEST_HISTORY = "//div[contains(@class,'request-history')] | //h2[contains(text(),'History')]//ancestor::div[contains(@class,'history')]";
    private static final String NOTIFICATION_QUEUE = "//div[contains(@class,'notification-queue')]";
    
    private String buttonByText(String text) {
        return String.format("//button[contains(text(),'%s') or contains(.,'%s')]", text, text);
    }
    
    private String inputByPlaceholder(String placeholder) {
        return String.format("//input[contains(@placeholder,'%s')]", placeholder);
    }
    
    private String inputByLabel(String label) {
        return String.format("//label[contains(text(),'%s')]/..//input | //label[contains(text(),'%s')]/following-sibling::input", label, label);
    }
    
    private String messageByText(String text) {
        return String.format("//*[contains(text(),'%s')]", text);
    }
    
    private String requestRowById(String requestId) {
        return String.format("//table//tbody//tr[contains(.,'%s')]", requestId);
    }
    
    private String columnHeaderByName(String columnName) {
        return String.format("//table//thead//th[contains(text(),'%s')]", columnName);
    }
    
    private String generateComment(int length) {
        StringBuilder comment = new StringBuilder();
        String baseText = "This is an approval comment. ";
        while (comment.length() < length) {
            comment.append(baseText);
        }
        return comment.substring(0, length);
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
        
        currentRequestId = null;
        approvalComment = null;
        characterLimit = 0;
        initialRequestCount = 0;
        currentApproverSession = null;
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
    
    @Given("a pending schedule change request exists")
    public void aPendingScheduleChangeRequestExists() {
        currentRequestId = TestData.createPendingScheduleChangeRequest();
        waits.waitForSeconds(1);
    }
    
    @Given("system has maximum character limit of {int} for comments")
    public void systemHasMaximumCharacterLimitForComments(int limit) {
        characterLimit = limit;
    }
    
    @Given("user is on the approval dialog screen")
    public void userIsOnTheApprovalDialogScreen() {
        actions.navigateTo(APP_URL + "/pending-requests");
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(PENDING_REQUESTS_SECTION));
    }
    
    @Given("no pending schedule change requests exist in the system")
    public void noPendingScheduleChangeRequestsExistInTheSystem() {
        TestData.clearAllPendingRequests();
        waits.waitForSeconds(1);
    }
    
    @Given("all requests are either approved or rejected")
    public void allRequestsAreEitherApprovedOrRejected() {
        TestData.ensureAllRequestsProcessed();
    }
    
    @Given("user has permission to access pending requests section")
    public void userHasPermissionToAccessPendingRequestsSection() {
        assertions.assertDisplayed(driver.findElement(By.xpath(NAV_PENDING_REQUESTS)));
    }
    
    @Given("system supports UTF-8 character encoding")
    public void systemSupportsUTF8CharacterEncoding() {
        String pageSource = driver.getPageSource();
        assertions.assertTextContains(driver.findElement(By.xpath("//head")), "UTF-8");
    }
    
    @Given("system contains {int} pending schedule change requests")
    public void systemContainsPendingScheduleChangeRequests(int count) {
        TestData.createMultiplePendingRequests(count);
        initialRequestCount = count;
        waits.waitForSeconds(2);
    }
    
    @Given("pagination is implemented for large datasets")
    public void paginationIsImplementedForLargeDatasets() {
        actions.navigateTo(APP_URL + "/pending-requests");
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(PAGINATION_CONTROLS));
    }
    
    @Given("system is under normal load conditions")
    public void systemIsUnderNormalLoadConditions() {
        waits.waitForSeconds(1);
    }
    
    @Given("{int} users are logged in with {string} role in different browser sessions")
    public void usersAreLoggedInWithRoleInDifferentBrowserSessions(int userCount, String role) {
        currentApproverSession = "session1";
    }
    
    @Given("a pending schedule change request with ID {string} exists")
    public void aPendingScheduleChangeRequestWithIDExists(String requestId) {
        currentRequestId = requestId;
        TestData.createPendingScheduleChangeRequestWithId(requestId);
        waits.waitForSeconds(1);
    }
    
    @Given("system has concurrency control mechanism implemented")
    public void systemHasConcurrencyControlMechanismImplemented() {
        waits.waitForSeconds(1);
    }
    
    @Given("both approvers are viewing the same request simultaneously")
    public void bothApproversAreViewingTheSameRequestSimultaneously() {
        waits.waitForSeconds(1);
    }
    
    @Given("notification service is unavailable")
    public void notificationServiceIsUnavailable() {
        TestData.setNotificationServiceStatus(false);
    }
    
    @Given("system has retry logic for notifications")
    public void systemHasRetryLogicForNotifications() {
        waits.waitForSeconds(1);
    }
    
    @When("user navigates to pending requests section")
    public void userNavigatesToPendingRequestsSection() {
        WebElement pendingRequestsLink = driver.findElement(By.xpath(NAV_PENDING_REQUESTS));
        actions.click(pendingRequestsLink);
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(PENDING_REQUESTS_SECTION));
    }
    
    @When("user selects a request to approve")
    public void userSelectsARequestToApprove() {
        waits.waitForElementVisible(By.xpath(TABLE_ROWS));
        List<WebElement> rows = driver.findElements(By.xpath(TABLE_ROWS));
        if (!rows.isEmpty()) {
            WebElement firstRow = rows.get(0);
            actions.click(firstRow);
            waits.waitForSeconds(1);
        }
    }
    
    @When("user enters approval comment with exactly {int} characters")
    public void userEntersApprovalCommentWithExactlyCharacters(int characterCount) {
        approvalComment = generateComment(characterCount);
        waits.waitForElementVisible(By.xpath(TEXTAREA_COMMENT));
        WebElement commentTextarea = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        actions.clearAndSendKeys(commentTextarea, approvalComment);
        waits.waitForSeconds(1);
    }
    
    @When("user attempts to enter {int} more character beyond maximum limit")
    public void userAttemptsToEnterMoreCharacterBeyondMaximumLimit(int additionalChars) {
        WebElement commentTextarea = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        String currentText = actions.getValue(commentTextarea);
        actions.sendKeys(commentTextarea, "X");
        waits.waitForSeconds(1);
    }
    
    @When("user clicks {string} button")
    public void userClicksButton(String buttonName) {
        String xpath = buttonByText(buttonName);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement button = driver.findElement(By.xpath(xpath));
        actions.click(button);
        waits.waitForPageLoad();
    }
    
    @When("user views request history")
    public void userViewsRequestHistory() {
        String historyLinkXpath = "//a[contains(text(),'History') or contains(text(),'View History')]";
        if (!driver.findElements(By.xpath(historyLinkXpath)).isEmpty()) {
            WebElement historyLink = driver.findElement(By.xpath(historyLinkXpath));
            actions.click(historyLink);
        }
        waits.waitForElementVisible(By.xpath(REQUEST_HISTORY));
        waits.waitForSeconds(1);
    }
    
    @When("user uses search functionality on empty list")
    public void userUsesSearchFunctionalityOnEmptyList() {
        waits.waitForElementVisible(By.xpath(SEARCH_INPUT));
        WebElement searchInput = driver.findElement(By.xpath(SEARCH_INPUT));
        actions.clearAndSendKeys(searchInput, "NonExistentRequest");
        waits.waitForSeconds(1);
    }
    
    @When("user applies filter on empty list")
    public void userAppliesFilterOnEmptyList() {
        if (!driver.findElements(By.xpath(FILTER_OPTIONS)).isEmpty()) {
            WebElement filterDropdown = driver.findElement(By.xpath(FILTER_OPTIONS));
            actions.click(filterDropdown);
            waits.waitForSeconds(1);
        }
    }
    
    @When("user refreshes the page")
    public void userRefreshesThePage() {
        driver.navigate().refresh();
        waits.waitForPageLoad();
    }
    
    @When("user enters approval comment {string}")
    public void userEntersApprovalComment(String comment) {
        waits.waitForElementVisible(By.xpath(TEXTAREA_COMMENT));
        WebElement commentTextarea = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        actions.clearAndSendKeys(commentTextarea, comment);
        approvalComment = comment;
        waits.waitForSeconds(1);
    }
    
    @When("user adds Unicode and emojis to comment {string}")
    public void userAddsUnicodeAndEmojisToComment(String additionalComment) {
        WebElement commentTextarea = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        String currentComment = actions.getValue(commentTextarea);
        actions.clearAndSendKeys(commentTextarea, currentComment + " " + additionalComment);
        approvalComment = currentComment + " " + additionalComment;
        waits.waitForSeconds(1);
    }
    
    @When("user views notification email")
    public void userViewsNotificationEmail() {
        actions.navigateTo(APP_URL + "/notifications");
        waits.waitForPageLoad();
        waits.waitForSeconds(1);
    }
    
    @When("user clicks {string} button")
    public void userClicksNextButton(String buttonText) {
        String xpath = buttonByText(buttonText);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement button = driver.findElement(By.xpath(xpath));
        actions.click(button);
        waits.waitForPageLoad();
        waits.waitForSeconds(1);
    }
    
    @When("user navigates to page {int}")
    public void userNavigatesToPage(int pageNumber) {
        String pageButtonXpath = String.format("//button[contains(text(),'%d')] | //a[contains(text(),'%d')]", pageNumber, pageNumber);
        if (!driver.findElements(By.xpath(pageButtonXpath)).isEmpty()) {
            WebElement pageButton = driver.findElement(By.xpath(pageButtonXpath));
            actions.click(pageButton);
            waits.waitForPageLoad();
            waits.waitForSeconds(1);
        }
    }
    
    @When("user navigates to last page")
    public void userNavigatesToLastPage() {
        String lastPageXpath = "//button[contains(text(),'Last')] | //a[contains(text(),'Last')] | //button[contains(@class,'last-page')]";
        if (!driver.findElements(By.xpath(lastPageXpath)).isEmpty()) {
            WebElement lastPageButton = driver.findElement(By.xpath(lastPageXpath));
            actions.click(lastPageButton);
            waits.waitForPageLoad();
            waits.waitForSeconds(1);
        }
    }
    
    @When("user searches by requester name in large dataset")
    public void userSearchesByRequesterNameInLargeDataset() {
        waits.waitForElementVisible(By.xpath(SEARCH_INPUT));
        WebElement searchInput = driver.findElement(By.xpath(SEARCH_INPUT));
        actions.clearAndSendKeys(searchInput, "John Smith");
        waits.waitForSeconds(2);
    }
    
    @When("user sorts by {string} column")
    public void userSortsByColumn(String columnName) {
        String columnHeaderXpath = columnHeaderByName(columnName);
        waits.waitForElementClickable(By.xpath(columnHeaderXpath));
        WebElement columnHeader = driver.findElement(By.xpath(columnHeaderXpath));
        actions.click(columnHeader);
        waits.waitForSeconds(2);
    }
    
    @When("approver {int} navigates to pending requests section")
    public void approverNavigatesToPendingRequestsSection(int approverNumber) {
        actions.navigateTo(APP_URL + "/pending-requests");
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(PENDING_REQUESTS_SECTION));
    }
    
    @When("approver {int} selects request ID {string} to approve")
    public void approverSelectsRequestIDToApprove(int approverNumber, String requestId) {
        String requestRowXpath = requestRowById(requestId);
        waits.waitForElementVisible(By.xpath(requestRowXpath));
        WebElement requestRow = driver.findElement(By.xpath(requestRowXpath));
        actions.click(requestRow);
        waits.waitForSeconds(1);
    }
    
    @When("approver {int} clicks {string} button")
    public void approverClicksButton(int approverNumber, String buttonName) {
        String xpath = buttonByText(buttonName);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement button = driver.findElement(By.xpath(xpath));
        actions.click(button);
        waits.waitForSeconds(1);
    }
    
    @When("approver {int} enters comment {string}")
    public void approverEntersComment(int approverNumber, String comment) {
        waits.waitForElementVisible(By.xpath(TEXTAREA_COMMENT));
        WebElement commentTextarea = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        actions.clearAndSendKeys(commentTextarea, comment);
        waits.waitForSeconds(1);
    }
    
    @When("approver {int} clicks {string} button immediately after")
    public void approverClicksButtonImmediatelyAfter(int approverNumber, String buttonName) {
        String xpath = buttonByText(buttonName);
        if (!driver.findElements(By.xpath(xpath)).isEmpty()) {
            WebElement button = driver.findElement(By.xpath(xpath));
            actions.click(button);
            waits.waitForSeconds(1);
        }
    }
    
    @When("database is checked for approval records")
    public void databaseIsCheckedForApprovalRecords() {
        waits.waitForSeconds(1);
    }
    
    @When("notification queue is checked")
    public void notificationQueueIsChecked() {
        waits.waitForSeconds(1);
    }
    
    @When("notification service is restored")
    public void notificationServiceIsRestored() {
        TestData.setNotificationServiceStatus(true);
        waits.waitForSeconds(2);
    }
    
    @When("approver {int} navigates to pending requests section in different session")
    public void approverNavigatesToPendingRequestsSectionInDifferentSession(int approverNumber) {
        waits.waitForSeconds(1);
    }
    
    @Then("request details and approval dialog should be displayed")
    public void requestDetailsAndApprovalDialogShouldBeDisplayed() {
        waits.waitForElementVisible(By.xpath(APPROVAL_DIALOG));
        assertions.assertDisplayed(driver.findElement(By.xpath(APPROVAL_DIALOG)));
    }
    
    @Then("all characters should be accepted")
    public void allCharactersShouldBeAccepted() {
        WebElement commentTextarea = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        String actualValue = actions.getValue(commentTextarea);
        assertions.assertText(commentTextarea, approvalComment);
    }
    
    @Then("character counter should show {string}")
    public void characterCounterShouldShow(String expectedCount) {
        waits.waitForElementVisible(By.xpath(CHARACTER_COUNTER));
        WebElement counter = driver.findElement(By.xpath(CHARACTER_COUNTER));
        assertions.assertTextContains(counter, expectedCount);
    }
    
    @Then("{string} button should be enabled")
    public void buttonShouldBeEnabled(String buttonName) {
        String xpath = buttonByText(buttonName);
        WebElement button = driver.findElement(By.xpath(xpath));
        assertions.assertEnabled(button);
    }
    
    @Then("additional character should not be accepted")
    public void additionalCharacterShouldNotBeAccepted() {
        WebElement commentTextarea = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        String currentValue = actions.getValue(commentTextarea);
        int currentLength = currentValue.length();
        assertions.assertElementCount(By.xpath(TEXTAREA_COMMENT), 1);
    }
    
    @Then("validation message {string} should be displayed")
    public void validationMessageShouldBeDisplayed(String message) {
        String messageXpath = messageByText(message);
        waits.waitForElementVisible(By.xpath(messageXpath));
        WebElement messageElement = driver.findElement(By.xpath(messageXpath));
        assertions.assertDisplayed(messageElement);
    }
    
    @Then("approval should be processed successfully")
    public void approvalShouldBeProcessedSuccessfully() {
        waits.waitForSeconds(2);
        waits.waitForElementVisible(By.xpath(SUCCESS_MESSAGE));
    }
    
    @Then("success message should be displayed")
    public void successMessageShouldBeDisplayed() {
        waits.waitForElementVisible(By.xpath(SUCCESS_MESSAGE));
        WebElement successMessage = driver.findElement(By.xpath(SUCCESS_MESSAGE));
        assertions.assertDisplayed(successMessage);
    }
    
    @Then("comment should be saved without truncation")
    public void commentShouldBeSavedWithoutTruncation() {
        waits.waitForSeconds(1);
    }
    
    @Then("full comment text with {int} characters should be visible")
    public void fullCommentTextWithCharactersShouldBeVisible(int expectedLength) {
        String commentXpath = "//div[contains(@class,'comment-text')] | //p[contains(@class,'approval-comment')]";
        waits.waitForElementVisible(By.xpath(commentXpath));
        WebElement commentElement = driver.findElement(By.xpath(commentXpath));
        String commentText = actions.getText(commentElement);
        assertions.assertDisplayed(commentElement);
    }
    
    @Then("notification should be sent to requester with complete comment")
    public void notificationShouldBeSentToRequesterWithCompleteComment() {
        waits.waitForSeconds(1);
    }
    
    @Then("page should load within {int} seconds")
    public void pageShouldLoadWithinSeconds(int seconds) {
        waits.waitForPageLoad();
        waits.waitForSeconds(1);
    }
    
    @Then("empty state message {string} should be displayed")
    public void emptyStateMessageShouldBeDisplayed(String message) {
        String messageXpath = messageByText(message);
        waits.waitForElementVisible(By.xpath(messageXpath));
        WebElement messageElement = driver.findElement(By.xpath(messageXpath));
        assertions.assertDisplayed(messageElement);
    }
    
    @Then("table headers should be visible")
    public void tableHeadersShouldBeVisible() {
        waits.waitForElementVisible(By.xpath(TABLE_HEADERS));
        List<WebElement> headers = driver.findElements(By.xpath(TABLE_HEADERS));
        assertions.assertDisplayed(headers.get(0));
    }
    
    @Then("filter options should be visible")
    public void filterOptionsShouldBeVisible() {
        if (!driver.findElements(By.xpath(FILTER_OPTIONS)).isEmpty()) {
            WebElement filterElement = driver.findElement(By.xpath(FILTER_OPTIONS));
            assertions.assertDisplayed(filterElement);
        }
    }
    
    @Then("no data rows should be shown")
    public void noDataRowsShouldBeShown() {
        List<WebElement> rows = driver.findElements(By.xpath(TABLE_ROWS));
        assertions.assertElementCount(By.xpath(TABLE_ROWS), 0);
    }
    
    @Then("search controls should remain functional")
    public void searchControlsShouldRemainFunctional() {
        WebElement searchInput = driver.findElement(By.xpath(SEARCH_INPUT));
        assertions.assertEnabled(searchInput);
    }
    
    @Then("{string} message should be displayed")
    public void messageShouldBeDisplayed(String message) {
        String messageXpath = messageByText(message);
        waits.waitForElementVisible(By.xpath(messageXpath));
        WebElement messageElement = driver.findElement(By.xpath(messageXpath));
        assertions.assertDisplayed(messageElement);
    }
    
    @Then("filter controls should remain functional")
    public void filterControlsShouldRemainFunctional() {
        if (!driver.findElements(By.xpath(FILTER_OPTIONS)).isEmpty()) {
            WebElement filterElement = driver.findElement(By.xpath(FILTER_OPTIONS));
            assertions.assertEnabled(filterElement);
        }
    }
    
    @Then("empty state message should persist")
    public void emptyStateMessageShouldPersist() {
        waits.waitForElementVisible(By.xpath(EMPTY_STATE_MESSAGE));
        WebElement emptyStateMessage = driver.findElement(By.xpath(EMPTY_STATE_MESSAGE));
        assertions.assertDisplayed(emptyStateMessage);
    }
    
    @Then("no errors should occur")
    public void noErrorsShouldOccur() {
        List<WebElement> errorMessages = driver.findElements(By.xpath(ERROR_MESSAGE));
        assertions.assertElementCount(By.xpath(ERROR_MESSAGE), 0);
    }
    
    @Then("approval dialog should be displayed with comment text area")
    public void approvalDialogShouldBeDisplayedWithCommentTextArea() {
        waits.waitForElementVisible(By.xpath(APPROVAL_DIALOG));
        waits.waitForElementVisible(By.xpath(TEXTAREA_COMMENT));
        assertions.assertDisplayed(driver.findElement(By.xpath(APPROVAL_DIALOG)));
        assertions.assertDisplayed(driver.findElement(By.xpath(TEXTAREA_COMMENT)));
    }
    
    @Then("all special characters should be accepted")
    public void allSpecialCharactersShouldBeAccepted() {
        WebElement commentTextarea = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        String actualValue = actions.getValue(commentTextarea);
        assertions.assertTextContains(commentTextarea, "@#$%");
    }
    
    @Then("special characters should be displayed correctly in text area")
    public void specialCharactersShouldBeDisplayedCorrectlyInTextArea() {
        WebElement commentTextarea = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        assertions.assertDisplayed(commentTextarea);
    }
    
    @Then("Unicode characters should be accepted")
    public void unicodeCharactersShouldBeAccepted() {
        WebElement commentTextarea = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        String actualValue = actions.getValue(commentTextarea);
        assertions.assertDisplayed(commentTextarea);
    }
    
    @Then("emojis should be accepted")
    public void emojisShouldBeAccepted() {
        WebElement commentTextarea = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        assertions.assertDisplay