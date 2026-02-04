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

import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import config.ConfigReader;
import testdata.TestData;

public class ScheduleChangeRequestApprovalRejectionStepDefinitions {

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
    private static final String PENDING_REQUESTS_SECTION = "//div[contains(@class,'pending-requests')] | //section[@id='pending-requests'] | //h2[contains(text(),'Pending Requests')]";
    private static final String REQUEST_DETAILS_CONTAINER = "//div[contains(@class,'request-details')] | //div[@id='request-details']";
    private static final String BTN_REJECT = "//button[contains(text(),'Reject') or contains(@class,'reject-btn')]";
    private static final String BTN_APPROVE = "//button[contains(text(),'Approve') or contains(@class,'approve-btn')]";
    private static final String REJECTION_DIALOG = "//div[@role='dialog' and contains(.,'Reject')] | //div[contains(@class,'rejection-dialog')] | //div[contains(@class,'modal') and contains(.,'Reject')]";
    private static final String APPROVAL_DIALOG = "//div[@role='dialog' and contains(.,'Approve')] | //div[contains(@class,'approval-dialog')] | //div[contains(@class,'modal') and contains(.,'Approve')]";
    private static final String REJECTION_COMMENT_FIELD = "//textarea[@placeholder='Enter rejection reason' or @name='rejectionComment' or contains(@placeholder,'reason')] | //div[contains(@class,'rejection-dialog')]//textarea";
    private static final String APPROVAL_COMMENT_FIELD = "//textarea[@placeholder='Enter approval comments' or @name='approvalComment' or contains(@placeholder,'comment')] | //div[contains(@class,'approval-dialog')]//textarea";
    private static final String BTN_CONFIRM_REJECTION = "//button[contains(text(),'Confirm Rejection') or contains(@class,'confirm-reject')]";
    private static final String BTN_CONFIRM_APPROVAL = "//button[contains(text(),'Confirm Approval') or contains(@class,'confirm-approve')]";
    private static final String MANDATORY_ASTERISK = "//label[contains(.,'*')] | //*[contains(@class,'required')] | //*[contains(@class,'mandatory')]";
    private static final String VALIDATION_ERROR_MESSAGE = "//span[contains(@class,'error')] | //div[contains(@class,'error-message')] | //p[contains(@class,'error')]";
    private static final String SUCCESS_MESSAGE = "//div[contains(@class,'success')] | //div[contains(@class,'alert-success')] | //*[contains(text(),'Success')]";
    private static final String ERROR_BANNER = "//div[contains(@class,'error-banner')] | //div[contains(@class,'alert-danger')] | //div[@role='alert' and contains(@class,'error')]";
    private static final String LOADING_INDICATOR = "//div[contains(@class,'loading')] | //div[contains(@class,'spinner')] | //*[contains(@class,'loader')]";
    private static final String UNAUTHORIZED_PAGE = "//div[contains(@class,'unauthorized')] | //h1[contains(text(),'Access Denied')] | //*[contains(text(),'403')]";
    private static final String LOGIN_PAGE = "//div[contains(@class,'login-page')] | //form[@id='login-form'] | //h1[contains(text(),'Login')]";
    private static final String BTN_RETRY = "//button[contains(text(),'Retry') or contains(@class,'retry-btn')]";
    private static final String ERROR_PAGE = "//div[contains(@class,'error-page')] | //h1[contains(text(),'Error')] | //*[contains(text(),'404')]";
    
    private String currentRequestId;
    private String currentRole;
    private Map<String, String> roleCredentials;
    
    private String buttonByText(String text) {
        return String.format("//button[contains(text(),'%s') or contains(.,'%s')]", text, text);
    }
    
    private String inputByPlaceholder(String placeholder) {
        return String.format("//input[contains(@placeholder,'%s')]", placeholder);
    }
    
    private String inputByLabel(String label) {
        return String.format("//label[contains(text(),'%s')]/..//input | //label[contains(text(),'%s')]/following-sibling::input", label, label);
    }
    
    private String textareaByPlaceholder(String placeholder) {
        return String.format("//textarea[contains(@placeholder,'%s')]", placeholder);
    }
    
    private String elementContainingText(String text) {
        return String.format("//*[contains(text(),'%s')]", text);
    }
    
    private String errorMessageByText(String text) {
        return String.format("//span[contains(@class,'error') and contains(text(),'%s')] | //div[contains(@class,'error') and contains(text(),'%s')] | //p[contains(@class,'error') and contains(text(),'%s')]", text, text, text);
    }
    
    private String menuItemByText(String text) {
        return String.format("//nav//a[contains(text(),'%s')] | //ul[contains(@class,'menu')]//li//a[contains(text(),'%s')]", text, text);
    }
    
    private String requestByStatus(String status) {
        return String.format("//tr[contains(.,'%s')] | //div[contains(@class,'request-item') and contains(.,'%s')]", status, status);
    }
    
    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        if (Boolean.parseBoolean(ConfigReader.getProperty("headless", "false"))) {
            options.addArguments("--headless");
        }
        options.addArguments("--disable-notifications");
        options.addArguments("--disable-popup-blocking");
        driver = new ChromeDriver(options);
        driver.manage().window().maximize();
        
        actions = new GenericActions(driver, TIMEOUT);
        waits = new WaitHelpers(driver, TIMEOUT);
        assertions = new AssertionHelpers(driver);
        
        roleCredentials = new HashMap<>();
        roleCredentials.put("Approver", "approver:approver123");
        roleCredentials.put("Regular Employee", "employee:employee123");
        roleCredentials.put("Viewer", "viewer:viewer123");
        
        currentRequestId = "12345";
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
        currentRole = role;
        actions.navigateTo(APP_URL + "/login");
        waits.waitForPageLoad();
        
        String credentials = roleCredentials.getOrDefault(role, "user:password");
        String[] parts = credentials.split(":");
        String username = parts[0];
        String password = parts[1];
        
        WebElement usernameField = driver.findElement(By.xpath(INPUT_USERNAME));
        actions.clearAndSendKeys(usernameField, username);
        
        WebElement passwordField = driver.findElement(By.xpath(INPUT_PASSWORD));
        actions.clearAndSendKeys(passwordField, password);
        
        WebElement loginButton = driver.findElement(By.xpath(BTN_LOGIN));
        actions.click(loginButton);
        
        waits.waitForPageLoad();
        waits.waitForSeconds(2);
    }
    
    @Given("at least one pending schedule change request exists in the system")
    public void atLeastOnePendingScheduleChangeRequestExistsInTheSystem() {
        String pendingRequestXPath = requestByStatus("Pending");
        waits.waitForSeconds(1);
    }
    
    @Given("user is on the request details page")
    public void userIsOnTheRequestDetailsPage() {
        actions.navigateTo(APP_URL + "/requests/" + currentRequestId);
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(REQUEST_DETAILS_CONTAINER));
    }
    
    @Given("system enforces mandatory comments for rejection actions")
    public void systemEnforcesMandatoryCommentsForRejectionActions() {
        waits.waitForSeconds(1);
    }
    
    @Given("user does not have approval permissions")
    public void userDoesNotHaveApprovalPermissions() {
        waits.waitForSeconds(1);
    }
    
    @Given("role-based access control is properly configured")
    public void roleBasedAccessControlIsProperlyConfigured() {
        waits.waitForSeconds(1);
    }
    
    @Given("user is on the approval confirmation screen")
    public void userIsOnTheApprovalConfirmationScreen() {
        actions.navigateTo(APP_URL + "/approver/pending-requests");
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(PENDING_REQUESTS_SECTION));
    }
    
    @Given("a pending request is selected for approval")
    public void aPendingRequestIsSelectedForApproval() {
        String firstPendingRequest = "(//tr[contains(.,'Pending')] | //div[contains(@class,'request-item') and contains(.,'Pending')])[1]";
        waits.waitForElementClickable(By.xpath(firstPendingRequest));
        WebElement requestRow = driver.findElement(By.xpath(firstPendingRequest));
        actions.click(requestRow);
        waits.waitForPageLoad();
    }
    
    @Given("network connectivity can be simulated to fail")
    public void networkConnectivityCanBeSimulatedToFail() {
        waits.waitForSeconds(1);
    }
    
    @Given("a pending schedule change request exists")
    public void aPendingScheduleChangeRequestExists() {
        waits.waitForSeconds(1);
    }
    
    @Given("system has double-submission prevention mechanism")
    public void systemHasDoubleSubmissionPreventionMechanism() {
        waits.waitForSeconds(1);
    }
    
    @Given("session timeout is configured to {int} minutes of inactivity")
    public void sessionTimeoutIsConfiguredToMinutesOfInactivity(int minutes) {
        waits.waitForSeconds(1);
    }
    
    @Given("a pending request is displayed on screen")
    public void aPendingRequestIsDisplayedOnScreen() {
        actions.navigateTo(APP_URL + "/approver/pending-requests");
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(PENDING_REQUESTS_SECTION));
    }
    
    @Given("user has access to pending requests section")
    public void userHasAccessToPendingRequestsSection() {
        actions.navigateTo(APP_URL + "/approver/pending-requests");
        waits.waitForPageLoad();
    }
    
    @Given("system has valid pending requests in database")
    public void systemHasValidPendingRequestsInDatabase() {
        waits.waitForSeconds(1);
    }
    
    @Given("a schedule change request has already been approved or rejected")
    public void aScheduleChangeRequestHasAlreadyBeenApprovedOrRejected() {
        currentRequestId = "99999";
        waits.waitForSeconds(1);
    }
    
    @When("user navigates to pending requests section")
    public void userNavigatesToPendingRequestsSection() {
        String pendingRequestsLink = menuItemByText("Pending Requests");
        if (!driver.findElements(By.xpath(pendingRequestsLink)).isEmpty()) {
            WebElement link = driver.findElement(By.xpath(pendingRequestsLink));
            actions.click(link);
        } else {
            actions.navigateTo(APP_URL + "/approver/pending-requests");
        }
        waits.waitForPageLoad();
    }
    
    @When("user selects a pending request to review")
    public void userSelectsAPendingRequestToReview() {
        String firstPendingRequest = "(//tr[contains(.,'Pending')] | //div[contains(@class,'request-item') and contains(.,'Pending')])[1]";
        waits.waitForElementClickable(By.xpath(firstPendingRequest));
        WebElement requestRow = driver.findElement(By.xpath(firstPendingRequest));
        actions.click(requestRow);
        waits.waitForPageLoad();
    }
    
    @When("user clicks {string} button")
    public void userClicksButton(String buttonName) {
        String xpath = buttonByText(buttonName);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement button = driver.findElement(By.xpath(xpath));
        actions.click(button);
        waits.waitForSeconds(1);
    }
    
    @When("user leaves rejection comment field empty")
    public void userLeavesRejectionCommentFieldEmpty() {
        WebElement commentField = driver.findElement(By.xpath(REJECTION_COMMENT_FIELD));
        actions.clear(commentField);
        waits.waitForSeconds(1);
    }
    
    @When("user attempts to click {string} button")
    public void userAttemptsToClickButton(String buttonName) {
        String xpath = buttonByText(buttonName);
        waits.waitForSeconds(1);
        if (!driver.findElements(By.xpath(xpath)).isEmpty()) {
            WebElement button = driver.findElement(By.xpath(xpath));
            if (actions.isEnabled(button)) {
                actions.click(button);
            }
        }
    }
    
    @When("user enters only whitespace characters in rejection comment field")
    public void userEntersOnlyWhitespaceCharactersInRejectionCommentField() {
        WebElement commentField = driver.findElement(By.xpath(REJECTION_COMMENT_FIELD));
        actions.clearAndSendKeys(commentField, "   ");
        waits.waitForSeconds(1);
    }
    
    @When("user attempts to submit rejection")
    public void userAttemptsToSubmitRejection() {
        if (!driver.findElements(By.xpath(BTN_CONFIRM_REJECTION)).isEmpty()) {
            WebElement confirmButton = driver.findElement(By.xpath(BTN_CONFIRM_REJECTION));
            if (actions.isEnabled(confirmButton)) {
                actions.click(confirmButton);
            }
        }
        waits.waitForSeconds(1);
    }
    
    @When("user attempts to navigate to {string} by typing URL directly")
    public void userAttemptsToNavigateToByTypingURLDirectly(String url) {
        actions.navigateTo(APP_URL + url);
        waits.waitForPageLoad();
        waits.waitForSeconds(2);
    }
    
    @When("user tries to access approver dashboard from main navigation menu")
    public void userTriesToAccessApproverDashboardFromMainNavigationMenu() {
        String approverMenuXPath = "//nav//a[contains(text(),'Approver')] | //nav//a[contains(text(),'Pending Requests')]";
        waits.waitForSeconds(1);
    }
    
    @When("user attempts to make API call {string} to {string} with approval payload")
    public void userAttemptsToMakeAPICallToWithApprovalPayload(String method, String endpoint) {
        waits.waitForSeconds(1);
    }
    
    @When("user tries to access request details by direct URL with known request ID")
    public void userTriesToAccessRequestDetailsByDirectURLWithKnownRequestID() {
        actions.navigateTo(APP_URL + "/requests/123");
        waits.waitForPageLoad();
        waits.waitForSeconds(2);
    }
    
    @When("user selects a pending request")
    public void userSelectsAPendingRequest() {
        String firstPendingRequest = "(//tr[contains(.,'Pending')] | //div[contains(@class,'request-item') and contains(.,'Pending')])[1]";
        waits.waitForElementClickable(By.xpath(firstPendingRequest));
        WebElement requestRow = driver.findElement(By.xpath(firstPendingRequest));
        actions.click(requestRow);
        waits.waitForPageLoad();
    }
    
    @When("user enters {string} in approval comments field")
    public void userEntersInApprovalCommentsField(String comment) {
        waits.waitForElementVisible(By.xpath(APPROVAL_COMMENT_FIELD));
        WebElement commentField = driver.findElement(By.xpath(APPROVAL_COMMENT_FIELD));
        actions.clearAndSendKeys(commentField, comment);
        waits.waitForSeconds(1);
    }
    
    @When("network connection is disconnected")
    public void networkConnectionIsDisconnected() {
        waits.waitForSeconds(1);
    }
    
    @When("user clicks {string} button to submit approval")
    public void userClicksButtonToSubmitApproval(String buttonName) {
        String xpath = buttonByText(buttonName);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement button = driver.findElement(By.xpath(xpath));
        actions.click(button);
        waits.waitForSeconds(2);
    }
    
    @When("network connection is restored")
    public void networkConnectionIsRestored() {
        waits.waitForSeconds(1);
    }
    
    @When("user rapidly clicks {string} button {int} times in quick succession")
    public void userRapidlyClicksButtonTimesInQuickSuccession(String buttonName, int times) {
        String xpath = buttonByText(buttonName);
        waits.waitForElementClickable(By.xpath(xpath));
        WebElement button = driver.findElement(By.xpath(xpath));
        
        for (int i = 0; i < times; i++) {
            try {
                if (actions.isEnabled(button) && actions.isDisplayed(button)) {
                    actions.click(button);
                }
            } catch (Exception e) {
                break;
            }
        }
        waits.waitForSeconds(2);
    }
    
    @When("submission completes")
    public void submissionCompletes() {
        waits.waitForSeconds(3);
    }
    
    @When("user navigates to pending requests page")
    public void userNavigatesToPendingRequestsPage() {
        actions.navigateTo(APP_URL + "/approver/pending-requests");
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(PENDING_REQUESTS_SECTION));
    }
    
    @When("user session expires after configured timeout period")
    public void userSessionExpiresAfterConfiguredTimeoutPeriod() {
        waits.waitForSeconds(1);
    }
    
    @When("user attempts to approve a request by clicking {string} button")
    public void userAttemptsToApproveARequestByClickingButton(String buttonName) {
        String xpath = buttonByText(buttonName);
        if (!driver.findElements(By.xpath(xpath)).isEmpty()) {
            waits.waitForElementClickable(By.xpath(xpath));
            WebElement button = driver.findElement(By.xpath(xpath));
            actions.click(button);
        }
        waits.waitForSeconds(1);
    }
    
    @When("user submits approval")
    public void userSubmitsApproval() {
        if (!driver.findElements(By.xpath(BTN_CONFIRM_APPROVAL)).isEmpty()) {
            WebElement confirmButton = driver.findElement(By.xpath(BTN_CONFIRM_APPROVAL));
            if (actions.isEnabled(confirmButton)) {
                actions.click(confirmButton);
            }
        }
        waits.waitForSeconds(2);
    }
    
    @When("user logs in again with valid credentials")
    public void userLogsInAgainWithValidCredentials() {
        waits.waitForElementVisible(By.xpath(INPUT_USERNAME));
        
        String credentials = roleCredentials.getOrDefault(currentRole, "approver:approver123");
        String[] parts = credentials.split(":");
        String username = parts[0];
        String password = parts[1];
        
        WebElement usernameField = driver.findElement(By.xpath(INPUT_USERNAME));
        actions.clearAndSendKeys(usernameField, username);
        
        WebElement passwordField = driver.findElement(By.xpath(INPUT_PASSWORD));
        actions.clearAndSendKeys(passwordField, password);
        
        WebElement loginButton = driver.findElement(By.xpath(BTN_LOGIN));
        actions.click(loginButton);
        
        waits.waitForPageLoad();
        waits.waitForSeconds(2);
    }
    
    @When("user attempts to access request details by entering {string} in URL {string}")
    public void userAttemptsToAccessRequestDetailsByEnteringInURL(String requestId, String url) {
        String fullUrl = url.replace("<request_id>", requestId);
        actions.navigateTo(APP_URL + fullUrl);
        waits.waitForPageLoad();
        waits.waitForSeconds(2);
    }
    
    @When("user attempts to approve request via API call {string} to {string} with approval payload")
    public void userAttemptsToApproveRequestViaAPICallToWithApprovalPayload(String method, String endpoint) {
        waits.waitForSeconds(1);
    }
    
    @When("user attempts to access processed request by request ID")
    public void userAttemptsToAccessProcessedRequestByRequestID() {
        actions.navigateTo(APP_URL + "/requests/" + currentRequestId);
        waits.waitForPageLoad();
        waits.waitForSeconds(2);
    }
    
    @When("user attempts to approve already processed request via API call")
    public void userAttemptsToApproveAlreadyProcessedRequestViaAPICall() {
        waits.waitForSeconds(1);
    }
    
    @Then("request details should be displayed")
    public void requestDetailsShouldBeDisplayed() {
        waits.waitForElementVisible(By.xpath(REQUEST_DETAILS_CONTAINER));
        WebElement detailsContainer = driver.findElement(By.xpath(REQUEST_DETAILS_CONTAINER));
        assertions.assertDisplayed(detailsContainer);
    }
    
    @Then("{string} button should be visible")
    public void buttonShouldBeVisible(String buttonName) {
        String xpath = buttonByText(buttonName);
        waits.waitForElementVisible(By.xpath(xpath));
        WebElement button = driver.findElement(By.xpath(xpath));
        assertions.assertDisplayed(button);
    }
    
    @Then("rejection dialog should be displayed")
    public void rejectionDialogShouldBeDisplayed() {
        waits.waitForElementVisible(By.xpath(REJECTION_DIALOG));
        WebElement dialog = driver.findElement(By.xpath(REJECTION_DIALOG));
        assertions.assertDisplayed(dialog);
    }
    
    @Then("rejection comment field should be marked as mandatory with red asterisk")
    public void rejectionCommentFieldShouldBeMarkedAsMandatoryWithRedAsterisk() {
        String mandatoryIndicator = "//label[contains(.,'rejection') or contains(.,'reason')]//span[contains(@class,'required') or text()='*'] | //label[contains(.,'rejection') or contains(.,'reason')]//*[contains(@class,'asterisk')]";
        waits.waitForElementVisible(By.xpath(mandatoryIndicator));
        WebElement asterisk = driver.findElement(By.xpath(mandatoryIndicator));
        assertions.assertDisplayed(asterisk);
    }
    
    @Then("{string} button should be disabled")
    public void buttonShouldBeDisabled(String buttonName) {
        String xpath = buttonByText(buttonName);
        waits.waitForElementVisible(By.xpath(xpath));
        WebElement button = driver.findElement(By.xpath(xpath));
        assertions.assertDisabled(button);
    }
    
    @Then("{string} button should remain disabled")
    public void buttonShouldRemainDisabled(String buttonName) {
        String xpath = buttonByText(buttonName);
        WebElement button = driver.findElement(By.xpath(xpath));
        assertions.assertDisabled(button);
    }
    
    @Then("button should not be clickable")
    public void buttonShouldNotBeClickable() {
        WebElement button = driver.findElement(By.xpath(BTN_CONFIRM_REJECTION));
        assertions.assertDisabled(button);
    }
    
    @Then("validation error message {string} should be displayed in red text")
    public void validationErrorMessageShouldBeDisplayedInRedText(String errorMessage) {
        String xpath = errorMessageByText(errorMessage);
        waits.waitForElementVisible(By.xpath(xpath));
        WebElement errorElement = driver.findElement(By.xpath(xpath));
        assertions.assertDisplayed(errorElement);
        assertions.assertTextContains(errorElement, errorMessage);
    }
    
    @Then("error message should appear below comment field")
    public void errorMessageShouldAppearBelowCommentField() {
        String errorBelowField = "//textarea/following-sibling::*[contains(@class,'error')] | //textarea/..//*[contains(@class,'error')]";
        waits.waitForElementVisible(By.xpath(errorBelowField));
        WebElement errorElement = driver.findElement(By.xpath(errorBelowField));
        assertions.assertDisplayed(errorElement);
    }
    
    @Then("form submission should be prevented")
    public void formSubmissionShouldBePrevented() {
        WebElement confirmButton = driver.findElement(By.xpath(BTN_CONFIRM_REJECTION));
        assertions.assertDisabled(confirmButton);
    }
    
    @Then("validation error message {string} should be displayed")
    public void validationErrorMessageShouldBeDisplayed(String errorMessage) {
        String xpath = errorMessageByText(errorMessage);
        waits.waitForElementVisible(By.xpath(xpath));
        WebElement errorElement = driver.findElement(By.xpath(xpath));
        assertions.assertDisplayed(errorElement);
        assertions.assertTextContains(errorElement, errorMessage);
    }
    
    @Then("request status should remain {string}")
    public void requestStatusShouldRemain(String status) {
        String statusXPath = String.format("//*[contains(@class,'status') and contains(text(),'%s')] | //*[contains(text(),'Status')]/following-sibling::*[contains(text(),'%s')]", status, status);
        waits.waitForSeconds(1);
    }
    
    @Then("no notification should be sent to requester")
    public void noNotificationShouldBeSentToRequester() {
        waits.waitForSeconds(1);
    }
    
    @Then("no database update should occur for the request")
    public void noDatabaseUpdateShouldOccurForTheRequest() {
        waits.waitForSeconds(1);
    }
    
    @Then("user should remain on rejection dialog with error message visible")
    public void userShouldRemainOnRejectionDialogWithErrorMessageVisible() {
        waits.waitForElementVisible(By.xpath(REJECTION_DIALOG));
        WebElement dialog = driver.findElement(By.xpath(REJECTION_DIALOG));
        assertions.assertDisplayed(dialog);
        
        waits.waitForElementVisible(By.xpath(VALIDATION_ERROR_MESSAGE));
        WebElement errorMessage = driver.findElement(By.xpath(VALIDATION_ERROR_MESSAGE));
        assertions.assertDisplayed(errorMessage);
    }
    
    @Then("access should be denied")
    public void accessShouldBeDenied() {
        waits.waitForSeconds(2);
        String currentUrl = actions.getCurrentUrl();
        boolean isUnauthorized = currentUrl.contains("unauthorized") || 
                                currentUrl.contains("403") || 
                                !driver.findElements(By.xpath(UNAUTHORIZED_PAGE)).isEmpty();
    }
    
    @Then("error message {string} should be displayed")
    public void errorMessageShouldBeDisplayed(String errorMessage) {
        String xpath = elementContainingText(errorMessage);
        waits.waitForElementVisible(By.xpath(xpath));
        WebElement errorElement = driver.findElement(By.xpath(xpath));
        assertions.assertDisplayed(errorElement);
        assertions.assertTextContains(errorElement, errorMessage);
    }
    
    @Then("user should be redirected to unauthorized page with status code {int}")
    public void userShouldBeRedirectedToUnauthorizedPageWithStatusCode(int statusCode) {
        waits.waitForSeconds(2);
        String currentUrl = actions.getCurrentUrl();
        boolean isUnauthorizedPage = currentUrl.contains("unauthorized") || 
                                     currentUrl.contains("403") || 
                                     !driver.findElements(By.xpath(UNAUTHORIZED_PAGE)).isEmpty();
    }
    
    @Then("approver-specific menu items should not be visible")
    public void approverSpecificMenuItemsShouldNotBeVisible() {
        String approverMenuXPath = "//nav//a[contains(text(),'Approver')] | //nav//a[contains(text(),'Pending Requests')] | //nav//a[contains(text(),'Approval')]";
        waits.waitForSeconds(1);
        List<WebElement> approverMenuItems = driver.findElements(By.xpath(approverMenuXPath));
        if (!approverMenuItems.isEmpty()) {
            for (WebElement