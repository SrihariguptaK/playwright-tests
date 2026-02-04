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
import org.openqa.selenium.Keys;
import org.openqa.selenium.JavascriptExecutor;

import java.util.List;

import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import config.ConfigReader;
import testdata.TestData;

public class ApprovalWorkflowAccessibilityStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private static final String APP_URL = ConfigReader.getProperty("app.url", "http://localhost:3000");
    private static final int TIMEOUT = Integer.parseInt(ConfigReader.getProperty("timeout", "30"));
    
    private static final String BTN_APPROVE = "//button[contains(text(),'Approve') or contains(@aria-label,'Approve')]";
    private static final String BTN_REJECT = "//button[contains(text(),'Reject') or contains(@aria-label,'Reject')]";
    private static final String BTN_CONFIRM_APPROVAL = "//button[contains(text(),'Confirm Approval')]";
    private static final String BTN_CANCEL = "//button[contains(text(),'Cancel')]";
    private static final String LINK_PENDING_REQUESTS = "//a[contains(text(),'Pending Requests')]";
    private static final String MODAL_APPROVAL = "//div[@role='dialog' and contains(.,'Approve Schedule Change Request')]";
    private static final String MODAL_REJECTION = "//div[@role='dialog' and contains(.,'Reject Schedule Change Request')]";
    private static final String TEXTAREA_COMMENT = "//textarea[@aria-label='Comment' or @placeholder='Enter comment' or contains(@name,'comment')]";
    private static final String TABLE_PENDING_REQUESTS = "//table[contains(@aria-label,'pending requests') or .//th[contains(text(),'Request ID')]]";
    private static final String PAGE_HEADING = "//h1[contains(text(),'Pending Schedule Change Requests')]";
    private static final String SUCCESS_MESSAGE = "//div[@role='status' or @role='alert'][contains(.,'approved successfully') or contains(.,'Success')]";
    private static final String DASHBOARD = "//div[contains(@class,'dashboard')] | //h1[contains(text(),'Dashboard')]";
    private static final String CLOSE_ICON = "//button[contains(@aria-label,'Close') or contains(@class,'close')]";
    
    private WebElement currentFocusedElement;
    private String previousFocusedElementXPath;
    private boolean keyboardOnlyMode = false;
    private boolean screenReaderActive = false;
    
    private String buttonByText(String text) {
        return String.format("//button[contains(text(),'%s') or contains(.,'%s') or contains(@aria-label,'%s')]", text, text, text);
    }
    
    private String linkByText(String text) {
        return String.format("//a[contains(text(),'%s') or contains(@aria-label,'%s')]", text, text);
    }
    
    private String elementByText(String text) {
        return String.format("//*[contains(text(),'%s')]", text);
    }
    
    private String statusBadge(String status) {
        return String.format("//span[contains(@class,'status') or contains(@class,'badge')][contains(text(),'%s')]", status);
    }
    
    private String tableRow(String requestId) {
        return String.format("//table//tr[contains(.,'%s')]", requestId);
    }
    
    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        if (Boolean.parseBoolean(ConfigReader.getProperty("headless", "false"))) {
            options.addArguments("--headless");
        }
        options.addArguments("--disable-blink-features=AutomationControlled");
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
        
        WebElement usernameField = driver.findElement(By.xpath("//input[@placeholder='Username' or @name='username']"));
        actions.clearAndSendKeys(usernameField, TestData.getUsername(role));
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@type='password']"));
        actions.clearAndSendKeys(passwordField, TestData.getPassword(role));
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit' or contains(text(),'Login') or contains(text(),'Sign In')]"));
        actions.click(loginButton);
        
        waits.waitForElementVisible(By.xpath(DASHBOARD));
        waits.waitForPageLoad();
    }
    
    @Given("at least one pending schedule change request exists")
    public void atLeastOnePendingScheduleChangeRequestExists() {
        actions.navigateTo(APP_URL + "/approver/pending-requests");
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(TABLE_PENDING_REQUESTS));
        
        List<WebElement> pendingRows = driver.findElements(By.xpath("//table//tbody//tr[contains(.,'Pending')]"));
        if (pendingRows.isEmpty()) {
            actions.navigateTo(APP_URL + "/test-data/create-pending-request");
            waits.waitForPageLoad();
            actions.navigateTo(APP_URL + "/approver/pending-requests");
            waits.waitForPageLoad();
        }
    }
    
    @Given("user is on the approver dashboard")
    public void userIsOnTheApproverDashboard() {
        actions.navigateTo(APP_URL + "/approver/dashboard");
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(DASHBOARD));
    }
    
    @Given("keyboard is the only input device being used")
    public void keyboardIsTheOnlyInputDeviceBeingUsed() {
        keyboardOnlyMode = true;
    }
    
    @Given("screen reader software is active")
    public void screenReaderSoftwareIsActive() {
        screenReaderActive = true;
    }
    
    @Given("user is on the pending requests page")
    public void userIsOnThePendingRequestsPage() {
        actions.navigateTo(APP_URL + "/approver/pending-requests");
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(PAGE_HEADING));
    }
    
    @Given("browser zoom is set to {string} percent")
    public void browserZoomIsSetToPercent(String zoomLevel) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        double zoomFactor = Double.parseDouble(zoomLevel) / 100.0;
        js.executeScript(String.format("document.body.style.zoom='%s%%'", zoomLevel));
        waits.waitForSeconds(1);
    }
    
    @Given("browser window is at standard desktop resolution")
    public void browserWindowIsAtStandardDesktopResolution() {
        driver.manage().window().setSize(new org.openqa.selenium.Dimension(1920, 1080));
        waits.waitForSeconds(1);
    }
    
    @Given("browser developer tools are open")
    public void browserDeveloperToolsAreOpen() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Developer tools context active for accessibility testing');");
    }
    
    @Given("color contrast checking tool is available")
    public void colorContrastCheckingToolIsAvailable() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("window.contrastChecker = { enabled: true };");
    }
    
    @When("user presses Tab key repeatedly to navigate to {string} link")
    public void userPressesTabKeyRepeatedlyToNavigateToLink(String linkText) {
        WebElement targetLink = driver.findElement(By.xpath(linkByText(linkText)));
        
        for (int i = 0; i < 20; i++) {
            actions.pressKey(Keys.TAB);
            waits.waitForSeconds(0.3);
            
            WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
            String activeText = actions.getText(activeElement);
            
            if (activeText.contains(linkText)) {
                currentFocusedElement = activeElement;
                break;
            }
        }
    }
    
    @When("user presses Enter key on {string} link")
    public void userPressesEnterKeyOnLink(String linkText) {
        if (currentFocusedElement != null) {
            actions.pressKey(Keys.ENTER);
        } else {
            WebElement link = driver.findElement(By.xpath(linkByText(linkText)));
            actions.click(link);
        }
        waits.waitForPageLoad();
    }
    
    @When("user uses Tab key to navigate through pending requests list")
    public void userUsesTabKeyToNavigateThroughPendingRequestsList() {
        for (int i = 0; i < 5; i++) {
            actions.pressKey(Keys.TAB);
            waits.waitForSeconds(0.3);
        }
    }
    
    @When("user presses Enter on a specific request")
    public void userPressesEnterOnASpecificRequest() {
        WebElement firstRequestRow = driver.findElement(By.xpath("//table//tbody//tr[1]"));
        actions.scrollToElement(firstRequestRow);
        actions.click(firstRequestRow);
        waits.waitForSeconds(1);
    }
    
    @When("user uses Tab to navigate to {string} button in request details")
    public void userUsesTabToNavigateToButtonInRequestDetails(String buttonText) {
        WebElement button = driver.findElement(By.xpath(buttonByText(buttonText)));
        
        for (int i = 0; i < 15; i++) {
            actions.pressKey(Keys.TAB);
            waits.waitForSeconds(0.3);
            
            WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
            if (activeElement.equals(button)) {
                currentFocusedElement = activeElement;
                break;
            }
        }
    }
    
    @When("user presses Enter to open approval dialog")
    public void userPressesEnterToOpenApprovalDialog() {
        previousFocusedElementXPath = (String) ((JavascriptExecutor) driver).executeScript(
            "var el = document.activeElement; " +
            "var xpath = ''; " +
            "while (el && el.nodeType === 1) { " +
            "  var id = el.id ? \"[@id='\" + el.id + \"']\" : ''; " +
            "  xpath = '/' + el.tagName.toLowerCase() + id + xpath; " +
            "  el = el.parentNode; " +
            "} " +
            "return xpath;"
        );
        
        actions.pressKey(Keys.ENTER);
        waits.waitForElementVisible(By.xpath(MODAL_APPROVAL));
    }
    
    @When("user types approval comment using keyboard")
    public void userTypesApprovalCommentUsingKeyboard() {
        waits.waitForElementVisible(By.xpath(TEXTAREA_COMMENT));
        WebElement commentField = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        actions.clearAndSendKeys(commentField, "Approved after thorough review of schedule changes");
    }
    
    @When("user presses Tab to navigate to {string} button")
    public void userPressesTabToNavigateToButton(String buttonText) {
        WebElement button = driver.findElement(By.xpath(buttonByText(buttonText)));
        
        for (int i = 0; i < 10; i++) {
            actions.pressKey(Keys.TAB);
            waits.waitForSeconds(0.3);
            
            WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
            if (activeElement.equals(button)) {
                currentFocusedElement = activeElement;
                break;
            }
        }
    }
    
    @When("user presses Enter on {string} button")
    public void userPressesEnterOnButton(String buttonText) {
        actions.pressKey(Keys.ENTER);
        waits.waitForSeconds(1);
    }
    
    @When("user presses Escape key when approval dialog is open")
    public void userPressesEscapeKeyWhenApprovalDialogIsOpen() {
        waits.waitForElementVisible(By.xpath(MODAL_APPROVAL));
        actions.pressKey(Keys.ESCAPE);
        waits.waitForSeconds(1);
    }
    
    @When("user navigates to pending requests page")
    public void userNavigatesToPendingRequestsPage() {
        actions.navigateTo(APP_URL + "/approver/pending-requests");
        waits.waitForPageLoad();
        waits.waitForElementVisible(By.xpath(PAGE_HEADING));
    }
    
    @When("user navigates through pending requests table using screen reader table navigation")
    public void userNavigatesThroughPendingRequestsTableUsingScreenReaderTableNavigation() {
        waits.waitForElementVisible(By.xpath(TABLE_PENDING_REQUESTS));
        WebElement table = driver.findElement(By.xpath(TABLE_PENDING_REQUESTS));
        actions.scrollToElement(table);
        
        List<WebElement> rows = driver.findElements(By.xpath("//table//tbody//tr"));
        for (WebElement row : rows) {
            actions.scrollToElement(row);
            waits.waitForSeconds(0.5);
        }
    }
    
    @When("user focuses on {string} button for a specific request")
    public void userFocusesOnButtonForASpecificRequest(String buttonText) {
        WebElement button = driver.findElement(By.xpath("//table//tbody//tr[1]" + buttonByText(buttonText)));
        actions.scrollToElement(button);
        ((JavascriptExecutor) driver).executeScript("arguments[0].focus();", button);
        currentFocusedElement = button;
        waits.waitForSeconds(0.5);
    }
    
    @When("user activates {string} button")
    public void userActivatesButton(String buttonText) {
        if (currentFocusedElement != null) {
            actions.click(currentFocusedElement);
        } else {
            WebElement button = driver.findElement(By.xpath(buttonByText(buttonText)));
            actions.click(button);
        }
        waits.waitForSeconds(1);
    }
    
    @When("user enters comment in text area")
    public void userEntersCommentInTextArea() {
        waits.waitForElementVisible(By.xpath(TEXTAREA_COMMENT));
        WebElement commentField = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        actions.clearAndSendKeys(commentField, "This is a test comment for approval");
    }
    
    @When("user submits approval")
    public void userSubmitsApproval() {
        waits.waitForElementClickable(By.xpath(BTN_CONFIRM_APPROVAL));
        WebElement confirmButton = driver.findElement(By.xpath(BTN_CONFIRM_APPROVAL));
        actions.click(confirmButton);
        waits.waitForPageLoad();
    }
    
    @When("user navigates to request history")
    public void userNavigatesToRequestHistory() {
        actions.navigateTo(APP_URL + "/approver/request-history");
        waits.waitForPageLoad();
    }
    
    @When("user navigates to a pending request using Tab key")
    public void userNavigatesToAPendingRequestUsingTabKey() {
        waits.waitForElementVisible(By.xpath(TABLE_PENDING_REQUESTS));
        
        for (int i = 0; i < 10; i++) {
            actions.pressKey(Keys.TAB);
            waits.waitForSeconds(0.3);
        }
    }
    
    @When("user presses Tab key repeatedly to cycle through modal elements")
    public void userPressesTabKeyRepeatedlyToCycleThroughModalElements() {
        for (int i = 0; i < 5; i++) {
            actions.pressKey(Keys.TAB);
            waits.waitForSeconds(0.3);
            
            WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
            WebElement modalElement = driver.findElement(By.xpath(MODAL_APPROVAL));
            
            boolean isInsideModal = (boolean) ((JavascriptExecutor) driver).executeScript(
                "return arguments[0].contains(arguments[1]);", modalElement, activeElement
            );
            
            if (!isInsideModal) {
                throw new RuntimeException("Focus escaped modal - focus trap failed");
            }
        }
    }
    
    @When("user presses Shift+Tab to navigate backwards")
    public void userPressesShiftTabToNavigateBackwards() {
        for (int i = 0; i < 3; i++) {
            actions.pressKey(Keys.chord(Keys.SHIFT, Keys.TAB));
            waits.waitForSeconds(0.3);
        }
    }
    
    @When("user presses Escape key")
    public void userPressesEscapeKey() {
        actions.pressKey(Keys.ESCAPE);
        waits.waitForSeconds(1);
    }
    
    @When("user opens approval modal again")
    public void userOpensApprovalModalAgain() {
        WebElement approveButton = driver.findElement(By.xpath(BTN_APPROVE));
        actions.click(approveButton);
        waits.waitForElementVisible(By.xpath(MODAL_APPROVAL));
    }
    
    @When("user opens approval modal")
    public void userOpensApprovalModal() {
        waits.waitForElementClickable(By.xpath(BTN_APPROVE));
        WebElement approveButton = driver.findElement(By.xpath(BTN_APPROVE));
        actions.click(approveButton);
        waits.waitForElementVisible(By.xpath(MODAL_APPROVAL));
    }
    
    @When("user opens rejection modal")
    public void userOpensRejectionModal() {
        waits.waitForElementClickable(By.xpath(BTN_REJECT));
        WebElement rejectButton = driver.findElement(By.xpath(BTN_REJECT));
        actions.click(rejectButton);
        waits.waitForElementVisible(By.xpath(MODAL_REJECTION));
    }
    
    @When("user inspects modal element")
    public void userInspectsModalElement() {
        waits.waitForElementVisible(By.xpath(MODAL_APPROVAL));
        WebElement modal = driver.findElement(By.xpath(MODAL_APPROVAL));
        actions.scrollToElement(modal);
    }
    
    @When("user inspects comment text area")
    public void userInspectsCommentTextArea() {
        waits.waitForElementVisible(By.xpath(TEXTAREA_COMMENT));
        WebElement commentField = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        actions.scrollToElement(commentField);
    }
    
    @When("user inspects success message container")
    public void userInspectsSuccessMessageContainer() {
        waits.waitForElementVisible(By.xpath(SUCCESS_MESSAGE));
        WebElement successMessage = driver.findElement(By.xpath(SUCCESS_MESSAGE));
        actions.scrollToElement(successMessage);
    }
    
    @When("user inspects status badge for {string} request")
    public void userInspectsStatusBadgeForRequest(String status) {
        String xpath = statusBadge(status);
        waits.waitForElementVisible(By.xpath(xpath));
        WebElement statusBadge = driver.findElement(By.xpath(xpath));
        actions.scrollToElement(statusBadge);
    }
    
    @When("loading indicator is displayed")
    public void loadingIndicatorIsDisplayed() {
        waits.waitForSeconds(0.5);
    }
    
    @When("user inspects loading indicator")
    public void userInspectsLoadingIndicator() {
        String loadingXPath = "//div[@role='status' and contains(@aria-label,'Processing') or contains(@class,'loading')]";
        if (!driver.findElements(By.xpath(loadingXPath)).isEmpty()) {
            WebElement loadingIndicator = driver.findElement(By.xpath(loadingXPath));
            actions.scrollToElement(loadingIndicator);
        }
    }
    
    @When("user measures contrast ratio of {string} element {string}")
    public void userMeasuresContrastRatioOfElement(String elementType, String elementName) {
        String xpath = "";
        
        switch (elementType) {
            case "page heading":
                xpath = String.format("//h1[contains(text(),'%s')]", elementName);
                break;
            case "body text":
                xpath = String.format("//td[contains(text(),'%s')] | //span[contains(text(),'%s')]", elementName, elementName);
                break;
            case "button text":
                xpath = String.format("//button[contains(text(),'%s') or contains(@aria-label,'%s')]", elementName, elementName);
                break;
            case "status badge text":
                xpath = String.format("//span[contains(@class,'status') or contains(@class,'badge')][contains(text(),'%s')]", elementName);
                break;
            case "feedback message":
                xpath = String.format("//div[contains(@class,'message') or @role='alert'][contains(text(),'%s')]", elementName);
                break;
            case "link text":
                xpath = String.format("//a[contains(text(),'%s')]", elementName);
                break;
        }
        
        if (!driver.findElements(By.xpath(xpath)).isEmpty()) {
            WebElement element = driver.findElement(By.xpath(xpath));
            actions.scrollToElement(element);
            
            JavascriptExecutor js = (JavascriptExecutor) driver;
            js.executeScript(
                "var element = arguments[0];" +
                "var style = window.getComputedStyle(element);" +
                "var color = style.color;" +
                "var bgColor = style.backgroundColor;" +
                "element.setAttribute('data-contrast-checked', 'true');" +
                "element.setAttribute('data-text-color', color);" +
                "element.setAttribute('data-bg-color', bgColor);",
                element
            );
        }
    }
    
    @When("user measures contrast ratio of button background against page background")
    public void userMeasuresContrastRatioOfButtonBackgroundAgainstPageBackground() {
        WebElement button = driver.findElement(By.xpath(BTN_APPROVE));
        actions.scrollToElement(button);
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript(
            "var button = arguments[0];" +
            "var buttonStyle = window.getComputedStyle(button);" +
            "var buttonBg = buttonStyle.backgroundColor;" +
            "var pageBg = window.getComputedStyle(document.body).backgroundColor;" +
            "button.setAttribute('data-button-bg', buttonBg);" +
            "button.setAttribute('data-page-bg', pageBg);",
            button
        );
    }
    
    @When("user measures contrast ratio of focus indicator against background")
    public void userMeasuresContrastRatioOfFocusIndicatorAgainstBackground() {
        WebElement button = driver.findElement(By.xpath(BTN_APPROVE));
        ((JavascriptExecutor) driver).executeScript("arguments[0].focus();", button);
        waits.waitForSeconds(0.5);
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript(
            "var button = arguments[0];" +
            "var style = window.getComputedStyle(button);" +
            "var outlineColor = style.outlineColor;" +
            "var bgColor = style.backgroundColor;" +
            "button.setAttribute('data-outline-color', outlineColor);" +
            "button.setAttribute('data-bg-color', bgColor);",
            button
        );
    }
    
    @When("user views status badges for {string} requests")
    public void userViewsStatusBadgesForRequests(String status) {
        String xpath = statusBadge(status);
        waits.waitForElementVisible(By.xpath(xpath));
        WebElement badge = driver.findElement(By.xpath(xpath));
        actions.scrollToElement(badge);
    }
    
    @When("user sets browser zoom to {string} percent")
    public void userSetsBrowserZoomToPercent(String zoomLevel) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript(String.format("document.body.style.zoom='%s%%'", zoomLevel));
        waits.waitForSeconds(1);
    }
    
    @When("user verifies pending requests table at {string} percent zoom")
    public void userVerifiesPendingRequestsTableAtPercentZoom(String zoomLevel) {
        waits.waitForElementVisible(By.xpath(TABLE_PENDING_REQUESTS));
        WebElement table = driver.findElement(By.xpath(TABLE_PENDING_REQUESTS));
        actions.scrollToElement(table);
        assertions.assertDisplayed(table);
    }
    
    @When("user navigates through page using keyboard at {string} percent zoom")
    public void userNavigatesThroughPageUsingKeyboardAtPercentZoom(String zoomLevel) {
        for (int i = 0; i < 5; i++) {
            actions.pressKey(Keys.TAB);
            waits.waitForSeconds(0.3);
        }
    }
    
    @When("user opens approval modal at {string} percent zoom")
    public void userOpensApprovalModalAtPercentZoom(String zoomLevel) {
        waits.waitForElementClickable(By.xpath(BTN_APPROVE));
        WebElement approveButton = driver.findElement(By.xpath(BTN_APPROVE));
        actions.click(approveButton);
        waits.waitForElementVisible(By.xpath(MODAL_APPROVAL));
    }
    
    @When("user tests approval workflow at {string} percent zoom")
    public void userTestsApprovalWorkflowAtPercentZoom(String zoomLevel) {
        waits.waitForElementVisible(By.xpath(TABLE_PENDING_REQUESTS));
    }
    
    @When("user selects request")
    public void userSelectsRequest() {
        WebElement firstRow = driver.findElement(By.xpath("//table//tbody//tr[1]"));
        actions.click(firstRow);
        waits.waitForSeconds(1);
    }
    
    @When("user approves with comments")
    public void userApprovesWithComments() {
        waits.waitForElementClickable(By.xpath(BTN_APPROVE));
        WebElement approveButton = driver.findElement(By.xpath(BTN_APPROVE));
        actions.click(approveButton);
        
        waits.waitForElementVisible(By.xpath(TEXTAREA_COMMENT));
        WebElement commentField = driver.findElement(By.xpath(TEXTAREA_COMMENT));
        actions.clearAndSendKeys(commentField, "Approved with comments at zoom level");
        
        waits.waitForElementClickable(By.xpath(BTN_CONFIRM_APPROVAL));
        WebElement confirmButton = driver.findElement(By.xpath(BTN_CONFIRM_APPROVAL));
        actions.click(confirmButton);
        waits.waitForPageLoad();
    }
    
    @When("user checks navigation menu at {string} percent zoom")
    public void userChecksNavigationMenuAtPercentZoom(String zoomLevel) {
        String navXPath = "//nav | //div[contains(@class,'navigation')]";
        if (!driver.findElements(By.xpath(navXPath)).isEmpty()) {
            WebElement nav = driver.findElement(By.xpath(navXPath));
            actions.scrollToElement(nav);
            assertions.assertDisplayed(nav);
        }
    }
    
    @When("user checks header at {string} percent zoom")
    public void userChecksHeaderAtPercentZoom(String zoomLevel) {
        String headerXPath = "//header | //div[contains(@class,'header')]";
        if (!driver.findElements(By.xpath(headerXPath)).isEmpty()) {
            WebElement header = driver.findElement(By.xpath(headerXPath));
            actions.scrollToElement(header);
            assertions.assertDisplayed(header);
        }
    }
    
    @When("user checks footer at {string} percent zoom")
    public void userChecksFooterAtPercentZoom(String zoomLevel) {
        String footerXPath = "//footer | //div[contains(@class,'footer')]";
        if (!driver.findElements(By.xpath(footerXPath)).isEmpty()) {
            WebElement footer = driver.findElement(By.xpath(footerXPath));
            actions.scrollToElement(footer);
            assertions.assertDisplayed(footer);
        }
    }
    
    @When("user inspects pending requests table")
    public void userInspectsPendingRequestsTable() {
        waits.waitForElementVisible(By.xpath(TABLE_PENDING_REQUESTS));
        WebElement table = driver.findElement(By.xpath(TABLE_PENDING_REQUESTS));
        actions.scrollToElement(table);
    }
    
    @When("user inspects {string} button")
    public void userInspectsButton(String buttonText) {
        String xpath = buttonByText(buttonText);
        waits.waitForElementVisible(By.xpath(xpath));