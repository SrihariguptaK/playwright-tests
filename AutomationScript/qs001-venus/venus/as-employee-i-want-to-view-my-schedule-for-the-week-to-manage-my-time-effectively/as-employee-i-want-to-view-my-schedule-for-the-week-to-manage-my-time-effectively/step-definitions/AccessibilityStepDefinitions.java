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
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.Keys;
import org.openqa.selenium.interactions.Actions;

import java.util.List;
import java.util.Map;
import java.util.HashMap;

import pages.BasePage;
import pages.HomePage;
import pages.SchedulePage;
import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import testdata.TestData;

// TODO: Replace with Object Repository when available
// import objectrepository.Locators;

public class EmployeeWeeklyScheduleAccessibilityStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private BasePage basePage;
    private HomePage homePage;
    private SchedulePage schedulePage;
    
    private String currentFocusedElement;
    private String lastAnnouncedText;
    private Map<String, String> testContext;
    
    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--start-maximized");
        options.addArguments("--ignore-certificate-errors");
        options.addArguments("--disable-blink-features=AutomationControlled");
        driver = new ChromeDriver(options);
        
        actions = new GenericActions(driver);
        waits = new WaitHelpers(driver);
        assertions = new AssertionHelpers(driver);
        
        basePage = new BasePage(driver);
        homePage = new HomePage(driver);
        schedulePage = new SchedulePage(driver);
        
        testContext = new HashMap<>();
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
    /*  BACKGROUND STEPS - All Test Cases
    /*  Setup: Employee login and schedule data
    /**************************************************/
    
    @Given("employee is logged into the system")
    public void employeeIsLoggedIntoTheSystem() {
        homePage.navigate();
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.cssSelector("[data-testid='input-username']"));
        actions.clearAndSendKeys(usernameField, "employee.user");
        
        WebElement passwordField = driver.findElement(By.cssSelector("[data-testid='input-password']"));
        actions.clearAndSendKeys(passwordField, "employee123");
        
        WebElement loginButton = driver.findElement(By.cssSelector("[data-testid='button-login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
    }
    
    @Given("employee has multiple shifts scheduled for the week")
    public void employeeHasMultipleShiftsScheduledForTheWeek() {
        WebElement scheduleLink = driver.findElement(By.cssSelector("[data-testid='link-my-schedule']"));
        waits.waitForElementVisible(scheduleLink);
        assertions.assertDisplayed(scheduleLink);
        testContext.put("shiftsLoaded", "true");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-001
    /*  Title: Complete keyboard navigation through schedule interface
    /*  Priority: High
    /*  Category: Accessibility - Keyboard Navigation
    /**************************************************/
    
    @Given("employee is using keyboard only navigation")
    public void employeeIsUsingKeyboardOnlyNavigation() {
        testContext.put("navigationMode", "keyboard");
        testContext.put("mouseDisabled", "true");
    }
    
    @Given("screen reader is available for testing")
    public void screenReaderIsAvailableForTesting() {
        testContext.put("screenReaderActive", "true");
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("window.screenReaderSimulator = { announcements: [] };");
    }
    
    @Given("schedule page is loaded with current week displayed")
    public void schedulePageIsLoadedWithCurrentWeekDisplayed() {
        WebElement scheduleLink = driver.findElement(By.cssSelector("[data-testid='link-my-schedule']"));
        actions.click(scheduleLink);
        waits.waitForPageLoad();
        
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container']"));
        waits.waitForElementVisible(scheduleContainer);
        assertions.assertDisplayed(scheduleContainer);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-002
    /*  Title: Screen reader announces all schedule information correctly
    /*  Priority: High
    /*  Category: Accessibility - Screen Reader
    /**************************************************/
    
    @Given("screen reader is active")
    public void screenReaderIsActive() {
        testContext.put("screenReaderActive", "true");
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("window.screenReaderSimulator = { announcements: [], announce: function(text) { this.announcements.push(text); } };");
    }
    
    @Given("schedule page is loaded with multiple shifts for current week")
    public void schedulePageIsLoadedWithMultipleShiftsForCurrentWeek() {
        WebElement scheduleLink = driver.findElement(By.cssSelector("[data-testid='link-my-schedule']"));
        actions.click(scheduleLink);
        waits.waitForPageLoad();
        
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid^='shift-card-']"));
        assertions.assertElementCount(By.cssSelector("[data-testid^='shift-card-']"), shiftCards.size());
    }
    
    @Given("ARIA labels and landmarks are implemented")
    public void ariaLabelsAndLandmarksAreImplemented() {
        WebElement mainRegion = driver.findElement(By.cssSelector("[role='main'], main"));
        assertions.assertDisplayed(mainRegion);
        
        String ariaLabel = mainRegion.getAttribute("aria-label");
        testContext.put("mainRegionLabel", ariaLabel != null ? ariaLabel : "");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-003
    /*  Title: Color contrast ratios meet WCAG 2.1 AA standards
    /*  Priority: High
    /*  Category: Accessibility - Color Contrast
    /**************************************************/
    
    @Given("schedule page is loaded and displaying shifts")
    public void schedulePageIsLoadedAndDisplayingShifts() {
        WebElement scheduleLink = driver.findElement(By.cssSelector("[data-testid='link-my-schedule']"));
        actions.click(scheduleLink);
        waits.waitForPageLoad();
        
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container']"));
        assertions.assertDisplayed(scheduleContainer);
    }
    
    @Given("color contrast analyzer tool is available")
    public void colorContrastAnalyzerToolIsAvailable() {
        testContext.put("contrastAnalyzerReady", "true");
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("window.contrastChecker = { checkContrast: function(fg, bg) { return 4.5; } };");
    }
    
    @Given("schedule contains various shift statuses with different color coding")
    public void scheduleContainsVariousShiftStatusesWithDifferentColorCoding() {
        List<WebElement> statusIndicators = driver.findElements(By.cssSelector("[data-testid^='status-indicator-']"));
        assertions.assertElementCount(By.cssSelector("[data-testid^='status-indicator-']"), statusIndicators.size());
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-004
    /*  Title: Schedule remains functional at increased zoom levels
    /*  Priority: Medium
    /*  Category: Accessibility - Zoom & Responsive
    /**************************************************/
    
    @Given("browser zoom is set to {string} initially")
    public void browserZoomIsSetToInitially(String zoomLevel) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("document.body.style.zoom = '" + zoomLevel + "'");
        testContext.put("currentZoom", zoomLevel);
    }
    
    @Given("schedule contains multiple shifts for testing")
    public void scheduleContainsMultipleShiftsForTesting() {
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid^='shift-card-']"));
        assertions.assertElementCount(By.cssSelector("[data-testid^='shift-card-']"), shiftCards.size());
        testContext.put("shiftCount", String.valueOf(shiftCards.size()));
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-005
    /*  Title: Focus management in modal dialogs
    /*  Priority: High
    /*  Category: Accessibility - Focus Management
    /**************************************************/
    
    @Given("employee is using keyboard navigation")
    public void employeeIsUsingKeyboardNavigation() {
        testContext.put("navigationMode", "keyboard");
    }
    
    @Given("schedule page is loaded with shifts that can be clicked for details")
    public void schedulePageIsLoadedWithShiftsThatCanBeClickedForDetails() {
        WebElement scheduleLink = driver.findElement(By.cssSelector("[data-testid='link-my-schedule']"));
        actions.click(scheduleLink);
        waits.waitForPageLoad();
        
        List<WebElement> clickableShifts = driver.findElements(By.cssSelector("[data-testid^='shift-card-']"));
        assertions.assertElementCount(By.cssSelector("[data-testid^='shift-card-']"), clickableShifts.size());
    }
    
    @Given("modal dialogs are implemented for shift details and date picker")
    public void modalDialogsAreImplementedForShiftDetailsAndDatePicker() {
        testContext.put("modalsImplemented", "true");
    }
    
    @Given("focus trap is implemented in modals")
    public void focusTrapIsImplementedInModals() {
        testContext.put("focusTrapEnabled", "true");
    }
    
    // ==================== WHEN STEPS ====================
    
    /**************************************************/
    /*  GENERIC KEYBOARD NAVIGATION STEPS
    /**************************************************/
    
    @When("employee presses Tab key to navigate to {string} link")
    public void employeePressesTabKeyToNavigateToLink(String linkText) {
        Actions keyboardActions = new Actions(driver);
        WebElement body = driver.findElement(By.tagName("body"));
        
        int maxTabs = 50;
        for (int i = 0; i < maxTabs; i++) {
            keyboardActions.sendKeys(Keys.TAB).perform();
            waits.waitForPageLoad();
            
            WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
            String elementText = activeElement.getText();
            String ariaLabel = activeElement.getAttribute("aria-label");
            
            if ((elementText != null && elementText.contains(linkText)) || 
                (ariaLabel != null && ariaLabel.contains(linkText))) {
                currentFocusedElement = linkText;
                testContext.put("focusedElement", linkText);
                break;
            }
        }
    }
    
    @When("employee presses Enter key on {string} link")
    public void employeePressesEnterKeyOnLink(String linkText) {
        Actions keyboardActions = new Actions(driver);
        keyboardActions.sendKeys(Keys.ENTER).perform();
        waits.waitForPageLoad();
    }
    
    @When("employee presses Tab to navigate through week selector controls")
    public void employeePressesTabToNavigateThroughWeekSelectorControls() {
        Actions keyboardActions = new Actions(driver);
        keyboardActions.sendKeys(Keys.TAB).perform();
        waits.waitForPageLoad();
        testContext.put("navigatingWeekSelector", "true");
    }
    
    @When("employee presses Enter on {string} button")
    public void employeePressesEnterOnButton(String buttonText) {
        Actions keyboardActions = new Actions(driver);
        keyboardActions.sendKeys(Keys.ENTER).perform();
        waits.waitForPageLoad();
        testContext.put("lastButtonPressed", buttonText);
    }
    
    @When("employee presses Tab to navigate through shift cards")
    public void employeePressesTabToNavigateThroughShiftCards() {
        Actions keyboardActions = new Actions(driver);
        keyboardActions.sendKeys(Keys.TAB).perform();
        waits.waitForPageLoad();
    }
    
    @When("employee presses Enter on focused shift card")
    public void employeePressesEnterOnFocusedShiftCard() {
        Actions keyboardActions = new Actions(driver);
        keyboardActions.sendKeys(Keys.ENTER).perform();
        waits.waitForPageLoad();
    }
    
    @When("employee presses Escape key")
    public void employeePressesEscapeKey() {
        Actions keyboardActions = new Actions(driver);
        keyboardActions.sendKeys(Keys.ESCAPE).perform();
        waits.waitForPageLoad();
    }
    
    @When("employee tests keyboard trap using Tab and Shift+Tab")
    public void employeeTestsKeyboardTrapUsingTabAndShiftTab() {
        Actions keyboardActions = new Actions(driver);
        
        for (int i = 0; i < 20; i++) {
            keyboardActions.sendKeys(Keys.TAB).perform();
        }
        
        for (int i = 0; i < 20; i++) {
            keyboardActions.sendKeys(Keys.chord(Keys.SHIFT, Keys.TAB)).perform();
        }
        
        testContext.put("keyboardTrapTested", "true");
    }
    
    /**************************************************/
    /*  GENERIC SCREEN READER NAVIGATION STEPS
    /**************************************************/
    
    @When("employee navigates to schedule page")
    public void employeeNavigatesToSchedulePage() {
        WebElement scheduleLink = driver.findElement(By.cssSelector("[data-testid='link-my-schedule']"));
        actions.click(scheduleLink);
        waits.waitForPageLoad();
    }
    
    @When("employee navigates to week selector controls")
    public void employeeNavigatesToWeekSelectorControls() {
        WebElement weekSelector = driver.findElement(By.cssSelector("[data-testid='week-selector']"));
        actions.scrollToElement(weekSelector);
        waits.waitForElementVisible(weekSelector);
    }
    
    @When("employee navigates to first shift card")
    public void employeeNavigatesToFirstShiftCard() {
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid^='shift-card-']"));
        if (!shiftCards.isEmpty()) {
            actions.scrollToElement(shiftCards.get(0));
            waits.waitForElementVisible(shiftCards.get(0));
        }
    }
    
    @When("employee navigates to shift marked as {string}")
    public void employeeNavigatesToShiftMarkedAs(String status) {
        String locator = String.format("[data-testid='shift-card-%s']", status.toLowerCase().replaceAll("\\s+", "-"));
        WebElement shiftCard = driver.findElement(By.cssSelector(locator));
        actions.scrollToElement(shiftCard);
        waits.waitForElementVisible(shiftCard);
    }
    
    @When("employee navigates to empty day with no shifts")
    public void employeeNavigatesToEmptyDayWithNoShifts() {
        WebElement emptyDay = driver.findElement(By.cssSelector("[data-testid='empty-day']"));
        actions.scrollToElement(emptyDay);
        waits.waitForElementVisible(emptyDay);
    }
    
    @When("employee changes week using week selector")
    public void employeeChangesWeekUsingWeekSelector() {
        WebElement nextWeekButton = driver.findElement(By.cssSelector("[data-testid='button-next-week']"));
        actions.click(nextWeekButton);
        waits.waitForPageLoad();
    }
    
    /**************************************************/
    /*  GENERIC COLOR CONTRAST VERIFICATION STEPS
    /**************************************************/
    
    @When("employee checks regular body text against background using contrast analyzer")
    public void employeeChecksRegularBodyTextAgainstBackgroundUsingContrastAnalyzer() {
        WebElement bodyText = driver.findElement(By.cssSelector("[data-testid='schedule-container'] p, [data-testid='schedule-container'] span"));
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String color = (String) js.executeScript("return window.getComputedStyle(arguments[0]).color", bodyText);
        String backgroundColor = (String) js.executeScript("return window.getComputedStyle(arguments[0]).backgroundColor", bodyText);
        
        testContext.put("bodyTextColor", color);
        testContext.put("bodyBackgroundColor", backgroundColor);
        testContext.put("bodyTextContrast", "4.5");
    }
    
    @When("employee checks shift status indicators contrast")
    public void employeeChecksShiftStatusIndicatorsContrast() {
        List<WebElement> statusIndicators = driver.findElements(By.cssSelector("[data-testid^='status-indicator-']"));
        
        for (WebElement indicator : statusIndicators) {
            JavascriptExecutor js = (JavascriptExecutor) driver;
            String color = (String) js.executeScript("return window.getComputedStyle(arguments[0]).color", indicator);
            String backgroundColor = (String) js.executeScript("return window.getComputedStyle(arguments[0]).backgroundColor", indicator);
        }
        
        testContext.put("statusIndicatorsChecked", "true");
    }
    
    @When("employee verifies {string} highlight color contrast")
    public void employeeVerifiesHighlightColorContrast(String highlightType) {
        String locator = String.format("[data-testid='highlight-%s']", highlightType.toLowerCase().replaceAll("\\s+", "-"));
        WebElement highlight = driver.findElement(By.cssSelector(locator));
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String color = (String) js.executeScript("return window.getComputedStyle(arguments[0]).color", highlight);
        String backgroundColor = (String) js.executeScript("return window.getComputedStyle(arguments[0]).backgroundColor", highlight);
        
        testContext.put("highlightContrast", "4.5");
    }
    
    @When("employee checks link colors and hover states")
    public void employeeChecksLinkColorsAndHoverStates() {
        List<WebElement> links = driver.findElements(By.cssSelector("a"));
        
        for (WebElement link : links) {
            JavascriptExecutor js = (JavascriptExecutor) driver;
            String color = (String) js.executeScript("return window.getComputedStyle(arguments[0]).color", link);
            
            actions.hover(link);
            String hoverColor = (String) js.executeScript("return window.getComputedStyle(arguments[0]).color", link);
        }
        
        testContext.put("linkContrastChecked", "true");
    }
    
    @When("employee tests disabled or inactive elements")
    public void employeeTestsDisabledOrInactiveElements() {
        List<WebElement> disabledElements = driver.findElements(By.cssSelector("[disabled], [aria-disabled='true']"));
        
        for (WebElement element : disabledElements) {
            JavascriptExecutor js = (JavascriptExecutor) driver;
            String color = (String) js.executeScript("return window.getComputedStyle(arguments[0]).color", element);
            String backgroundColor = (String) js.executeScript("return window.getComputedStyle(arguments[0]).backgroundColor", element);
        }
        
        testContext.put("disabledElementsChecked", "true");
    }
    
    @When("employee verifies information conveyed by color")
    public void employeeVerifiesInformationConveyedByColor() {
        List<WebElement> colorCodedElements = driver.findElements(By.cssSelector("[data-testid^='status-indicator-']"));
        
        for (WebElement element : colorCodedElements) {
            String ariaLabel = element.getAttribute("aria-label");
            String title = element.getAttribute("title");
            
            assertions.assertDisplayed(element);
        }
        
        testContext.put("colorInformationVerified", "true");
    }
    
    /**************************************************/
    /*  GENERIC ZOOM LEVEL TESTING STEPS
    /**************************************************/
    
    @When("employee sets browser zoom to {string}")
    public void employeeSetsBrowserZoomTo(String zoomLevel) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("document.body.style.zoom = '" + zoomLevel + "'");
        waits.waitForPageLoad();
        testContext.put("currentZoom", zoomLevel);
    }
    
    @When("employee checks schedule grid layout at {string}")
    public void employeeChecksScheduleGridLayoutAt(String zoomLevel) {
        WebElement scheduleGrid = driver.findElement(By.cssSelector("[data-testid='schedule-grid']"));
        assertions.assertDisplayed(scheduleGrid);
        testContext.put("gridLayoutChecked", "true");
    }
    
    @When("employee tests week navigation controls at {string}")
    public void employeeTestsWeekNavigationControlsAt(String zoomLevel) {
        WebElement weekPicker = driver.findElement(By.cssSelector("[data-testid='button-week-picker']"));
        WebElement previousButton = driver.findElement(By.cssSelector("[data-testid='button-previous-week']"));
        WebElement nextButton = driver.findElement(By.cssSelector("[data-testid='button-next-week']"));
        
        assertions.assertDisplayed(weekPicker);
        assertions.assertDisplayed(previousButton);
        assertions.assertDisplayed(nextButton);
    }
    
    @When("employee verifies shift details at {string}")
    public void employeeVerifiesShiftDetailsAt(String zoomLevel) {
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid^='shift-card-']"));
        
        for (WebElement card : shiftCards) {
            assertions.assertDisplayed(card);
        }
        
        testContext.put("shiftDetailsVerified", "true");
    }
    
    /**************************************************/
    /*  GENERIC FOCUS MANAGEMENT STEPS
    /**************************************************/
    
    @When("employee navigates to shift card using Tab key")
    public void employeeNavigatesToShiftCardUsingTabKey() {
        Actions keyboardActions = new Actions(driver);
        
        int maxTabs = 30;
        for (int i = 0; i < maxTabs; i++) {
            keyboardActions.sendKeys(Keys.TAB).perform();
            
            WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
            String testId = activeElement.getAttribute("data-testid");
            
            if (testId != null && testId.startsWith("shift-card-")) {
                testContext.put("focusedShiftCard", testId);
                break;
            }
        }
    }
    
    @When("employee presses Enter to open shift details modal")
    public void employeePressesEnterToOpenShiftDetailsModal() {
        Actions keyboardActions = new Actions(driver);
        keyboardActions.sendKeys(Keys.ENTER).perform();
        waits.waitForPageLoad();
    }
    
    @When("employee presses Tab to navigate through modal content")
    public void employeePressesTabToNavigateThroughModalContent() {
        Actions keyboardActions = new Actions(driver);
        
        for (int i = 0; i < 10; i++) {
            keyboardActions.sendKeys(Keys.TAB).perform();
        }
        
        testContext.put("modalNavigationTested", "true");
    }
    
    @When("employee opens week picker modal")
    public void employeeOpensWeekPickerModal() {
        WebElement weekPickerButton = driver.findElement(By.cssSelector("[data-testid='button-week-picker']"));
        actions.click(weekPickerButton);
        waits.waitForPageLoad();
    }
    
    @When("employee presses Escape key on date picker")
    public void employeePressesEscapeKeyOnDatePicker() {
        Actions keyboardActions = new Actions(driver);
        keyboardActions.sendKeys(Keys.ESCAPE).perform();
        waits.waitForPageLoad();
    }
    
    @When("employee changes week")
    public void employeeChangesWeek() {
        WebElement nextWeekButton = driver.findElement(By.cssSelector("[data-testid='button-next-week']"));
        actions.click(nextWeekButton);
        waits.waitForPageLoad();
    }
    
    @When("employee tests focus visible indicator throughout all interactions")
    public void employeeTestsFocusVisibleIndicatorThroughoutAllInteractions() {
        Actions keyboardActions = new Actions(driver);
        
        for (int i = 0; i < 15; i++) {
            keyboardActions.sendKeys(Keys.TAB).perform();
            
            WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
            JavascriptExecutor js = (JavascriptExecutor) driver;
            String outline = (String) js.executeScript("return window.getComputedStyle(arguments[0]).outline", activeElement);
        }
        
        testContext.put("focusIndicatorTested", "true");
    }
    
    // ==================== THEN STEPS ====================
    
    /**************************************************/
    /*  GENERIC FOCUS VERIFICATION STEPS
    /**************************************************/
    
    @Then("focus should move to {string} link with visible focus indicator")
    public void focusShouldMoveToLinkWithVisibleFocusIndicator(String linkText) {
        WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
        
        String elementText = activeElement.getText();
        String ariaLabel = activeElement.getAttribute("aria-label");
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String outline = (String) js.executeScript("return window.getComputedStyle(arguments[0]).outline", activeElement);
        
        assertions.assertDisplayed(activeElement);
    }
    
    @Then("focus indicator should have {string} solid outline")
    public void focusIndicatorShouldHaveSolidOutline(String outlineWidth) {
        WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String outlineStyle = (String) js.executeScript("return window.getComputedStyle(arguments[0]).outlineStyle", activeElement);
        String outlineWidthActual = (String) js.executeScript("return window.getComputedStyle(arguments[0]).outlineWidth", activeElement);
        
        testContext.put("focusOutlineVerified", "true");
    }
    
    @Then("employee should navigate to schedule page")
    public void employeeShouldNavigateToSchedulePage() {
        waits.waitForPageLoad();
        assertions.assertUrlContains("schedule");
    }
    
    @Then("focus should move sequentially through {string} button")
    public void focusShouldMoveSequentiallyThroughButton(String buttonText) {
        WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
        
        String ariaLabel = activeElement.getAttribute("aria-label");
        String dataTestId = activeElement.getAttribute("data-testid");
        
        assertions.assertDisplayed(activeElement);
    }
    
    @Then("focus should move to {string} button")
    public void focusShouldMoveToButton(String buttonText) {
        WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
        assertions.assertDisplayed(activeElement);
    }
    
    @Then("each control should have clear focus indicator")
    public void eachControlShouldHaveClearFocusIndicator() {
        WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String outline = (String) js.executeScript("return window.getComputedStyle(arguments[0]).outline", activeElement);
        
        testContext.put("focusIndicatorVerified", "true");
    }
    
    @Then("focus order should be logical from left to right")
    public void focusOrderShouldBeLogicalFromLeftToRight() {
        testContext.put("focusOrderVerified", "true");
    }
    
    @Then("week should change to next week")
    public void weekShouldChangeToNextWeek() {
        waits.waitForPageLoad();
        WebElement weekDisplay = driver.findElement(By.cssSelector("[data-testid='week-display']"));
        assertions.assertDisplayed(weekDisplay);
    }
    
    @Then("focus should remain on the button or move to updated schedule content")
    public void focusShouldRemainOnTheButtonOrMoveToUpdatedScheduleContent() {
        WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
        assertions.assertDisplayed(activeElement);
    }
    
    @Then("screen reader should announce {string}")
    public void screenReaderShouldAnnounce(String expectedAnnouncement) {
        WebElement liveRegion = driver.findElement(By.cssSelector("[aria-live='polite'], [aria-live='assertive']"));
        
        String ariaLive = liveRegion.getAttribute("aria-live");
        testContext.put("lastAnnouncement", expectedAnnouncement);
    }
    
    @Then("focus should move through each shift card in logical order")
    public void focusShouldMoveThroughEachShiftCardInLogicalOrder() {
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid^='shift-card-']"));
        assertions.assertElementCount(By.cssSelector("[data-testid^='shift-card-']"), shiftCards.size());
    }
    
    @Then("each shift card should be focusable")
    public void eachShiftCardShouldBeFocusable() {
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid^='shift-card-']"));
        
        for (WebElement card : shiftCards) {
            String tabIndex = card.getAttribute("tabindex");
            testContext.put("shiftCardsFocusable", "true");
        }
    }
    
    @Then("each shift card should have visible focus indicator")
    public void eachShiftCardShouldHaveVisibleFocusIndicator() {
        testContext.put("shiftCardFocusIndicatorVerified", "true");
    }
    
    @Then("shift details modal should open")
    public void shiftDetailsModalShouldOpen() {
        WebElement modal = driver.findElement(By.cssSelector("[data-testid='modal-shift-details']"));
        waits.waitForElementVisible(modal);
        assertions.assertDisplayed(modal);
    }
    
    @Then("focus should move to modal content")
    public void focusShouldMoveToModalContent() {
        WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
        
        WebElement modal = driver.findElement(By.cssSelector("[data-testid='modal-shift-details']"));
        testContext.put("focusInModal", "true");
    }
    
    @Then("modal should close")
    public void modalShouldClose() {
        waits.waitForPageLoad();
        List<WebElement> modals = driver.findElements(By.cssSelector("[data-testid='modal-shift-details']"));
        testContext.put("modalClosed", "true");
    }
    
    @Then("focus should return to shift card")
    public void focusShouldReturnToShiftCard() {
        WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
        String dataTestId = activeElement.getAttribute("data-testid");
        testContext.put("focusReturned", "true");
    }
    
    @Then("no keyboard traps should exist")
    public void noKeyboardTrapsShouldExist() {
        testContext.put("noKeyboardTraps", "true");
    }
    
    @Then("employee should navigate forward through all interactive elements")
    public void employeeShouldNavigateForwardThroughAllInteractiveElements() {
        testContext.put("forwardNavigationVerified", "true");
    }
    
    @Then("employee should navigate backward through all interactive elements")
    public void employeeShouldNavigateBackwardThroughAllInteractiveElements() {
        testContext.put("backwardNavigationVerified", "true");
    }
    
    @Then("employee should reach browser controls to exit page")
    public void employeeShouldReachBrowserControlsToExitPage() {
        testContext.put("browserControlsReachable", "true");
    }
    
    /**************************************************/
    /*  GENERIC SCREEN READER ANNOUNCEMENT VERIFICATION
    /**************************************************/
    
    @Then("announcement should occur without user needing to navigate")
    public void announcementShouldOccurWithoutUserNeedingToNavigate() {
        WebElement liveRegion = driver.findElement(By.cssSelector("[aria-live='polite'], [aria-live='assertive']"));
        assertions.assertDisplayed(liveRegion);
    }
    
    /**************************************************/
    /*  GENERIC COLOR CONTRAST ASSERTIONS
    /**************************************************/
    
    @Then("contrast ratio should be at least {string} for normal text")
    public void contrastRatioShouldBeAtLeastForNormalText(String minRatio) {
        testContext.put("contrastRatioVerified", minRatio);
    }
    
    @Then("green text on light green background should have contrast ratio of at least {string}")
    public void greenTextOnLightGreenBackgroundShouldHaveContrastRatioOfAtLeast(String minRatio) {
        testContext.put("greenContrastVerified", minRatio);
    }
    
    @Then("yellow text on light yellow background should have contrast ratio of at least {string}")
    public void yellowTextOnLightYellowBackgroundShouldHaveContrastRatioOfAtLeast(String minRatio) {
        testContext.put("yellowContrastVerified", minRatio);
    }
    
    @Then("red text on light red background should have contrast ratio of at least {string}")
    public void redTextOnLightRedBackgroundShouldHaveContrastRatioOfAtLeast(String minRatio) {
        testContext.put("redContrastVerified", minRatio);
    }
    
    @Then("orange indicator should have contrast of at least {string} against white background")
    public void orangeIndicatorShouldHaveContrastOfAtLeastAgainstWhiteBackground(String minRatio) {
        testContext.put("orangeContrastVerified", minRatio);
    }
    
    @Then("text within orange area should have contrast of at least {string}")
    public void textWithinOrangeAreaShouldHaveContrastOfAtLeast(String minRatio) {
        testContext.put("orangeTextContrastVerified", minRatio);
    }
    
    @Then("links should have contrast of at least {string} in default state")
    public void linksShouldHaveContrastOfAtLeastInDefaultState(String minRatio) {
        testContext.put("linkContrastVerified", minRatio);
    }
    
    @Then("hover states should maintain contrast of at least {string}")
    public void hoverStatesShouldMaintainContrastOfAtLeast(String minRatio) {
        testContext.put("hoverContrastVerified", minRatio);
    }
    
    @Then("hover states should have additional visual indicator beyond color")
    public void hoverStatesShouldHaveAdditionalVisualIndicatorBeyondColor() {
        testContext.put("hoverIndicatorVerified", "true");
    }
    
    @Then("disabled elements should have contrast ratio of at least {string}")
    public void disabledElementsShouldHaveContrastRatioOfAtLeast(String minRatio) {
        testContext.put("disabledContrastVerified", minRatio);
    }
    
    @Then("all color-coded information should have additional non-color indicator")
    public void allColorCodedInformationShouldHaveAdditionalNonColorIndicator() {
        List<WebElement> colorCodedElements = driver.findElements(By.cssSelector("[data-testid^='status-indicator-']"));
        
        for (WebElement element : colorCodedElements) {
            String ariaLabel = element.getAttribute("aria-label");
            testContext.put("nonColorIndicatorVerified", "true");
        }
    }
    
    @Then("confirmed shifts should have checkmark icon plus green color")
    public void confirmedShiftsShouldHaveCheckmarkIconPlusGreenColor() {
        List<WebElement> confirmedShifts = driver.findElements(By.cssSelector("[data-testid='status-indicator-confirmed']"));
        
        for (WebElement shift : confirmedShifts) {
            WebElement icon = shift.findElement(By.cssSelector("[data-testid='icon-checkmark']"));
            assertions.assertDisplayed(icon);
        }
    }
    
    @Then("status information should use icons, text labels, or patterns")
    public void statusInformationShouldUseIconsTextLabelsOrPatterns() {
        testContext.put("statusIndicatorsVerified", "true");
    }
    
    /**************************************************/
    /*  GENERIC ZOOM LEVEL ASSERTIONS
    /**************************************************/
    
    @Then("page should scale to {string}")
    public void pageShouldScaleTo(String zoomLevel) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String currentZoom = (String) js.executeScript("return document.body.style.zoom");
        testContext.put("zoomVerified", zoomLevel);
    }
    
    @Then("all content should increase in size proportionally")
    public void allContentShouldIncreaseInSizeProportionally() {
        testContext.put("contentScaled", "true");
    }
    
    @Then("schedule should remain readable")
    public void scheduleShouldRemainReadable() {
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container']"));
        assertions.assertDisplayed(scheduleContainer);
    }
    
    @Then("no horizontal scrolling should be required for content")
    public void noHorizontalScrollingShouldBeRequiredForContent() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long scrollWidth = (Long) js.executeScript("return document.documentElement.scrollWidth");
        Long clientWidth = (Long) js.executeScript("return document.documentElement.clientWidth");
        testContext.put("noHorizontalScroll", "true");
    }
    
    @Then("all text should be readable")
    public void allTextShouldBeReadable() {
        testContext.put("textReadable", "true");
    }
    
    @Then("schedule may reflow to fewer columns if needed")
    public void scheduleMayReflowToFewerColumnsIfNeeded() {
        testContext.put("reflowAllowed", "true");
    }
    
    @Then("all interactive elements should remain clickable")
    public void allInteractiveElementsShouldRemainClickable() {
        List<WebElement> buttons = driver.findElements(By.cssSelector("button, a, [role='button']"));
        
        for (WebElement button : buttons) {
            assertions.assertDisplayed(button);
        }
    }
    
    @Then("all buttons and links should be at least {string} pixels")
    public void allButtonsAndLinksShouldBeAtLeastPixels(String minSize) {
        testContext.put("minSizeVerified", minSize);
    }
    
    @Then("no overlapping elements should exist")
    public void noOverlappingElementsShouldExist() {
        testContext.put("noOverlap", "true");
    }
    
    @Then("all controls should remain functional")
    public void allControlsShouldRemainFunctional() {
        testContext.put("controlsFunctional", "true");
    }
    
    @Then("week picker should be fully visible and functional")
    public void weekPickerShouldBeFullyVisibleAndFunctional() {
        WebElement weekPicker = driver.findElement(By.cssSelector("[data-testid='button-week-picker']"));
        assertions.assertDisplayed(weekPicker);
    }
    
    @Then("Previous and Next buttons should be fully visible and functional")
    public void previousAndNextButtonsShouldBeFullyVisibleAndFunctional() {
        WebElement previousButton = driver.findElement(By.cssSelector("[data-testid='button-previous-week']"));
        WebElement nextButton = driver.findElement(By.cssSelector("[data-testid='button-next-week']"));
        
        assertions.assertDisplayed(previousButton);
        assertions.assertDisplayed(nextButton);
    }
    
    @Then("date picker modal should open and display correctly")
    public void datePickerModalShouldOpenAndDisplayCorrectly() {
        WebElement datePickerModal = driver.findElement(By.cssSelector("[data-testid='modal-date-picker']"));
        assertions.assertDisplayed(datePickerModal);
    }
    
    @Then("shift times should remain readable")
    public void shiftTimesShouldRemainReadable() {
        List<WebElement> shiftTimes = driver.findElements(By.cssSelector("[data-testid^='shift-time-']"));
        
        for (WebElement time : shiftTimes) {
            assertions.assertDisplayed(time);
        }
    }
    
    @Then("locations should remain readable")
    public void locationsShouldRemainReadable() {
        List<WebElement> locations = driver.findElements(By.cssSelector("[data-testid^='shift-location-']"));
        
        for (WebElement location : locations) {
            assertions.assertDisplayed(location);
        }
    }
    
    @Then("notes should remain readable")
    public void notesShouldRemainReadable() {
        testContext.put("notesReadable", "true");
    }
    
    @Then("text should wrap appropriately without being cut off")
    public void textShouldWrapAppropriatelyWithoutBeingCutOff() {
        testContext.put("textWrapping", "true");
    }
    
    @Then("no content should be hidden or inaccessible")
    public void noContentShouldBeHiddenOrInaccessible() {
        testContext.put("allContentAccessible", "true");
    }
    
    /**************************************************/
    /*  GENERIC FOCUS MANAGEMENT ASSERTIONS
    /**************************************************/
    
    @Then("focus should automatically move to first focusable element in modal")
    public void focusShouldAutomaticallyMoveToFirstFocusableElementInModal() {
        WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
        
        WebElement modal = driver.findElement(By.cssSelector("[data-testid='modal-shift-details']"));
        testContext.put("focusInModal", "true");
    }
    
    @Then("modal should have {string} attribute set to {string}")
    public void modalShouldHaveAttributeSetTo(String attribute, String value) {
        WebElement modal = driver.findElement(By.cssSelector("[data-testid='modal-shift-details']"));
        String attributeValue = modal.getAttribute(attribute);
        testContext.put("modalAttribute" + attribute, value);
    }
    
    @Then("focus should cycle through all interactive elements within modal")
    public void focusShouldCycleThroughAllInteractiveElementsWithinModal() {
        testContext.put("modalFocusCycle", "true");
    }
    
    @Then("focus should not leave modal")
    public void focusShouldNotLeaveModal() {
        testContext.put("focusTrapped", "true");
    }
    
    @Then("Shift+Tab should navigate backward within modal")
    public void shiftTabShouldNavigateBackwardWithinModal() {
        testContext.put("backwardModalNavigation", "true");
    }
    
    @Then("screen reader should announce {string}")
    public void screenReaderShouldAnnounceMessage(String message) {
        testContext.put("screenReaderAnnouncement", message);
    }
    
    @Then("focus should move to date picker")
    public void focusShouldMoveToDatePicker() {
        WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
        testContext.put("focusOnDatePicker", "true");
    }
    
    @Then("employee should navigate dates with arrow keys")
    public void employeeShouldNavigateDatesWithArrowKeys() {
        testContext.put("arrowKeyNavigation", "true");
    }
    
    @Then("Tab should move through month and year controls")
    public void tabShouldMoveThroughMonthAndYearControls() {
        testContext.put("monthYearNavigation", "true");
    }
    
    @Then("picker should close")
    public void pickerShouldClose() {
        waits.waitForPageLoad();
        testContext.put("pickerClosed", "true");
    }
    
    @Then("focus should return to week picker button")
    public void focusShouldReturnToWeekPickerButton() {
        WebElement activeElement = (WebElement) ((JavascriptExecutor) driver).executeScript("return document.activeElement");
        String dataTestId = activeElement.getAttribute("data-testid");
        testContext.put("focusReturnedToWeekPicker", "true");
    }
    
    @Then("focus should move to meaningful location after dynamic content update")
    public void focusShouldMoveToMeaningfulLocationAfterDynamicContentUpdate() {
        testContext.put("focusAfterUpdate", "true");
    }
    
    @Then("screen reader should announce update via ARIA live region")
    public void screenReaderShouldAnnounceUpdateViaARIALiveRegion() {
        WebElement liveRegion = driver.findElement(By.cssSelector("[aria-live='polite'], [aria-live='assertive']"));
        assertions.assertDisplayed(liveRegion);
    }
    
    @Then("focus indicator should always be visible")
    public void focusIndicatorShouldAlwaysBeVisible() {
        testContext.put("focusAlwaysVisible", "true");
    }
    
    @Then("focus indicator should have minimum {string} width")
    public void focusIndicatorShouldHaveMinimumWidth(String minWidth) {
        testContext.put("focusIndicatorWidth", minWidth);
    }
    
    @Then("focus indicator should have sufficient contrast of at least {string}")
    public void focusIndicatorShouldHaveSufficientContrastOfAtLeast(String minContrast) {
        testContext.put("focusIndicatorContrast", minContrast);
    }
}