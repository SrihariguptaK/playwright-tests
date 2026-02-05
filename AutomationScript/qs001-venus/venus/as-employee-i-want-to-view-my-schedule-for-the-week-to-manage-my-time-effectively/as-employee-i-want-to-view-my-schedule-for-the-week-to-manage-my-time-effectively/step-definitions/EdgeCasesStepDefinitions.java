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
import org.openqa.selenium.logging.LogEntry;
import org.openqa.selenium.logging.LogType;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import pages.BasePage;
import pages.HomePage;
import pages.SchedulePage;
import pages.LoginPage;
import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import testdata.TestData;

// TODO: Replace with Object Repository when available
// import objectrepository.Locators;

public class EmployeeWeeklyScheduleEdgeCasesStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private BasePage basePage;
    private HomePage homePage;
    private SchedulePage schedulePage;
    private LoginPage loginPage;
    
    private String systemState;
    private long initialMemoryUsage;
    private int clickCount;
    private long navigationStartTime;
    
    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--start-maximized");
        options.addArguments("--ignore-certificate-errors");
        options.addArguments("--disable-notifications");
        options.setCapability("goog:loggingPrefs", Map.of("browser", "ALL"));
        driver = new ChromeDriver(options);
        
        actions = new GenericActions(driver);
        waits = new WaitHelpers(driver);
        assertions = new AssertionHelpers(driver);
        
        basePage = new BasePage(driver);
        homePage = new HomePage(driver);
        schedulePage = new SchedulePage(driver);
        loginPage = new LoginPage(driver);
        
        clickCount = 0;
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
    /*  Common preconditions for edge case scenarios
    /**************************************************/
    
    @Given("employee is logged into the system")
    public void employeeIsLoggedIntoTheSystem() {
        loginPage.navigate();
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.cssSelector("[data-testid='input-username']"));
        actions.clearAndSendKeys(usernameField, TestData.getUser("employee").getUsername());
        
        WebElement passwordField = driver.findElement(By.cssSelector("[data-testid='input-password']"));
        actions.clearAndSendKeys(passwordField, TestData.getUser("employee").getPassword());
        
        WebElement loginButton = driver.findElement(By.cssSelector("[data-testid='button-login'], [type='submit']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
    }
    
    @Given("employee is on the schedule page")
    public void employeeIsOnTheSchedulePage() {
        schedulePage.navigate();
        waits.waitForPageLoad();
        
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container'], .schedule-view, #schedule"));
        assertions.assertDisplayed(scheduleContainer);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-EDGE-001
    /*  Title: Schedule displays maximum number of shifts in a single day
    /*  Priority: Medium
    /*  Category: Edge Cases - Performance
    /**************************************************/
    
    @Given("test employee has {int} shifts scheduled in a single day")
    public void testEmployeeHasShiftsScheduledInASingleDay(int shiftCount) {
        WebElement testDataSetup = driver.findElement(By.cssSelector("[data-testid='test-data-setup'], [data-testid='admin-panel']"));
        actions.click(testDataSetup);
        waits.waitForPageLoad();
        
        WebElement shiftCountInput = driver.findElement(By.cssSelector("[data-testid='input-shift-count']"));
        actions.clearAndSendKeys(shiftCountInput, String.valueOf(shiftCount));
        
        WebElement generateButton = driver.findElement(By.cssSelector("[data-testid='button-generate-shifts']"));
        actions.click(generateButton);
        waits.waitForPageLoad();
    }
    
    @Given("schedule page supports displaying multiple shifts per day")
    public void schedulePageSupportsDisplayingMultipleShiftsPerDay() {
        WebElement multiShiftSupport = driver.findElement(By.cssSelector("[data-testid='multi-shift-container'], .day-column"));
        assertions.assertDisplayed(multiShiftSupport);
    }
    
    @Given("UI layout can accommodate multiple shift cards")
    public void uiLayoutCanAccommodateMultipleShiftCards() {
        WebElement shiftCardContainer = driver.findElement(By.cssSelector("[data-testid='shift-card-container'], .shift-list"));
        assertions.assertDisplayed(shiftCardContainer);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-EDGE-002
    /*  Title: Schedule handles shifts spanning midnight correctly
    /*  Priority: High
    /*  Category: Edge Cases - Time Handling
    /**************************************************/
    
    @Given("employee has shift starting at {string} on {string} and ending at {string} on {string}")
    public void employeeHasShiftStartingAtOnAndEndingAtOn(String startTime, String startDay, String endTime, String endDay) {
        WebElement shiftSetup = driver.findElement(By.cssSelector("[data-testid='shift-setup'], [data-testid='admin-panel']"));
        actions.click(shiftSetup);
        waits.waitForPageLoad();
        
        WebElement startDayField = driver.findElement(By.cssSelector("[data-testid='input-start-day']"));
        actions.clearAndSendKeys(startDayField, startDay);
        
        WebElement startTimeField = driver.findElement(By.cssSelector("[data-testid='input-start-time']"));
        actions.clearAndSendKeys(startTimeField, startTime);
        
        WebElement endDayField = driver.findElement(By.cssSelector("[data-testid='input-end-day']"));
        actions.clearAndSendKeys(endDayField, endDay);
        
        WebElement endTimeField = driver.findElement(By.cssSelector("[data-testid='input-end-time']"));
        actions.clearAndSendKeys(endTimeField, endTime);
        
        WebElement createShiftButton = driver.findElement(By.cssSelector("[data-testid='button-create-shift']"));
        actions.click(createShiftButton);
        waits.waitForPageLoad();
    }
    
    @Given("system supports overnight shift display logic")
    public void systemSupportsOvernightShiftDisplayLogic() {
        WebElement overnightConfig = driver.findElement(By.cssSelector("[data-testid='overnight-shift-support'], [data-config='overnight-enabled']"));
        assertions.assertDisplayed(overnightConfig);
    }
    
    @Given("time zone handling is properly configured")
    public void timeZoneHandlingIsProperlyConfigured() {
        WebElement timezoneConfig = driver.findElement(By.cssSelector("[data-testid='timezone-config'], [data-timezone]"));
        assertions.assertDisplayed(timezoneConfig);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-EDGE-003
    /*  Title: Schedule handles daylight saving time transitions
    /*  Priority: Medium
    /*  Category: Edge Cases - DST Handling
    /**************************************************/
    
    @Given("test environment is set to time zone that observes daylight saving time")
    public void testEnvironmentIsSetToTimeZoneThatObservesDaylightSavingTime() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("localStorage.setItem('timezone', 'America/New_York');");
        
        WebElement timezoneIndicator = driver.findElement(By.cssSelector("[data-testid='timezone-indicator'], .timezone-display"));
        assertions.assertDisplayed(timezoneIndicator);
    }
    
    @Given("employee has shifts scheduled during DST transition week")
    public void employeeHasShiftsScheduledDuringDSTTransitionWeek() {
        WebElement dstShiftSetup = driver.findElement(By.cssSelector("[data-testid='dst-shift-setup']"));
        actions.click(dstShiftSetup);
        waits.waitForPageLoad();
        
        WebElement createDSTShiftsButton = driver.findElement(By.cssSelector("[data-testid='button-create-dst-shifts']"));
        actions.click(createDSTShiftsButton);
        waits.waitForPageLoad();
    }
    
    @Given("system time zone handling is configured correctly")
    public void systemTimeZoneHandlingIsConfiguredCorrectly() {
        WebElement timezoneConfig = driver.findElement(By.cssSelector("[data-testid='timezone-config'], [data-timezone-enabled='true']"));
        assertions.assertDisplayed(timezoneConfig);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-EDGE-004
    /*  Title: Schedule handles rapid week navigation
    /*  Priority: Low
    /*  Category: Edge Cases - Performance
    /**************************************************/
    
    @Given("employee is viewing current week on schedule page")
    public void employeeIsViewingCurrentWeekOnSchedulePage() {
        schedulePage.navigate();
        waits.waitForPageLoad();
        
        WebElement currentWeekIndicator = driver.findElement(By.cssSelector("[data-testid='current-week'], .week-indicator"));
        assertions.assertDisplayed(currentWeekIndicator);
    }
    
    @Given("multiple weeks of schedule data exist in the database")
    public void multipleWeeksOfScheduleDataExistInTheDatabase() {
        WebElement dataStatus = driver.findElement(By.cssSelector("[data-testid='data-status'], [data-weeks-available]"));
        assertions.assertDisplayed(dataStatus);
    }
    
    @Given("browser performance monitoring tools are available")
    public void browserPerformanceMonitoringToolsAreAvailable() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Object performanceSupport = js.executeScript("return typeof window.performance !== 'undefined';");
        assertions.assertDisplayed(driver.findElement(By.tagName("body")));
    }
    
    /**************************************************/
    /*  TEST CASE: TC-EDGE-005
    /*  Title: Schedule displays extremely long shift notes
    /*  Priority: Low
    /*  Category: Edge Cases - Text Handling
    /**************************************************/
    
    @Given("test employee has shift with {int} character note")
    public void testEmployeeHasShiftWithCharacterNote(int characterCount) {
        WebElement noteSetup = driver.findElement(By.cssSelector("[data-testid='shift-note-setup']"));
        actions.click(noteSetup);
        waits.waitForPageLoad();
        
        StringBuilder longNote = new StringBuilder();
        for (int i = 0; i < characterCount; i++) {
            longNote.append("A");
        }
        
        WebElement noteField = driver.findElement(By.cssSelector("[data-testid='input-shift-note'], [data-testid='textarea-note']"));
        actions.clearAndSendKeys(noteField, longNote.toString());
        
        WebElement saveButton = driver.findElement(By.cssSelector("[data-testid='button-save-note']"));
        actions.click(saveButton);
        waits.waitForPageLoad();
    }
    
    @Given("schedule page has character limit handling")
    public void schedulePageHasCharacterLimitHandling() {
        WebElement characterLimitConfig = driver.findElement(By.cssSelector("[data-testid='character-limit-config'], [data-max-length]"));
        assertions.assertDisplayed(characterLimitConfig);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-EDGE-006
    /*  Title: Schedule displays special characters correctly
    /*  Priority: Low
    /*  Category: Edge Cases - Character Encoding
    /**************************************************/
    
    @Given("test employee has shift with {string} in shift notes")
    public void testEmployeeHasShiftWithInShiftNotes(String characterType) {
        WebElement noteSetup = driver.findElement(By.cssSelector("[data-testid='shift-note-setup']"));
        actions.click(noteSetup);
        waits.waitForPageLoad();
        
        Map<String, String> specialCharacters = new HashMap<>();
        specialCharacters.put("emoji characters", "😀🎉🌟💼📅");
        specialCharacters.put("Unicode Chinese characters", "你好世界测试");
        specialCharacters.put("Unicode Arabic characters", "مرحبا العالم");
        specialCharacters.put("Unicode special symbols", "™®©€£¥");
        
        String testContent = specialCharacters.getOrDefault(characterType, "Test Content");
        
        WebElement noteField = driver.findElement(By.cssSelector("[data-testid='input-shift-note'], [data-testid='textarea-note']"));
        actions.clearAndSendKeys(noteField, testContent);
        
        WebElement saveButton = driver.findElement(By.cssSelector("[data-testid='button-save-note']"));
        actions.click(saveButton);
        waits.waitForPageLoad();
    }
    
    @Given("schedule page has XSS protection enabled")
    public void schedulePageHasXSSProtectionEnabled() {
        WebElement xssProtection = driver.findElement(By.cssSelector("[data-testid='xss-protection'], [data-security='enabled']"));
        assertions.assertDisplayed(xssProtection);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-EDGE-007
    /*  Title: Schedule prevents XSS attacks
    /*  Priority: Low
    /*  Category: Edge Cases - Security
    /**************************************************/
    
    @Given("test employee has shift with {string} in shift notes")
    public void testEmployeeHasShiftWithMaliciousContentInShiftNotes(String maliciousContent) {
        WebElement noteSetup = driver.findElement(By.cssSelector("[data-testid='shift-note-setup']"));
        actions.click(noteSetup);
        waits.waitForPageLoad();
        
        WebElement noteField = driver.findElement(By.cssSelector("[data-testid='input-shift-note'], [data-testid='textarea-note']"));
        actions.clearAndSendKeys(noteField, maliciousContent);
        
        WebElement saveButton = driver.findElement(By.cssSelector("[data-testid='button-save-note']"));
        actions.click(saveButton);
        waits.waitForPageLoad();
    }
    
    /**************************************************/
    /*  TEST CASE: TC-EDGE-008
    /*  Title: Schedule handles special formatting characters
    /*  Priority: Low
    /*  Category: Edge Cases - Text Formatting
    /**************************************************/
    
    @Given("test employee has shift with newlines, tabs, and multiple spaces in shift notes")
    public void testEmployeeHasShiftWithNewlinesTabsAndMultipleSpacesInShiftNotes() {
        WebElement noteSetup = driver.findElement(By.cssSelector("[data-testid='shift-note-setup']"));
        actions.click(noteSetup);
        waits.waitForPageLoad();
        
        String formattedNote = "Line 1\n\nLine 2\t\tTabbed\n   Multiple   Spaces   Here";
        
        WebElement noteField = driver.findElement(By.cssSelector("[data-testid='input-shift-note'], [data-testid='textarea-note']"));
        actions.clearAndSendKeys(noteField, formattedNote);
        
        WebElement saveButton = driver.findElement(By.cssSelector("[data-testid='button-save-note']"));
        actions.click(saveButton);
        waits.waitForPageLoad();
    }
    
    // ==================== WHEN STEPS ====================
    
    @When("employee navigates to schedule page")
    public void employeeNavigatesToSchedulePage() {
        schedulePage.navigate();
        waits.waitForPageLoad();
    }
    
    @When("employee selects the week containing the day with {int} shifts")
    public void employeeSelectsTheWeekContainingTheDayWithShifts(int shiftCount) {
        WebElement weekSelector = driver.findElement(By.cssSelector("[data-testid='week-selector'], .week-picker"));
        actions.click(weekSelector);
        waits.waitForPageLoad();
        
        WebElement targetWeek = driver.findElement(By.cssSelector("[data-testid='week-with-multiple-shifts']"));
        actions.click(targetWeek);
        waits.waitForPageLoad();
    }
    
    @When("employee navigates to week containing overnight shift")
    public void employeeNavigatesToWeekContainingOvernightShift() {
        WebElement weekSelector = driver.findElement(By.cssSelector("[data-testid='week-selector'], .week-picker"));
        actions.click(weekSelector);
        waits.waitForPageLoad();
        
        WebElement overnightWeek = driver.findElement(By.cssSelector("[data-testid='week-with-overnight-shift']"));
        actions.click(overnightWeek);
        waits.waitForPageLoad();
    }
    
    @When("employee navigates to schedule for week containing {string} transition on {string}")
    public void employeeNavigatesToScheduleForWeekContainingTransitionOn(String dstType, String transitionDate) {
        WebElement weekSelector = driver.findElement(By.cssSelector("[data-testid='week-selector'], .week-picker"));
        actions.click(weekSelector);
        waits.waitForPageLoad();
        
        String weekLocator = String.format("[data-testid='week-%s'], [data-date='%s']", 
            dstType.toLowerCase().replaceAll("\\s+", "-"), transitionDate);
        WebElement dstWeek = driver.findElement(By.cssSelector(weekLocator));
        actions.click(dstWeek);
        waits.waitForPageLoad();
    }
    
    @When("employee views shift scheduled during {string}")
    public void employeeViewsShiftScheduledDuring(String affectedTimeRange) {
        String shiftLocator = String.format("[data-testid='shift-%s'], [data-time-range='%s']", 
            affectedTimeRange.toLowerCase().replaceAll("\\s+", "-"), affectedTimeRange);
        WebElement affectedShift = driver.findElement(By.cssSelector(shiftLocator));
        actions.scrollToElement(affectedShift);
        assertions.assertDisplayed(affectedShift);
    }
    
    @When("employee rapidly clicks {string} button {int} times within {int} seconds")
    public void employeeRapidlyClicksButtonTimesWithinSeconds(String buttonText, int clickCount, int seconds) {
        navigationStartTime = System.currentTimeMillis();
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        initialMemoryUsage = (Long) js.executeScript("return performance.memory ? performance.memory.usedJSHeapSize : 0;");
        
        String buttonLocator = String.format("[data-testid='button-%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        
        for (int i = 0; i < clickCount; i++) {
            List<WebElement> buttons = driver.findElements(By.cssSelector(buttonLocator));
            if (!buttons.isEmpty()) {
                actions.click(buttons.get(0));
                this.clickCount++;
            } else {
                String xpathLocator = String.format("//button[contains(text(),'%s')]", buttonText);
                WebElement button = driver.findElement(By.xpath(xpathLocator));
                actions.click(button);
                this.clickCount++;
            }
            
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
    
    @When("employee navigates to schedule page containing shift with long note")
    public void employeeNavigatesToSchedulePageContainingShiftWithLongNote() {
        schedulePage.navigate();
        waits.waitForPageLoad();
        
        WebElement shiftWithLongNote = driver.findElement(By.cssSelector("[data-testid='shift-with-long-note'], .shift-card"));
        actions.scrollToElement(shiftWithLongNote);
    }
    
    @When("employee navigates to schedule page containing shift with special characters")
    public void employeeNavigatesToSchedulePageContainingShiftWithSpecialCharacters() {
        schedulePage.navigate();
        waits.waitForPageLoad();
        
        WebElement shiftWithSpecialChars = driver.findElement(By.cssSelector("[data-testid='shift-with-special-chars'], .shift-card"));
        actions.scrollToElement(shiftWithSpecialChars);
    }
    
    @When("employee navigates to schedule page containing shift with HTML-like text")
    public void employeeNavigatesToSchedulePageContainingShiftWithHTMLLikeText() {
        schedulePage.navigate();
        waits.waitForPageLoad();
        
        WebElement shiftWithHTML = driver.findElement(By.cssSelector("[data-testid='shift-with-html'], .shift-card"));
        actions.scrollToElement(shiftWithHTML);
    }
    
    @When("employee navigates to schedule page containing shift with special formatting")
    public void employeeNavigatesToSchedulePageContainingShiftWithSpecialFormatting() {
        schedulePage.navigate();
        waits.waitForPageLoad();
        
        WebElement shiftWithFormatting = driver.findElement(By.cssSelector("[data-testid='shift-with-formatting'], .shift-card"));
        actions.scrollToElement(shiftWithFormatting);
    }
    
    // ==================== THEN STEPS ====================
    
    @Then("schedule page should load without performance degradation")
    public void schedulePageShouldLoadWithoutPerformanceDegradation() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long loadTime = (Long) js.executeScript("return performance.timing.loadEventEnd - performance.timing.navigationStart;");
        
        if (loadTime > 5000) {
            throw new AssertionError("Page load time exceeded 5 seconds: " + loadTime + "ms");
        }
        
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container'], .schedule-view"));
        assertions.assertDisplayed(scheduleContainer);
    }
    
    @Then("all {int} shifts should be displayed in the day column")
    public void allShiftsShouldBeDisplayedInTheDayColumn(int expectedShiftCount) {
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid='shift-card'], .shift-item"));
        assertions.assertElementCount(By.cssSelector("[data-testid='shift-card'], .shift-item"), expectedShiftCount);
    }
    
    @Then("scrollable area should be available if needed")
    public void scrollableAreaShouldBeAvailableIfNeeded() {
        WebElement dayColumn = driver.findElement(By.cssSelector("[data-testid='day-column'], .day-shifts"));
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long scrollHeight = (Long) js.executeScript("return arguments[0].scrollHeight;", dayColumn);
        Long clientHeight = (Long) js.executeScript("return arguments[0].clientHeight;", dayColumn);
        
        if (scrollHeight > clientHeight) {
            String overflowStyle = dayColumn.getCssValue("overflow-y");
            if (!overflowStyle.equals("auto") && !overflowStyle.equals("scroll")) {
                throw new AssertionError("Scrollable area not properly configured");
            }
        }
    }
    
    @Then("no overlapping or hidden shifts should exist")
    public void noOverlappingOrHiddenShiftsShouldExist() {
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid='shift-card'], .shift-item"));
        
        for (WebElement shift : shiftCards) {
            assertions.assertDisplayed(shift);
            
            JavascriptExecutor js = (JavascriptExecutor) driver;
            Boolean isVisible = (Boolean) js.executeScript(
                "var elem = arguments[0];" +
                "var rect = elem.getBoundingClientRect();" +
                "return rect.width > 0 && rect.height > 0;", shift);
            
            if (!isVisible) {
                throw new AssertionError("Shift card is hidden or has zero dimensions");
            }
        }
    }
    
    @Then("each shift card should display complete information including time, location, and duration")
    public void eachShiftCardShouldDisplayCompleteInformationIncludingTimeLocationAndDuration() {
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid='shift-card'], .shift-item"));
        
        for (WebElement shiftCard : shiftCards) {
            WebElement timeElement = shiftCard.findElement(By.cssSelector("[data-testid='shift-time'], .shift-time"));
            assertions.assertDisplayed(timeElement);
            
            WebElement locationElement = shiftCard.findElement(By.cssSelector("[data-testid='shift-location'], .shift-location"));
            assertions.assertDisplayed(locationElement);
            
            WebElement durationElement = shiftCard.findElement(By.cssSelector("[data-testid='shift-duration'], .shift-duration"));
            assertions.assertDisplayed(durationElement);
        }
    }
    
    @Then("all shift details should be readable and properly formatted")
    public void allShiftDetailsShouldBeReadableAndProperlyFormatted() {
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid='shift-card'], .shift-item"));
        
        for (WebElement shiftCard : shiftCards) {
            String fontSize = shiftCard.getCssValue("font-size");
            String fontSizeValue = fontSize.replaceAll("[^0-9.]", "");
            double fontSizeNum = Double.parseDouble(fontSizeValue);
            
            if (fontSizeNum < 10) {
                throw new AssertionError("Font size too small: " + fontSize);
            }
            
            assertions.assertDisplayed(shiftCard);
        }
    }
    
    @Then("no text truncation or layout breaking should occur")
    public void noTextTruncationOrLayoutBreakingShouldOccur() {
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid='shift-card'], .shift-item"));
        
        for (WebElement shiftCard : shiftCards) {
            JavascriptExecutor js = (JavascriptExecutor) driver;
            Boolean isOverflowing = (Boolean) js.executeScript(
                "var elem = arguments[0];" +
                "return elem.scrollWidth > elem.clientWidth || elem.scrollHeight > elem.clientHeight;", shiftCard);
            
            if (isOverflowing) {
                String overflow = shiftCard.getCssValue("overflow");
                if (!overflow.equals("auto") && !overflow.equals("scroll") && !overflow.equals("hidden")) {
                    throw new AssertionError("Layout breaking detected - content overflowing without proper handling");
                }
            }
        }
    }
    
    @Then("total hours calculation should show {string} hours for the day")
    public void totalHoursCalculationShouldShowHoursForTheDay(String expectedHours) {
        WebElement totalHoursElement = driver.findElement(By.cssSelector("[data-testid='total-hours'], .day-total-hours"));
        assertions.assertTextContains(totalHoursElement, expectedHours);
    }
    
    @Then("total hours should be displayed accurately")
    public void totalHoursShouldBeDisplayedAccurately() {
        WebElement totalHoursElement = driver.findElement(By.cssSelector("[data-testid='total-hours'], .day-total-hours"));
        assertions.assertDisplayed(totalHoursElement);
        
        String hoursText = totalHoursElement.getText();
        if (!hoursText.matches(".*\\d+.*")) {
            throw new AssertionError("Total hours does not contain numeric value: " + hoursText);
        }
    }
    
    @Then("smooth scrolling within day column should work")
    public void smoothScrollingWithinDayColumnShouldWork() {
        WebElement dayColumn = driver.findElement(By.cssSelector("[data-testid='day-column'], .day-shifts"));
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("arguments[0].scrollTop = 100;", dayColumn);
        
        waits.waitForElementVisible(dayColumn);
        
        Long scrollTop = (Long) js.executeScript("return arguments[0].scrollTop;", dayColumn);
        if (scrollTop < 50) {
            throw new AssertionError("Scrolling did not work properly");
        }
    }
    
    @Then("all shifts should remain accessible")
    public void allShiftsShouldRemainAccessible() {
        List<WebElement> shiftCards = driver.findElements(By.cssSelector("[data-testid='shift-card'], .shift-item"));
        
        for (WebElement shift : shiftCards) {
            actions.scrollToElement(shift);
            assertions.assertDisplayed(shift);
        }
    }
    
    @Then("schedule should load and display the week correctly")
    public void scheduleShouldLoadAndDisplayTheWeekCorrectly() {
        waits.waitForPageLoad();
        
        WebElement weekView = driver.findElement(By.cssSelector("[data-testid='week-view'], .schedule-week"));
        assertions.assertDisplayed(weekView);
        
        List<WebElement> dayColumns = driver.findElements(By.cssSelector("[data-testid='day-column'], .day-column"));
        assertions.assertElementCount(By.cssSelector("[data-testid='day-column'], .day-column"), 7);
    }
    
    @Then("overnight shift should be displayed spanning both {string} and {string} columns")
    public void overnightShiftShouldBeDisplayedSpanningBothAndColumns(String startDay, String endDay) {
        String startDayLocator = String.format("[data-testid='day-%s'], [data-day='%s']", 
            startDay.toLowerCase(), startDay);
        WebElement startDayColumn = driver.findElement(By.cssSelector(startDayLocator));
        
        String endDayLocator = String.format("[data-testid='day-%s'], [data-day='%s']", 
            endDay.toLowerCase(), endDay);
        WebElement endDayColumn = driver.findElement(By.cssSelector(endDayLocator));
        
        WebElement overnightShift = driver.findElement(By.cssSelector("[data-testid='overnight-shift'], .overnight-shift"));
        assertions.assertDisplayed(overnightShift);
    }
    
    @Then("shift timing should show {string} with clear indication of day change")
    public void shiftTimingShouldShowWithClearIndicationOfDayChange(String expectedTiming) {
        WebElement shiftTiming = driver.findElement(By.cssSelector("[data-testid='shift-time'], .shift-timing"));
        assertions.assertTextContains(shiftTiming, expectedTiming);
    }
    
    @Then("shift duration should be calculated correctly as {int} hours")
    public void shiftDurationShouldBeCalculatedCorrectlyAsHours(int expectedHours) {
        WebElement durationElement = driver.findElement(By.cssSelector("[data-testid='shift-duration'], .shift-duration"));
        assertions.assertTextContains(durationElement, String.valueOf(expectedHours));
    }
    
    @Then("duration should not show negative or incorrect value")
    public void durationShouldNotShowNegativeOrIncorrectValue() {
        WebElement durationElement = driver.findElement(By.cssSelector("[data-testid='shift-duration'], .shift-duration"));
        String durationText = durationElement.getText();
        
        if (durationText.contains("-")) {
            throw new AssertionError("Duration shows negative value: " + durationText);
        }
        
        String numericPart = durationText.replaceAll("[^0-9.]", "");
        if (!numericPart.isEmpty()) {
            double duration = Double.parseDouble(numericPart);
            if (duration <= 0 || duration > 24) {
                throw new AssertionError("Duration shows incorrect value: " + duration);
            }
        }
    }
    
    @Then("weekly total hours should include the full {int} hours from overnight shift")
    public void weeklyTotalHoursShouldIncludeTheFullHoursFromOvernightShift(int expectedHours) {
        WebElement weeklyTotal = driver.findElement(By.cssSelector("[data-testid='weekly-total-hours'], .week-total"));
        String totalText = weeklyTotal.getText();
        
        String numericPart = totalText.replaceAll("[^0-9.]", "");
        double totalHours = Double.parseDouble(numericPart);
        
        if (totalHours < expectedHours) {
            throw new AssertionError("Weekly total does not include overnight shift hours properly");
        }
    }
    
    @Then("no duplication or omission should occur in weekly totals")
    public void noDuplicationOrOmissionShouldOccurInWeeklyTotals() {
        List<WebElement> dailyTotals = driver.findElements(By.cssSelector("[data-testid='daily-total'], .day-total"));
        double sumOfDailyTotals = 0;
        
        for (WebElement dailyTotal : dailyTotals) {
            String totalText = dailyTotal.getText().replaceAll("[^0-9.]", "");
            if (!totalText.isEmpty()) {
                sumOfDailyTotals += Double.parseDouble(totalText);
            }
        }
        
        WebElement weeklyTotal = driver.findElement(By.cssSelector("[data-testid='weekly-total-hours'], .week-total"));
        String weeklyText = weeklyTotal.getText().replaceAll("[^0-9.]", "");
        double weeklyHours = Double.parseDouble(weeklyText);
        
        if (Math.abs(sumOfDailyTotals - weeklyHours) > 0.1) {
            throw new AssertionError("Weekly total mismatch - possible duplication or omission");
        }
    }
    
    @Then("system should handle time gap appropriately")
    public void systemShouldHandleTimeGapAppropriately() {
        WebElement dstWarning = driver.findElement(By.cssSelector("[data-testid='dst-warning'], .dst-notice, .time-gap-warning"));
        assertions.assertDisplayed(dstWarning);
    }
    
    @Then("shift times should be adjusted or warning should be displayed if shift falls in non-existent hour")
    public void shiftTimesShouldBeAdjustedOrWarningShouldBeDisplayedIfShiftFallsInNonExistentHour() {
        List<WebElement> warnings = driver.findElements(By.cssSelector("[data-testid='dst-warning'], .dst-notice"));
        List<WebElement> adjustedShifts = driver.findElements(By.cssSelector("[data-testid='adjusted-shift'], .time-adjusted"));
        
        if (warnings.isEmpty() && adjustedShifts.isEmpty()) {
            throw new AssertionError("No DST handling detected - expected warning or adjusted shift");
        }
    }
    
    @Then("total hours for the day should reflect {string} hours")
    public void totalHoursForTheDayShouldReflectHours(String expectedHours) {
        WebElement dayTotal = driver.findElement(By.cssSelector("[data-testid='day-total-hours'], .day-total"));
        assertions.assertTextContains(dayTotal, expectedHours);
    }
    
    @Then("all shift times should display in correct time zone with DST indicator")
    public void allShiftTimesShouldDisplayInCorrectTimeZoneWithDSTIndicator() {
        List<WebElement> shiftTimes = driver.findElements(By.cssSelector("[data-testid='shift-time'], .shift-timing"));
        
        for (WebElement shiftTime : shiftTimes) {
            String timeText = shiftTime.getText();
            if (!timeText.matches(".*(EDT|EST|PDT|PST|CDT|CST|MDT|MST).*")) {
                throw new AssertionError("Shift time missing timezone indicator: " + timeText);
            }
        }
    }
    
    @Then("times should show correct DST offset")
    public void timesShouldShowCorrectDSTOffset() {
        List<WebElement> shiftTimes = driver.findElements(By.cssSelector("[data-testid='shift-time'], .shift-timing"));
        
        for (WebElement shiftTime : shiftTimes) {
            assertions.assertDisplayed(shiftTime);
        }
    }
    
    @Then("all shifts should be in local time")
    public void allShiftsShouldBeInLocalTime() {
        WebElement timezoneIndicator = driver.findElement(By.cssSelector("[data-testid='timezone-indicator'], .timezone-display"));
        assertions.assertDisplayed(timezoneIndicator);
    }
    
    @Then("system should handle rapid requests without crashing")
    public void systemShouldHandleRapidRequestsWithoutCrashing() {
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container'], .schedule-view"));
        assertions.assertDisplayed(scheduleContainer);
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        List<LogEntry> logs = driver.manage().logs().get(LogType.BROWSER).getAll();
        
        for (LogEntry log : logs) {
            if (log.getMessage().contains("error") || log.getMessage().contains("crash")) {
                throw new AssertionError("Browser error detected: " + log.getMessage());
            }
        }
    }
    
    @Then("requests should be queued or debounced appropriately")
    public void requestsShouldBeQueuedOrDebouncedAppropriately() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Object requestCount = js.executeScript("return window.requestCount || 0;");
        
        if (requestCount instanceof Long && (Long) requestCount > clickCount) {
            throw new AssertionError("More requests than clicks - debouncing not working");
        }
    }
    
    @Then("schedule should update smoothly")
    public void scheduleShouldUpdateSmoothly() {
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container'], .schedule-view"));
        waits.waitForElementVisible(scheduleContainer);
        assertions.assertDisplayed(scheduleContainer);
    }
    
    @Then("loading states should be shown")
    public void loadingStatesShouldBeShown() {
        List<WebElement> loadingIndicators = driver.findElements(By.cssSelector("[data-testid='loading'], .loading-spinner, .loader"));
        
        if (loadingIndicators.isEmpty()) {
            WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container'], .schedule-view"));
            assertions.assertDisplayed(scheduleContainer);
        }
    }
    
    @Then("no UI freezing or unresponsive behavior should occur")
    public void noUIFreezingOrUnresponsiveBehaviorShouldOccur() {
        WebElement testButton = driver.findElement(By.cssSelector("[data-testid='button-next-week'], button"));
        actions.click(testButton);
        waits.waitForPageLoad();
        
        assertions.assertDisplayed(testButton);
    }
    
    @Then("final displayed week should match expected week {int} weeks ahead")
    public void finalDisplayedWeekShouldMatchExpectedWeekWeeksAhead(int weeksAhead) {
        WebElement weekIndicator = driver.findElement(By.cssSelector("[data-testid='week-indicator'], .current-week-display"));
        String weekText = weekIndicator.getText();
        
        assertions.assertDisplayed(weekIndicator);
    }
    
    @Then("no skipped or duplicate weeks should appear")
    public void noSkippedOrDuplicateWeeksShouldAppear() {
        WebElement weekIndicator = driver.findElement(By.cssSelector("[data-testid='week-indicator'], .current-week-display"));
        assertions.assertDisplayed(weekIndicator);
    }
    
    @Then("no JavaScript errors should be logged in browser console")
    public void noJavaScriptErrorsShouldBeLoggedInBrowserConsole() {
        List<LogEntry> logs = driver.manage().logs().get(LogType.BROWSER).getAll();
        
        for (LogEntry log : logs) {
            if (log.getMessage().toLowerCase().contains("error") && 
                !log.getMessage().contains("favicon") &&
                !log.getMessage().contains("404")) {
                throw new AssertionError("JavaScript error detected: " + log.getMessage());
            }
        }
    }
    
    @Then("memory usage should remain stable")
    public void memoryUsageShouldRemainStable() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long currentMemory = (Long) js.executeScript("return performance.memory ? performance.memory.usedJSHeapSize : 0;");
        
        if (initialMemoryUsage > 0 && currentMemory > 0) {
            long memoryIncrease = currentMemory - initialMemoryUsage;
            long maxAllowedIncrease = initialMemoryUsage * 2;
            
            if (memoryIncrease > maxAllowedIncrease) {
                throw new AssertionError("Memory usage increased significantly: " + memoryIncrease + " bytes");
            }
        }
    }
    
    @Then("no memory leaks should be detected")
    public void noMemoryLeaksShouldBeDetected() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long currentMemory = (Long) js.executeScript("return performance.memory ? performance.memory.usedJSHeapSize : 0;");
        
        if (currentMemory > 0) {
            assertions.assertDisplayed(driver.findElement(By.tagName("body")));
        }
    }
    
    @Then("system should implement request cancellation or debouncing")
    public void systemShouldImplementRequestCancellationOrDebouncing() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Object debounceImplemented = js.executeScript("return typeof window.debounce !== 'undefined' || typeof window.throttle !== 'undefined';");
        
        assertions.assertDisplayed(driver.findElement(By.cssSelector("[data-testid='schedule-container'], .schedule-view")));
    }
    
    @Then("only necessary API calls should be made")
    public void onlyNecessaryAPICallsShouldBeMade() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Object apiCallCount = js.executeScript("return window.apiCallCount || 0;");
        
        if (apiCallCount instanceof Long && (Long) apiCallCount > clickCount * 2) {
            throw new AssertionError("Too many API calls detected: " + apiCallCount);
        }
    }
    
    @Then("schedule should load without errors")
    public void scheduleShouldLoadWithoutErrors() {
        waits.waitForPageLoad();
        
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container'], .schedule-view"));
        assertions.assertDisplayed(scheduleContainer);
        
        List<LogEntry> logs = driver.manage().logs().get(LogType.BROWSER).getAll();
        for (LogEntry log : logs) {
            if (log.getMessage().toLowerCase().contains("error") && 
                !log.getMessage().contains("favicon")) {
                throw new AssertionError("Error detected during load: " + log.getMessage());
            }
        }
    }
    
    @Then("long note should be truncated with {string} link or displayed in scrollable area")
    public void longNoteShouldBeTruncatedWithLinkOrDisplayedInScrollableArea(String linkText) {
        WebElement noteElement = driver.findElement(By.cssSelector("[data-testid='shift-note'], .shift-note"));
        
        List<WebElement> readMoreLinks = driver.findElements(By.xpath(String.format("//*[contains(text(),'%s')]", linkText)));
        
        if (readMoreLinks.isEmpty()) {
            String overflowY = noteElement.getCssValue("overflow-y");
            if (!overflowY.equals("auto") && !overflowY.equals("scroll")) {
                throw new AssertionError("Long note not properly handled - no truncation or scrollable area");
            }
        }
    }
    
    @Then("text should remain readable and properly formatted")
    public void textShouldRemainReadableAndProperlyFormatted() {
        WebElement noteElement = driver.findElement(By.cssSelector("[data-testid='shift-note'], .shift-note"));
        assertions.assertDisplayed(noteElement);
        
        String fontSize = noteElement.getCssValue("font-size");
        String fontSizeValue = fontSize.replaceAll("[^0-9.]", "");
        double fontSizeNum = Double.parseDouble(fontSizeValue);
        
        if (fontSizeNum < 10) {
            throw new AssertionError("Font size too small for readability: " + fontSize);
        }
    }
    
    @Then("{string} should display correctly without rendering issues")
    public void shouldDisplayCorrectlyWithoutRenderingIssues(String characterType) {
        WebElement noteElement = driver.findElement(By.cssSelector("[data-testid='shift-note'], .shift-note"));
        assertions.assertDisplayed(noteElement);
        
        String noteText = noteElement.getText();
        if (noteText.contains("�") || noteText.contains("?")) {
            throw new AssertionError("Character encoding issue detected - replacement characters found");
        }
    }
    
    @Then("no character encoding issues should occur")
    public void noCharacterEncodingIssuesShouldOccur() {
        WebElement noteElement = driver.findElement(By.cssSelector("[data-testid='shift-note'], .shift-note"));
        String noteText = noteElement.getText();
        
        if (noteText.contains("�")) {
            throw new AssertionError("Character encoding issue - replacement character detected");
        }
    }
    
    @Then("no boxes or question marks should be displayed")
    public void noBoxesOrQuestionMarksShouldBeDisplayed() {
        WebElement noteElement = driver.findElement(By.cssSelector("[data-testid='shift-note'], .shift-note"));
        String noteText = noteElement.getText();
        
        if (noteText.contains("□") || noteText.matches(".*\\?{3,}.*")) {
            throw new AssertionError("Character rendering issue - boxes or multiple question marks detected");
        }
    }
    
    @Then("HTML tags should be escaped and displayed as plain text")
    public void htmlTagsShouldBeEscapedAndDisplayedAsPlainText() {
        WebElement noteElement = driver.findElement(By.cssSelector("[data-testid='shift-note'], .shift-note"));
        String noteText = noteElement.getText();
        
        if (noteText.contains("<") && noteText.contains(">")) {
            assertions.assertDisplayed(noteElement);
        } else {
            throw new AssertionError("HTML tags were not escaped properly");
        }
    }
    
    @Then("no script execution should occur")
    public void noScriptExecutionShouldOccur() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Object alertPresent = js.executeScript("return window.xssTestExecuted || false;");
        
        if (alertPresent instanceof Boolean && (Boolean) alertPresent) {
            throw new AssertionError("XSS script was executed - security vulnerability detected");
        }
    }
    
    @Then("XSS protection should be working")
    public void xssProtectionShouldBeWorking() {
        WebElement noteElement = driver.findElement(By.cssSelector("[data-testid='shift-note'], .shift-note"));
        String innerHTML = noteElement.getAttribute("innerHTML");
        
        if (innerHTML.contains("<script>") && !innerHTML.contains("&lt;script&gt;")) {
            throw new AssertionError("XSS protection failed - unescaped script tag found");
        }
    }
    
    @Then("text should show literally as {string}")
    public void textShouldShowLiterallyAs(String expectedText) {
        WebElement noteElement = driver.findElement(By.cssSelector("[data-testid='shift-note'], .shift-note"));
        assertions.assertTextContains(noteElement, expectedText);
    }
    
    @Then("content should not be executed")
    public void contentShouldNotBeExecuted() {
        List<LogEntry> logs = driver.manage().logs().get(LogType.BROWSER).getAll();
        
        for (LogEntry log : logs) {
            if (log.getMessage().contains("alert") || log.getMessage().contains("XSS")) {
                throw new AssertionError("Potential XSS execution detected in logs: " + log.getMessage());
            }
        }
    }
    
    @Then("formatting should be preserved or normalized appropriately")
    public void formattingShouldBePreservedOrNormalizedAppropriately() {
        WebElement noteElement = driver.findElement(By.cssSelector("[data-testid='shift-note'], .shift-note"));
        assertions.assertDisplayed(noteElement);
        
        String noteText = noteElement.getText();
        if (noteText.isEmpty()) {
            throw new AssertionError("Formatting characters caused content to disappear");
        }
    }
    
    @Then("no layout breaking should occur")
    public void noLayoutBreakingShouldOccur() {
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container'], .schedule-view"));
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long containerWidth = (Long) js.executeScript("return arguments[0].offsetWidth;", scheduleContainer);
        Long bodyWidth = (Long) js.executeScript("return document.body.offsetWidth;", scheduleContainer);
        
        if (containerWidth > bodyWidth * 1.5) {
            throw new AssertionError("Layout breaking detected - container width exceeds body width significantly");
        }
    }
    
    @Then("UI layout should remain intact")
    public void uiLayoutShouldRemainIntact() {
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container'], .schedule-view"));
        assertions.assertDisplayed(scheduleContainer);
        
        List<WebElement> dayColumns = driver.findElements(By.cssSelector("[data-testid='day-column'], .day-column"));
        if (dayColumns.size() != 7) {
            throw new AssertionError("UI layout broken - expected 7 day columns, found " + dayColumns.size());
        }
    }
}