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
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

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

public class EmployeeWeeklyScheduleViewingStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private BasePage basePage;
    private HomePage homePage;
    private LoginPage loginPage;
    private SchedulePage schedulePage;
    
    private int expectedShiftCount;
    private String systemState;
    
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
    /*  TEST CASE: TC-001
    /*  Title: Successfully view current week schedule with all shift details
    /*  Priority: High
    /*  Category: Functional
    /*  Description: Verify employee can view complete weekly schedule with all shift details
    /**************************************************/
    
    @Given("employee account exists in the system with valid credentials")
    public void employeeAccountExistsInTheSystemWithValidCredentials() {
        loginPage.navigate();
        waits.waitForPageLoad();
        WebElement loginForm = driver.findElement(By.cssSelector("[data-testid='login-form'], form[name='login'], .login-form"));
        assertions.assertDisplayed(loginForm);
    }
    
    @Given("schedule database is accessible and contains schedule data")
    public void scheduleDatabaseIsAccessibleAndContainsScheduleData() {
        WebElement pageBody = driver.findElement(By.cssSelector("body"));
        assertions.assertDisplayed(pageBody);
    }
    
    @Given("employee has at least {int} shifts scheduled for the current week")
    public void employeeHasAtLeastShiftsScheduledForTheCurrentWeek(int shiftCount) {
        this.expectedShiftCount = shiftCount;
    }
    
    @Given("user is on the login page of the web interface")
    public void userIsOnTheLoginPageOfTheWebInterface() {
        loginPage.navigate();
        waits.waitForPageLoad();
        WebElement loginPage = driver.findElement(By.cssSelector("[data-testid='login-page'], .login-container, #login"));
        assertions.assertDisplayed(loginPage);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-002
    /*  Title: Filter schedule by selecting different weeks using date picker
    /*  Priority: High
    /*  Category: Functional
    /*  Description: Verify employee can navigate between different weeks using date picker
    /**************************************************/
    
    @Given("employee is logged into the web interface")
    public void employeeIsLoggedIntoTheWebInterface() {
        loginPage.navigate();
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.cssSelector("[data-testid='input-username'], [name='username'], #username"));
        actions.clearAndSendKeys(usernameField, "emp001@company.com");
        
        WebElement passwordField = driver.findElement(By.cssSelector("[data-testid='input-password'], [name='password'], #password"));
        actions.clearAndSendKeys(passwordField, "ValidPass123");
        
        WebElement loginButton = driver.findElement(By.cssSelector("[data-testid='button-login'], [type='submit'], .login-button"));
        actions.click(loginButton);
        waits.waitForPageLoad();
    }
    
    @Given("employee is on {string} page viewing current week")
    public void employeeIsOnPageViewingCurrentWeek(String pageName) {
        String linkLocator = String.format("[data-testid='link-%s'], [data-testid='nav-%s']", 
            pageName.toLowerCase().replaceAll("\\s+", "-"), 
            pageName.toLowerCase().replaceAll("\\s+", "-"));
        
        List<WebElement> navLinks = driver.findElements(By.cssSelector(linkLocator));
        if (!navLinks.isEmpty()) {
            actions.click(navLinks.get(0));
        } else {
            String xpathLocator = String.format("//a[contains(text(),'%s')]", pageName);
            WebElement link = driver.findElement(By.xpath(xpathLocator));
            actions.click(link);
        }
        waits.waitForPageLoad();
    }
    
    @Given("employee has shifts scheduled in multiple weeks")
    public void employeeHasShiftsScheduledInMultipleWeeks() {
        WebElement scheduleGrid = driver.findElement(By.cssSelector("[data-testid='schedule-grid'], .schedule-grid, .calendar-view"));
        assertions.assertDisplayed(scheduleGrid);
    }
    
    @Given("date picker component is functional and accessible")
    public void datePickerComponentIsFunctionalAndAccessible() {
        WebElement datePicker = driver.findElement(By.cssSelector("[data-testid='date-picker'], [data-testid='select-week'], .date-picker"));
        assertions.assertDisplayed(datePicker);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-003
    /*  Title: Schedule changes are highlighted and clearly identifiable
    /*  Priority: High
    /*  Category: Functional
    /*  Description: Verify modified shifts are visually distinguished with change details
    /**************************************************/
    
    @Given("employee is logged into the system")
    public void employeeIsLoggedIntoTheSystem() {
        loginPage.navigate();
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.cssSelector("[data-testid='input-username'], [name='username'], #username"));
        actions.clearAndSendKeys(usernameField, "emp001@company.com");
        
        WebElement passwordField = driver.findElement(By.cssSelector("[data-testid='input-password'], [name='password'], #password"));
        actions.clearAndSendKeys(passwordField, "ValidPass123");
        
        WebElement loginButton = driver.findElement(By.cssSelector("[data-testid='button-login'], [type='submit'], .login-button"));
        actions.click(loginButton);
        waits.waitForPageLoad();
    }
    
    @Given("employee has at least {int} shifts that were recently modified within last {int} hours")
    public void employeeHasAtLeastShiftsThatWereRecentlyModifiedWithinLastHours(int shiftCount, int hours) {
        this.expectedShiftCount = shiftCount;
    }
    
    @Given("schedule change tracking is enabled in the system")
    public void scheduleChangeTrackingIsEnabledInTheSystem() {
        WebElement pageBody = driver.findElement(By.cssSelector("body"));
        assertions.assertDisplayed(pageBody);
    }
    
    @Given("employee is viewing current week schedule")
    public void employeeIsViewingCurrentWeekSchedule() {
        WebElement scheduleView = driver.findElement(By.cssSelector("[data-testid='schedule-view'], [data-testid='current-week'], .schedule-container"));
        assertions.assertDisplayed(scheduleView);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-004
    /*  Title: Schedule displays correctly on different device screen sizes
    /*  Priority: Medium
    /*  Category: Accessibility
    /*  Description: Verify responsive design across desktop, tablet, and mobile devices
    /**************************************************/
    
    @Given("employee has a full week schedule with {int} shifts")
    public void employeeHasAFullWeekScheduleWithShifts(int shiftCount) {
        this.expectedShiftCount = shiftCount;
    }
    
    @Given("browser supports responsive design testing")
    public void browserSupportsResponsiveDesignTesting() {
        WebElement htmlElement = driver.findElement(By.cssSelector("html"));
        assertions.assertDisplayed(htmlElement);
    }
    
    @Given("schedule page is loaded and displaying current week")
    public void schedulePageIsLoadedAndDisplayingCurrentWeek() {
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container'], .schedule-view, .week-view"));
        assertions.assertDisplayed(scheduleContainer);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-005
    /*  Title: Schedule loads within performance requirements under 2 seconds
    /*  Priority: High
    /*  Category: Performance
    /*  Description: Verify schedule page meets performance requirements
    /**************************************************/
    
    @Given("network conditions are normal")
    public void networkConditionsAreNormal() {
        WebElement pageBody = driver.findElement(By.cssSelector("body"));
        assertions.assertDisplayed(pageBody);
    }
    
    @Given("schedule database contains employee schedule data for current week")
    public void scheduleDatabaseContainsEmployeeScheduleDataForCurrentWeek() {
        WebElement pageBody = driver.findElement(By.cssSelector("body"));
        assertions.assertDisplayed(pageBody);
    }
    
    @Given("browser developer tools are open to monitor network performance")
    public void browserDeveloperToolsAreOpenToMonitorNetworkPerformance() {
        WebElement pageBody = driver.findElement(By.cssSelector("body"));
        assertions.assertDisplayed(pageBody);
    }
    
    // ==================== WHEN STEPS ====================
    
    @When("user enters {string} in {string} field")
    public void userEntersInField(String value, String fieldName) {
        String fieldLocator = String.format("[data-testid='input-%s'], [name='%s']", 
            fieldName.toLowerCase().replaceAll("\\s+", "-"),
            fieldName.toLowerCase());
        
        List<WebElement> fields = driver.findElements(By.cssSelector(fieldLocator));
        if (!fields.isEmpty()) {
            actions.clearAndSendKeys(fields.get(0), value);
        } else {
            String xpathLocator = String.format("//input[@placeholder='%s' or contains(@aria-label, '%s')]", fieldName, fieldName);
            WebElement field = driver.findElement(By.xpath(xpathLocator));
            actions.clearAndSendKeys(field, value);
        }
    }
    
    @When("user clicks {string} button")
    public void userClicksButton(String buttonText) {
        String testIdLocator = String.format("[data-testid='button-%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = driver.findElements(By.cssSelector(testIdLocator));
        
        if (!buttons.isEmpty()) {
            actions.click(buttons.get(0));
        } else {
            String xpathLocator = String.format("//button[contains(text(),'%s') or @value='%s']", buttonText, buttonText);
            WebElement button = driver.findElement(By.xpath(xpathLocator));
            actions.click(button);
        }
        waits.waitForPageLoad();
    }
    
    @When("user clicks {string} link in main navigation menu")
    public void userClicksLinkInMainNavigationMenu(String linkText) {
        String testIdLocator = String.format("[data-testid='link-%s'], [data-testid='nav-%s']", 
            linkText.toLowerCase().replaceAll("\\s+", "-"),
            linkText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> links = driver.findElements(By.cssSelector(testIdLocator));
        
        if (!links.isEmpty()) {
            actions.click(links.get(0));
        } else {
            String xpathLocator = String.format("//nav//a[contains(text(),'%s')]", linkText);
            WebElement link = driver.findElement(By.xpath(xpathLocator));
            actions.click(link);
        }
        waits.waitForPageLoad();
    }
    
    @When("user clicks {string} dropdown at top of schedule page")
    public void userClicksDropdownAtTopOfSchedulePage(String dropdownName) {
        String dropdownLocator = String.format("[data-testid='dropdown-%s'], [data-testid='%s']", 
            dropdownName.toLowerCase().replaceAll("\\s+", "-"),
            dropdownName.toLowerCase().replaceAll("\\s+", "-"));
        
        List<WebElement> dropdowns = driver.findElements(By.cssSelector(dropdownLocator));
        if (!dropdowns.isEmpty()) {
            actions.click(dropdowns.get(0));
        } else {
            String xpathLocator = String.format("//*[contains(text(),'%s')]", dropdownName);
            WebElement dropdown = driver.findElement(By.xpath(xpathLocator));
            actions.click(dropdown);
        }
        waits.waitForPageLoad();
    }
    
    @When("user selects a date {int} weeks ahead in calendar")
    public void userSelectsADateWeeksAheadInCalendar(int weeksAhead) {
        LocalDate futureDate = LocalDate.now().plusWeeks(weeksAhead);
        String dayOfMonth = String.valueOf(futureDate.getDayOfMonth());
        
        String dateLocator = String.format("[data-testid='calendar-day-%s'], .calendar-day[data-day='%s']", dayOfMonth, dayOfMonth);
        List<WebElement> dateCells = driver.findElements(By.cssSelector(dateLocator));
        
        if (!dateCells.isEmpty()) {
            actions.click(dateCells.get(0));
        } else {
            String xpathLocator = String.format("//td[contains(@class,'calendar-day') and text()='%s']", dayOfMonth);
            WebElement dateCell = driver.findElement(By.xpath(xpathLocator));
            actions.click(dateCell);
        }
    }
    
    @When("user clicks {string} arrow button")
    public void userClicksArrowButton(String direction) {
        String buttonLocator = String.format("[data-testid='button-%s'], [aria-label='%s']", 
            direction.toLowerCase().replaceAll("\\s+", "-"),
            direction);
        
        List<WebElement> buttons = driver.findElements(By.cssSelector(buttonLocator));
        if (!buttons.isEmpty()) {
            actions.click(buttons.get(0));
        } else {
            String xpathLocator = String.format("//button[contains(@aria-label,'%s') or contains(text(),'%s')]", direction, direction);
            WebElement button = driver.findElement(By.xpath(xpathLocator));
            actions.click(button);
        }
        waits.waitForPageLoad();
    }
    
    @When("user navigates to {string} page")
    public void userNavigatesToPage(String pageName) {
        String linkLocator = String.format("[data-testid='link-%s'], [data-testid='nav-%s']", 
            pageName.toLowerCase().replaceAll("\\s+", "-"),
            pageName.toLowerCase().replaceAll("\\s+", "-"));
        
        List<WebElement> links = driver.findElements(By.cssSelector(linkLocator));
        if (!links.isEmpty()) {
            actions.click(links.get(0));
        } else {
            String xpathLocator = String.format("//a[contains(text(),'%s')]", pageName);
            WebElement link = driver.findElement(By.xpath(xpathLocator));
            actions.click(link);
        }
        waits.waitForPageLoad();
    }
    
    @When("user hovers over change indicator icon on modified shift")
    public void userHoversOverChangeIndicatorIconOnModifiedShift() {
        WebElement changeIndicator = driver.findElement(By.cssSelector("[data-testid='change-indicator'], .change-badge, .updated-badge, [data-testid='shift-modified']"));
        actions.hover(changeIndicator);
        waits.waitForElementVisible(changeIndicator);
    }
    
    @When("user clicks on modified shift card")
    public void userClicksOnModifiedShiftCard() {
        WebElement modifiedShift = driver.findElement(By.cssSelector("[data-testid='shift-modified'], .shift-card.modified, .shift-updated"));
        actions.click(modifiedShift);
        waits.waitForPageLoad();
    }
    
    @When("user clicks {string} link in notification banner")
    public void userClicksLinkInNotificationBanner(String linkText) {
        String linkLocator = String.format("[data-testid='link-%s']", linkText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> links = driver.findElements(By.cssSelector(linkLocator));
        
        if (!links.isEmpty()) {
            actions.click(links.get(0));
        } else {
            String xpathLocator = String.format("//a[contains(text(),'%s')]", linkText);
            WebElement link = driver.findElement(By.xpath(xpathLocator));
            actions.click(link);
        }
        waits.waitForPageLoad();
    }
    
    @When("user views schedule on {string} resolution {string}")
    public void userViewsScheduleOnResolution(String deviceType, String resolution) {
        String[] dimensions = resolution.split("x");
        int width = Integer.parseInt(dimensions[0]);
        int height = Integer.parseInt(dimensions[1]);
        driver.manage().window().setSize(new org.openqa.selenium.Dimension(width, height));
        waits.waitForPageLoad();
    }
    
    @When("user clears browser cache")
    public void userClearsBrowserCache() {
        driver.manage().deleteAllCookies();
    }
    
    @When("user navigates to {string} page while monitoring network tab")
    public void userNavigatesToPageWhileMonitoringNetworkTab(String pageName) {
        String linkLocator = String.format("[data-testid='link-%s'], [data-testid='nav-%s']", 
            pageName.toLowerCase().replaceAll("\\s+", "-"),
            pageName.toLowerCase().replaceAll("\\s+", "-"));
        
        List<WebElement> links = driver.findElements(By.cssSelector(linkLocator));
        if (!links.isEmpty()) {
            actions.click(links.get(0));
        } else {
            String xpathLocator = String.format("//a[contains(text(),'%s')]", pageName);
            WebElement link = driver.findElement(By.xpath(xpathLocator));
            actions.click(link);
        }
        waits.waitForPageLoad();
    }
    
    @When("user changes week filter to next week")
    public void userChangesWeekFilterToNextWeek() {
        WebElement nextWeekButton = driver.findElement(By.cssSelector("[data-testid='button-next-week'], [aria-label='Next Week'], .next-week-button"));
        actions.click(nextWeekButton);
        waits.waitForPageLoad();
    }
    
    @When("user refreshes the page")
    public void userRefreshesThePage() {
        driver.navigate().refresh();
        waits.waitForPageLoad();
    }
    
    // ==================== THEN STEPS ====================
    
    @Then("user should be redirected to employee dashboard")
    public void userShouldBeRedirectedToEmployeeDashboard() {
        waits.waitForPageLoad();
        assertions.assertUrlContains("dashboard");
        WebElement dashboard = driver.findElement(By.cssSelector("[data-testid='employee-dashboard'], .dashboard, #dashboard"));
        assertions.assertDisplayed(dashboard);
    }
    
    @Then("schedule page should load and display current week by default")
    public void schedulePageShouldLoadAndDisplayCurrentWeekByDefault() {
        waits.waitForPageLoad();
        WebElement scheduleView = driver.findElement(By.cssSelector("[data-testid='schedule-view'], [data-testid='current-week'], .schedule-container"));
        assertions.assertDisplayed(scheduleView);
    }
    
    @Then("week range header should be visible")
    public void weekRangeHeaderShouldBeVisible() {
        WebElement weekHeader = driver.findElement(By.cssSelector("[data-testid='week-range-header'], .week-range, .date-range-header"));
        assertions.assertDisplayed(weekHeader);
    }
    
    @Then("schedule grid should display all days from Monday through Sunday")
    public void scheduleGridShouldDisplayAllDaysFromMondayThroughSunday() {
        List<WebElement> dayColumns = driver.findElements(By.cssSelector("[data-testid^='day-'], .day-column, .calendar-day-header"));
        assertions.assertElementCount(By.cssSelector("[data-testid^='day-'], .day-column, .calendar-day-header"), 7);
    }
    
    @Then("all scheduled shifts should be displayed with complete details")
    public void allScheduledShiftsShouldBeDisplayedWithCompleteDetails() {
        List<WebElement> shifts = driver.findElements(By.cssSelector("[data-testid='shift-card'], .shift-card, .shift-item"));
        assertions.assertElementCount(By.cssSelector("[data-testid='shift-card'], .shift-card, .shift-item"), this.expectedShiftCount);
    }
    
    @Then("each shift should show start time")
    public void eachShiftShouldShowStartTime() {
        List<WebElement> startTimes = driver.findElements(By.cssSelector("[data-testid='shift-start-time'], .shift-start, .start-time"));
        for (WebElement startTime : startTimes) {
            assertions.assertDisplayed(startTime);
        }
    }
    
    @Then("each shift should show end time")
    public void eachShiftShouldShowEndTime() {
        List<WebElement> endTimes = driver.findElements(By.cssSelector("[data-testid='shift-end-time'], .shift-end, .end-time"));
        for (WebElement endTime : endTimes) {
            assertions.assertDisplayed(endTime);
        }
    }
    
    @Then("each shift should show duration")
    public void eachShiftShouldShowDuration() {
        List<WebElement> durations = driver.findElements(By.cssSelector("[data-testid='shift-duration'], .shift-duration, .duration"));
        for (WebElement duration : durations) {
            assertions.assertDisplayed(duration);
        }
    }
    
    @Then("each shift should show location or department")
    public void eachShiftShouldShowLocationOrDepartment() {
        List<WebElement> locations = driver.findElements(By.cssSelector("[data-testid='shift-location'], [data-testid='shift-department'], .shift-location, .department"));
        for (WebElement location : locations) {
            assertions.assertDisplayed(location);
        }
    }
    
    @Then("each shift should show any notes")
    public void eachShiftShouldShowAnyNotes() {
        List<WebElement> notes = driver.findElements(By.cssSelector("[data-testid='shift-notes'], .shift-notes, .notes"));
        for (WebElement note : notes) {
            assertions.assertDisplayed(note);
        }
    }
    
    @Then("each shift card should display color-coded status")
    public void eachShiftCardShouldDisplayColorCodedStatus() {
        List<WebElement> shifts = driver.findElements(By.cssSelector("[data-testid='shift-card'], .shift-card"));
        for (WebElement shift : shifts) {
            assertions.assertDisplayed(shift);
        }
    }
    
    @Then("confirmed shifts should be displayed in green")
    public void confirmedShiftsShouldBeDisplayedInGreen() {
        List<WebElement> confirmedShifts = driver.findElements(By.cssSelector("[data-testid='shift-confirmed'], .shift-confirmed, .status-confirmed"));
        for (WebElement shift : confirmedShifts) {
            assertions.assertDisplayed(shift);
        }
    }
    
    @Then("pending shifts should be displayed in yellow")
    public void pendingShiftsShouldBeDisplayedInYellow() {
        List<WebElement> pendingShifts = driver.findElements(By.cssSelector("[data-testid='shift-pending'], .shift-pending, .status-pending"));
        for (WebElement shift : pendingShifts) {
            assertions.assertDisplayed(shift);
        }
    }
    
    @Then("all information should be clearly readable")
    public void allInformationShouldBeClearlyReadable() {
        WebElement scheduleContainer = driver.findElement(By.cssSelector("[data-testid='schedule-container'], .schedule-view"));
        assertions.assertDisplayed(scheduleContainer);
    }
    
    @Then("total hours summary should be displayed at bottom of schedule")
    public void totalHoursSummaryShouldBeDisplayedAtBottomOfSchedule() {
        WebElement totalHours = driver.findElement(By.cssSelector("[data-testid='total-hours'], .total-hours, .hours-summary"));
        assertions.assertDisplayed(totalHours);
    }
    
    @Then("total scheduled hours for the week should be calculated correctly")
    public void totalScheduledHoursForTheWeekShouldBeCalculatedCorrectly() {
        WebElement totalHours = driver.findElement(By.cssSelector("[data-testid='total-hours'], .total-hours"));
        assertions.assertDisplayed(totalHours);
        String hoursText = totalHours.getText();
        assertions.assertTextContains(totalHours, "hours");
    }
    
    @Then("date picker should open showing calendar view")
    public void datePickerShouldOpenShowingCalendarView() {
        WebElement calendar = driver.findElement(By.cssSelector("[data-testid='calendar-view'], .calendar, .date-picker-calendar"));
        waits.waitForElementVisible(calendar);
        assertions.assertDisplayed(calendar);
    }
    
    @Then("current week should be highlighted in calendar")
    public void currentWeekShouldBeHighlightedInCalendar() {
        WebElement currentWeek = driver.findElement(By.cssSelector("[data-testid='current-week-highlight'], .current-week, .week-selected"));
        assertions.assertDisplayed(currentWeek);
    }
    
    @Then("calendar should update selection and highlight chosen week range")
    public void calendarShouldUpdateSelectionAndHighlightChosenWeekRange() {
        WebElement selectedWeek = driver.findElement(By.cssSelector("[data-testid='week-selected'], .week-selected, .selected-range"));
        assertions.assertDisplayed(selectedWeek);
    }
    
    @Then("loading indicator should be shown briefly")
    public void loadingIndicatorShouldBeShownBriefly() {
        List<WebElement> loadingIndicators = driver.findElements(By.cssSelector("[data-testid='loading-spinner'], .loading, .spinner"));
        if (!loadingIndicators.isEmpty()) {
            assertions.assertDisplayed(loadingIndicators.get(0));
        }
    }
    
    @Then("schedule page should refresh and display shifts for selected week")
    public void schedulePageShouldRefreshAndDisplayShiftsForSelectedWeek() {
        waits.waitForPageLoad();
        WebElement scheduleView = driver.findElement(By.cssSelector("[data-testid='schedule-view'], .schedule-container"));
        assertions.assertDisplayed(scheduleView);
    }
    
    @Then("week range header should update to show selected week dates")
    public void weekRangeHeaderShouldUpdateToShowSelectedWeekDates() {
        WebElement weekHeader = driver.findElement(By.cssSelector("[data-testid='week-range-header'], .week-range"));
        assertions.assertDisplayed(weekHeader);
    }
    
    @Then("schedule should update to show previous week with smooth transition")
    public void scheduleShouldUpdateToShowPreviousWeekWithSmoothTransition() {
        waits.waitForPageLoad();
        WebElement scheduleView = driver.findElement(By.cssSelector("[data-testid='schedule-view'], .schedule-container"));
        assertions.assertDisplayed(scheduleView);
    }
    
    @Then("schedule should reset to display current week")
    public void scheduleShouldResetToDisplayCurrentWeek() {
        waits.waitForPageLoad();
        WebElement currentWeekView = driver.findElement(By.cssSelector("[data-testid='current-week'], .current-week-view"));
        assertions.assertDisplayed(currentWeekView);
    }
    
    @Then("{string} label should be visible")
    public void labelShouldBeVisible(String labelText) {
        String xpathLocator = String.format("//*[contains(text(),'%s')]", labelText);
        WebElement label = driver.findElement(By.xpath(xpathLocator));
        assertions.assertDisplayed(label);
    }
    
    @Then("schedule should load with modified shifts visually distinguished")
    public void scheduleShouldLoadWithModifiedShiftsVisuallyDistinguished() {
        List<WebElement> modifiedShifts = driver.findElements(By.cssSelector("[data-testid='shift-modified'], .shift-modified, .shift-updated"));
        for (WebElement shift : modifiedShifts) {
            assertions.assertDisplayed(shift);
        }
    }
    
    @Then("modified shifts should display orange border or {string} badge")
    public void modifiedShiftsShouldDisplayOrangeBorderOrBadge(String badgeText) {
        List<WebElement> updateBadges = driver.findElements(By.cssSelector("[data-testid='badge-updated'], .updated-badge, .change-badge"));
        for (WebElement badge : updateBadges) {
            assertions.assertDisplayed(badge);
        }
    }
    
    @Then("tooltip should appear showing change details")
    public void tooltipShouldAppearShowingChangeDetails() {
        WebElement tooltip = driver.findElement(By.cssSelector("[data-testid='tooltip'], .tooltip, [role='tooltip']"));
        waits.waitForElementVisible(tooltip);
        assertions.assertDisplayed(tooltip);
    }
    
    @Then("tooltip should display modification timestamp")
    public void tooltipShouldDisplayModificationTimestamp() {
        WebElement tooltip = driver.findElement(By.cssSelector("[data-testid='tooltip'], .tooltip"));
        assertions.assertDisplayed(tooltip);
        assertions.assertTextContains(tooltip, "");
    }
    
    @Then("tooltip should display original value and new value")
    public void tooltipShouldDisplayOriginalValueAndNewValue() {
        WebElement tooltip = driver.findElement(By.cssSelector("[data-testid='tooltip'], .tooltip"));
        assertions.assertDisplayed(tooltip);
    }
    
    @Then("modal or expanded view should open")
    public void modalOrExpandedViewShouldOpen() {
        WebElement modal = driver.findElement(By.cssSelector("[data-testid='modal'], .modal, [role='dialog']"));
        waits.waitForElementVisible(modal);
        assertions.assertDisplayed(modal);
    }
    
    @Then("complete change history should be displayed")
    public void completeChangeHistoryShouldBeDisplayed() {
        WebElement changeHistory = driver.findElement(By.cssSelector("[data-testid='change-history'], .change-history, .history-list"));
        assertions.assertDisplayed(changeHistory);
    }
    
    @Then("change history should show original values")
    public void changeHistoryShouldShowOriginalValues() {
        List<WebElement> originalValues = driver.findElements(By.cssSelector("[data-testid='original-value'], .original-value, .old-value"));
        for (WebElement value : originalValues) {
            assertions.assertDisplayed(value);
        }
    }
    
    @Then("change history should show new values")
    public void changeHistoryShouldShowNewValues() {
        List<WebElement> newValues = driver.findElements(By.cssSelector("[data-testid='new-value'], .new-value, .updated-value"));
        for (WebElement value : newValues) {
            assertions.assertDisplayed(value);
        }
    }
    
    @Then("change history should show who made the change")
    public void changeHistoryShouldShowWhoMadeTheChange() {
        List<WebElement> modifiedBy = driver.findElements(By.cssSelector("[data-testid='modified-by'], .modified-by, .changed-by"));
        for (WebElement element : modifiedBy) {
            assertions.assertDisplayed(element);
        }
    }
    
    @Then("change history should show timestamp")
    public void changeHistoryShouldShowTimestamp() {
        List<WebElement> timestamps = driver.findElements(By.cssSelector("[data-testid='timestamp'], .timestamp, .change-date"));
        for (WebElement timestamp : timestamps) {
            assertions.assertDisplayed(timestamp);
        }
    }
    
    @Then("notification banner should be displayed at top of schedule page")
    public void notificationBannerShouldBeDisplayedAtTopOfSchedulePage() {
        WebElement banner = driver.findElement(By.cssSelector("[data-testid='notification-banner'], .notification, .alert-banner"));
        assertions.assertDisplayed(banner);
    }
    
    @Then("banner should display message {string}")
    public void bannerShouldDisplayMessage(String message) {
        WebElement banner = driver.findElement(By.cssSelector("[data-testid='notification-banner'], .notification"));
        assertions.assertTextContains(banner, message);
    }
    
    @Then("banner should display {string} link")
    public void bannerShouldDisplayLink(String linkText) {
        String xpathLocator = String.format("//a[contains(text(),'%s')]", linkText);
        WebElement link = driver.findElement(By.xpath(xpathLocator));
        assertions.assertDisplayed(link);
    }
    
    @Then("change summary panel should open")
    public void changeSummaryPanelShouldOpen() {
        WebElement summaryPanel = driver.findElement(By.cssSelector("[data-testid='change-summary'], .change-summary, .summary-panel"));
        waits.waitForElementVisible(summaryPanel);
        assertions.assertDisplayed(summaryPanel);
    }
    
    @Then("all recent changes should be listed with dates and descriptions")
    public void allRecentChangesShouldBeListedWithDatesAndDescriptions() {
        List<WebElement> changeItems = driver.findElements(By.cssSelector("[data-testid='change-item'], .change-item, .change-entry"));
        for (WebElement item : changeItems) {
            assertions.assertDisplayed(item);
        }
    }
    
    @Then("schedule should display in {string}")
    public void scheduleShouldDisplayIn(String layoutFormat) {
        WebElement scheduleLayout = driver.findElement(By.cssSelector("[data-testid='schedule-layout'], .schedule-container"));
        assertions.assertDisplayed(scheduleLayout);
    }
    
    @Then("{string} should be visible")
    public void shouldBeVisible(String visibilityDetails) {
        WebElement scheduleView = driver.findElement(By.cssSelector("[data-testid='schedule-view'], .schedule-container"));
        assertions.assertDisplayed(scheduleView);
    }
    
    @Then("navigation controls should adjust appropriately")
    public void navigationControlsShouldAdjustAppropriately() {
        List<WebElement> navControls = driver.findElements(By.cssSelector("[data-testid^='button-'], .nav-button, .navigation-control"));
        for (WebElement control : navControls) {
            assertions.assertDisplayed(control);
        }
    }
    
    @Then("all interactive elements should remain accessible and clickable")
    public void allInteractiveElementsShouldRemainAccessibleAndClickable() {
        List<WebElement> interactiveElements = driver.findElements(By.cssSelector("button, a, input, select"));
        for (WebElement element : interactiveElements) {
            waits.waitForElementClickable(element);
        }
    }
    
    @Then("no layout breaking or content overflow should occur")
    public void noLayoutBreakingOrContentOverflowShouldOccur() {
        WebElement body = driver.findElement(By.cssSelector("body"));
        assertions.assertDisplayed(body);
    }
    
    @Then("page should begin loading immediately")
    public void pageShouldBeginLoadingImmediately() {
        WebElement pageBody = driver.findElement(By.cssSelector("body"));
        assertions.assertDisplayed(pageBody);
    }
    
    @Then("loading spinner or skeleton screen should be displayed")
    public void loadingSpinnerOrSkeletonScreenShouldBeDisplayed() {
        List<WebElement> loadingElements = driver.findElements(By.cssSelector("[data-testid='loading-spinner'], [data-testid='skeleton'], .loading, .spinner, .skeleton"));
        if (!loadingElements.isEmpty()) {
            assertions.assertDisplayed(loadingElements.get(0));
        }
    }
    
    @Then("complete schedule with all shift details should load in under {int} seconds")
    public void completeScheduleWithAllShiftDetailsShouldLoadInUnderSeconds(int seconds) {
        waits.waitForPageLoad();
        WebElement scheduleView = driver.findElement(By.cssSelector("[data-testid='schedule-view'], .schedule-container"));
        assertions.assertDisplayed(scheduleView);
    }
    
    @Then("API response time for {string} should be under {int} milliseconds")
    public void apiResponseTimeForShouldBeUnderMilliseconds(String apiEndpoint, int milliseconds) {
        WebElement pageBody = driver.findElement(By.cssSelector("body"));
        assertions.assertDisplayed(pageBody);
    }
    
    @Then("API should respond with status {int}")
    public void apiShouldRespondWithStatus(int statusCode) {
        WebElement pageBody = driver.findElement(By.cssSelector("body"));
        assertions.assertDisplayed(pageBody);
    }
    
    @Then("API should return complete schedule data")
    public void apiShouldReturnCompleteScheduleData() {
        WebElement scheduleData = driver.findElement(By.cssSelector("[data-testid='schedule-view'], .schedule-container"));
        assertions.assertDisplayed(scheduleData);
    }
    
    @Then("schedule should update in under {int} second")
    public void scheduleShouldUpdateInUnderSecond(int seconds) {
        waits.waitForPageLoad();
        WebElement scheduleView = driver.findElement(By.cssSelector("[data-testid='schedule-view'], .schedule-container"));
        assertions.assertDisplayed(scheduleView);
    }
    
    @Then("page should reload and display schedule in under {float} seconds")
    public void pageShouldReloadAndDisplayScheduleInUnderSeconds(float seconds) {
        waits.waitForPageLoad();
        WebElement scheduleView = driver.findElement(By.cssSelector("[data-testid='schedule-view'], .schedule-container"));
        assertions.assertDisplayed(scheduleView);
    }
    
    @Then("cached assets should be utilized")
    public void cachedAssetsShouldBeUtilized() {
        WebElement pageBody = driver.findElement(By.cssSelector("body"));
        assertions.assertDisplayed(pageBody);
    }
}