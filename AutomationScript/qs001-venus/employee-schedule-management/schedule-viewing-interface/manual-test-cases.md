# Manual Test Cases

## Story: As Employee, I want to view my daily schedule to plan my workday effectively
**Story ID:** story-13

### Test Case: Validate successful daily schedule display for authenticated employee
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has assigned shifts in the schedule database for the current day
- Web portal is accessible and operational
- Employee schedule database is populated with accurate data
- OAuth2 authentication service is running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click Login button | Login successful and employee dashboard is displayed |
| 3 | Click on the Schedule section from the navigation menu | Daily schedule page is displayed showing the current date |
| 4 | Verify the current day is highlighted on the schedule view | Current day is visually highlighted for easy identification |
| 5 | Review the displayed shift start time for the current day | Shift start time matches the employee's assigned shift in the database |
| 6 | Review the displayed shift end time for the current day | Shift end time matches the employee's assigned shift in the database |
| 7 | Verify the location information displayed for the shift | Location matches the assigned location in the employee's schedule |
| 8 | Verify the role information displayed for the shift | Role matches the assigned role in the employee's schedule |
| 9 | Check that all schedule details are complete and accurate | Schedule details are accurate, complete, and match database records |

**Postconditions:**
- Employee remains logged in
- Daily schedule page remains accessible
- No errors are logged in the system
- Session remains active

---

### Test Case: Verify navigation between days in schedule view
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee is on the daily schedule page
- Schedule data exists for previous and next days
- Navigation buttons are visible and enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current date displayed on the daily schedule page | Current date is clearly visible and matches today's date |
| 2 | Click the 'Next Day' button | Page refreshes and displays the schedule for the next day |
| 3 | Verify the date displayed has incremented by one day | Date shown is one day after the previous date |
| 4 | Verify shift details are displayed for the next day if shifts exist | Shift details for the next day are displayed correctly or 'No shifts scheduled' message appears |
| 5 | Click the 'Previous Day' button twice | Page refreshes and displays the schedule for the day before the original date |
| 6 | Verify the date displayed has decremented correctly | Date shown is one day before the original starting date |
| 7 | Verify shift details are displayed for the previous day if shifts exist | Shift details for the previous day are displayed correctly or 'No shifts scheduled' message appears |
| 8 | Navigate forward and backward multiple times rapidly | No errors occur, page loads correctly each time, and navigation is smooth |
| 9 | Check browser console for any JavaScript errors | No errors are present in the browser console |

**Postconditions:**
- Employee remains on the daily schedule page
- Navigation buttons remain functional
- No system errors are generated
- Page performance remains consistent

---

### Test Case: Test access restriction to own schedule only
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the web portal
- Another employee's schedule URL is known or can be constructed
- Role-based access control is configured
- OAuth2 authentication is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Obtain or construct the schedule URL for another employee (e.g., /api/schedules/daily?employeeId=12345) | URL is properly formatted |
| 2 | Attempt to access another employee's schedule by entering the URL directly in the browser | Access is denied and an appropriate error message is displayed (e.g., '403 Forbidden - You do not have permission to view this schedule') |
| 3 | Verify that no schedule data from the other employee is visible on the page | No unauthorized schedule data is displayed |
| 4 | Check the HTTP response code in browser developer tools | HTTP 403 Forbidden status code is returned |
| 5 | Navigate back to the employee's own schedule URL | Navigation is successful |
| 6 | Access own schedule using the standard navigation menu | Schedule is displayed successfully with all shift details |
| 7 | Verify that only the logged-in employee's schedule data is visible | Only authorized schedule data for the logged-in employee is displayed |
| 8 | Inspect the page source and network requests for any data leakage | No other employee's data is present in the page source or API responses |
| 9 | Verify security logs capture the unauthorized access attempt | Security event is logged with appropriate details |

**Postconditions:**
- Employee can only access their own schedule
- Security measures remain active
- Unauthorized access attempt is logged
- No data breach has occurred

---

## Story: As Employee, I want to view my weekly schedule to plan my workweek efficiently
**Story ID:** story-14

### Test Case: Validate weekly schedule display with correct shift details
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has assigned shifts in the schedule database for the current week
- Web portal is accessible and operational
- Weekly schedule view feature is enabled
- OAuth2 authentication service is running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click Login button | Login is successful and employee dashboard is displayed |
| 3 | Click on the Schedule section from the navigation menu | Schedule page is displayed |
| 4 | Select the 'Weekly View' option or tab | Weekly schedule calendar is displayed in a grid format showing 7 days |
| 5 | Verify the current week is highlighted or indicated | Current week is visually highlighted for easy identification |
| 6 | Verify the calendar displays all 7 days of the week (Sunday through Saturday or Monday through Sunday) | All 7 days are displayed with correct day names and dates |
| 7 | Review the shift details displayed for Monday | Shift start time, end time, location, and role are displayed correctly and match database records |
| 8 | Review the shift details displayed for each remaining day of the week | Each day shows accurate shift details matching the employee's assignments in the database |
| 9 | Verify days with no scheduled shifts display appropriately | Days without shifts show 'No shifts scheduled' or remain empty with clear indication |
| 10 | Verify the page load time from clicking Weekly View to full display | Weekly schedule loads within 4 seconds |

**Postconditions:**
- Employee remains logged in
- Weekly schedule view remains accessible
- No errors are logged in the system
- Calendar data is accurate and complete

---

### Test Case: Verify navigation between weeks
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee is on the weekly schedule view page
- Schedule data exists for previous and next weeks
- Navigation buttons ('Next Week' and 'Previous Week') are visible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current week date range displayed on the weekly schedule page | Current week date range is clearly visible (e.g., 'Jan 1 - Jan 7, 2024') |
| 2 | Click the 'Next Week' button | Page refreshes and displays the schedule for the next week |
| 3 | Verify the week date range has advanced by 7 days | Date range shown is 7 days after the previous week (e.g., 'Jan 8 - Jan 14, 2024') |
| 4 | Verify shift details are displayed correctly for the next week | Shift details for the next week are displayed accurately or appropriate message if no shifts exist |
| 5 | Click the 'Previous Week' button twice | Page refreshes and displays the schedule for the week before the original week |
| 6 | Verify the week date range has decremented correctly | Date range shown is 7 days before the original starting week |
| 7 | Verify shift details are displayed correctly for the previous week | Shift details for the previous week are displayed accurately or appropriate message if no shifts exist |
| 8 | Navigate forward and backward between weeks multiple times rapidly | Navigation is smooth, no errors occur, and page loads correctly each time |
| 9 | Check browser console for any JavaScript errors during navigation | No errors are present in the browser console |
| 10 | Verify the calendar grid structure remains consistent during navigation | Calendar grid displays properly with all 7 days visible for each week |

**Postconditions:**
- Employee remains on the weekly schedule page
- Navigation buttons remain functional
- No system errors are generated
- Page performance remains consistent

---

### Test Case: Test shift type filtering
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee is on the weekly schedule view page
- Employee has multiple shift types assigned in the current week (e.g., Morning, Evening, Night)
- Shift type filter dropdown or options are visible on the page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note all shifts currently displayed in the weekly schedule | All shifts for the week are visible with various shift types |
| 2 | Locate the shift type filter control (dropdown, checkboxes, or buttons) | Shift type filter control is visible and accessible |
| 3 | Click on the shift type filter and view available options | Filter displays all available shift types (e.g., Morning, Evening, Night, Weekend) |
| 4 | Select a specific shift type from the filter (e.g., 'Morning') | Filter selection is registered and applied |
| 5 | Verify the schedule updates to show only the selected shift type | Only shifts matching the selected type are displayed; other shift types are hidden |
| 6 | Verify the shift details (time, location, role) remain accurate for displayed shifts | Displayed shift details are complete and accurate |
| 7 | Verify days without the selected shift type show appropriately | Days without the filtered shift type appear empty or show 'No shifts of this type' |
| 8 | Clear the filter or select 'All Shift Types' option | Filter is cleared successfully |
| 9 | Verify the full schedule is displayed again with all shift types | All shifts for the week are visible again, matching the original display |
| 10 | Verify that filtering does not affect the week date range or navigation | Week date range remains the same and navigation buttons remain functional |
| 11 | Apply filter, navigate to next week, and verify filter persists or resets as designed | Filter behavior during navigation matches system design (either persists or resets appropriately) |

**Postconditions:**
- Employee remains on the weekly schedule page
- Filter functionality remains operational
- All schedule data remains intact and unmodified
- No errors are generated during filtering operations

---

## Story: As Employee, I want to filter my schedule by shift type to focus on relevant assignments
**Story ID:** story-17

### Test Case: Validate shift type filtering updates schedule display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has an active schedule with multiple shift types (morning, evening, night)
- Schedule page is accessible and loaded
- Shift type filter controls are visible on the schedule page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page | Schedule page loads successfully displaying all shifts for the employee |
| 2 | Locate the shift type filter control on the schedule page | Shift type filter dropdown/checkbox is visible with options: Morning, Evening, Night |
| 3 | Select 'Morning' shift filter from the filter control | Schedule updates immediately to display only morning shifts, other shift types are hidden from view |
| 4 | Verify the filtered schedule contains only morning shifts | All displayed shifts are morning shifts, no evening or night shifts are visible |
| 5 | Select multiple shift types by choosing 'Morning' and 'Evening' filters | Schedule updates to show shifts matching both morning and evening types, night shifts remain hidden |
| 6 | Verify the filtered schedule contains only the selected shift types | Only morning and evening shifts are displayed, night shifts are not visible |
| 7 | Clear all filters by deselecting all shift types or clicking 'Clear Filters' button | Full schedule is displayed showing all shift types (morning, evening, and night) |
| 8 | Verify all shifts are now visible | Complete schedule with all shift types is displayed without any filtering applied |

**Postconditions:**
- Schedule displays all shifts without filters applied
- Filter controls are reset to default state
- Employee session remains active
- No errors are logged in the system

---

### Test Case: Verify filter input validation
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has access to the schedule page
- Schedule page is loaded with filter controls visible
- Employee has an active schedule with assigned shifts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page | Schedule page loads successfully with all shifts displayed |
| 2 | Locate the shift type filter input field | Filter input control is visible and accessible |
| 3 | Attempt to input an invalid filter value (e.g., special characters, SQL injection string, or non-existent shift type like 'InvalidShift') | System displays a validation error message indicating invalid input, such as 'Invalid shift type selected' or 'Please select a valid shift type' |
| 4 | Verify the schedule display remains unchanged | Schedule continues to display the previous valid state, invalid input is ignored and not applied |
| 5 | Verify the error message is clearly visible to the employee | Error message is displayed in a prominent location near the filter control with clear text |
| 6 | Correct the filter input by selecting a valid shift type (e.g., 'Evening') | Validation error message disappears and the filter is accepted |
| 7 | Verify the schedule updates with the corrected filter | Schedule updates immediately to display only evening shifts, confirming the valid filter is applied successfully |
| 8 | Verify the filtered results load within 3 seconds | Schedule with filtered results loads and displays within the 3-second performance requirement |

**Postconditions:**
- Schedule displays shifts filtered by the valid shift type
- No invalid data is processed or stored
- Error messages are cleared after valid input
- System logs validation errors appropriately
- Employee session remains active and stable

---

## Story: As Employee, I want to view my monthly schedule to plan long-term commitments
**Story ID:** story-18

### Test Case: Validate monthly schedule display with shift indicators
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has assigned shifts in the current month and upcoming months
- Monthly schedule view option is available in the navigation menu
- System has access to the schedule database with current data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as an employee with valid credentials | Employee successfully logs in and is redirected to the dashboard or home page |
| 2 | Navigate to and select the 'Monthly Schedule View' option from the menu | Monthly schedule view is activated and begins loading |
| 3 | Wait for the monthly calendar to load | Monthly calendar for the current month is displayed in calendar format with dates arranged in a grid (Sunday-Saturday or Monday-Sunday) |
| 4 | Verify shift indicators are visible on dates with assigned shifts | Dates with assigned shifts display visual indicators (e.g., colored dots, badges, or icons) showing shift presence |
| 5 | Verify the current month is highlighted or clearly indicated | Current month name and year are displayed prominently, and today's date is highlighted |
| 6 | Verify the calendar loads within 5 seconds | Monthly schedule completes loading and is fully interactive within the 5-second performance requirement |
| 7 | Click the 'Next Month' navigation button | Calendar transitions to display the next month's schedule with appropriate shift indicators |
| 8 | Verify the next month's schedule is displayed correctly | Next month's calendar is shown with correct dates and shift indicators for assigned shifts |
| 9 | Hover the mouse cursor over a date with a shift indicator | Shift details tooltip or popup appears showing shift information (e.g., shift type, time, location) |
| 10 | Verify the shift details displayed are accurate and complete | Shift details match the employee's assigned schedule including shift type, start time, end time, and any relevant notes |
| 11 | Move the mouse cursor away from the shift indicator | Shift details tooltip or popup disappears, returning to the normal calendar view |

**Postconditions:**
- Monthly calendar remains displayed and functional
- Employee can continue navigating between months
- Shift data remains accurate and unchanged
- Employee session remains active
- No errors are displayed or logged

---

### Test Case: Verify navigation between months
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Monthly schedule view is already displayed showing the current month
- Employee has shifts assigned in previous and upcoming months
- Navigation controls (Previous Month and Next Month buttons) are visible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify the current month is displayed in the monthly schedule view | Current month and year are displayed at the top of the calendar with today's date highlighted |
| 2 | Locate and click the 'Previous Month' navigation button | Calendar transitions smoothly to display the previous month |
| 3 | Verify the previous month's schedule is displayed correctly | Previous month's name and year are shown, calendar displays correct dates for that month, and shift indicators appear on dates with assigned shifts |
| 4 | Verify the schedule loads within 5 seconds | Previous month's schedule loads completely and is interactive within the 5-second performance requirement |
| 5 | Verify no errors are displayed during navigation | Navigation completes successfully without error messages or system failures |
| 6 | Click the 'Next Month' navigation button | Calendar transitions forward to display the next month (returning to current month) |
| 7 | Verify the next month's schedule is displayed correctly | Next month's name and year are shown, calendar displays correct dates, and shift indicators are present on assigned shift dates |
| 8 | Verify the schedule loads within 5 seconds | Next month's schedule loads completely within the 5-second performance requirement |
| 9 | Click the 'Next Month' button multiple times consecutively (3-4 times) | Calendar navigates forward through multiple months sequentially without errors, each month displaying correctly |
| 10 | Click the 'Previous Month' button multiple times consecutively to return to the original month | Calendar navigates backward through months without errors, returning to the starting month with all data intact |
| 11 | Verify the schedule data remains accurate after multiple navigations | All shift indicators and details remain accurate and consistent with the employee's assigned schedule |

**Postconditions:**
- Monthly calendar is displayed and fully functional
- Navigation controls remain responsive
- Schedule data integrity is maintained
- Employee session remains active
- No navigation errors are logged in the system

---

## Story: As Employee, I want the schedule interface to be responsive so I can view my schedule on any device
**Story ID:** story-20

### Test Case: Validate responsive layout on various devices
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- Employee has valid login credentials
- Schedule data is available in the system
- Test devices available: desktop (1920x1080), tablet (768x1024), and mobile (375x667)
- Supported browsers installed: Chrome, Firefox, Safari, Edge
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open desktop browser (Chrome) and navigate to the schedule page URL | Schedule page loads successfully with desktop layout displaying full navigation, sidebar, and schedule grid in multi-column format |
| 2 | Verify all UI elements are properly aligned and visible on desktop screen | All elements (header, navigation menu, schedule grid, filters, buttons) are properly positioned without horizontal scrolling |
| 3 | Resize browser window to tablet dimensions (768x1024) or open on tablet device | Layout automatically adjusts to tablet view with condensed navigation and optimized grid layout for medium screen size |
| 4 | Verify all controls and content are accessible on tablet view | All interactive elements are visible and accessible, navigation may collapse to hamburger menu, schedule grid adjusts to fit screen width |
| 5 | Open schedule page on mobile browser (375x667) or resize to mobile dimensions | Layout transforms to mobile-optimized single-column view with stacked elements and mobile-friendly navigation |
| 6 | Verify all controls are accessible and usable on mobile view | All buttons are touch-friendly (minimum 44x44px), text is readable without zooming, no horizontal scrolling required |
| 7 | Test touch interactions on mobile/tablet: tap buttons, swipe schedule, scroll content | All touch gestures work smoothly, buttons respond to taps, scrolling is fluid, no accidental clicks occur |
| 8 | Rotate mobile/tablet device from portrait to landscape orientation | Layout adjusts automatically to new orientation maintaining usability and proper element positioning |
| 9 | Test on additional browsers (Firefox, Safari, Edge) on each device type | Responsive behavior is consistent across all supported browsers with no layout breaking or functionality loss |

**Postconditions:**
- Schedule interface displays correctly on all tested devices
- No layout issues or broken elements remain
- User session remains active
- Browser can be closed normally

---

### Test Case: Test load times on mobile network
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Employee has valid login credentials
- Mobile device with 4G network connection available
- Network throttling tools configured (Chrome DevTools or similar)
- Schedule data is populated in the system
- Browser cache is cleared
- Performance measurement tool is ready (browser DevTools Network tab)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Clear browser cache and cookies on mobile device | Cache and cookies are successfully cleared, confirmed by browser settings |
| 2 | Enable 4G network throttling in Chrome DevTools or ensure device is on actual 4G network | Network conditions are set to 4G (approximately 4 Mbps download, 3 Mbps upload) |
| 3 | Open browser DevTools Network tab and start recording performance metrics | Network monitoring is active and ready to capture load time data |
| 4 | Navigate to the schedule page URL on mobile browser | Page begins loading and progress is visible in the browser |
| 5 | Wait for page to fully load and measure the total load time from navigation start to page interactive | Page loads completely within 3 seconds, all content is visible and interactive |
| 6 | Verify DOM Content Loaded event time in DevTools | DOM Content Loaded occurs within 2 seconds |
| 7 | Verify all critical resources (CSS, JavaScript, images) load within the 3-second window | All critical resources are loaded, page is fully functional within 3 seconds |
| 8 | Test page load time on 3G network (slower connection) for comparison | Page loads within acceptable timeframe, performance degradation is graceful |
| 9 | Repeat test 3 times and calculate average load time | Average load time across all attempts is consistently under 3 seconds on 4G network |

**Postconditions:**
- Performance metrics are documented
- Page load time meets the 3-second requirement
- Network throttling is disabled
- Browser DevTools can be closed
- Test results are recorded for reporting

---

## Story: As Employee, I want to navigate easily between different schedule views to find information quickly
**Story ID:** story-21

### Test Case: Validate navigation between schedule views
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the system
- Employee has access to the schedule page
- Schedule data exists for daily, weekly, and monthly views
- Navigation controls (tabs/buttons) for all three views are visible
- Browser is on a supported version

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page and verify default view is displayed | Schedule page loads with one of the views (daily/weekly/monthly) displayed by default |
| 2 | Locate and click on the 'Weekly View' tab or button in the navigation controls | Weekly schedule view is displayed showing the current week with all scheduled shifts, dates are clearly labeled, and layout shows 7-day grid |
| 3 | Verify weekly view displays correct schedule data for the current week | All shifts and appointments for the week are visible, data is accurate and properly formatted |
| 4 | Click on the 'Monthly View' tab or button in the navigation controls | Monthly schedule view is displayed showing the current month in calendar format with all scheduled items visible |
| 5 | Verify monthly view displays correct schedule data for the current month | All shifts for the month are visible in calendar grid, dates are properly labeled, current day is highlighted |
| 6 | Click on the 'Daily View' tab or button in the navigation controls | Daily schedule view is displayed showing today's schedule with detailed time slots and all scheduled activities |
| 7 | Verify daily view displays correct schedule data for the current day | All shifts and time slots for today are visible with detailed information, timeline is clearly marked |
| 8 | Measure the time taken to switch from daily to weekly view | View transition completes within 2 seconds with smooth loading |
| 9 | Measure the time taken to switch from weekly to monthly view | View transition completes within 2 seconds with smooth loading |
| 10 | Navigate through all three views in sequence: daily → weekly → monthly → daily | All transitions work smoothly, each view loads within 2 seconds, no errors occur, data remains consistent |

**Postconditions:**
- All schedule views are accessible and functional
- Employee remains on the schedule page
- No errors are displayed
- User session remains active
- Last selected view is displayed

---

### Test Case: Verify active view visual feedback
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system
- Employee is on the schedule page
- All three view options (daily, weekly, monthly) are visible in navigation
- Default view is loaded
- Browser supports CSS styling for visual feedback

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Observe the initial state of navigation tabs/buttons when schedule page loads | One view tab (default view) is visually highlighted or marked as active with distinct styling (e.g., different color, underline, bold text, or background) |
| 2 | Click on the 'Daily View' tab and observe the visual feedback | Daily view tab becomes highlighted/active with visual indicator (e.g., blue background, bold text, underline), other tabs return to inactive state |
| 3 | Verify that weekly and monthly tabs are visually distinct from the active daily tab | Inactive tabs (weekly and monthly) have different styling than the active daily tab, clearly showing they are not selected |
| 4 | Click on the 'Weekly View' tab and observe the visual state change | Weekly view tab becomes highlighted/active, daily tab returns to inactive state, visual transition is smooth and immediate |
| 5 | Verify the active state styling is consistent with design standards | Active tab styling matches UI design specifications with clear contrast and visibility |
| 6 | Click on the 'Monthly View' tab and observe the visual feedback | Monthly view tab becomes highlighted/active, weekly tab returns to inactive state, visual indicator is clear and consistent |
| 7 | Hover over inactive tabs and observe any hover state feedback | Inactive tabs show hover state (if designed) without conflicting with active state styling, providing clear interactive feedback |
| 8 | Rapidly switch between all three views and verify visual feedback updates correctly | Active state indicator updates immediately with each click, no visual lag or incorrect highlighting occurs |
| 9 | Refresh the page while on a specific view and verify active state persists | After refresh, the previously selected view remains active and is visually highlighted correctly |

**Postconditions:**
- Active view is clearly indicated visually
- Visual feedback is consistent across all view switches
- No visual glitches or styling errors remain
- User can clearly identify which view is currently active
- Page remains functional

---

