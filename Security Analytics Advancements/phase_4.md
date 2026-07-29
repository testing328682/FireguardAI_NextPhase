# Phase 4 – Advanced Device Inventory Table

## Goal

The Executive Dashboard (Phase 1), Analytics Charts (Phase 2), and Operational Widgets (Phase 3) provide an executive overview of the environment.

This phase redesigns the device table into a modern security inventory that closely matches the approved Security Analytics dashboard.

The table should become the primary navigation point into Device Findings while preserving all existing backend functionality.

Do not modify the original Findings page.

Do not modify any analysis logic.

---

# Layout

The table should appear directly below the Operational Widgets.

Layout:

---------------------------------------------------

Toolbar

---------------------------------------------------

Device Table

---------------------------------------------------

Pagination

---------------------------------------------------

The table should span the full available width.

---

# Toolbar

Keep the toolbar clean and lightweight.

Include only:

- Search
- Customer Filter (MSP only)
- Configure Filter

Do not introduce additional filters during this phase.

Reuse the styling already used throughout the application.

---

# Search

Continue supporting instant search by:

- Device Name
- Customer Name
- Model
- Serial Number

Searching should update the table immediately without refreshing the page.

---

# Customer Filter

Visible only for MSP organizations.

Changing the selected customer should update:

- Executive Cards
- Analytics Charts
- Operational Widgets
- Device Table

Reuse the existing filtering logic.

---

# Configure Filter

Support:

- All
- Configured
- Not Configured

Reuse the existing filtering logic.

---

# Device Table

Redesign the existing table to closely match the approved dashboard design.

Columns must appear in the following order:

| Device Name | Customer | Model | Serial Number | Firmware | Security Score | Grade | Critical | High | Medium | Low | Last Analysis | Actions |

No additional columns should be introduced during this phase.

---

## Device Name

Display:

- Device icon
- Device Name
- Retrieve Mode badge

Examples:

TZ670-Boston     [API]

TZ570-HQ         [Manual]

Badge colours:

- API → Green
- Manual → Blue

Clicking anywhere on the row (except the Actions menu) should continue opening the Device Findings page.

---

## Customer

Display the registered customer name.

Only visible for MSP organizations.

Support sorting.

Examples:

Acme Corp

Global Systems

SecureNet

---

## Model

Display only the firewall model.

Examples:

TZ670

NSA2700

NSa3650

Support sorting.

---

## Serial Number

Display the complete serial number.

Examples:

2CB8-ED82-8D68

X0A1B2C3D4E5

Requirements:

- Use a monospace font.
- Searchable.
- Tooltip should display the complete serial number if truncated.
- Support sorting.

---

## Firmware

Display the installed firmware version.

Examples:

7.3.2.0487

7.2.6.0211

Support sorting.

---

## Security Score

Display the numeric security score.

Examples:

81

61

53

Color coding:

80–100 → Green

60–79 → Yellow

40–59 → Orange

Below 40 → Red

Support sorting.

---

## Grade

Display the existing circular grade badge.

Examples:

🟢 B

🟠 D

🔴 F

Reuse the existing grading logic.

Support sorting.

---

## Critical

Display only the Critical findings count.

Use existing severity colours.

Support sorting.

---

## High

Display only the High findings count.

Support sorting.

---

## Medium

Display only the Medium findings count.

Support sorting.

---

## Low

Display only the Low findings count.

Support sorting.

---

## Last Analysis

Display relative time.

Examples:

2h ago

5h ago

Yesterday

3 days ago

Hover tooltip should display:

Jul 6, 2026, 04:30 PM UTC

Support sorting.

---

## Actions

Display the existing three-dot menu.

Do not modify existing actions.

Leave room for future functionality.

---

# Row Design

Each row should:

- Highlight on hover.
- Display a pointer cursor.
- Preserve the existing click behaviour.
- Clicking anywhere except the Actions menu should open Device Findings.

Maintain the current dark theme styling.

---

# Sorting

Support sorting on:

- Device Name
- Customer
- Model
- Serial Number
- Firmware
- Security Score
- Grade
- Critical
- High
- Medium
- Low
- Last Analysis

Sorting should happen instantly.

---

# Pagination

Continue using the existing pagination.

Default page size:

- 25

Supported page sizes:

- 25
- 50
- 100

Changing filters or search should automatically return to Page 1.

---

# Empty State

Display:

"No devices match the selected filters."

Provide a **Clear Filters** button.

---

# Loading State

Display skeleton rows while data is loading.

Do not display an empty table.

---

# Responsive Behaviour

Desktop

- Display all columns.

Tablet

- Collapse less important columns if required.

Mobile

- Allow horizontal scrolling.

Do not convert rows into cards.

---

# Performance

Continue using:

- Existing backend pagination
- Existing filtering
- Existing search

Do not load every device into the browser.

---

# Preserve Existing Functionality

Do not modify:

- Findings calculations
- Security score calculations
- Grade calculations
- Device navigation
- Search logic
- Filtering logic
- Pagination logic

This phase is only a UI redesign of the device inventory.

---

# Acceptance Criteria

This phase is complete when:

- The device table visually matches the approved Security Analytics dashboard.
- The table contains the following columns in order:

  - Device Name
  - Customer
  - Model
  - Serial Number
  - Firmware
  - Security Score
  - Grade
  - Critical
  - High
  - Medium
  - Low
  - Last Analysis
  - Actions

- Retrieve Mode badges (API / Manual) appear beside the Device Name.
- Search continues working.
- Customer Filter continues working.
- Configure Filter continues working.
- Pagination continues working.
- Sorting is implemented.
- Clicking a row opens Device Findings.
- No backend functionality is modified.
- The original Findings page remains unchanged.