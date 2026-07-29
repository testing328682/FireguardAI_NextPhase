# Phase 3 - Operational Intelligence Widgets

## Goal

The first two phases provide an executive view of the environment.

This phase focuses on operational visibility by introducing widgets that help administrators understand the current operational state of their environment without opening individual devices.

Unlike the Executive Summary, these widgets are intended for administrators who manage the environment daily.

These widgets should appear directly below the analytics charts implemented in Phase 2.

Do not modify any existing functionality from previous phases.

Do not modify the existing **Findings** page.

---

# Layout

Create a responsive row containing five equally sized cards.

Layout:

---

Device Health | Analysis Activity | API Connection Status

Recently Changed Devices | Customer Overview

---

All cards should have:

* Equal height
* Consistent spacing
* Rounded corners
* Card title
* Small information (ⓘ) icon
* Loading skeleton
* Empty state
* Responsive layout

Each widget should use the existing FirewallGuard design language.

---

# Widget 1 - Device Health

## Goal

Provide a quick operational overview of the current device inventory.

Instead of showing security findings, this widget should summarize the operational state of managed devices.

---

## Display

Show the following values:

Configured Devices

Not Configured Devices

Expired License Devices

Example

Configured

138

Not Configured

4

Expired License

5

---

## Calculation

Configured

Devices successfully configured via:

* Manual TSR upload
* API

Not Configured

Devices registered but not yet configured.

Expired License

Configured devices whose assigned license has expired.

Do not include:

* Decommissioned devices

---

## Colors

Configured

Green

Not Configured

Orange

Expired

Red

---

## Interaction

Clicking each row filters the device table.

Example

Click

Expired License

↓

Only expired devices remain visible.

---

# Widget 2 - Analysis Activity

## Goal

Show how the platform is being used.

This widget provides statistics about analysis operations during the selected time period.

---

## Display

Automatic Scans

Manual API Pulls

Manual TSR Uploads

Failed Pulls

Example

Automatic Scans

24

Manual Pulls (API)

8

Manual Uploads

11

Failed Pulls

2

---

## Calculation

Respect the selected dashboard time period.

Only include completed operations.

Failed Pulls

Should represent:

API connection failures

Authentication failures

Timeouts

Download failures

---

## Interaction

Clicking a metric filters the activity list in future phases.

No action required yet.

---

# Widget 3 - API Connection Status

## Goal

Provide visibility into API-managed devices.

This allows administrators to immediately identify API connectivity issues.

---

## Display

API Connected

API Failed

Manual Devices

Example

API Connected

132

API Failed

4

Manual Devices

38

---

## Calculation

API Connected

Configured using API

Latest API test successful

API Failed

Configured using API

Latest API test failed

Manual Devices

Configured via manual TSR upload

---

## Interaction

Clicking:

API Failed

↓

Filter device table to devices currently failing API communication.

---

## Future Use

Later phases may include:

* API latency
* Last successful pull
* Connection history

Do not implement those now.

---

# Widget 4 - Recently Changed Devices

## Goal

Highlight devices whose security posture has recently changed.

This allows administrators to immediately identify environments that improved or deteriorated.

---

## Display

Show the latest five devices whose score changed.

Columns

Device Name

Trend

Old Score

New Score

Time

Example

TZ670-Boston

Improved

42 → 81

2h ago

NSA2700-DC

Dropped

76 → 61

5h ago

TZ370-Branch

Improved

55 → 78

1d ago

---

## Trend Colors

Improved

Green

Dropped

Red

No Change

Gray

---

## Calculation

Compare the latest completed analysis with the previous completed analysis.

Ignore devices with only one analysis.

---

## Interaction

Clicking a device opens its Device Findings page.

---

# Widget 5 - Customer Overview

## Goal

Provide MSP administrators with a high-level customer summary.

This widget is intended only for MSP organizations.

---

## Visibility

Professional Plan

Hide this widget.

MSP Plan

Display the widget.

---

## Display

Columns

Customer

Devices

Average Score

Critical Findings

Example

Acme Corp

42

78

6

Tech Solutions

31

72

9

Global Systems

28

81

4

SecureNet

17

69

4

---

## Footer

Display totals.

Example

Customers

4

Devices

118

Average Score

75

Critical Findings

23

---

## Sorting

Sort by:

Highest number of Critical findings.

---

## Interaction

Clicking a customer filters the dashboard.

This should synchronize with the existing Customer filter.

---

# Widget Behavior

All widgets must respect:

* Customer Filter
* Search
* Configure Filter
* Time Range

Changing any filter must refresh every widget automatically.

No page reload should occur.

---

# Loading State

Display animated skeletons while loading.

Each widget loads independently.

One slow widget must never block another.

---

# Empty States

If no information exists, display appropriate messages.

Examples

Device Health

"No devices available."

Analysis Activity

"No analyses during this period."

API Status

"No API configured devices."

Recently Changed Devices

"No score changes detected."

Customer Overview

"No customer data available."

---

# Performance

Whenever possible, retrieve all operational widget data from a single dashboard API.

Avoid making one request per widget.

The page should remain responsive even when managing thousands of devices.

---

# UI Requirements

All widgets must:

* Match FirewallGuard AI styling.
* Use consistent typography.
* Use consistent spacing.
* Use the existing color palette.
* Animate values smoothly.
* Display hover effects.
* Remain responsive.

These widgets should complement the Executive Dashboard rather than compete with it visually.

---

# Acceptance Criteria

This phase is complete when:

* Device Health widget is implemented.
* Analysis Activity widget is implemented.
* API Connection Status widget is implemented.
* Recently Changed Devices widget is implemented.
* Customer Overview widget is implemented for MSP organizations.
* All widgets respect dashboard filters.
* Clicking supported widgets filters the device table correctly.
* Loading and empty states are implemented.
* Existing functionality from Phases 1 and 2 remains unchanged.
* The original Findings page remains untouched.
