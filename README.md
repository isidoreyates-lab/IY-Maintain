# IY Maintain

**Take Control of Your Assets, Equipment, Parts & Maintenance
Operations.**

IY Maintain is a cloud-based Computerized Maintenance Management System
(CMMS) developed by **IY Digital Innovations**. It brings equipment
records, maintenance activities, spare-parts inventory and operational
reporting together in one role-based workspace.

**Live application:** https://maintain.iyinnovations.com\
**Developer:** IY Digital Innovations\
**Support:** support@iyinnovations.com

------------------------------------------------------------------------

## Overview

IY Maintain helps organizations keep track of their operational assets
and maintenance activities while maintaining visibility over spare-parts
inventory and related transactions.

The platform is designed to support day-to-day maintenance operations
across companies, sites, departments and authorized users.

## Key capabilities

### Asset and fleet management

-   Maintain machine and equipment records.
-   Review fleet information and operating status.
-   Keep machine-related information available to authorized users.

### Maintenance management

-   Record and review maintenance activities.
-   Maintain a history of maintenance work.
-   Monitor maintenance activity through operational dashboards and
    reports.

### Parts and inventory management

-   Monitor parts inventory and stock availability.
-   Record incoming stock and parts receipts.
-   Record parts issued to machines, technicians or work activities.
-   Track low-stock and out-of-stock items.
-   Maintain parts updates and replenishment information.
-   Transfer parts between authorized operating locations through the
    applicable approval process.

### Reporting and oversight

-   Review maintenance and parts activity.
-   Generate operational reports.
-   Use dashboards to monitor inventory, fleet and maintenance
    indicators.
-   Review relevant activity and audit information according to user
    permissions.

### Users, roles and workspaces

-   Support role-based access to system functions.
-   Organize workspaces around company, site and department structures.
-   Restrict access to information and actions according to configured
    permissions.

> Available features and access depend on the organization's
> configuration, subscription and assigned user permissions.

------------------------------------------------------------------------

## Technology

The application uses the following core technologies:

-   **Frontend:** HTML, CSS and JavaScript.
-   **Backend services:** Supabase.
-   **Authentication and data services:** Supabase services configured
    for the IY Maintain application.
-   **Hosting:** GitHub Pages.
-   **Custom domain:** `maintain.iyinnovations.com`.

The frontend is delivered as a web application. Backend data and
authentication services are provided by the configured Supabase project.

## Accessing IY Maintain

Open the live application:

**https://maintain.iyinnovations.com**

Sign in using the account credentials provided by your organization. If
you do not yet have an account, use the account-creation or invitation
process made available by your organization.

For account-access problems, contact your organization's IY Maintain
administrator or email **support@iyinnovations.com**.

## Deployment and maintenance

IY Maintain is hosted through GitHub Pages and uses a custom domain.

When publishing an approved release:

1.  Use the approved, tested application HTML file.
2.  Publish the application entry file to the configured GitHub Pages
    source.
3.  Confirm the custom domain is configured correctly in GitHub Pages.
4.  Confirm HTTPS is enabled and the site loads over `https://`.
5.  Test sign-in, account access and key workflows after deployment.

**Important:** Keep a backup of the last known-good release before
publishing changes. Do not replace stable production files with untested
versions.

## Security notes

-   Use HTTPS when accessing the application.
-   Do not share passwords or account credentials.
-   Do not publish Supabase service-role keys, database passwords or
    other private secrets in this repository or frontend code.
-   Client-side publishable/anonymous credentials must rely on correctly
    configured Supabase Row Level Security (RLS) policies and backend
    permissions.
-   Assign users only the roles and permissions required for their work.
-   Report suspected unauthorized access or security issues to the
    system administrator.

## Support

For product support and technical enquiries:

**IY Digital Innovations**\
Email: <support@iyinnovations.com>\
Application:
[maintain.iyinnovations.com](https://maintain.iyinnovations.com)

------------------------------------------------------------------------

© IY Digital Innovations. All rights reserved.

IY Maintain is a product of IY Digital Innovations. This repository and
application are maintained by IY Digital Innovations. No open-source
licence is granted unless a separate licence file explicitly states
otherwise.
