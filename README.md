# IY Maintain

IY Maintain is a maintenance and parts management web application connected to Supabase.

## Deployment

This repository is designed for static hosting. The application entry point is `index.html`.

### GitHub Pages / Cloudflare Pages

Upload the contents of this folder to a GitHub repository. For Cloudflare Pages, use the repository as a static site with no build command and the output directory set to `/`.

## Backend

The application uses Supabase for database and authentication. Keep Supabase credentials in the application configuration exactly as intended for the project.

## Current modules

- Dashboard
- Parts
  - Search & Issue Parts
  - Receive Parts
  - Inventory
  - Parts Updates
- Maintenance
  - Maintenance Dashboard
  - Maintenance Entry
  - Maintenance Log
  - Machines
- Reports
  - Parts Reports
  - Maintenance Reports
- System
  - Settings
  - Users & Roles
  - User Activity
  - Backup Data

## Notes

Procurement is intentionally not part of this deployment baseline.
