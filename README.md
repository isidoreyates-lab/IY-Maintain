# IY Maintain V24.10

Parts Updates workflow fix.

Changes:
- Parts Update status `ORDERED` now creates an active Parts Order and removes the source Parts Update.
- Parts Updates no longer depend on the legacy move-to-order RPC.
- Manual Parts Updates can be created for a new part number; a new part is created with zero opening stock.
- Existing parts can be selected from the Part Number suggestions and description/machine can auto-fill.
- Existing Parts Orders Edit and Receive workflow remains intact.
