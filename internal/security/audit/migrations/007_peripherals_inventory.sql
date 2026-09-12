ALTER TABLE uem_inventory_audit DROP CONSTRAINT uem_inventory_audit_action_check;
ALTER TABLE uem_inventory_audit ADD CONSTRAINT uem_inventory_audit_action_check
 CHECK (action IN ('inventory.desktop.read','inventory.software.read','inventory.network.read','inventory.storage.read','inventory.peripherals.read'));
