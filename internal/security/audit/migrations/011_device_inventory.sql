ALTER TABLE uem_inventory_audit DROP CONSTRAINT uem_inventory_audit_action_check;
ALTER TABLE uem_inventory_audit ADD CONSTRAINT uem_inventory_audit_action_check
 CHECK (action IN ('inventory.desktop.read','inventory.software.read','inventory.network.read','inventory.storage.read','inventory.peripherals.read','inventory.memory.read','inventory.shares.read','inventory.security.read','inventory.devices.list'));
ALTER TABLE uem_inventory_audit DROP CONSTRAINT uem_inventory_audit_site_id_check;
ALTER TABLE uem_inventory_audit ADD CONSTRAINT uem_inventory_audit_site_id_check
 CHECK (site_id>0 OR (site_id=0 AND action='inventory.devices.list'));
