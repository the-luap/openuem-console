ALTER TABLE uem_inventory_audit DROP CONSTRAINT uem_inventory_audit_action_check;
ALTER TABLE uem_inventory_audit ADD CONSTRAINT uem_inventory_audit_action_check
 CHECK (action IN ('inventory.desktop.read','inventory.software.read','inventory.network.read','inventory.storage.read','inventory.peripherals.read','inventory.memory.read','inventory.shares.read','inventory.security.read','inventory.devices.list','inventory.devices.export_csv','inventory.devices.export_json','inventory.groups.list','inventory.groups.read','inventory.groups.create','inventory.groups.revise','inventory.tags.list','inventory.tags.read','inventory.tags.create','inventory.tags.update','inventory.tags.delete','inventory.tags.assign','inventory.tags.unassign'));
ALTER TABLE uem_inventory_audit DROP CONSTRAINT uem_inventory_audit_resource_id_check;
ALTER TABLE uem_inventory_audit ADD CONSTRAINT uem_inventory_audit_resource_id_check
 CHECK (length(resource_id) BETWEEN 1 AND 255 OR (action IN ('inventory.tags.assign','inventory.tags.unassign') AND length(resource_id) BETWEEN 1 AND 320));
