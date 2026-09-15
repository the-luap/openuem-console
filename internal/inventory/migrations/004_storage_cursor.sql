-- Bound continuation within each kind of reported storage to its owner.
CREATE INDEX IF NOT EXISTS uem_inventory_physical_cursor ON physical_disks(agent_physicaldisks,id);
CREATE INDEX IF NOT EXISTS uem_inventory_logical_cursor ON logical_disks(agent_logicaldisks,id);
