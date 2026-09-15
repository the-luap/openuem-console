-- Bound continuation to one device rather than scanning global report IDs.
-- Large installations can create this index concurrently before an upgrade.
CREATE INDEX IF NOT EXISTS uem_inventory_software_cursor ON apps(agent_apps,id);
