-- Bound network report continuation to its current device.
CREATE INDEX IF NOT EXISTS uem_inventory_network_cursor ON network_adapters(agent_networkadapters,id);
