CREATE FUNCTION uem_mac_rotation_channel_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.entity_id IS DISTINCT FROM OLD.entity_id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
    NEW.site_id IS DISTINCT FROM OLD.site_id OR NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
  IF TG_TABLE_NAME='uem_mac_mdm_channels' THEN
   PERFORM mdm_apple_cancel_filevault_rotation(NULL,OLD.device_id);
  ELSE
   PERFORM mdm_apple_cancel_filevault_rotation(OLD.device_id,NULL);
  END IF;
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER uem_mac_rotation_mdm_change AFTER UPDATE OR DELETE ON uem_mac_mdm_channels
 FOR EACH ROW EXECUTE FUNCTION uem_mac_rotation_channel_change();
CREATE TRIGGER uem_mac_rotation_agent_change AFTER UPDATE OR DELETE ON uem_mac_agent_channels
 FOR EACH ROW EXECUTE FUNCTION uem_mac_rotation_channel_change();

CREATE FUNCTION uem_mac_rotation_hardware_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.model IS DISTINCT FROM OLD.model OR NEW.serial IS DISTINCT FROM OLD.serial OR
    NEW.platform_uuid IS DISTINCT FROM OLD.platform_uuid OR NEW.provisioning_udid IS DISTINCT FROM OLD.provisioning_udid OR
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.site_id IS DISTINCT FROM OLD.site_id THEN
  IF TG_TABLE_NAME='uem_agent_hardware' THEN
   PERFORM mdm_apple_cancel_filevault_rotation(OLD.device_id,NULL);
  ELSE
   PERFORM mdm_apple_cancel_filevault_rotation(ac.device_id,NULL) FROM uem_mac_agent_channels ac WHERE ac.entity_id=OLD.id;
  END IF;
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER uem_mac_rotation_inventory_change AFTER UPDATE OR DELETE ON uem_agent_hardware
 FOR EACH ROW EXECUTE FUNCTION uem_mac_rotation_hardware_change();
CREATE TRIGGER uem_mac_rotation_hardware_change AFTER UPDATE OR DELETE ON uem_mac_devices
 FOR EACH ROW EXECUTE FUNCTION uem_mac_rotation_hardware_change();
