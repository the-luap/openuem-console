package windows

import "strconv"

// receiveSyncMLText buffers only the five bounded DevInfo nodes and the DevId
// probe. A complete object's advertised size is checked before it can be used.
// Chunk errors terminate this narrow exchange; they never apply a partial object.
func receiveSyncMLText(session *syncMLSession, request, response *SyncMLMessage, command SyncMLCommand, item SyncMLItem, current string) (string, string, error) {
	if !syncMLTextMetadata(command.Meta) || !syncMLTextMetadata(item.Meta) || len(current)+len(item.Data.Text) > maxSyncMLDeviceInfoBytes {
		return "", "", ErrSyncMLSession
	}
	var size *uint64
	if command.Meta != nil {
		size = command.Meta.Size
	}
	if item.Meta != nil && item.Meta.Size != nil {
		if size != nil && *size != *item.Meta.Size {
			return "", "", ErrSyncMLSession
		}
		size = item.Meta.Size
	}
	pending := session.State.IncomingChunk
	if pending != nil && (pending.Kind != command.Kind || pending.URI != item.Source.URI) {
		failSyncMLChunk(session, request, response, command, "1225")
		return "", "1225", nil
	}
	assembled := current + item.Data.Text
	if pending != nil {
		if size != nil {
			return "", "", ErrSyncMLSession
		}
		if uint64(len(assembled)) > pending.Size || !item.MoreData && uint64(len(assembled)) != pending.Size || item.MoreData && uint64(len(assembled)) == pending.Size {
			failSyncMLChunk(session, request, response, command, "424")
			return "", "424", nil
		}
	} else {
		if item.MoreData && (size == nil || *size == 0) {
			return "", "", ErrSyncMLSession
		}
		if size != nil && (!item.MoreData && uint64(len(assembled)) != *size || item.MoreData && uint64(len(assembled)) >= *size) {
			failSyncMLChunk(session, request, response, command, "424")
			return "", "424", nil
		}
		if item.MoreData {
			session.State.IncomingChunk = &syncMLIncomingChunk{Kind: command.Kind, URI: item.Source.URI, Size: *size}
		}
	}
	if item.MoreData {
		return assembled, "213", nil
	}
	session.State.IncomingChunk = nil
	return assembled, "200", nil
}

func failSyncMLChunk(session *syncMLSession, request, response *SyncMLMessage, command SyncMLCommand, code string) {
	session.Phase = "failed"
	if code == "1225" {
		response.Commands = append(response.Commands, SyncMLCommand{Kind: "Alert", ID: strconv.Itoa(len(response.Commands) + 1), Data: &SyncMLData{Text: code}})
	} else {
		syncMLStatus(response, request.Header.MessageID, command.ID, command.Kind, code)
	}
}
