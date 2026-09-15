package computers_views

import (
	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdstate"
)

func netbirdProfileOptions(stored string) []nats.NetbirdProfile {
	profiles, err := netbirdstate.Decode(stored)
	if err != nil {
		return nil
	}
	return profiles
}
