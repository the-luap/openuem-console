CREATE TABLE uem_desktop_invitation_releases (
    invitation_id UUID PRIMARY KEY REFERENCES uem_agent_invitations(id),
    release_digest TEXT NOT NULL REFERENCES uem_desktop_releases(digest)
);
CREATE INDEX uem_desktop_invitation_releases_digest ON uem_desktop_invitation_releases(release_digest);
