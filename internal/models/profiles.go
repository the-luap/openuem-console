package models

import (
	"context"
	"strconv"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/profile"
	"github.com/open-uem/ent/site"
	"github.com/open-uem/ent/tenant"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func (m *Model) CountAllProfiles(c *partials.CommonInfo) (int, error) {
	query := m.Client.Profile.Query()

	siteID, err := strconv.Atoi(c.SiteID)
	if err != nil {
		return -1, err
	}

	tenantID, err := strconv.Atoi(c.TenantID)
	if err != nil {
		return -1, err
	}

	if tenantID == -1 {
		query = query.Where(profile.And(profile.Not(profile.HasSite()), profile.Not(profile.HasTenant())))
	} else {
		if siteID == -1 {
			query = query.Where(profile.HasTenantWith(tenant.ID(tenantID)), profile.Not(profile.HasSite()))
		} else {
			query = query.Where(profile.HasSiteWith(site.ID(siteID), site.HasTenantWith(tenant.ID(tenantID))))
		}
	}

	return query.Count(context.Background())
}

func (m *Model) GetProfilesByPage(p partials.PaginationAndSort, c *partials.CommonInfo) ([]*ent.Profile, error) {
	var err error
	var profiles []*ent.Profile

	query := m.Client.Profile.Query().WithTasks().WithTags().WithIssues(func(q *ent.ProfileIssueQuery) {
		q.WithTasksreports(func(q *ent.TaskReportQuery) { q.WithTask().All(context.Background()) }).All(context.Background())
	}).Limit(p.PageSize).Offset((p.CurrentPage - 1) * p.PageSize)

	siteID, err := strconv.Atoi(c.SiteID)
	if err != nil {
		return nil, err
	}

	tenantID, err := strconv.Atoi(c.TenantID)
	if err != nil {
		return nil, err
	}

	if tenantID == -1 {
		query = query.Where(profile.And(profile.Not(profile.HasSite()), profile.Not(profile.HasTenant())))
	} else {
		if siteID == -1 {
			query = query.Where(profile.HasTenantWith(tenant.ID(tenantID)), profile.Not(profile.HasSite()))
		} else {
			query = query.Where(profile.HasSiteWith(site.ID(siteID), site.HasTenantWith(tenant.ID(tenantID))))
		}
	}

	switch p.SortBy {
	case "name":
		if p.SortOrder == "asc" {
			profiles, err = query.Order(ent.Asc(profile.FieldName)).All(context.Background())
		} else {
			profiles, err = query.Order(ent.Desc(profile.FieldName)).All(context.Background())
		}
	default:
		profiles, err = query.Order(ent.Desc(profile.FieldName)).All(context.Background())
	}

	if err != nil {
		return nil, err
	}
	return profiles, nil
}

func (m *Model) GetProfileById(profileId int, c *partials.CommonInfo) (*ent.Profile, error) {

	return m.Client.Profile.Query().WithTags().WithTasks().WithIssues().Where(profile.ID(profileId)).First(context.Background())
}
