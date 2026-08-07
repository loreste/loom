package main

import (
	"testing"

	"github.com/loreste/loom/config"
)

func TestValidateConfigRequiresPostgresTenantRLS(t *testing.T) {
	base := config.AppDB{
		URL:              "postgres://app@example/loom",
		Driver:           "pgx",
		Pool:             "main",
		RequireTenantRLS: true,
		TenantSetting:    "app.tenant_id",
	}
	if err := validateConfig(base); err != nil {
		t.Fatal(err)
	}
	base.TenantSetting = "app.wrong"
	if err := validateConfig(base); err == nil {
		t.Fatal("wrong tenant setting must be rejected")
	}
}

func TestValidateConfigRejectsMissingDatabase(t *testing.T) {
	if err := validateConfig(config.AppDB{}); err == nil {
		t.Fatal("missing database must be rejected")
	}
}
