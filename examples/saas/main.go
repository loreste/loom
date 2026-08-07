// Command saas validates the production-shaped configuration for a
// multi-tenant PostgreSQL RLS deployment. The application role and migration
// owner are intentionally separate; the RLS SQL lives in rls.sql.
package main

import (
	"fmt"
	"os"

	"github.com/loreste/loom/config"
	"github.com/loreste/loom/tenancy"
)

func validateConfig(c config.AppDB) error {
	if c.URL == "" {
		return fmt.Errorf("LOOM_APP_DB_URL is required")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if c.RequireTenantRLS || os.Getenv("LOOM_APP_DB_REQUIRE_TENANT_RLS") == "true" {
		if c.TenantSetting != "app.tenant_id" {
			return fmt.Errorf("tenant setting must be app.tenant_id")
		}
	}
	if _, err := tenancy.NewResolver("tenant_id"); err != nil {
		return err
	}
	return nil
}

func main() {
	if err := validateConfig(config.LoadAppDB()); err != nil {
		fmt.Fprintln(os.Stderr, "saas configuration rejected:", err)
		os.Exit(2)
	}
	fmt.Println("SaaS RLS configuration validated; apply rls.sql with a migration owner")
}
