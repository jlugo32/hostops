package cli

import (
	"reflect"

	"github.com/jlugo32/hostops/internal/adapters/backups"
	"github.com/jlugo32/hostops/internal/adapters/logs"
	"github.com/jlugo32/hostops/internal/audit"
	"github.com/jlugo32/hostops/internal/baseline"
	"github.com/jlugo32/hostops/internal/confirm"
	"github.com/jlugo32/hostops/internal/output"
)

// SchemaTypes maps each published schema id to its Go type. Adding an output
// type without listing it here fails TestEveryOutputHasSchema.
var SchemaTypes = map[string]reflect.Type{
	"sites.v1":          reflect.TypeOf(SitesList{}),
	"site.v1":           reflect.TypeOf(SiteGet{}),
	"sites-check.v1":    reflect.TypeOf(SitesCheck{}),
	"cert-status.v1":    reflect.TypeOf(CertStatus{}),
	"service-status.v1": reflect.TypeOf(ServiceStatus{}),
	"firewall.v1":       reflect.TypeOf(Firewall{}),
	"fail2ban.v1":       reflect.TypeOf(Fail2ban{}),
	"baseline.v1":       reflect.TypeOf(baseline.Report{}),
	"backups.v1":        reflect.TypeOf(BackupList{}),
	"backup-verify.v1":  reflect.TypeOf(backups.Report{}),
	"db-list.v1":        reflect.TypeOf(DBList{}),
	"db-size.v1":        reflect.TypeOf(DBSize{}),
	"db-slowlog.v1":     reflect.TypeOf(DBSlowlog{}),
	"logs-top.v1":       reflect.TypeOf(logs.Top{}),
	"journal.v1":        reflect.TypeOf(Journal{}),
	"audit-verify.v1":   reflect.TypeOf(audit.VerifyReport{}),
	"plan.v1":           reflect.TypeOf(confirm.DryRun{}),
	"confirm.v1":        reflect.TypeOf(confirm.Envelope{}),
	"result.v1":         reflect.TypeOf(WriteResult{}),
	"error.v1":          reflect.TypeOf(output.ErrorDoc{}),
}
