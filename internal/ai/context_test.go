package ai

import (
	"context"
	"testing"

	"quetzalog/internal/database"
	"quetzalog/internal/findings"
)

func TestContextIncludesAssetsAndTelemetry(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	fs := findings.NewStore(db)
	cb := NewContextBuilder(fs, nil).
		WithAssets(func(ctx context.Context, host string) *AssetBrief {
			if host != "db1" {
				return nil
			}
			return &AssetBrief{
				Name:            "db1",
				EntityType:      "server",
				Criticality:     "critical",
				InternetExposed: false,
				Draft:           false,
			}
		}).
		WithCoverage(func(ctx context.Context, host string) *CoverageBrief {
			if host != "db1" {
				return nil
			}
			return &CoverageBrief{
				Asset:       "db1",
				CoveragePct: 45,
				Missing:     []string{"os.linux.journal", "net.flow"},
			}
		})

	f := &findings.Finding{
		ID:       "f-1",
		Title:    "Suspicious login",
		Severity: "critical",
		Status:   "new",
		Host:     "db1",
	}
	fctx, err := cb.Build(context.Background(), f, 10)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(fctx.Assets) != 1 || fctx.Assets[0].Name != "db1" || fctx.Assets[0].Criticality != "critical" {
		t.Errorf("assets block: %+v", fctx.Assets)
	}
	if len(fctx.Telemetry) != 1 || fctx.Telemetry[0].CoveragePct != 45 {
		t.Errorf("telemetry block: %+v", fctx.Telemetry)
	}
}

func TestContextOmitsBlocksWhenProvidersUnset(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cb := NewContextBuilder(findings.NewStore(db), nil)
	f := &findings.Finding{ID: "f-2", Title: "t", Severity: "info", Host: "h1"}
	fctx, err := cb.Build(context.Background(), f, 10)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(fctx.Assets) != 0 || len(fctx.Telemetry) != 0 {
		t.Errorf("blocks must be omitted without providers: assets=%v telemetry=%v", fctx.Assets, fctx.Telemetry)
	}
}
