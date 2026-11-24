package main

import (
	"slices"
	"testing"

	"antispambee/internal/postgresstore"
)

func TestOperationalAlertsSeparateQueueAndDependencyFailures(t *testing.T) {
	if alerts := operationalAlerts(false, false, postgresstore.OperationsStatus{RetryingActions: 1, ModelErrors: 1}, 1); len(alerts) != 0 {
		t.Fatalf("one retry must not trigger an alert: %+v", alerts)
	}
	alerts := operationalAlerts(true, false, postgresstore.OperationsStatus{FailedActions: 1}, 3)
	var kinds []string
	for _, alert := range alerts {
		kinds = append(kinds, alert.kind)
	}
	if !slices.Equal(kinds, []string{"queue_slow", "telegram_actions", "classification"}) {
		t.Fatalf("alerts: %v", kinds)
	}
}
