package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/grafana/grafana/pkg/services/datasources"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
)

// validateRecordingRuleTargets rejects recording rules whose target data source has
// allowAsRecordingRulesTarget turned off. The recording rule writer checks the same setting
// before every remote write, so a data source that is excluded after a rule is saved is not written either.
func (st DBstore) validateRecordingRuleTargets(ctx context.Context, rules []*ngmodels.AlertRule) error {
	if st.DatasourceService == nil {
		return nil
	}
	for _, rule := range rules {
		if rule == nil || rule.Record == nil {
			continue
		}
		uid := rule.Record.TargetDatasourceUID
		if uid == "" {
			uid = st.Cfg.RecordingRules.DefaultDatasourceUID
		}
		if uid == "" {
			continue
		}
		ds, err := st.DatasourceService.GetDataSource(ctx, &datasources.GetDataSourceQuery{UID: uid, OrgID: rule.OrgID})
		if errors.Is(err, datasources.ErrDataSourceNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get target data source %q of recording rule %q: %w", uid, rule.Title, err)
		}
		if !ds.AllowedAsRecordingRulesTarget(st.DefaultAllowRecordingRulesTarget) {
			return fmt.Errorf("%w: recording rule %q cannot write to data source %q because it is not allowed as a recording rules target",
				ngmodels.ErrAlertRuleFailedValidation, rule.Title, uid)
		}
	}
	return nil
}

// recordingTargetChanged reports whether an update makes the rule write to a data source it did not write to before.
func recordingTargetChanged(existing, updated *ngmodels.AlertRule) bool {
	if updated.Record == nil {
		return false
	}
	if existing == nil || existing.Record == nil {
		return true
	}
	return existing.OrgID != updated.OrgID || existing.Record.TargetDatasourceUID != updated.Record.TargetDatasourceUID
}
