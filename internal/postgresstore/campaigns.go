package postgresstore

import (
	"context"
	"fmt"
	"slices"

	"antispambee/internal/moderation"
)

func (s *Store) ObserveCampaign(ctx context.Context, tenant string, target moderation.ActionTarget, indicators []moderation.CampaignIndicator, confirmed bool) ([]string, error) {
	if len(indicators) == 0 {
		return nil, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var kinds []string
	for _, indicator := range indicators {
		if _, err := tx.Exec(ctx, `INSERT INTO moderation_campaign_observations(tenant_id,chat_id,kind,fingerprint,user_id,message_id,confirmed_advertising)
			VALUES($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (tenant_id,chat_id,kind,fingerprint,message_id) DO UPDATE
			SET confirmed_advertising=moderation_campaign_observations.confirmed_advertising OR EXCLUDED.confirmed_advertising`,
			tenant, target.ChatID, indicator.Kind, indicator.Fingerprint, target.UserID, target.MessageID, confirmed); err != nil {
			return nil, fmt.Errorf("record campaign indicator: %w", err)
		}
		if slices.Contains(kinds, indicator.Kind) {
			continue
		}
		var linked bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM moderation_campaign_observations
			WHERE tenant_id=$1 AND chat_id=$2 AND kind=$3 AND fingerprint=$4 AND user_id<>$5
			AND confirmed_advertising AND observed_at>=now()-interval '45 minutes')`,
			tenant, target.ChatID, indicator.Kind, indicator.Fingerprint, target.UserID).Scan(&linked); err != nil {
			return nil, fmt.Errorf("match known campaign: %w", err)
		}
		if linked {
			kinds = append(kinds, indicator.Kind)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return kinds, nil
}
