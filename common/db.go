package common

import (
	"context"

	"cloud.google.com/go/datastore"
	log "github.com/sirupsen/logrus"
)

const (
	ALERT_KIND = "alert"
	IP_KIND    = "whitelisted_ip"
)

type DBClient struct {
	dsClient *datastore.Client
}

func NewDBClient(ctx context.Context, projectID string) (*DBClient, error) {
	dsClient, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return &DBClient{dsClient}, nil
}

func (db *DBClient) Close() error {
	return db.dsClient.Close()
}

func (db *DBClient) whitelistedIpKey(ip string) *datastore.Key {
	return datastore.NameKey(IP_KIND, ip, nil)
}

func (db *DBClient) alertKey(alertId string) *datastore.Key {
	return datastore.NameKey(ALERT_KIND, alertId, nil)
}

func (db *DBClient) SaveWhitelistedIp(ctx context.Context, whitelistedIp *WhitelistedIP) error {
	_, err := db.dsClient.Put(ctx, db.whitelistedIpKey(whitelistedIp.IP), whitelistedIp)
	return err
}

func (db *DBClient) GetAlert(ctx context.Context, alertId string) (*Alert, error) {
	var alert Alert
	err := db.dsClient.Get(ctx, db.alertKey(alertId), &alert)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &alert, nil
}

func (db *DBClient) UpdateAlert(ctx context.Context, alert *Alert, status string) error {
	tx, err := db.dsClient.NewTransaction(ctx)
	if err != nil {
		log.Errorf("updateAlert: %v", err)
		return err
	}

	found := false
	for _, am := range alert.Metadata {
		if am.Key == "status" {
			am.Value = status
			found = true
		}
	}
	//handle case where there is no status
	if !found {
		alert.Metadata = append(alert.Metadata, AlertMeta{Key: "status", Value: status})
	}

	if _, err := tx.Put(db.alertKey(alert.Id), alert); err != nil {
		log.Errorf("updateAlert tx.Put: %v", err)
		return err
	}
	if _, err := tx.Commit(); err != nil {
		log.Errorf("updateAlert tx.Commit: %v", err)
		return err
	}
	return nil
}
