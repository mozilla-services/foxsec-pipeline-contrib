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
	dsClient  *datastore.Client
	namespace string
}

func NewDBClient(ctx context.Context, projectID string, namespace string) (*DBClient, error) {
	dsClient, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return &DBClient{dsClient, namespace}, nil
}

func (db *DBClient) Close() error {
	return db.dsClient.Close()
}

func (db *DBClient) whitelistedIpKey(ip string) *datastore.Key {
	nk := datastore.NameKey(IP_KIND, ip, nil)
	if db.namespace != "" {
		nk.Namespace = db.namespace
	}
	return nk
}

func (db *DBClient) alertKey(alertId string) *datastore.Key {
	nk := datastore.NameKey(ALERT_KIND, alertId, nil)
	if db.namespace != "" {
		nk.Namespace = db.namespace
	}
	return nk
}

func (db *DBClient) RemoveExpiredWhitelistedIps(ctx context.Context) error {
	ips, err := db.GetAllWhitelistedIps(ctx)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.IsExpired() {
			err = db.DeleteWhitelistedIp(ctx, ip)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (db *DBClient) GetAllWhitelistedIps(ctx context.Context) ([]*WhitelistedIP, error) {
	var ips []*WhitelistedIP
	_, err := db.dsClient.GetAll(ctx, datastore.NewQuery(IP_KIND), &ips)
	return ips, err
}

func (db *DBClient) SaveWhitelistedIp(ctx context.Context, whitelistedIp *WhitelistedIP) error {
	_, err := db.dsClient.Put(ctx, db.whitelistedIpKey(whitelistedIp.IP), whitelistedIp)
	return err
}

func (db *DBClient) DeleteWhitelistedIp(ctx context.Context, whitelistedIp *WhitelistedIP) error {
	return db.dsClient.Delete(ctx, db.whitelistedIpKey(whitelistedIp.IP))
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
