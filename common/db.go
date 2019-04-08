package common

import (
	"context"
	"encoding/json"

	"cloud.google.com/go/datastore"
)

const (
	ALERT_KIND      = "alert"
	ALERT_NAMESPACE = "alert"
	IP_KIND         = "whitelisted_ip"
	IP_NAMESPACE    = "whitelisted_ip"
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

type StateField struct {
	State string `datastore:"state" json:"state"`
}

func WhitelistedIpToState(wip *WhitelistedIP) (*StateField, error) {
	buf, err := json.Marshal(wip)
	if err != nil {
		return nil, err
	}
	return &StateField{string(buf)}, nil
}

func StateToWhitelistedIp(sf *StateField) (*WhitelistedIP, error) {
	var wip WhitelistedIP
	err := json.Unmarshal([]byte(sf.State), &wip)
	if err != nil {
		return nil, err
	}
	return &wip, nil
}

func (db *DBClient) Close() error {
	return db.dsClient.Close()
}

func (db *DBClient) whitelistedIpKey(ip string) *datastore.Key {
	nk := datastore.NameKey(IP_KIND, ip, nil)
	nk.Namespace = IP_NAMESPACE
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
	var states []*StateField
	nq := datastore.NewQuery(IP_KIND).Namespace(IP_NAMESPACE)
	_, err := db.dsClient.GetAll(ctx, nq, &states)
	for _, state := range states {
		ip, err := StateToWhitelistedIp(state)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, err
}

func (db *DBClient) SaveWhitelistedIp(ctx context.Context, whitelistedIp *WhitelistedIP) error {
	sf, err := WhitelistedIpToState(whitelistedIp)
	if err != nil {
		return err
	}
	_, err = db.dsClient.Put(ctx, db.whitelistedIpKey(whitelistedIp.IP), sf)
	return err
}

func (db *DBClient) DeleteWhitelistedIp(ctx context.Context, whitelistedIp *WhitelistedIP) error {
	return db.dsClient.Delete(ctx, db.whitelistedIpKey(whitelistedIp.IP))
}

func (db *DBClient) alertKey(ip string) *datastore.Key {
	nk := datastore.NameKey(ALERT_KIND, ip, nil)
	nk.Namespace = ALERT_NAMESPACE
	return nk
}

func StateToAlert(sf *StateField) (*Alert, error) {
	var alert Alert
	err := json.Unmarshal([]byte(sf.State), &alert)
	if err != nil {
		return nil, err
	}
	return &alert, nil
}

func (db *DBClient) GetAlert(ctx context.Context, alertId string) (*Alert, error) {
	var alert Alert
	err := db.dsClient.Get(ctx, db.alertKey(alertId), &alert)
	if err != nil {
		return nil, err
	}
	return &alert, nil
}

func (db *DBClient) GetAllAlerts(ctx context.Context) ([]*Alert, error) {
	var alerts []*Alert
	var states []*StateField
	nq := datastore.NewQuery(ALERT_KIND).Namespace(ALERT_NAMESPACE)
	_, err := db.dsClient.GetAll(ctx, nq, &states)
	for _, state := range states {
		alert, err := StateToAlert(state)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	return alerts, err
}

func (db *DBClient) UpdateAlert(ctx context.Context, alert *Alert, status string) error {
	tx, err := db.dsClient.NewTransaction(ctx)
	if err != nil {
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
		return err
	}
	if _, err := tx.Commit(); err != nil {
		return err
	}
	return nil
}
