package purger

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

var (
	PROJECT_ID           string
	ALERT_ESCALATION_TTL time.Duration
	SESCLIENT            *common.SESClient
	DB                   *common.DBClient
)

func init() {
	mozlogrus.Enable("escalator")
	PROJECT_ID = os.Getenv("GCP_PROJECT")
	KEYNAME := os.Getenv("KMS_KEYNAME")

	var err error

	ALERT_ESCALATION_TTL, err = time.ParseDuration(os.Getenv("ALERT_ESCALATION_TTL"))
	if err != nil {
		log.Fatalf("Failed to parse alert escalation ttl: %s | Err: %s", os.Getenv("ALERT_ESCALATION_TTL"), err)
	}

	kms, err := common.NewKMSClient()
	if err != nil {
		log.Fatalf("Could not create kms client. Err: %s", err)
	}
	accessKeyId, err := kms.DecryptEnvVar(KEYNAME, "AWS_ACCESS_KEY_ID")
	if err != nil {
		log.Fatalf("Could not decrypt aws access key. Err: %s", err)
	}
	secretAccessKey, err := kms.DecryptEnvVar(KEYNAME, "AWS_SECRET_ACCESS_KEY")
	if err != nil {
		log.Fatalf("Could not decrypt aws secret access key. Err: %s", err)
	}

	SESCLIENT, err = common.NewSESClient(os.Getenv("AWS_REGION"), accessKeyId, secretAccessKey, os.Getenv("SES_SENDER_EMAIL"), os.Getenv("ESCALATION_EMAIL"))
	if err != nil {
		log.Fatalf("Could not setup SESClient. Err: %s", err)
	}

	DB, err = common.NewDBClient(context.Background(), PROJECT_ID)
	if err != nil {
		log.Fatalf("Error creating db client: %s", err)
	}
}

func Escalator(w http.ResponseWriter, r *http.Request) {
	log.Info("Running Escalator func")

	alerts, err := DB.GetAllAlerts(r.Context())
	if err != nil {
		log.Errorf("Error getting all alerts: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	for _, alert := range alerts {
		log.Infof("Check alert %s", alert.Id)
		if alert.IsStatus(common.ALERT_NEW) && alert.OlderThan(ALERT_ESCALATION_TTL) {
			log.Infof("Escalating alert %s", alert.Id)
			returnEarly := false
			err := SESCLIENT.SendEscalationEmail(alert)
			if err != nil {
				log.Errorf("Error escalating alert (%s). Err: %s", alert.Id, err)
				returnEarly = true
			}
			err = DB.UpdateAlert(r.Context(), alert, common.ALERT_ESCALATED)
			if err != nil {
				log.Errorf("Error updating alert as escalated (%s). Err: %s", alert.Id, err)
				returnEarly = true
			}
			if returnEarly {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
	}
	w.WriteHeader(http.StatusOK)
}
