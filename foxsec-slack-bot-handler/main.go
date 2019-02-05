package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	"cloud.google.com/go/datastore"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

var (
	globalConfig Config
	client       = &http.Client{
		Timeout: 10 * time.Second,
	}
	KEYNAME = os.Getenv("KMS_KEYNAME")
)

const (
	ALERT_KIND     = "alert"
	EMAIL_CHAR_SET = "UTF-8"
)

func init() {
	mozlogrus.Enable("cloudtrail-streamer")
	InitConfig()
}

type Config struct {
	slackSigningSecret string
	escalationEmail    string
	awsSecretAccessKey string
	awsAccessKeyId     string
	awsRegion          string
	sesSenderEmail     string
	sesClient          *ses.SES
}

func InitConfig() error {
	kms, err := common.NewKMSClient()
	if err != nil {
		log.Fatalf("Could not create kms client. Err: %s", err)
	}

	globalConfig.slackSigningSecret, err = kms.DecryptSymmetric(KEYNAME, os.Getenv("SLACK_SIGNING_SECRET"))
	if err != nil {
		log.Fatalf("Could not decrypt slack signing secret. Err: %s", err)
	}

	globalConfig.escalationEmail = os.Getenv("ESCALATION_EMAIL")
	if globalConfig.escalationEmail == "" {
		log.Fatalf("No ESCALATION_EMAIL provided.")
	}

	globalConfig.awsRegion = os.Getenv("AWS_REGION")
	globalConfig.awsSecretAccessKey, err = kms.DecryptSymmetric(KEYNAME, os.Getenv("AWS_SECRET_ACCESS_KEY"))
	if err != nil {
		log.Fatalf("Could not decrypt aws secret access key. Err: %s", err)
	}
	globalConfig.awsAccessKeyId, err = kms.DecryptSymmetric(KEYNAME, os.Getenv("AWS_ACCESS_KEY_ID"))
	if err != nil {
		log.Fatalf("Could not decrypt aws access key id. Err: %s", err)
	}

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(globalConfig.awsRegion),
		Credentials: credentials.NewStaticCredentials(globalConfig.awsAccessKeyId, globalConfig.awsSecretAccessKey, ""),
	})
	globalConfig.sesClient = ses.New(sess)

	return nil
}

func emailEscalation(alert *common.Alert) error {
	subject := fmt.Sprintf("[foxsec-pipeline-alert] Escalating alert - %s", alert.Summary)

	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			CcAddresses: []*string{},
			ToAddresses: []*string{
				aws.String(globalConfig.escalationEmail),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Text: &ses.Content{
					Charset: aws.String(EMAIL_CHAR_SET),
					Data:    aws.String(alert.PrettyPrint()),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String(EMAIL_CHAR_SET),
				Data:    aws.String(subject),
			},
		},
		Source: aws.String(globalConfig.sesSenderEmail),
	}

	// Attempt to send the email.
	_, err := globalConfig.sesClient.SendEmail(input)

	// Display error messages if they occur.
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ses.ErrCodeMessageRejected:
				log.Errorf("ses.ErrCodeMessageRejected: %s", aerr.Error())
			case ses.ErrCodeMailFromDomainNotVerifiedException:
				log.Errorf("ses.ErrCodeMailFromDomainNotVerifiedException: %s", aerr.Error())
			case ses.ErrCodeConfigurationSetDoesNotExistException:
				log.Errorf("ses.ErrCodeConfigurationSetDoesNotExistException: %s", aerr.Error())
			default:
				log.Errorf("misc ses error: %s", aerr.Error())
			}
		} else {
			log.Errorf("ses error: %s", err)
		}

		return err
	}

	return nil
}

type DBClient struct {
	dsClient *datastore.Client
}

func (db *DBClient) alertKey(alertId string) *datastore.Key {
	return datastore.NameKey(ALERT_KIND, alertId, nil)
}

func (db *DBClient) getAlert(alertId string) (*common.Alert, error) {
	var alert common.Alert
	err := db.dsClient.Get(context.TODO(), db.alertKey(alertId), &alert)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &alert, nil
}

func (db *DBClient) updateAlert(alert *common.Alert, status string) error {
	tx, err := db.dsClient.NewTransaction(context.TODO())
	if err != nil {
		log.Errorf("updateAlert: %v", err)
		return err
	}

	//TODO - handle case where there is no status
	for _, am := range alert.Metadata {
		if am.Key == "status" {
			am.Value = status
		}
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

// Send email to pagerduty using AWS SES
func (db *DBClient) escalateAlert(alert *common.Alert) error {
	err := emailEscalation(alert)
	if err != nil {
		log.Error(err)
		return err
	}
	err = db.updateAlert(alert, "ESCALATED")
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func handleAuthConfirm(req slack.InteractionCallback, db *DBClient) (*slack.Msg, error) {
	alertId := strings.Split(req.CallbackID, "_")[1]
	alert, err := db.getAlert(alertId)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	response := "Error responding; please contact SecOps (secops@mozilla.com)"
	if req.Actions[0].Name == "auth_yes" {
		err := db.updateAlert(alert, "ACKNOWLEDGED")
		if err != nil {
			log.Error(err)
		}
		response = "Thank you for responding! Alert acknowledged"
	} else if req.Actions[0].Name == "auth_no" {
		err := db.escalateAlert(alert)
		if err != nil {
			log.Error(err)
		}
		response = "Thank you for responding! Alert has been escalated to SecOps (secops@mozilla.com)"
	}

	return &slack.Msg{Text: response, ReplaceOriginal: false}, nil
}

func isAuthConfirm(req slack.InteractionCallback) bool {
	if strings.HasPrefix(req.CallbackID, "auth_confirmation") {
		return true
	}

	return false
}

func FoxsecSlackHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	// Check signature
	sv, err := slack.NewSecretsVerifier(r.Header, globalConfig.slackSigningSecret)
	if err != nil {
		log.Error(err.Error())
		return
	}
	err = sv.Ensure()
	if err != nil {
		log.Error(err.Error())
		return
	}

	dsClient, err := datastore.NewClient(context.TODO(), "")
	if err != nil {
		log.Error(err.Error())
		return
	}
	defer dsClient.Close()
	db := &DBClient{dsClient}

	// Handle interaction callback
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error(err.Error())
		return
	}
	var req slack.InteractionCallback
	err = json.Unmarshal(buf, &req)
	if err != nil {
		log.Error(err.Error())
		return
	}

	if isAuthConfirm(req) {
		resp, err := handleAuthConfirm(req, db)
		if err != nil {
			log.Error(err.Error())
			return
		}
		log.Info(resp)

		msg, err := json.Marshal(resp)
		if err != nil {
			log.Error(err.Error())
			return
		}
		_, err = client.Post(req.ResponseURL, "application/json", bytes.NewBuffer(msg))
		if err != nil {
			log.Error(err.Error())
			return
		}
	}

	return
}
