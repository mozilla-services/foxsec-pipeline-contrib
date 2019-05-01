package slackbotbackground

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"
	"github.com/mozilla-services/foxsec-pipeline-contrib/common/persons_api"

	"cloud.google.com/go/pubsub"
	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

const (
	WHITELIST_IP_SLASH_COMMAND         = "/whitelist_ip"
	STAGING_WHITELIST_IP_SLASH_COMMAND = "/staging_whitelist_ip"
	DEFAULT_EXPIRATION_DURATION        = time.Hour * 24
	DURATION_DOC                       = "FoxsecBot uses Go's time.ParseDuration internally " +
		"with some custom checks. Examples: '72h' or '2h45m'. " +
		"Valid time units are 'm' and 'h'. If you omit a duration, " +
		"the default (24 hours) is used. If your duration is under 5 minutes, it is increased to 5 minutes."
)

var (
	globalConfig            Config
	client                  *http.Client
	KEYNAME                 string
	PROJECT_ID              string
	FOXSEC_SLACK_CHANNEL_ID string
	DB                      *common.DBClient
	ALERT_ESCALATION_TTL    time.Duration
)

func init() {
	mozlogrus.Enable("slackbot-background")
	client = &http.Client{
		Timeout: 10 * time.Second,
	}
	KEYNAME = os.Getenv("KMS_KEYNAME")
	PROJECT_ID = os.Getenv("GCP_PROJECT")
	FOXSEC_SLACK_CHANNEL_ID = os.Getenv("FOXSEC_SLACK_CHANNEL_ID")
	if FOXSEC_SLACK_CHANNEL_ID == "" {
		log.Fatal("Could not find FOXSEC_SLACK_CHANNEL_ID env var")
	}
	InitConfig()

	var err error
	DB, err = common.NewDBClient(context.Background(), PROJECT_ID)
	if err != nil {
		log.Errorf("Error creating db client: %s", err)
		return
	}

	ALERT_ESCALATION_TTL, err = time.ParseDuration(os.Getenv("ALERT_ESCALATION_TTL"))
	if err != nil {
		log.Fatalf("Failed to parse alert escalation ttl: %s | Err: %s", os.Getenv("ALERT_ESCALATION_TTL"), err)
	}
}

type Config struct {
	slackAuthToken      string
	slackClient         *slack.Client
	personsClientId     string
	personsClientSecret string
	personsClient       *persons_api.Client
	allowedGroups       []string
	sesClient           *common.SESClient
}

func InitConfig() {
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

	globalConfig.sesClient, err = common.NewSESClient(os.Getenv("AWS_REGION"), accessKeyId, secretAccessKey, os.Getenv("SES_SENDER_EMAIL"), os.Getenv("ESCALATION_EMAIL"))
	if err != nil {
		log.Fatalf("Could not setup SESClient. Err: %s", err)
	}

	globalConfig.slackAuthToken, err = kms.DecryptEnvVar(KEYNAME, "SLACK_AUTH_TOKEN")
	if err != nil {
		log.Fatalf("Could not decrypt slack auth token. Err: %s", err)
	}

	globalConfig.slackClient = slack.New(globalConfig.slackAuthToken)

	globalConfig.personsClientId, err = kms.DecryptEnvVar(KEYNAME, "PERSONS_CLIENT_ID")
	if err != nil {
		log.Fatalf("Could not decrypt persons client id. Err: %s", err)
	}

	globalConfig.personsClientSecret, err = kms.DecryptEnvVar(KEYNAME, "PERSONS_CLIENT_SECRET")
	if err != nil {
		log.Fatalf("Could not decrypt persons client secret. Err: %s", err)
	}

	globalConfig.personsClient, err = persons_api.NewClient(
		globalConfig.personsClientId,
		globalConfig.personsClientSecret,
		os.Getenv("PERSONS_BASE_URL"),
		os.Getenv("PERSONS_AUTH0_URL"),
	)
	if err != nil {
		log.Fatalf("Could not create persons api client: %s", err)
	}

	globalConfig.allowedGroups = strings.Split(os.Getenv("ALLOWED_LDAP_GROUPS"), ",")
}

func alertEscalator(ctx context.Context) error {
	alerts, err := DB.GetAllAlerts(ctx)
	if err != nil {
		log.Errorf("Error getting all alerts: %s", err)
		return err
	}

	for _, alert := range alerts {
		log.Infof("Checking alert %s", alert.Id)
		if alert.IsStatus(common.ALERT_NEW) && alert.OlderThan(ALERT_ESCALATION_TTL) {
			log.Infof("Escalating alert %s", alert.Id)
			alert.SetMetadata("status", common.ALERT_ESCALATED)

			// TODO: If we retry based off an error here, we could
			//		   potentially send an escalation email multiple times.
			err := globalConfig.sesClient.SendEscalationEmail(alert)
			if err != nil {
				log.Errorf("Error escalating alert (%s). Err: %s", alert.Id, err)
				return err
			}
			err = DB.SaveAlert(ctx, alert)
			if err != nil {
				log.Errorf("Error updating alert as escalated (%s). Err: %s", alert.Id, err)
				return err
			}
		}
	}

	return nil
}

func SlackbotBackground(ctx context.Context, psmsg pubsub.Message) error {
	td, err := common.PubSubMessageToTriggerData(psmsg)
	if err != nil {
		log.Errorf("Error decoding pubsub message: %s", err)
		return nil
	}

	if td.Action == common.SlashCommand {
		log.Infof("Got slash command: %s", td.SlashCommand.Cmd)
		if td.SlashCommand.Cmd == WHITELIST_IP_SLASH_COMMAND || td.SlashCommand.Cmd == STAGING_WHITELIST_IP_SLASH_COMMAND {
			resp, err := handleWhitelistCmd(ctx, td.SlashCommand, DB)
			if err != nil {
				log.Errorf("error handling whitelist command: %s", err)
			}
			if resp != nil {
				err = sendSlackCallback(resp, td.SlashCommand.ResponseURL)
				if err != nil {
					log.Errorf("error sending slack callback within slash command: %s", err)
					return err
				}
			}
		}
	} else if td.Action == common.Interaction {
		log.Info("Got interaction action trigger")
		if isAlertConfirm(td.Interaction.CallbackID) {
			resp, err := handleAlertConfirm(ctx, td.Interaction, DB)
			if err != nil {
				log.Errorf("Error handling alert confirmation interaction: %s", err)
			}
			if resp != nil {
				err = sendSlackCallback(resp, td.Interaction.ResponseURL)
				if err != nil {
					log.Errorf("error sending slack callback for interaction: %s", err)
					return err
				}
			}
		}
	} else if td.Action == common.ScheduledTask {
		log.Info("Got scheduled task action trigger")
		// We don't want to return an error here, as we don't need the
		// pubsub/cloudfunction retry mechanism to retry these, as they are scheduled tasks.
		err = alertEscalator(ctx)
		if err != nil {
			log.Errorf("Error escalating alerts: %s", err)
		}
		err = DB.RemoveExpiredWhitelistedIps(ctx)
		if err != nil {
			log.Errorf("Error purging expired whitelisted ips: %s", err)
		}
	}

	return nil
}
