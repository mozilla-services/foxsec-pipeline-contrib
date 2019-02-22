package foxsecslackbot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

var (
	globalConfig Config
	client       *http.Client
	KEYNAME      string
	PROJECT_ID   string
)

const (
	EMAIL_CHAR_SET             = "UTF-8"
	WHITELIST_IP_SLASH_COMMAND = "/whitelist_ip"
)

func init() {
	// TODO - Set as option
	log.SetLevel(log.DebugLevel)

	mozlogrus.Enable("foxsec-slack-bot")
	client = &http.Client{
		Timeout: 10 * time.Second,
	}
	KEYNAME = os.Getenv("KMS_KEYNAME")
	PROJECT_ID = os.Getenv("GCP_PROJECT")
	InitConfig()
}

type Config struct {
	slackSigningSecret string
	slackAuthToken     string
	slackClient        *slack.Client
}

func InitConfig() {
	kms, err := common.NewKMSClient()
	if err != nil {
		log.Fatalf("Could not create kms client. Err: %s", err)
	}

	log.Infof("Decrypting with key: %s", KEYNAME)

	globalConfig.slackSigningSecret, err = kms.DecryptEnvVar(KEYNAME, "SLACK_SIGNING_SECRET")
	if err != nil {
		log.Fatalf("Could not decrypt slack signing secret. Err: %s", err)
	}

	globalConfig.slackAuthToken, err = kms.DecryptEnvVar(KEYNAME, "SLACK_AUTH_TOKEN")
	if err != nil {
		log.Fatalf("Could not decrypt slack auth token. Err: %s", err)
	}

	globalConfig.slackClient = slack.New(globalConfig.slackAuthToken)
}

func handleWhitelistCmd(ctx context.Context, cmd slack.SlashCommand, db *common.DBClient) (*slack.Msg, error) {
	msg := &slack.Msg{}

	splitCmd := strings.Split(cmd.Text, " ")
	ip := net.ParseIP(splitCmd[0])
	if ip == nil {
		m := fmt.Sprintf("Got invalid IP: %s", splitCmd[0])
		msg.Text = m
		return msg, errors.New(m)
	}

	expiresDur, err := time.ParseDuration(splitCmd[1])
	if err != nil {
		log.Errorf("Error parsing duration: %s", err)
		msg.Text = "Was unable to correctly parse duration"
		return msg, err
	}
	expiresAt := time.Now().Add(expiresDur)

	userProfile, err := globalConfig.slackClient.GetUserProfile(cmd.UserID, false)
	if err != nil {
		log.Errorf("Error getting user profile: %s", err)
		msg.Text = "Was unable to get your email from Slack."
		return msg, err
	}

	err = db.SaveWhitelistedIp(ctx, common.NewWhitelistedIP(ip.String(), expiresAt, userProfile.Email))
	if err != nil {
		log.Errorf("Error saving whitelisted ip: %s", err)
		msg.Text = "Error saving IP to whitelist"
		return msg, err
	}

	msg.Text = fmt.Sprintf("Successfully saved %s to the whitelist. Will expire at %s", ip, expiresAt.Format(time.UnixDate))
	return msg, nil
}

func sendSlackCallback(msg *slack.Msg, responseUrl string) error {
	j, err := json.Marshal(msg)
	if err != nil {
		log.Errorf("Error marshalling slack message: %s", err)
		return err
	}
	_, err = client.Post(responseUrl, "application/json", bytes.NewBuffer(j))
	if err != nil {
		log.Errorf("Error sending slack callback: %s", err)
		return err
	}
	return nil
}

func verifySignature(r *http.Request) error {
	// Check signature
	sv, err := slack.NewSecretsVerifier(r.Header, globalConfig.slackSigningSecret)
	if err != nil {
		log.Errorf("Error creating secrets verifier: %s", err)
		return err
	}

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Error reading request body: %s", err)
		return err
	}
	sv.Write(buf)
	// Add body again, so that slack lib helpers (like SlashCommandParse) can be used.
	r.Body = ioutil.NopCloser(bytes.NewBuffer(buf))

	err = sv.Ensure()
	if err != nil {
		log.Errorf("Error checking signature in header: %s", err)
		return err
	}

	return nil
}

func FoxsecSlackBot(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	log.Debug("Verifying slack signature")
	err := verifySignature(r)
	if err != nil {
		log.Errorf("Error verifying signature: %s", err)
		return
	}
	log.Debug("Slack signature verified")

	log.Debug("Creating db client")
	db, err := common.NewDBClient(r.Context(), PROJECT_ID, "")
	if err != nil {
		log.Errorf("Error creating db client: %s", err)
		return
	}
	defer db.Close()
	log.Debug("db client created")

	if cmd, err := slack.SlashCommandParse(r); err == nil {
		log.Debug("Slash command parsed")
		log.Infof("Command: %s", cmd.Command)
		if cmd.Command == WHITELIST_IP_SLASH_COMMAND {
			log.Debug("Handling whitelist ip command")
			resp, err := handleWhitelistCmd(r.Context(), cmd, db)
			if err != nil {
				log.Errorf("error handling whitelist command: %s", err)
				return
			}
			err = sendSlackCallback(resp, cmd.ResponseURL)
			if err != nil {
				log.Errorf("error sending slack callback within slash command: %s", err)
				return
			}
		}
	}

	return
}
