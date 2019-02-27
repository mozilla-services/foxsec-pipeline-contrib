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
	"strings"
	"time"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
)

func parseCommandText(text string) (net.IP, time.Time, string, error) {
	splitCmd := strings.Split(text, " ")

	ip := net.ParseIP(splitCmd[0])
	if ip == nil {
		m := fmt.Sprintf("Got invalid IP: %s", splitCmd[0])
		errMsg := m
		return net.IP{}, time.Time{}, errMsg, errors.New(m)
	}

	var expiresDur time.Duration
	var err error
	if len(splitCmd) == 2 {
		expiresDur, err = time.ParseDuration(splitCmd[1])
		if err != nil {
			log.Errorf("Error parsing duration: %s", err)
			errMsg := fmt.Sprintf("Was unable to parse duration: %s\n%s", splitCmd[1], DURATION_DOC)
			return net.IP{}, time.Time{}, errMsg, err
		}
		// Clamp expires duration to >5 minutes
		if expiresDur < time.Minute*5 {
			expiresDur = time.Minute * 5
		}
	} else {
		expiresDur = DEFAULT_EXPIRATION_DURATION
	}

	expiresAt := time.Now().Add(expiresDur)

	return ip, expiresAt, "", nil
}

func handleWhitelistCmd(ctx context.Context, cmd slack.SlashCommand, db *common.DBClient) (*slack.Msg, error) {
	msg := &slack.Msg{}

	ip, expiresAt, errMsg, err := parseCommandText(cmd.Text)
	if err != nil {
		msg.Text = errMsg
		return msg, err
	}

	userProfile, err := globalConfig.slackClient.GetUserProfile(cmd.UserID, false)
	if err != nil {
		log.Errorf("Error getting user profile: %s", err)
		msg.Text = "Was unable to get your email from Slack."
		return msg, err
	}

	auditMsg := fmt.Sprintf("%s submitted %s to be whitelisted until %s", userProfile.Email, ip.String(), expiresAt)
	log.Info(auditMsg)
	err = db.SaveWhitelistedIp(ctx, common.NewWhitelistedIP(ip.String(), expiresAt, userProfile.Email))
	if err != nil {
		log.Errorf("Error saving whitelisted ip: %s", err)
		msg.Text = "Error saving IP to whitelist."
		return msg, err
	}

	// send to audit channel
	_, _, err = globalConfig.slackClient.PostMessage(FOXSEC_SLACK_CHANNEL_ID, slack.MsgOptionText(auditMsg, false))
	if err != nil {
		log.Errorf("Error sending audit message to foxsec bot slack channel: %s", err)
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
