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
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
)

var rxEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

func checkUsersGroups(email string) (bool, error) {
	if len(email) > 254 || !rxEmail.MatchString(email) {
		return false, fmt.Errorf("Email (%s) is invalid", email)
	}

	person, err := globalConfig.personsClient.GetPersonByEmail(email)
	if err != nil {
		return false, err
	}

	for group := range person.AccessInformation.LDAP.Values {
		for _, allowedGroup := range globalConfig.allowedGroups {
			if group == allowedGroup {
				return true, nil
			}
		}
	}

	return false, nil
}

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

	allowed, err := checkUsersGroups(userProfile.Email)
	if err != nil {
		log.Errorf("Error with checking user's (%s) ldap groups: %s", userProfile.Email, err)
		msg.Text = "Error checking your ldap groups."
		return msg, err
	}
	if !allowed {
		err = fmt.Errorf("User (%s) is not allowed to use this slack command.", userProfile.Email)
		log.Error(err)
		msg.Text = "You are not authorized to perform that command."
		return msg, err
	}

	auditMsg := fmt.Sprintf("%s submitted %s to be whitelisted until %s", userProfile.Email, ip.String(), expiresAt.Format(time.UnixDate))
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

func InteractionCallbackParse(reqBody []byte) (*slack.InteractionCallback, error) {
	var req slack.InteractionCallback
	// Deal with slack weirdness. Body is `payload=<escaped json>`
	jsonStr, err := url.QueryUnescape(string(reqBody)[8:])
	err = json.Unmarshal([]byte(jsonStr), &req)
	if err != nil {
		log.Errorf("Error parsing interaction callback: Body: %s | Err: %s", reqBody, err)
		return nil, err
	}
	return &req, nil
}

func isAlertConfirm(req *slack.InteractionCallback) bool {
	if strings.HasPrefix(req.CallbackID, "alert_confirmation") {
		return true
	}

	return false
}

func handleAlertConfirm(ctx context.Context, callback *slack.InteractionCallback, db *common.DBClient) (*slack.Msg, error) {
	// callback id = "alert_confirmation_<id>"
	alertId := strings.Split(callback.CallbackID, "_")[2]
	alert, err := db.GetAlert(ctx, alertId)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	response := &slack.Msg{
		Text:            "Error responding; please contact SecOps (secops@mozilla.com)",
		ReplaceOriginal: true,
	}

	if !alert.IsStatus(common.ALERT_NEW) {
		response.Text = fmt.Sprintf("Thank you for responding! Alert has already been marked as %s.\nalert id: %s", alert.GetMetadata("status"), alert.Id)
		return response, nil
	}

	if callback.Actions[0].Name == "alert_yes" {
		alert.SetMetadata("status", common.ALERT_ACKNOWLEDGED)
		err := db.SaveAlert(ctx, alert)
		if err != nil {
			log.Errorf("Error marking alert (%s) as acknowledged. Err: %s", alert.Id, err)
			return response, err
		}
		response.Text = fmt.Sprintf("Thank you for responding! Alert has been acknowledged.\nalert id: %s", alert.Id)
	} else if callback.Actions[0].Name == "alert_no" {
		err := globalConfig.sesClient.SendEscalationEmail(alert)
		if err != nil {
			log.Errorf("Error escalating alert (%s). Err: %s", alert.Id, err)
			return response, err
		}
		alert.SetMetadata("status", common.ALERT_ESCALATED)
		err = db.SaveAlert(ctx, alert)
		if err != nil {
			log.Errorf("Error updating alert as escalated (%s). Err: %s", alert.Id, err)
			return response, err
		}
		response.Text = fmt.Sprintf("Thank you for responding! Alert has been escalated.\nalert id: %s", alert.Id)
	}

	return response, nil
}
