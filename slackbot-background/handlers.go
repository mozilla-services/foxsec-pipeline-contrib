package slackbotbackground

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
)

func handleWhitelistCmd(ctx context.Context, cmd common.SlashCommandData, db *common.DBClient) (*slack.Msg, error) {
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

func handleAlertConfirm(ctx context.Context, callback common.InteractionData, db *common.DBClient) (*slack.Msg, error) {
	// callback id = "alert_confirmation_<id>"
	alertId := strings.Split(callback.CallbackID, "_")[2]
	alert, err := db.GetAlert(ctx, alertId)
	if err != nil {
		log.Errorf("Could not find alert with ID %s (from Callback ID: %s). Err: %s", alertId, callback.CallbackID, err)
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

	if callback.ActionName == "alert_yes" {
		alert.SetMetadata("status", common.ALERT_ACKNOWLEDGED)
		err := db.SaveAlert(ctx, alert)
		if err != nil {
			log.Errorf("Error marking alert (%s) as acknowledged. Err: %s", alert.Id, err)
			return response, err
		}
		response.Text = fmt.Sprintf("Thank you for responding! Alert has been acknowledged.\nalert id: %s", alert.Id)
	} else if callback.ActionName == "alert_no" {
		// Override `escalate_to` to use the default (which should be the security teams main pagerduty email)
		alert.SetMetadata("escalate_to", "")
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
