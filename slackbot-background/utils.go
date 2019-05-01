package slackbotbackground

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

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

func isAlertConfirm(callbackId string) bool {
	return strings.HasPrefix(callbackId, "alert_confirmation")
}
