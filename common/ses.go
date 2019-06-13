package common

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
)

const (
	EMAIL_CHAR_SET = "UTF-8"
)

type SESClient struct {
	sesClient              *ses.SES
	senderEmail            string
	defaultEscalationEmail string
}

func NewSESClientFromConfig(config *Configuration) (*SESClient, error) {
	return NewSESClient(
		config.AwsRegion,
		config.AwsAccessKeyId,
		config.AwsSecretAccessKey,
		config.SesSenderEmail,
		config.DefaultEscalationEmail,
	)
}

func NewSESClient(region, accessKeyId, secretAccessKey, senderEmail, escalationEmail string) (*SESClient, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(accessKeyId, secretAccessKey, ""),
	})
	if err != nil {
		return nil, err
	}
	return &SESClient{
		sesClient:              ses.New(sess),
		senderEmail:            senderEmail,
		defaultEscalationEmail: escalationEmail,
	}, nil
}

func (sesc *SESClient) SendEscalationEmail(alert *Alert) error {
	subject := fmt.Sprintf("[foxsec-alert] Escalating alert - %s", alert.Summary)

	escalationEmail := alert.GetMetadata(ESCALATE_TO)
	if escalationEmail == "" {
		escalationEmail = sesc.defaultEscalationEmail
	}

	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			CcAddresses: []*string{},
			ToAddresses: []*string{
				aws.String(escalationEmail),
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
		Source: aws.String(sesc.senderEmail),
	}

	_, err := sesc.sesClient.SendEmail(input)
	if err != nil {
		return err
	}

	return nil
}
