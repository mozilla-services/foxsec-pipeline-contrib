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
	sesClient       *ses.SES
	senderEmail     string
	escalationEmail string
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
		sesClient:       ses.New(sess),
		senderEmail:     senderEmail,
		escalationEmail: escalationEmail,
	}, nil
}

func (sesc *SESClient) SendEscalationEmail(alert *Alert) error {
	subject := fmt.Sprintf("[foxsec-pipeline-alert] Escalating alert - %s", alert.Summary)

	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			CcAddresses: []*string{},
			ToAddresses: []*string{
				aws.String(sesc.escalationEmail),
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
