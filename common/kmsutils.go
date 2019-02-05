package common

import (
	"context"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type KMSClient struct {
	client *cloudkms.KeyManagementClient
}

func NewKMSClient() (*KMSClient, error) {
	client, err := cloudkms.NewKeyManagementClient(context.TODO())
	if err != nil {
		return nil, err
	}
	return &KMSClient{client: client}, nil
}

func (kms *KMSClient) DecryptSymmetric(keyName string, ciphertext string) (string, error) {
	ctx := context.Background()

	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:       keyName,
		Ciphertext: []byte(ciphertext),
	}
	// Call the API.
	resp, err := kms.client.Decrypt(ctx, req)
	if err != nil {
		return "", err
	}
	return string(resp.Plaintext), nil
}
