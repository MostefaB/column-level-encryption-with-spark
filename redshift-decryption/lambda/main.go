package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type RedshiftEvent struct {
	RequestId        string          `json:"request_id"`
	Cluster          string          `json:"cluster"`
	User             string          `json:"user"`
	Database         string          `json:"database"`
	ExternalFunction string          `json:"external_function"`
	QueryId          int             `json:"query_id"`
	NumRecords       int             `json:"num_records"`
	Arguments        [][]interface{} `json:"arguments"`
}

type RedshiftResponse struct {
	Success    bool          `json:"success"`
	ErrorMsg   string        `json:"error_msg,omitempty"`
	NumRecords int           `json:"num_records"`
	Results    []interface{} `json:"results"`
}

func handleRequest(ctx context.Context, event RedshiftEvent) (string, error) {
	log.Printf("Processing requestId: %s, queryId: %d\n", event.RequestId, event.QueryId)

	// Prepare the response structure
	response := RedshiftResponse{
		Success:    true,
		NumRecords: event.NumRecords,
		Results:    make([]interface{}, event.NumRecords),
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.Printf("Failed to load AWS config: %v\n", err)
		response.Success = false
		response.ErrorMsg = "Failed to load AWS configuration"
		return marshalResponse(response)
	}

	kmsClient := kms.NewFromConfig(cfg)

	// Process each record
	for i, record := range event.Arguments {
		if record[0] == nil {
			continue
		}

		// Extract encrypted DEK and ciphertext
		encryptedValue := record[0].(string)
		parts := strings.Split(encryptedValue, "::")
		if len(parts) != 2 {
			log.Printf("Invalid encrypted value format: %s\n", encryptedValue)
			response.Results[i] = "Invalid encrypted value format"
			continue
		}

		encryptedDEKBase64 := parts[0]
		ciphertextBase64 := parts[1]

		// Decode and decrypt the DEK
		encryptedDEK, err := base64.StdEncoding.DecodeString(encryptedDEKBase64)
		if err != nil {
			log.Printf("Failed to decode encrypted DEK: %v\n", err)
			response.Results[i] = "Failed to decode encrypted DEK"
			continue
		}

		decryptOutput, err := kmsClient.Decrypt(ctx, &kms.DecryptInput{
			CiphertextBlob: encryptedDEK,
		})
		if err != nil {
			log.Printf("Failed to decrypt DEK: %v\n", err)
			response.Results[i] = "Failed to decrypt DEK"
			continue
		}
		plaintextDEK := decryptOutput.Plaintext

		// Decode and decrypt the column value
		ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
		if err != nil {
			log.Printf("Failed to decode ciphertext: %v\n", err)
			response.Results[i] = "Failed to decode ciphertext"
			continue
		}

		decryptedValue, err := decryptAES(ciphertext, plaintextDEK)
		if err != nil {
			log.Printf("Failed to decrypt value: %v\n", err)
			response.Results[i] = "Failed to decrypt value"
			continue
		}

		response.Results[i] = decryptedValue
	}

	log.Printf("Decryption completed for queryId: %d\n", event.QueryId)
	return marshalResponse(response)
}

func decryptAES(ciphertext, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return string(plaintext), nil
}

func marshalResponse(response RedshiftResponse) (string, error) {
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal response: %v\n", err)
		return "", err
	}
	return string(jsonResponse), nil
}

func main() {
	log.SetPrefix("[REDSHIFT COLUMN DECRYPT]: ")
	log.SetFlags(log.LstdFlags)
	lambda.Start(handleRequest)
}
