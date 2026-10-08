package realtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type fakeSQS struct {
	deleted []types.DeleteMessageBatchRequestEntry
}

func (f *fakeSQS) ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	return &sqs.ReceiveMessageOutput{}, nil
}
func (f *fakeSQS) DeleteMessageBatch(_ context.Context, input *sqs.DeleteMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
	f.deleted = append(f.deleted, input.Entries...)
	return &sqs.DeleteMessageBatchOutput{}, nil
}

func TestProcessBatchDeletesOnlyPersistedMessagesAndCoalescesDirtyAccount(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/realtime/events" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"accepted","account":"123456789012","alert":{"title":"test"}}`))
	}))
	defer api.Close()
	client := &fakeSQS{}
	worker := NewWorker(client, "queue", api.URL, NewHub(), time.Minute)
	body, _ := json.Marshal(envelope{ID: "event-1", Account: "123456789012", Region: "us-east-1", Source: "aws.ec2", Detail: map[string]any{"eventName": "PutBucketPolicy"}})
	worker.processBatch(context.Background(), []types.Message{
		{MessageId: aws.String("good"), ReceiptHandle: aws.String("receipt"), Body: aws.String(string(body))},
		{MessageId: aws.String("bad"), ReceiptHandle: aws.String("receipt-2"), Body: aws.String("not-json")},
	})
	if len(client.deleted) != 1 || aws.ToString(client.deleted[0].Id) != "good" {
		t.Fatalf("deleted %#v", client.deleted)
	}
	dirty := worker.takeDirty()
	if len(dirty) != 1 || len(dirty["123456789012"]) != 1 {
		t.Fatalf("dirty %#v", dirty)
	}
}

func TestIgnoredFailedAPICallIsDeletedWithoutDirtyingAccount(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ignored","account":"123456789012"}`))
	}))
	defer api.Close()
	client := &fakeSQS{}
	worker := NewWorker(client, "queue", api.URL, NewHub(), time.Minute)
	body, _ := json.Marshal(envelope{ID: "event-failed", Account: "123456789012", Region: "us-east-1", Source: "aws.iam", Detail: map[string]any{"eventName": "CreateAccessKey", "errorCode": "AccessDenied"}})
	worker.processBatch(context.Background(), []types.Message{{MessageId: aws.String("ignored"), ReceiptHandle: aws.String("receipt"), Body: aws.String(string(body))}})
	if len(client.deleted) != 1 {
		t.Fatalf("expected ignored event to be acknowledged")
	}
	if len(worker.takeDirty()) != 0 {
		t.Fatal("ignored event must not trigger reconciliation")
	}
}
