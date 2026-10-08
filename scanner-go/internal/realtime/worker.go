package realtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type sqsAPI interface {
	ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessageBatch(context.Context, *sqs.DeleteMessageBatchInput, ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error)
}

type envelope struct {
	ID      string         `json:"id"`
	Account string         `json:"account"`
	Region  string         `json:"region"`
	Source  string         `json:"source"`
	Time    string         `json:"time"`
	Detail  map[string]any `json:"detail"`
}

type ingestResponse struct {
	Status    string         `json:"status"`
	Duplicate bool           `json:"duplicate"`
	Account   string         `json:"account"`
	Alert     map[string]any `json:"alert"`
}

type Worker struct {
	client     sqsAPI
	queueURL   string
	apiBase    string
	http       *http.Client
	hub        *Hub
	flushEvery time.Duration
	dirtyMu    sync.Mutex
	dirty      map[string]map[string]struct{}
}

func NewWorker(client sqsAPI, queueURL, apiBase string, hub *Hub, flushEvery time.Duration) *Worker {
	return &Worker{client: client, queueURL: queueURL, apiBase: apiBase, hub: hub, flushEvery: flushEvery, http: &http.Client{Timeout: 15 * time.Second}, dirty: make(map[string]map[string]struct{})}
}

func (w *Worker) Run(ctx context.Context) {
	go w.flushLoop(ctx)
	backoff := time.Second
	for ctx.Err() == nil {
		output, err := w.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: aws.String(w.queueURL), MaxNumberOfMessages: 10, WaitTimeSeconds: 20})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("realtime SQS receive failed", "error", err)
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		if len(output.Messages) > 0 {
			w.processBatch(ctx, output.Messages)
		}
	}
}

func (w *Worker) processBatch(ctx context.Context, messages []types.Message) {
	entries := make([]types.DeleteMessageBatchRequestEntry, 0, len(messages))
	for index, msg := range messages {
		if msg.Body == nil || msg.ReceiptHandle == nil {
			continue
		}
		var event envelope
		if err := json.Unmarshal([]byte(*msg.Body), &event); err != nil || event.ID == "" || event.Account == "" || event.Region == "" || event.Source == "" || event.Detail == nil {
			slog.Warn("leaving malformed realtime event for DLQ", "message_id", aws.ToString(msg.MessageId), "error", err)
			continue
		}
		response, err := w.ingest(ctx, event)
		if err != nil {
			slog.Error("realtime event persistence failed", "event_id", event.ID, "error", err)
			continue
		}
		if response.Status == "accepted" {
			w.markDirty(event.Account, event.Region)
			if response.Alert != nil && !response.Duplicate {
				w.hub.Broadcast(map[string]any{"type": "security_mutation", "event_id": event.ID, "account": event.Account, "region": event.Region, "alert": response.Alert, "received_at": time.Now().UTC()})
			}
		}
		id := fmt.Sprintf("m%d", index)
		if msg.MessageId != nil && *msg.MessageId != "" {
			id = *msg.MessageId
		}
		entries = append(entries, types.DeleteMessageBatchRequestEntry{Id: aws.String(id), ReceiptHandle: msg.ReceiptHandle})
	}
	if len(entries) == 0 {
		return
	}
	result, err := w.client.DeleteMessageBatch(ctx, &sqs.DeleteMessageBatchInput{QueueUrl: aws.String(w.queueURL), Entries: entries})
	if err != nil {
		slog.Error("realtime SQS batch delete failed", "error", err)
		return
	}
	for _, failure := range result.Failed {
		slog.Error("realtime SQS message delete failed", "id", aws.ToString(failure.Id), "code", aws.ToString(failure.Code))
	}
}

func (w *Worker) ingest(ctx context.Context, event envelope) (ingestResponse, error) {
	body, _ := json.Marshal(event)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.apiBase+"/internal/realtime/events", bytes.NewReader(body))
	if err != nil {
		return ingestResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.http.Do(req)
	if err != nil {
		return ingestResponse{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ingestResponse{}, fmt.Errorf("API status %d: %s", resp.StatusCode, string(data))
	}
	var result ingestResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return result, err
	}
	return result, nil
}

func (w *Worker) markDirty(account, region string) {
	w.dirtyMu.Lock()
	defer w.dirtyMu.Unlock()
	if w.dirty[account] == nil {
		w.dirty[account] = make(map[string]struct{})
	}
	w.dirty[account][region] = struct{}{}
}

func (w *Worker) takeDirty() map[string][]string {
	w.dirtyMu.Lock()
	defer w.dirtyMu.Unlock()
	result := make(map[string][]string, len(w.dirty))
	for account, regionSet := range w.dirty {
		for region := range regionSet {
			result[account] = append(result[account], region)
		}
		sort.Strings(result[account])
	}
	w.dirty = make(map[string]map[string]struct{})
	return result
}

func (w *Worker) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(w.flushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.flush(ctx)
			return
		case <-ticker.C:
			w.flush(ctx)
		}
	}
}

func (w *Worker) flush(ctx context.Context) {
	for account, regions := range w.takeDirty() {
		body, _ := json.Marshal(map[string]any{"account": account, "regions": regions})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, w.apiBase+"/internal/realtime/reconcile", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := w.http.Do(req)
		if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if resp != nil {
				resp.Body.Close()
			}
			slog.Error("realtime graph reconciliation enqueue failed", "account", account, "error", err)
			for _, region := range regions {
				w.markDirty(account, region)
			}
			continue
		}
		resp.Body.Close()
		w.hub.Broadcast(map[string]any{"type": "reconciliation_queued", "account": account, "regions": regions, "at": time.Now().UTC()})
	}
}
