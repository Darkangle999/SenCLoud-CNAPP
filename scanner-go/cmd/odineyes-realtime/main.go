package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/odineyes/odineyes/scanner/internal/realtime"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hub := realtime.NewHub()
	mux := http.NewServeMux()
	mux.Handle("/ws", hub)
	mux.HandleFunc("/broadcast", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var message map[string]any
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		if err := decoder.Decode(&message); err != nil || message["type"] == nil {
			http.Error(w, "invalid broadcast", http.StatusBadRequest)
			return
		}
		hub.Broadcast(message)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		queues, _ := configuredQueues()
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "queue_configured": len(queues) > 0, "queue_regions": len(queues)})
	})
	server := &http.Server{Addr: ":8090", Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 65 * time.Second}
	go func() {
		slog.Info("realtime WebSocket server listening", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("realtime HTTP server failed", "error", err)
			stop()
		}
	}()
	queues, err := configuredQueues()
	if err != nil {
		slog.Error("invalid real-time queue configuration", "error", err)
		os.Exit(1)
	}
	if len(queues) == 0 {
		slog.Warn("real-time queue is not configured; WebSocket health remains available")
	} else {
		for region, queueURL := range queues {
			cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
			if err != nil {
				slog.Error("AWS configuration failed for real-time Region", "region", region, "error", err)
				continue
			}
			worker := realtime.NewWorker(sqs.NewFromConfig(cfg), queueURL, env("ODINEYES_REALTIME_API_BASE", "http://odineyes-api:8000"), hub, 60*time.Second)
			go worker.Run(ctx)
			slog.Info("real-time queue worker started", "region", region)
		}
	}
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hub.Shutdown(shutdownCtx)
	_ = server.Shutdown(shutdownCtx)
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

type queueConfig struct {
	URL string `json:"url"`
}

func configuredQueues() (map[string]string, error) {
	raw := os.Getenv("ODINEYES_REALTIME_QUEUES_JSON")
	if raw == "" {
		if queueURL := os.Getenv("ODINEYES_REALTIME_QUEUE_URL"); queueURL != "" {
			return map[string]string{env("AWS_REGION", "us-east-1"): queueURL}, nil
		}
		return map[string]string{}, nil
	}
	var configured map[string]queueConfig
	if err := json.Unmarshal([]byte(raw), &configured); err != nil {
		return nil, fmt.Errorf("ODINEYES_REALTIME_QUEUES_JSON must be JSON: %w", err)
	}
	queues := make(map[string]string, len(configured))
	for region, config := range configured {
		if region == "" || config.URL == "" {
			return nil, fmt.Errorf("each real-time queue needs a Region and url")
		}
		queues[region] = config.URL
	}

	// Regional workers must consume their own Region's queue. Leaving this
	// unset preserves the legacy single-process development mode, while a
	// deployed worker uses AWS_REGION (or the explicit override) to prevent a
	// Mumbai task from long-polling a Virginia queue.
	workerRegion := os.Getenv("ODINEYES_REALTIME_WORKER_REGION")
	if workerRegion == "" {
		workerRegion = os.Getenv("AWS_REGION")
	}
	if workerRegion != "" && len(queues) > 1 {
		queueURL, ok := queues[workerRegion]
		if !ok {
			return nil, fmt.Errorf("no real-time queue configured for worker Region %q", workerRegion)
		}
		return map[string]string{workerRegion: queueURL}, nil
	}
	return queues, nil
}
