package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/odineyes/odineyes/scanner/internal/protocol"
	"github.com/odineyes/odineyes/scanner/internal/scanner"
)

const maxRequestBytes = 1 << 20

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxRequestBytes+1))
	if err != nil {
		fatalResponse("", fmt.Errorf("read scan request: %w", err))
	}
	if len(data) > maxRequestBytes {
		fatalResponse("", fmt.Errorf("scan request exceeds %d bytes", maxRequestBytes))
	}
	request, err := protocol.DecodeRequest(data)
	if err != nil {
		fatalResponse("", err)
	}

	timeout := time.Duration(request.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	if timeout > time.Hour {
		timeout = time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	collector, err := scanner.New(ctx, request)
	if err != nil {
		fatalResponse(request.AccountIdentifier, err)
	}
	response := collector.Collect(ctx)
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		slog.Error("encode scan response", "error", err)
		os.Exit(1)
	}
}

func fatalResponse(accountID string, err error) {
	response := protocol.ScanResponse{
		SchemaVersion:     protocol.SchemaVersion,
		Collector:         "odineyes-go-aws/v1",
		AccountIdentifier: accountID,
		Resources:         []protocol.RawResource{},
		Authoritative:     []protocol.Scope{},
		Errors:            []protocol.CollectionError{},
		Metrics: protocol.Metrics{
			ByType: map[string]int{},
		},
		FatalError: err.Error(),
	}
	_ = json.NewEncoder(os.Stdout).Encode(response)
	slog.Error("scan failed", "account_id", accountID, "error", err)
	os.Exit(1)
}
