// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cloudwatchlogs_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/falcosecurity/plugins/shared/go/aws/cloudwatchlogs"
)

type fakeEvent struct {
	ID        string `json:"eventId"`
	Stream    string `json:"logStreamName"`
	Timestamp int64  `json:"timestamp"`
	Ingestion int64  `json:"ingestionTime"`
	Message   string `json:"message"`
}

// fakeLogs speaks the CloudWatch Logs JSON 1.1 protocol and answers
// FilterLogEvents like the real service: events with timestamp >= startTime,
// oldest first. Events can be added between polls to model late ingestion.
type fakeLogs struct {
	mu       sync.Mutex
	events   []fakeEvent
	requests int
}

func (f *fakeLogs) add(events ...fakeEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, events...)
}

func (f *fakeLogs) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func (f *fakeLogs) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("X-Amz-Target") != "Logs_20140328.FilterLogEvents" {
		http.Error(w, "unexpected request", http.StatusBadRequest)
		return
	}
	var req struct {
		StartTime int64 `json:"startTime"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.requests++
	var out []fakeEvent
	for _, e := range f.events {
		if e.Timestamp >= req.StartTime {
			out = append(out, e)
		}
	}
	f.mu.Unlock()
	slices.SortFunc(out, func(a, b fakeEvent) int { return int(a.Timestamp - b.Timestamp) })
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(map[string]any{"events": out})
}

func TestOpenDeliversEachEventOnceAcrossStreams(t *testing.T) {
	const window = int64(60_000) // documented reorder window, in ms
	// Far enough in the past that the shift, not the reorder window, bounds
	// the first read: the late events below are inside it.
	base := time.Now().Add(-100 * time.Second).UnixMilli()
	ev := func(id, stream string, ts int64) fakeEvent {
		return fakeEvent{ID: id, Stream: stream, Timestamp: ts, Ingestion: ts + 3000, Message: id}
	}

	tests := []struct {
		name string
		// events that appear after the first poll delivered "newest"
		late []fakeEvent
		want []string
	}{
		{
			name: "event ingested late by another stream, 5s older than the newest, is delivered once",
			late: []fakeEvent{ev("late", "kube-apiserver-audit-b", base-5_000)},
			want: []string{"newest", "late", "sentinel"},
		},
		{
			name: "event re-read inside the window is not delivered twice",
			want: []string{"newest", "sentinel"},
		},
		{
			// Documents the limit of the fix: lag beyond the window is lost.
			name: "event ingested late by more than the window is not delivered",
			late: []fakeEvent{ev("late", "kube-apiserver-audit-b", base-window-10_000)},
			want: []string{"newest", "sentinel"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeLogs{}
			srv := httptest.NewServer(fake)
			defer srv.Close()
			client := cloudwatchlogs.CreateClient(aws.Config{
				Region:       "us-east-1",
				BaseEndpoint: aws.String(srv.URL),
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
				}),
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			events, errs := client.Open(ctx,
				cloudwatchlogs.CreateFilter("", "/aws/eks/test/cluster", "kube-apiserver-audit", nil),
				cloudwatchlogs.CreateOptions(200*time.Second, time.Millisecond, 100))

			var got []string
			next := func() string {
				t.Helper()
				select {
				case e, ok := <-events:
					if !ok {
						t.Fatal("event channel closed")
					}
					got = append(got, *e.EventId)
					return *e.EventId
				case err := <-errs:
					t.Fatalf("client error: %v", err)
				case <-time.After(10 * time.Second):
					t.Fatalf("timed out, delivered so far: %v", got)
				}
				return ""
			}

			fake.add(ev("newest", "kube-apiserver-audit-a", base))
			for next() != "newest" {
			}
			// "sentinel" is newer than everything else, so every event the
			// poll returns arrives before it.
			fake.add(append(tc.late, ev("sentinel", "kube-apiserver-audit-a", base+1_000))...)
			for next() != "sentinel" {
			}

			// Let a few more polls re-read the window, then stop.
			deadline := time.Now().Add(10 * time.Second)
			for n := fake.requestCount(); fake.requestCount() < n+3; {
				if time.Now().After(deadline) {
					t.Fatal("client stopped polling")
				}
				time.Sleep(time.Millisecond)
			}
			cancel()
			go func() {
				for range errs {
				}
			}()
			for e := range events {
				got = append(got, *e.EventId)
			}

			if !slices.Equal(got, tc.want) {
				t.Fatalf("delivered %v, want %v", got, tc.want)
			}
		})
	}
}
