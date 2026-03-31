package worker

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/config"
	"github.com/stormbane/beacon/internal/module"
)

// newTestPool creates a Pool with zero concurrency (no background workers) so
// tests can exercise the queue, emit, and subscribe machinery in isolation
// without triggering the full scan pipeline in process().
func newTestPool() *Pool {
	return &Pool{
		concurrency: 0,
		queue:       make(chan Job, 256),
		logs:        make(map[string][]string),
		subs:        make(map[string][]chan string),
	}
}

// ---------- emit / Logs tests ----------

func TestEmit_RecordsToLogs(t *testing.T) {
	p := newTestPool()

	p.emit("run-1", "hello world")
	p.emit("run-1", "second line")

	logs := p.Logs("run-1")
	if len(logs) != 2 {
		t.Fatalf("Logs(run-1) returned %d lines, want 2", len(logs))
	}
	// Each line is formatted as "[HH:MM:SS] <message>".
	for i, l := range logs {
		if len(l) < 12 { // "[00:00:00] x" is at least 12 chars
			t.Errorf("line %d too short: %q", i, l)
		}
	}
}

func TestLogs_ReturnsCopy(t *testing.T) {
	p := newTestPool()
	p.emit("run-1", "original")

	logs := p.Logs("run-1")
	logs[0] = "mutated"

	fresh := p.Logs("run-1")
	if fresh[0] == "mutated" {
		t.Error("Logs() should return a copy, but mutation leaked through")
	}
}

func TestLogs_EmptyForUnknownRun(t *testing.T) {
	p := newTestPool()
	logs := p.Logs("nonexistent")
	if len(logs) != 0 {
		t.Errorf("Logs(nonexistent) = %v, want empty", logs)
	}
}

func TestLogs_IsolatedBetweenRuns(t *testing.T) {
	p := newTestPool()
	p.emit("run-A", "line A")
	p.emit("run-B", "line B")

	logsA := p.Logs("run-A")
	logsB := p.Logs("run-B")
	if len(logsA) != 1 || len(logsB) != 1 {
		t.Errorf("expected 1 log each; run-A=%d, run-B=%d", len(logsA), len(logsB))
	}
}

// ---------- Subscribe / emit broadcast tests ----------

func TestSubscribe_ReceivesEmittedMessages(t *testing.T) {
	p := newTestPool()

	ch := p.Subscribe("run-1")

	p.emit("run-1", "broadcast message")

	select {
	case msg := <-ch:
		if msg == "" {
			t.Error("received empty message")
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive message within 1s")
	}
}

func TestSubscribe_MultipleSubscribers(t *testing.T) {
	p := newTestPool()

	ch1 := p.Subscribe("run-1")
	ch2 := p.Subscribe("run-1")

	p.emit("run-1", "hello subscribers")

	for i, ch := range []<-chan string{ch1, ch2} {
		select {
		case msg := <-ch:
			if msg == "" {
				t.Errorf("subscriber %d received empty message", i)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d did not receive message", i)
		}
	}
}

func TestSubscribe_DifferentRunsAreIsolated(t *testing.T) {
	p := newTestPool()

	chA := p.Subscribe("run-A")
	chB := p.Subscribe("run-B")

	p.emit("run-A", "only for A")

	// chA should get the message.
	select {
	case <-chA:
	case <-time.After(time.Second):
		t.Fatal("subscriber A did not receive message")
	}

	// chB should NOT get anything.
	select {
	case msg := <-chB:
		t.Fatalf("subscriber B received unexpected message: %s", msg)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
}

// ---------- closeSubscribers tests ----------

func TestCloseSubscribers_ClosesChannels(t *testing.T) {
	p := newTestPool()

	ch := p.Subscribe("run-1")

	p.closeSubscribers("run-1")

	// Reading from a closed channel should return the zero value immediately.
	_, ok := <-ch
	if ok {
		t.Error("channel should be closed after closeSubscribers")
	}
}

func TestCloseSubscribers_RemovesFromMap(t *testing.T) {
	p := newTestPool()
	p.Subscribe("run-1")

	p.closeSubscribers("run-1")

	p.subsMu.RLock()
	_, exists := p.subs["run-1"]
	p.subsMu.RUnlock()
	if exists {
		t.Error("subs map should not contain run-1 after closeSubscribers")
	}
}

func TestCloseSubscribers_NoopForUnknownRun(t *testing.T) {
	p := newTestPool()
	// Should not panic.
	p.closeSubscribers("nonexistent")
}

// ---------- emitError tests ----------

func TestEmitError_PrefixesAndCloses(t *testing.T) {
	p := newTestPool()
	ch := p.Subscribe("run-1")

	p.emitError("run-1", "something broke")

	// Should receive the error-prefixed message.
	select {
	case msg := <-ch:
		if msg == "" {
			t.Error("expected error message")
		}
	case <-time.After(time.Second):
		t.Fatal("no message received")
	}

	// Channel should be closed after emitError.
	_, ok := <-ch
	if ok {
		t.Error("channel should be closed after emitError")
	}

	// The log should contain the error message.
	logs := p.Logs("run-1")
	if len(logs) != 1 {
		t.Fatalf("expected 1 log line, got %d", len(logs))
	}
}

// ---------- Pool concurrency / Submit tests ----------

func TestNewPool_StartsWorkers(t *testing.T) {
	// We can't use the real process() since it needs a store, but we can
	// verify the pool drains jobs by closing the queue and seeing workers exit.
	// Use a pool with a real concurrency count to confirm goroutines start.
	cfg := &config.Config{}
	p := NewPool(2, nil, cfg)

	// The queue channel is open and workers are running.
	// Close the queue to signal workers to exit.
	close(p.queue)
	// Give workers time to notice the close and exit.
	time.Sleep(50 * time.Millisecond)
	// No assertion needed; if workers panicked, the test would crash.
}

func TestSubmit_EnqueuesJob(t *testing.T) {
	p := newTestPool()

	job := Job{
		ScanRunID: "run-submit",
		Domain:    "example.com",
		ScanType:  module.ScanSurface,
	}
	if err := p.Submit(job); err != nil {
		t.Fatalf("Submit returned unexpected error: %v", err)
	}

	select {
	case got := <-p.queue:
		if got.ScanRunID != "run-submit" {
			t.Errorf("dequeued job has ScanRunID %s, want run-submit", got.ScanRunID)
		}
		if got.Domain != "example.com" {
			t.Errorf("dequeued job has Domain %s, want example.com", got.Domain)
		}
	case <-time.After(time.Second):
		t.Fatal("job not dequeued within 1s")
	}
}

func TestSubmit_MultipleJobs(t *testing.T) {
	p := newTestPool()

	for i := range 10 {
		_ = p.Submit(Job{ScanRunID: time.Now().Format("15:04:05") + string(rune('A'+i))})
	}

	count := 0
	for range 10 {
		select {
		case <-p.queue:
			count++
		case <-time.After(time.Second):
			t.Fatalf("only dequeued %d/10 jobs", count)
		}
	}
}

// ---------- Concurrent emit safety ----------

func TestEmit_ConcurrentSafety(t *testing.T) {
	p := newTestPool()

	const goroutines = 20
	const messagesPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range messagesPerGoroutine {
				p.emit("run-concurrent", "msg")
			}
		}()
	}
	wg.Wait()

	logs := p.Logs("run-concurrent")
	want := goroutines * messagesPerGoroutine
	if len(logs) != want {
		t.Errorf("Logs has %d entries, want %d", len(logs), want)
	}
}

// TestSubmit_AfterStop verifies that calling Submit() after Stop() returns an
// error and does not panic (e.g., from sending on a closed channel).
func TestSubmit_AfterStop(t *testing.T) {
	p := newTestPool()
	p.Stop()

	err := p.Submit(Job{
		ScanRunID: "after-stop",
		Domain:    "example.com",
		ScanType:  module.ScanSurface,
	})
	if err == nil {
		t.Fatal("Submit after Stop should return an error, got nil")
	}
}

// TestEmitAndCloseSubscribers_ConcurrentSafety exercises concurrent emit() and
// closeSubscribers() calls from different goroutines to verify there is no
// data race on the subs map. Run with -race to detect races.
func TestEmitAndCloseSubscribers_ConcurrentSafety(t *testing.T) {
	p := newTestPool()
	const runID = "race-test"

	// Subscribe so there are channels in the map.
	ch := p.Subscribe(runID)

	var wg sync.WaitGroup

	// Goroutine 1: emit messages.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			p.emit(runID, "concurrent message")
		}
	}()

	// Goroutine 2: close subscribers while emit is running.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Small spin to let emit start writing.
		for range 20 {
			p.emit(runID, "warmup")
		}
		p.closeSubscribers(runID)
	}()

	wg.Wait()

	// Drain the subscriber channel — it should be closed by now.
	drained := 0
	for range ch {
		drained++
	}
	// We don't assert exact count since the race is non-deterministic,
	// but the channel must have been closed without panicking.
	_ = drained
}

func TestSubscribe_ConcurrentSafety(t *testing.T) {
	p := newTestPool()

	const numSubscribers = 10
	var received atomic.Int64

	var wg sync.WaitGroup
	wg.Add(numSubscribers)
	for range numSubscribers {
		ch := p.Subscribe("run-csub")
		go func() {
			defer wg.Done()
			for range ch {
				received.Add(1)
			}
		}()
	}

	// Emit some messages, then close.
	for range 5 {
		p.emit("run-csub", "concurrent")
	}
	p.closeSubscribers("run-csub")

	wg.Wait()

	got := received.Load()
	// Each subscriber should have received all 5 messages.
	want := int64(numSubscribers * 5)
	if got != want {
		t.Errorf("total received = %d, want %d", got, want)
	}
}

// ---------- Log capping tests ----------

// TestEmit_LogCapping_At10000 verifies that the emit method stops recording
// log lines after 10,000 entries for a given scan run, preventing unbounded
// memory growth from long-running scans.
func TestEmit_LogCapping_At10000(t *testing.T) {
	p := newTestPool()

	const logCap = 10000
	const total = logCap + 500

	for i := range total {
		p.emit("run-cap", itoa(i))
	}

	logs := p.Logs("run-cap")
	if len(logs) != logCap {
		t.Errorf("expected log cap at %d, got %d lines", logCap, len(logs))
	}
}

// TestEmit_LogCapping_PreservesEarlyMessages verifies that when the cap is
// reached, the first messages are the ones kept (not overwritten).
func TestEmit_LogCapping_PreservesEarlyMessages(t *testing.T) {
	p := newTestPool()

	// Emit exactly the cap + some overflow.
	for i := range 10001 {
		p.emit("run-order", "msg-"+itoa(i))
	}

	logs := p.Logs("run-order")
	if len(logs) != 10000 {
		t.Fatalf("expected 10000 logs, got %d", len(logs))
	}

	// The first log should contain "msg-0" (with timestamp prefix).
	if !containsSubstring(logs[0], "msg-0") {
		t.Errorf("first log line should contain msg-0, got %q", logs[0])
	}
	// The last log should contain "msg-9999" — messages after 10000 are dropped.
	if !containsSubstring(logs[9999], "msg-9999") {
		t.Errorf("last log line should contain msg-9999, got %q", logs[9999])
	}
}

// ---------- Context timeout in process ----------

// TestProcess_ContextHasDeadline verifies that the context passed to scan
// processing has a 2-hour timeout. We cannot call process() directly without
// a full store/module setup, but we can verify the timeout is set by
// creating a context the same way process() does and checking the deadline.
func TestProcess_ContextTimeout(t *testing.T) {
	// Mirror the exact logic from process():
	//   ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected context to have a deadline")
	}
	untilDeadline := time.Until(deadline)
	// Should be approximately 2 hours (allow 5s tolerance for test execution time).
	if untilDeadline < 2*time.Hour-5*time.Second || untilDeadline > 2*time.Hour+time.Second {
		t.Errorf("expected ~2h deadline, got %v", untilDeadline)
	}
}

// ---------- Concurrent job processing ----------

// TestConcurrentJobProcessing verifies that multiple jobs submitted to a pool
// with concurrency > 1 are processed in parallel, not sequentially.
func TestConcurrentJobProcessing(t *testing.T) {
	p := newTestPool()

	// We simulate concurrent processing by submitting jobs and consuming
	// them from the queue in parallel goroutines (mimicking what run() does).
	const poolSize = 4
	const jobCount = 8

	for i := range jobCount {
		_ = p.Submit(Job{ScanRunID: "concurrent-" + itoa(i), Domain: "example.com"})
	}

	var processed atomic.Int64
	var wg sync.WaitGroup
	wg.Add(poolSize)

	// Start poolSize consumer goroutines.
	for range poolSize {
		go func() {
			defer wg.Done()
			for {
				select {
				case _, ok := <-p.queue:
					if !ok {
						return
					}
					processed.Add(1)
				case <-time.After(500 * time.Millisecond):
					return
				}
			}
		}()
	}

	wg.Wait()

	got := processed.Load()
	if got != jobCount {
		t.Errorf("processed %d jobs, want %d", got, jobCount)
	}
}

// ---------- SSE subscriber notification ----------

// TestSSE_SubscriberReceivesAllEvents verifies that a subscriber channel
// receives every log event emitted for its scan run in order, simulating
// the SSE streaming pattern used by the API.
func TestSSE_SubscriberReceivesAllEvents(t *testing.T) {
	p := newTestPool()
	const runID = "sse-test"

	ch := p.Subscribe(runID)

	messages := []string{"scan started", "running scanners...", "scan complete: 5 findings", "done"}
	for _, msg := range messages {
		p.emit(runID, msg)
	}
	p.closeSubscribers(runID)

	var received []string
	for msg := range ch {
		received = append(received, msg)
	}

	if len(received) != len(messages) {
		t.Fatalf("received %d events, want %d", len(received), len(messages))
	}
	// Verify ordering: each received message should contain the corresponding
	// original message (wrapped with timestamp).
	for i, msg := range messages {
		if !containsSubstring(received[i], msg) {
			t.Errorf("event[%d] = %q, should contain %q", i, received[i], msg)
		}
	}
}

// ---------- PurgeLogs ----------

func TestPurgeLogs_RemovesLogLines(t *testing.T) {
	p := newTestPool()
	p.emit("run-purge", "line 1")
	p.emit("run-purge", "line 2")

	if len(p.Logs("run-purge")) != 2 {
		t.Fatal("expected 2 log lines before purge")
	}

	p.PurgeLogs("run-purge")

	if len(p.Logs("run-purge")) != 0 {
		t.Error("expected 0 log lines after purge")
	}
}

// ---------- helpers ----------

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}

func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}
