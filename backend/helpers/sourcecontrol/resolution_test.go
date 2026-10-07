/*
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sourcecontrol

import (
	"errors"
	"sync"
	"testing"
	"time"
)

const evidence = "cccccccc-bbbb-cccc-dddd-eeeeeeeeeeee"

type resolutionMemory struct {
	memoryStore
	journalMu sync.Mutex
	journal   map[string]Resolution
	failPhase string
}

func (s *resolutionMemory) LoadResolution(op string) (Resolution, bool, error) {
	s.journalMu.Lock()
	defer s.journalMu.Unlock()
	r, ok := s.journal[op]
	return r, ok, nil
}
func (s *resolutionMemory) SaveResolution(r Resolution) error {
	s.journalMu.Lock()
	defer s.journalMu.Unlock()
	if r.Phase == s.failPhase {
		return errors.New("journal unavailable")
	}
	if s.journal == nil {
		s.journal = map[string]Resolution{}
	}
	s.journal[r.Operation] = r
	return nil
}
func TestQuiesceDrainsAndPermanentlyRejectsOldRequests(t *testing.T) {
	s := &resolutionMemory{}
	c := New(s, secret)
	acquire(t, c)
	done, err := c.Write(Token(secret, operation))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		_, err := c.Quiesce(secret, operation, evidence, []uint64{1, 2})
		result <- err
	}()
	<-started
	select {
	case err := <-result:
		t.Fatalf("did not drain handler: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	done()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	c = New(s, secret)
	if _, err = c.Write(Token(secret, operation)); err != ErrHeld {
		t.Fatalf("old write: %v", err)
	}
	if _, err = c.Check(secret, operation); err != ErrHeld {
		t.Fatalf("old continuity: %v", err)
	}
	if _, err = c.Write(""); err != ErrHeld {
		t.Fatal(err)
	}
	if _, err = c.Acquire(secret, operation, []uint64{1, 2}); err != ErrHeld {
		t.Fatal(err)
	}
	if err = c.Cancel(secret, operation); err != ErrHeld {
		t.Fatal(err)
	}
	if err = c.Release(secret, operation); err != ErrHeld {
		t.Fatal(err)
	}
	if _, err = c.Quiesce(secret, operation, otherOperation, []uint64{1, 2}); err != ErrHeld {
		t.Fatal(err)
	}
	if _, err = c.Quiesce(secret, operation, evidence, []uint64{3}); err != ErrHeld {
		t.Fatal(err)
	}
	done, err = c.ResolutionWrite(ResolutionToken(secret, operation, evidence))
	if err != nil {
		t.Fatal(err)
	}
	done()
	if _, err = c.ResolutionWrite(Token(secret, operation)); err != ErrHeld {
		t.Fatal(err)
	}
	if _, err = c.Pipeline(1); err != ErrHeld {
		t.Fatal(err)
	}
}
func TestQuiesceCannotDisplaceOtherOwnerButCanRecoverLostFence(t *testing.T) {
	s := &resolutionMemory{}
	c := New(s, secret)
	if _, err := c.Acquire(secret, otherOperation, []uint64{3}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Quiesce(secret, operation, evidence, []uint64{1, 2}); err != ErrHeld {
		t.Fatal(err)
	}
	if _, err := c.Check(secret, otherOperation); err != nil {
		t.Fatal(err)
	}
	if err := c.Release(secret, otherOperation); err != nil {
		t.Fatal(err)
	}
	r, err := c.Quiesce(secret, operation, evidence, []uint64{1, 2})
	if err != nil || r.Phase != Quiesced {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestQuiesceFailuresKeepOldTokenRevokedAndRetryDrainsAgain(t *testing.T) {
	for _, stage := range []string{"fence", "journal"} {
		t.Run(stage, func(t *testing.T) {
			s := &resolutionMemory{}
			c := New(s, secret)
			acquire(t, c)
			if stage == "fence" {
				s.failSave = true
			} else {
				s.failPhase = Quiesced
			}
			if _, err := c.Quiesce(secret, operation, evidence, []uint64{1, 2}); err != ErrUnavailable {
				t.Fatal(err)
			}
			c = New(s, secret)
			if _, err := c.Write(Token(secret, operation)); err != ErrHeld {
				t.Fatal(err)
			}
			if _, err := c.Acquire(secret, operation, []uint64{1, 2}); err != ErrHeld {
				t.Fatal(err)
			}
			s.failSave = false
			s.failPhase = ""
			if _, err := c.Quiesce(secret, operation, evidence, []uint64{1, 2}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestResolutionReleaseDrainsCleanupAndSurvivesNextOperation(t *testing.T) {
	s := &resolutionMemory{}
	c := New(s, secret)
	if _, err := c.Quiesce(secret, operation, evidence, nil); err != nil {
		t.Fatal(err)
	}
	done, err := c.ResolutionWrite(ResolutionToken(secret, operation, evidence))
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := c.ReleaseResolution(secret, operation, evidence); result <- err }()
	select {
	case err := <-result:
		t.Fatalf("cleanup not drained: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	done()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err = c.Acquire(secret, otherOperation, nil); err != nil {
		t.Fatal(err)
	}
	c = New(s, secret)
	r, err := c.ReleaseResolution(secret, operation, evidence)
	if err != nil || r.Phase != Released {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err = c.Check(secret, otherOperation); err != nil {
		t.Fatal(err)
	}
	if _, err = c.ResolutionWrite(ResolutionToken(secret, operation, evidence)); err != ErrHeld {
		t.Fatal(err)
	}
	if _, err = c.ResolutionStatus(secret, operation, evidence); err != nil {
		t.Fatal(err)
	}
}
func TestResolutionReleaseCrashStagesPreserveReceiptAndOtherOwner(t *testing.T) {
	for _, stage := range []string{"intent", "fence", "receipt"} {
		t.Run(stage, func(t *testing.T) {
			s := &resolutionMemory{}
			c := New(s, secret)
			if _, err := c.Quiesce(secret, operation, evidence, nil); err != nil {
				t.Fatal(err)
			}
			switch stage {
			case "intent":
				s.failPhase = Releasing
			case "fence":
				s.failSave = true
			case "receipt":
				s.failPhase = Released
			}
			if _, err := c.ReleaseResolution(secret, operation, evidence); err != ErrUnavailable {
				t.Fatal(err)
			}
			if stage == "receipt" {
				if _, err := c.Acquire(secret, otherOperation, nil); err != nil {
					t.Fatal(err)
				}
			}
			s.failPhase = ""
			s.failSave = false
			c = New(s, secret)
			r, err := c.ReleaseResolution(secret, operation, evidence)
			if err != nil || r.Phase != Released {
				t.Fatalf("%+v %v", r, err)
			}
			if stage == "receipt" {
				if _, err := c.Check(secret, otherOperation); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func TestResolutionRejectsInvalidAuthAndEvidence(t *testing.T) {
	c := New(&resolutionMemory{}, secret)
	if _, err := c.Quiesce("wrong", operation, evidence, nil); err != ErrUnavailable {
		t.Fatal(err)
	}
	if _, err := c.Quiesce(secret, operation, "invalid", nil); err != ErrInput {
		t.Fatal(err)
	}
	if _, err := c.Quiesce(secret, operation, evidence, []uint64{1, 1}); err != ErrInput {
		t.Fatal(err)
	}
	if _, err := c.Quiesce(secret, operation, evidence, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReleaseResolution(secret, operation, otherOperation); err != ErrHeld {
		t.Fatal(err)
	}
	if _, err := c.ResolutionStatus(secret, operation, otherOperation); err != ErrHeld {
		t.Fatal(err)
	}
	if _, err := New(&memoryStore{}, secret).Quiesce(secret, operation, evidence, nil); err != ErrUnavailable {
		t.Fatal(err)
	}
}

func TestResolutionTokenMatchesCCIProtocolVector(t *testing.T) {
	if got := ResolutionToken(secret, operation, evidence); got != "e859ab69a73e844f6705e46a3bfc357ebf60c14eb3af511a9b8bab794985ba2d" {
		t.Fatal("resolution token protocol mismatch")
	}
}
