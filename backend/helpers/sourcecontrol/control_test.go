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
	"strings"
	"sync"
	"testing"
	"time"
)

const operation = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
const otherOperation = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"

var secret = strings.Repeat("s", 32)

type memoryStore struct {
	mu        sync.Mutex
	state     State
	fail      bool
	cancelled map[string]bool
	failSave  bool
}

func (s *memoryStore) Cancelled(operation string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return false, errors.New("offline")
	}
	return s.cancelled[operation], nil
}
func (s *memoryStore) Cancel(operation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("offline")
	}
	if s.cancelled == nil {
		s.cancelled = map[string]bool{}
	}
	s.cancelled[operation] = true
	return nil
}
func (s *memoryStore) Load() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return State{}, errors.New("offline")
	}
	return s.state, nil
}
func (s *memoryStore) Save(state State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail || s.failSave {
		return errors.New("offline")
	}
	s.state = state
	return nil
}
func acquire(t *testing.T, c *Control) {
	t.Helper()
	if _, err := c.Acquire(secret, operation, []uint64{2, 1}); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentOwnershipAndExplicitRelease(t *testing.T) {
	store := &memoryStore{}
	c := New(store, secret)
	acquire(t, c)
	c = New(store, secret) // restart retains the fence
	if _, err := c.Write(""); err != ErrHeld {
		t.Fatalf("ordinary write: %v", err)
	}
	release, err := c.Write(Token(secret, operation))
	if err != nil {
		t.Fatal(err)
	}
	release()
	acquire(t, c)
	if _, err := c.Acquire(secret, otherOperation, []uint64{1, 2}); err != ErrHeld {
		t.Fatalf("other owner: %v", err)
	}
	if _, err := c.Acquire(secret, operation, []uint64{1}); err != ErrHeld {
		t.Fatalf("changed scope: %v", err)
	}
	if err := c.Release(secret, otherOperation); err != ErrHeld {
		t.Fatalf("other release: %v", err)
	}
	if err := c.Release(secret, operation); err != nil {
		t.Fatal(err)
	}
	if err := c.Release(secret, operation); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(Token(secret, operation)); err != ErrHeld {
		t.Fatalf("late owner write: %v", err)
	}
	release, err = c.Write("")
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestPipelineAdmission(t *testing.T) {
	c := New(&memoryStore{}, secret)
	acquire(t, c)
	for _, id := range []uint64{0, 1, 2} {
		if _, err := c.Pipeline(id); err != ErrHeld {
			t.Fatalf("id %d: %v", id, err)
		}
	}
	release, err := c.Pipeline(3)
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestAcquireDrainsInFlightWork(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		t.Run(map[bool]string{false: "write", true: "pipeline"}[pipeline], func(t *testing.T) {
			c := New(&memoryStore{}, secret)
			var release func()
			var err error
			if pipeline {
				release, err = c.Pipeline(1)
			} else {
				release, err = c.Write("")
			}
			if err != nil {
				t.Fatal(err)
			}
			started := make(chan struct{})
			done := make(chan error, 1)
			go func() { close(started); _, err := c.Acquire(secret, operation, []uint64{1}); done <- err }()
			<-started
			select {
			case err := <-done:
				release()
				t.Fatalf("acquired before drain: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			release()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("did not acquire after drain")
			}
		})
	}
}

func TestInvalidOrUnavailableStateFailsClosed(t *testing.T) {
	for _, store := range []*memoryStore{
		{fail: true}, {state: State{Held: true}},
		{state: State{Operation: operation, Blueprints: []uint64{0}, Held: true}},
		{state: State{Operation: operation, Blueprints: []uint64{2, 1}, Held: true}},
	} {
		c := New(store, secret)
		if _, err := c.Write(""); err != ErrUnavailable {
			t.Fatalf("write: %v", err)
		}
		if _, err := c.Pipeline(3); err != ErrUnavailable {
			t.Fatalf("pipeline: %v", err)
		}
		if _, err := c.Acquire(secret, operation, nil); err != ErrUnavailable {
			t.Fatalf("acquire: %v", err)
		}
	}
	store := &memoryStore{}
	c := New(store, secret)
	acquire(t, c)
	store.fail = true
	if err := c.Release(secret, operation); err != ErrUnavailable {
		t.Fatal(err)
	}
	store.fail = false
	if _, err := c.Write(""); err != ErrHeld {
		t.Fatalf("failed release lost protection: %v", err)
	}
}

func TestCredentialsAndInputs(t *testing.T) {
	store := &memoryStore{}
	c := New(store, secret)
	if _, err := c.Acquire("bad", operation, nil); err != ErrUnavailable {
		t.Fatal(err)
	}
	for _, ids := range [][]uint64{{0}, {1, 1}, make([]uint64, 1001)} {
		if _, err := c.Acquire(secret, operation, ids); err != ErrInput {
			t.Fatalf("input: %v", err)
		}
	}
	if _, err := c.Acquire(secret, "invalid", nil); err != ErrInput {
		t.Fatal(err)
	}
	if _, err := c.Acquire(secret, operation, nil); err != nil {
		t.Fatal(err)
	}
	c = New(store, "") // removing the deployment secret must not remove protection
	if _, err := c.Write(""); err != ErrHeld {
		t.Fatal(err)
	}
	if err := c.Release("", operation); err != ErrUnavailable {
		t.Fatal(err)
	}
}

func TestCancellationSurvivesRestartAndOtherOperations(t *testing.T) {
	store := &memoryStore{}
	c := New(store, secret)
	acquire(t, c)
	if err := c.Cancel(secret, operation); err != nil {
		t.Fatal(err)
	}
	c = New(store, secret)
	if _, err := c.Acquire(secret, operation, []uint64{1, 2}); err != ErrHeld {
		t.Fatalf("delayed acquire: %v", err)
	}
	if _, err := c.Acquire(secret, otherOperation, []uint64{3}); err != nil {
		t.Fatal(err)
	}
	if err := c.Cancel(secret, operation); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(secret, otherOperation); err != nil {
		t.Fatalf("other fence changed: %v", err)
	}
	if _, err := c.Write(Token(secret, operation)); err != ErrHeld {
		t.Fatalf("old token: %v", err)
	}
}
func TestCancelBeforeAcquireAndFailedRelease(t *testing.T) {
	store := &memoryStore{}
	c := New(store, secret)
	if err := c.Cancel(secret, operation); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Acquire(secret, operation, nil); err != ErrHeld {
		t.Fatal(err)
	}
	if err := c.Cancel("wrong", otherOperation); err != ErrUnavailable {
		t.Fatal(err)
	}
	if _, err := c.Acquire(secret, otherOperation, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCancelReleaseFailureRemainsRetryable(t *testing.T) {
	store := &memoryStore{}
	c := New(store, secret)
	acquire(t, c)
	store.failSave = true
	if err := c.Cancel(secret, operation); err != ErrUnavailable {
		t.Fatal(err)
	}
	store.failSave = false
	c = New(store, secret)
	if _, err := c.Acquire(secret, operation, []uint64{1, 2}); err != ErrHeld {
		t.Fatalf("tombstone lost: %v", err)
	}
	if err := c.Cancel(secret, operation); err != nil {
		t.Fatal(err)
	}
	release, err := c.Write("")
	if err != nil {
		t.Fatal(err)
	}
	release()
}
func TestCancelRacesDelayedAcquire(t *testing.T) {
	for i := 0; i < 30; i++ {
		store := &memoryStore{}
		c := New(store, secret)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := c.Acquire(secret, operation, nil)
			if err != nil && err != ErrHeld {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := c.Cancel(secret, operation); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if _, err := c.Check(secret, operation); err != ErrHeld {
			t.Fatalf("fence resurrected: %v", err)
		}
		if _, err := New(store, secret).Acquire(secret, operation, nil); err != ErrHeld {
			t.Fatal(err)
		}
	}
}
