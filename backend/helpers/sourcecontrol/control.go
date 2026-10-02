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

// Package sourcecontrol fences configuration writes and new pipeline admission.
// DevLake already enforces one backend process per database (lockDatabase).
// The durable fence survives that process; it has no timeout-based release.
package sourcecontrol

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"sync"
)

var ErrHeld = errors.New("source configuration is controlled by another operation")
var ErrUnavailable = errors.New("source control unavailable")
var ErrInput = errors.New("invalid source control request")
var operationPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type State struct {
	Operation  string   `json:"operation"`
	Blueprints []uint64 `json:"blueprints"`
	Held       bool     `json:"held"`
}

type Store interface {
	Load() (State, error)
	Save(State) error
}

type Control struct {
	store  Store
	secret string
	// Separate locks avoid reentrant RWMutex locking when an HTTP handler starts
	// a pipeline. Acquisition always drains HTTP writes before pipeline creation.
	writes    sync.RWMutex
	pipelines sync.RWMutex
}

func New(store Store, secret string) *Control { return &Control{store: store, secret: secret} }
func (c *Control) Authorized(key string) bool {
	return len(c.secret) >= 32 && subtle.ConstantTimeCompare([]byte(key), []byte(c.secret)) == 1
}
func Token(secret, operation string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("cci-source-control-v1:" + operation))
	return hex.EncodeToString(mac.Sum(nil))
}

func canonical(operation string, ids []uint64) ([]uint64, error) {
	if !operationPattern.MatchString(operation) || len(ids) > 1000 {
		return nil, ErrInput
	}
	result := append([]uint64{}, ids...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	for i, id := range result {
		if id == 0 || (i > 0 && result[i-1] == id) {
			return nil, ErrInput
		}
	}
	return result, nil
}
func same(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (c *Control) load() (State, error) {
	state, err := c.store.Load()
	if err != nil {
		return State{}, ErrUnavailable
	}
	if state.Operation == "" && !state.Held && len(state.Blueprints) == 0 {
		return state, nil
	}
	ids, err := canonical(state.Operation, state.Blueprints)
	if err != nil || !same(ids, state.Blueprints) {
		return State{}, ErrUnavailable
	}
	return state, nil
}

func (c *Control) Acquire(key, operation string, ids []uint64) (State, error) {
	if !c.Authorized(key) {
		return State{}, ErrUnavailable
	}
	ids, err := canonical(operation, ids)
	if err != nil {
		return State{}, err
	}
	c.writes.Lock()
	defer c.writes.Unlock()
	c.pipelines.Lock()
	defer c.pipelines.Unlock()
	previous, err := c.load()
	if err != nil {
		return State{}, ErrUnavailable
	}
	if previous.Held && (previous.Operation != operation || !same(previous.Blueprints, ids)) {
		return State{}, ErrHeld
	}
	next := State{Operation: operation, Blueprints: ids, Held: true}
	if err = c.store.Save(next); err != nil {
		return State{}, ErrUnavailable
	}
	return next, nil
}

// Check authenticates ownership without exposing another operation's state.
func (c *Control) Check(key, operation string) (State, error) {
	if !c.Authorized(key) {
		return State{}, ErrUnavailable
	}
	c.writes.RLock()
	defer c.writes.RUnlock()
	state, err := c.load()
	if err != nil {
		return State{}, ErrUnavailable
	}
	if !state.Held || state.Operation != operation {
		return State{}, ErrHeld
	}
	return state, nil
}

// Release is an explicit successful-completion operation, never a defer/TTL.
func (c *Control) Release(key, operation string) error {
	if !c.Authorized(key) {
		return ErrUnavailable
	}
	c.writes.Lock()
	defer c.writes.Unlock()
	c.pipelines.Lock()
	defer c.pipelines.Unlock()
	state, err := c.load()
	if err != nil {
		return ErrUnavailable
	}
	if state.Operation != operation {
		return ErrHeld
	}
	state.Held = false
	if c.store.Save(state) != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *Control) Write(token string) (func(), error) {
	c.writes.RLock()
	state, err := c.load()
	if err != nil {
		c.writes.RUnlock()
		return nil, ErrUnavailable
	}
	if (!state.Held && token != "") || (state.Held && (len(c.secret) < 32 || !hmac.Equal([]byte(token), []byte(Token(c.secret, state.Operation))))) {
		c.writes.RUnlock()
		return nil, ErrHeld
	}
	return c.writes.RUnlock, nil
}

// Existing pipelines may drain; only new work is fenced. Unattributed manual
// plans (id=0) cannot prove independence and are refused while a fence is held.
func (c *Control) Pipeline(id uint64) (func(), error) {
	c.pipelines.RLock()
	state, err := c.load()
	if err != nil {
		c.pipelines.RUnlock()
		return nil, ErrUnavailable
	}
	blocked := state.Held && id == 0
	for _, candidate := range state.Blueprints {
		blocked = blocked || (state.Held && candidate == id)
	}
	if blocked {
		c.pipelines.RUnlock()
		return nil, ErrHeld
	}
	return c.pipelines.RUnlock, nil
}
