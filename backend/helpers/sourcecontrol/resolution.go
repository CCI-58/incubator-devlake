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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Resolution certifies drained HTTP handlers and revoked old admission only.
// It does NOT certify that connection data has been reconciled or cleaned up.
type Resolution struct {
	Operation  string   `json:"operation"`
	Evidence   string   `json:"evidence"`
	Blueprints []uint64 `json:"blueprints"`
	Phase      string   `json:"phase"`
}

const Quiesced = "QUIESCED"
const Releasing = "RELEASING"
const Released = "RELEASED"

// Kept separate for older stores: an unsupported store cannot advertise or use
// quiescence. Production initializes this durable journal before API startup.
type ResolutionStore interface {
	LoadResolution(string) (Resolution, bool, error)
	SaveResolution(Resolution) error
}

func (c *Control) SupportsQuiescence() bool { _, ok := c.store.(ResolutionStore); return ok }
func (c *Control) resolution(operation string) (Resolution, bool, error) {
	s, ok := c.store.(ResolutionStore)
	if !ok {
		return Resolution{}, false, nil
	}
	r, found, err := s.LoadResolution(operation)
	if err != nil {
		return Resolution{}, false, ErrUnavailable
	}
	if found {
		ids, err := canonical(r.Operation, r.Blueprints)
		if err != nil || r.Operation != operation || !operationPattern.MatchString(r.Evidence) || !same(ids, r.Blueprints) ||
			(r.Phase != Quiesced && r.Phase != Releasing && r.Phase != Released) {
			return Resolution{}, false, ErrUnavailable
		}
	}
	return r, found, nil
}
func (c *Control) saveResolution(r Resolution) error {
	s, ok := c.store.(ResolutionStore)
	if !ok || s.SaveResolution(r) != nil {
		return ErrUnavailable
	}
	return nil
}
func (c *Control) Quiesce(key, operation, evidence string, ids []uint64) (Resolution, error) {
	if !c.Authorized(key) || !c.SupportsQuiescence() {
		return Resolution{}, ErrUnavailable
	}
	ids, err := canonical(operation, ids)
	if err != nil || !operationPattern.MatchString(evidence) {
		return Resolution{}, ErrInput
	}
	// Exclusive acquisition waits for every admitted mutating handler to finish.
	// It also drains recovery handlers admitted with a separate evidence token.
	c.writes.Lock()
	defer c.writes.Unlock()
	c.pipelines.Lock()
	defer c.pipelines.Unlock()
	r, found, err := c.resolution(operation)
	if err != nil {
		return Resolution{}, err
	}
	if found {
		if r.Evidence != evidence || !same(r.Blueprints, ids) {
			return Resolution{}, ErrHeld
		}
		if r.Phase != Quiesced {
			return r, nil
		}
	}
	state, err := c.load()
	if err != nil {
		return Resolution{}, err
	}
	if state.Held && (state.Operation != operation || !same(state.Blueprints, ids)) {
		return Resolution{}, ErrHeld
	}
	if found && (!state.Held || state.Operation != operation) {
		return Resolution{}, ErrHeld
	}
	// Tombstone first: failure at any subsequent step must never enable the old
	// token or a delayed acquire. A retry drains again before recording evidence.
	if c.store.Cancel(operation) != nil {
		return Resolution{}, ErrUnavailable
	}
	if c.store.Save(State{Operation: operation, Blueprints: ids, Held: true}) != nil {
		return Resolution{}, ErrUnavailable
	}
	r = Resolution{Operation: operation, Evidence: evidence, Blueprints: ids, Phase: Quiesced}
	if !found {
		if err = c.saveResolution(r); err != nil {
			return Resolution{}, err
		}
	}
	return r, nil
}
func (c *Control) ResolutionStatus(key, operation, evidence string) (Resolution, error) {
	if !c.Authorized(key) || !c.SupportsQuiescence() {
		return Resolution{}, ErrUnavailable
	}
	if !operationPattern.MatchString(operation) || !operationPattern.MatchString(evidence) {
		return Resolution{}, ErrInput
	}
	c.writes.RLock()
	defer c.writes.RUnlock()
	r, found, err := c.resolution(operation)
	if err != nil {
		return Resolution{}, err
	}
	if !found || r.Evidence != evidence {
		return Resolution{}, ErrHeld
	}
	if r.Phase == Quiesced {
		state, err := c.load()
		if err != nil {
			return Resolution{}, err
		}
		cancelled, err := c.store.Cancelled(operation)
		if err != nil {
			return Resolution{}, ErrUnavailable
		}
		if !cancelled || !state.Held || state.Operation != operation || !same(state.Blueprints, r.Blueprints) {
			return Resolution{}, ErrHeld
		}
	}
	return r, nil
}

// ReleaseResolution must only be invoked after CCI verifies reconciliation and
// cleanup. It drains cleanup writes, records intent before releasing, and keeps
// the receipt after subsequent operations so a lost response can be recovered.
func (c *Control) ReleaseResolution(key, operation, evidence string) (Resolution, error) {
	if !c.Authorized(key) || !c.SupportsQuiescence() {
		return Resolution{}, ErrUnavailable
	}
	if !operationPattern.MatchString(operation) || !operationPattern.MatchString(evidence) {
		return Resolution{}, ErrInput
	}
	c.writes.Lock()
	defer c.writes.Unlock()
	c.pipelines.Lock()
	defer c.pipelines.Unlock()
	r, found, err := c.resolution(operation)
	if err != nil {
		return Resolution{}, err
	}
	if !found || r.Evidence != evidence {
		return Resolution{}, ErrHeld
	}
	if r.Phase == Released {
		return r, nil
	}
	state, err := c.load()
	if err != nil {
		return Resolution{}, err
	}
	if r.Phase == Quiesced {
		if !state.Held || state.Operation != operation || !same(state.Blueprints, r.Blueprints) {
			return Resolution{}, ErrHeld
		}
		r.Phase = Releasing
		if err = c.saveResolution(r); err != nil {
			return Resolution{}, err
		}
	}
	// RELEASING is durable before Held=false. If another operation has since
	// acquired the singleton, never release it: only finish our historical receipt.
	if state.Operation == operation && state.Held {
		state.Held = false
		if c.store.Save(state) != nil {
			return Resolution{}, ErrUnavailable
		}
	}
	r.Phase = Released
	if err = c.saveResolution(r); err != nil {
		return Resolution{}, err
	}
	return r, nil
}
func ResolutionToken(secret, operation, evidence string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("cci-source-resolution-v1:" + operation + ":" + evidence))
	return hex.EncodeToString(mac.Sum(nil))
}

// A dedicated header avoids mistaking an old operation token for cleanup rights.
// Existing direct/internal versus /rest authentication rules remain unchanged.
// Cleanup ownership is new;
// it never claims continuity with the lost source operation fence.
func (c *Control) ResolutionWrite(token string) (func(), error) {
	c.writes.RLock()
	reject := func(err error) (func(), error) { c.writes.RUnlock(); return nil, err }
	state, err := c.load()
	if err != nil {
		return reject(err)
	}
	if !state.Held || len(c.secret) < 32 {
		return reject(ErrHeld)
	}
	r, found, err := c.resolution(state.Operation)
	if err != nil {
		return reject(err)
	}
	if !found || r.Phase != Quiesced || !same(r.Blueprints, state.Blueprints) || !hmac.Equal([]byte(token), []byte(ResolutionToken(c.secret, r.Operation, r.Evidence))) {
		return reject(ErrHeld)
	}
	return c.writes.RUnlock, nil
}
