// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policykey

import (
	"fmt"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

func (key *PolicyKey) String() string {

	trafficDirectionString := (trafficdirection.TrafficDirection)(key.TrafficDirection).String()
	if key.DestPort != 0 {
		return fmt.Sprintf("%s: %d %d/%d", trafficDirectionString, key.Identity, byteorder.NetworkToHost(key.DestPort), key.Nexthdr)
	}
	return fmt.Sprintf("%s: %d", trafficDirectionString, key.Identity)
}

// GetIdentity returns the identity in key.
func (key *PolicyKey) GetIdentity() uint32 {
	return key.Identity
}

// GetPort returns the port in key. Note that the port may be in host or network
// byte-order.
func (key *PolicyKey) GetPort() uint16 {
	return key.DestPort
}

// GetProto returns the protocol for key.
func (key *PolicyKey) GetProto() uint8 {
	return key.Nexthdr
}

// GetDirection returns the traffic direction for key.
func (key *PolicyKey) GetDirection() uint8 {
	return key.TrafficDirection
}

// ToHost returns a copy of key with fields converted from network byte-order
// to host-byte-order if necessary.
func (key *PolicyKey) ToHost() PolicyKey {
	if key == nil {
		return PolicyKey{}
	}

	n := *key
	n.DestPort = byteorder.NetworkToHost(n.DestPort).(uint16)
	return n
}

// ToNetwork returns a copy of key with fields converted from host byte-order
// to network-byte-order if necessary.
func (key *PolicyKey) ToNetwork() PolicyKey {
	if key == nil {
		return PolicyKey{}
	}

	n := *key
	n.DestPort = byteorder.HostToNetwork(n.DestPort).(uint16)
	return n
}

// PolicyKey represents a key in the BPF policy map for an endpoint. It must
// match the layout of policy_key in bpf/lib/common.h.
type PolicyKey struct {
	Identity         uint32
	DestPort         uint16 // In network byte-order
	Nexthdr          uint8
	TrafficDirection uint8
}
