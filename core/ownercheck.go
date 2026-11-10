// Copyright 2024 Mia srl
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

package core

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

var (
	// ErrOwnerMismatch is returned when the resource owner does not match the
	// caller identity. It is meant to be mapped to an HTTP 403 by upper layers.
	ErrOwnerMismatch = errors.New("resource owner does not match the caller")
	// ErrOwnerNotFound is returned when a policy declares an owner binding but
	// the owner value cannot be extracted from the input. The check is
	// fail-closed: it is meant to be mapped to an HTTP 403 by upper layers.
	ErrOwnerNotFound = errors.New("resource owner not found in input")
	// ErrOwnerInputInvalid is returned when the input cannot be traversed
	// according to the configured owner path (e.g. a segment resolves to a
	// scalar value). It is meant to be mapped to an HTTP 400 by upper layers.
	ErrOwnerInputInvalid = errors.New("invalid input for owner binding")
)

// OwnerBinding declares a resource-owner binding for a policy. When a policy
// does not declare any binding, the owner check is skipped entirely so that
// legacy policies keep working unchanged.
type OwnerBinding struct {
	// OwnerPath is the dotted path of the owner field inside the evaluated
	// input, e.g. "request.body.resource.owner" or "response.body.created_by".
	OwnerPath string `json:"ownerPath"`

	// AdminGroups are the caller groups that bypass the owner check. Caller
	// membership is resolved from the existing input user information.
	AdminGroups []string `json:"adminGroups,omitempty"`
}

// Enabled reports whether a binding is actually declared. A zero-value
// OwnerBinding means "no binding" and must remain transparent to legacy
// policies.
func (binding OwnerBinding) Enabled() bool {
	return binding.OwnerPath != ""
}

// ownerChecker is the standalone resource-owner enforcement unit. It works on
// the read-only parsed Rego input and never mutates it, so its result can be
// merged with the Rego evaluation without touching the shared input.
type ownerChecker struct {
	binding OwnerBinding
}

func newOwnerChecker(binding OwnerBinding) *ownerChecker {
	if !binding.Enabled() {
		return nil
	}
	return &ownerChecker{binding: binding}
}

// check enforces the owner binding against the parsed input. The caller
// identity is taken from the input user, reusing the existing user
// information instead of introducing a separate resolution mechanism.
//
// Semantics:
//   - no binding declared: transparent pass (nil error);
//   - caller belongs to an admin group: override, pass;
//   - binding declared but owner cannot be resolved: fail-closed
//     (ErrOwnerNotFound);
//   - malformed input along the configured path: ErrOwnerInputInvalid, kept
//     distinct from the authorization failures so upper layers can map it to
//     400 while the others map to 403;
//   - owner resolved but different from the caller: ErrOwnerMismatch.
func (checker *ownerChecker) check(input EvalInput) error {
	if checker == nil || !checker.binding.Enabled() {
		return nil
	}

	// Admin override is evaluated first and is based solely on the existing
	// user groups, so an administrator bypasses the binding even when no owner
	// (or caller id) can be resolved.
	if callerInAdminGroups(input, checker.binding.AdminGroups) {
		return nil
	}

	callerID, err := extractStringField(input, []string{"user", "id"})
	if err != nil {
		// The caller identity always comes from the existing user info: a
		// missing/malformed one makes the binding impossible to evaluate, so
		// fail closed.
		return fmt.Errorf("%w: cannot resolve caller identity: %s", ErrOwnerNotFound, err.Error())
	}
	if callerID == "" {
		return fmt.Errorf("%w: caller id is empty", ErrOwnerNotFound)
	}

	segments := strings.Split(checker.binding.OwnerPath, ".")
	owner, err := extractStringField(input, segments)
	if err != nil {
		if errors.Is(err, errOwnerFieldNotFound) {
			return fmt.Errorf("%w at path %q: %s", ErrOwnerNotFound, checker.binding.OwnerPath, err.Error())
		}
		return fmt.Errorf("%w at path %q: %s", ErrOwnerInputInvalid, checker.binding.OwnerPath, err.Error())
	}
	if owner == "" {
		return fmt.Errorf("%w at path %q: owner value is empty", ErrOwnerNotFound, checker.binding.OwnerPath)
	}

	if owner != callerID {
		return fmt.Errorf("%w: resource owner %q, caller %q", ErrOwnerMismatch, owner, callerID)
	}
	return nil
}

var errOwnerFieldNotFound = errors.New("field not found")

// termObject returns the object carried by the term, or false if the term is
// nil or does not hold an object.
func termObject(term *ast.Term) (ast.Object, bool) {
	if term == nil {
		return nil, false
	}
	object, ok := term.Value.(ast.Object)
	return object, ok
}

// extractStringField walks the parsed input following the given segments and
// returns the terminal value as a string. It only reads the ast.Term, it does
// not mutate it.
func extractStringField(input EvalInput, segments []string) (string, error) {
	if input == nil {
		return "", fmt.Errorf("%w: input is nil", errOwnerFieldNotFound)
	}

	current := input
	for index, segment := range segments {
		if segment == "" {
			return "", fmt.Errorf("empty path segment at position %d", index)
		}

		object, ok := current.Value.(ast.Object)
		if !ok {
			return "", fmt.Errorf("segment %q cannot be traversed: value is not an object", segment)
		}

		next := object.Get(ast.StringTerm(segment))
		if next == nil {
			return "", fmt.Errorf("%w: segment %q", errOwnerFieldNotFound, segment)
		}
		current = next
	}

	switch value := current.Value.(type) {
	case ast.String:
		return string(value), nil
	case ast.Number:
		// Some resources store identifiers as numbers; comparing against the
		// string caller id works on the textual representation.
		return value.String(), nil
	case ast.Null:
		return "", fmt.Errorf("%w: value is null", errOwnerFieldNotFound)
	default:
		return "", fmt.Errorf("terminal value is not a scalar string, got %T", current.Value)
	}
}

// callerInAdminGroups resolves group membership from the existing input user
// groups. Missing groups simply mean the override does not apply.
func callerInAdminGroups(input EvalInput, adminGroups []string) bool {
	if len(adminGroups) == 0 {
		return false
	}

	rootObject, ok := termObject(input)
	if !ok {
		return false
	}
	groupsTerm := rootObject.Get(ast.StringTerm("user"))
	if groupsTerm == nil {
		return false
	}
	userObject, ok := groupsTerm.Value.(ast.Object)
	if !ok {
		return false
	}
	groups := userObject.Get(ast.StringTerm("groups"))
	if groups == nil {
		return false
	}

	groupArray, ok := groups.Value.(*ast.Array)
	if !ok {
		return false
	}

	adminSet := make(map[string]struct{}, len(adminGroups))
	for _, group := range adminGroups {
		adminSet[group] = struct{}{}
	}

	for index := 0; index < groupArray.Len(); index++ {
		element := groupArray.Elem(index)
		if group, ok := element.Value.(ast.String); ok {
			if _, isAdmin := adminSet[string(group)]; isAdmin {
				return true
			}
		}
	}
	return false
}
