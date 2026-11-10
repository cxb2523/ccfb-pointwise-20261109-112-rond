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
	"context"
	"errors"
	"testing"

	"github.com/rond-authz/rond/logging"

	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/require"
)

func mustBuildOwnerEvalInput(t *testing.T, input Input) EvalInput {
	t.Helper()
	evalInput, err := CreateRegoQueryInput(logging.NewNoOpLogger(), input, RegoInputOptions{})
	require.NoError(t, err)
	return evalInput
}

func ownerInput(userID string, groups []string, requestBody any, responseBody any) Input {
	return Input{
		Request:  InputRequest{Method: "GET", Path: "/documents/1", Body: requestBody},
		Response: InputResponse{Body: responseBody},
		User:     InputUser{ID: userID, Groups: groups},
	}
}

func TestOwnerChecker(t *testing.T) {
	t.Parallel()

	doc := func(owner string) map[string]any {
		return map[string]any{"owner": owner, "title": "invoice"}
	}
	nestedDoc := map[string]any{
		"resource": map[string]any{"owner": "alice", "id": "doc-1"},
	}
	legacyDoc := map[string]any{"title": "no binding here"}

	testCases := []struct {
		name        string
		binding     OwnerBinding
		input       Input
		expectedErr error
	}{
		{
			name:    "same owner is allowed",
			binding: OwnerBinding{OwnerPath: "request.body.owner"},
			input:   ownerInput("alice", nil, doc("alice"), nil),
		},
		{
			name:        "cross owner is rejected (horizontal privilege escalation)",
			binding:     OwnerBinding{OwnerPath: "request.body.owner"},
			input:       ownerInput("bob", nil, doc("alice"), nil),
			expectedErr: ErrOwnerMismatch,
		},
		{
			name:        "owner missing fails closed",
			binding:     OwnerBinding{OwnerPath: "request.body.owner"},
			input:       ownerInput("alice", nil, map[string]any{"title": "invoice"}, nil),
			expectedErr: ErrOwnerNotFound,
		},
		{
			name:        "null owner fails closed",
			binding:     OwnerBinding{OwnerPath: "request.body.owner"},
			input:       ownerInput("alice", nil, map[string]any{"owner": nil}, nil),
			expectedErr: ErrOwnerNotFound,
		},
		{
			name:        "empty owner value fails closed",
			binding:     OwnerBinding{OwnerPath: "request.body.owner"},
			input:       ownerInput("alice", nil, map[string]any{"owner": ""}, nil),
			expectedErr: ErrOwnerNotFound,
		},
		{
			name:    "legacy request without binding is transparently allowed",
			binding: OwnerBinding{},
			input:   ownerInput("bob", nil, legacyDoc, nil),
		},
		{
			name:    "admin group overrides cross-owner mismatch",
			binding: OwnerBinding{OwnerPath: "request.body.owner", AdminGroups: []string{"administrators"}},
			input:   ownerInput("bob", []string{"developers", "administrators"}, doc("alice"), nil),
		},
		{
			name:    "admin group overrides even when owner is missing and caller id is empty",
			binding: OwnerBinding{OwnerPath: "request.body.owner", AdminGroups: []string{"administrators"}},
			input:   ownerInput("", []string{"administrators"}, map[string]any{"title": "no owner"}, nil),
		},
		{
			name:        "non-admin group does not override cross-owner mismatch",
			binding:     OwnerBinding{OwnerPath: "request.body.owner", AdminGroups: []string{"administrators"}},
			input:       ownerInput("bob", []string{"developers"}, doc("alice"), nil),
			expectedErr: ErrOwnerMismatch,
		},
		{
			name:    "nested path extraction allows same owner",
			binding: OwnerBinding{OwnerPath: "request.body.resource.owner"},
			input:   ownerInput("alice", nil, nestedDoc, nil),
		},
		{
			name:        "nested path extraction rejects cross owner",
			binding:     OwnerBinding{OwnerPath: "request.body.resource.owner"},
			input:       ownerInput("bob", nil, nestedDoc, nil),
			expectedErr: ErrOwnerMismatch,
		},
		{
			name:        "path segment on scalar value is an input error, distinct from not found",
			binding:     OwnerBinding{OwnerPath: "request.body.owner.subfield"},
			input:       ownerInput("alice", nil, doc("alice"), nil),
			expectedErr: ErrOwnerInputInvalid,
		},
		{
			name:        "terminal non-scalar value is an input error",
			binding:     OwnerBinding{OwnerPath: "request.body.resource"},
			input:       ownerInput("alice", nil, nestedDoc, nil),
			expectedErr: ErrOwnerInputInvalid,
		},
		{
			name:        "missing field is distinguishable from malformed input",
			binding:     OwnerBinding{OwnerPath: "request.body.created_by"},
			input:       ownerInput("alice", nil, doc("alice"), nil),
			expectedErr: ErrOwnerNotFound,
		},
		{
			name:    "owner path on response body works as well",
			binding: OwnerBinding{OwnerPath: "response.body.created_by"},
			input:   ownerInput("alice", nil, nil, map[string]any{"created_by": "alice"}),
		},
		{
			name:        "caller without id fails closed",
			binding:     OwnerBinding{OwnerPath: "request.body.owner"},
			input:       ownerInput("", nil, doc("alice"), nil),
			expectedErr: ErrOwnerNotFound,
		},
		{
			name:    "numeric owner matching caller id is allowed",
			binding: OwnerBinding{OwnerPath: "request.body.owner"},
			input:   ownerInput("42", nil, map[string]any{"owner": 42}, nil),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			evalInput := mustBuildOwnerEvalInput(t, testCase.input)
			checker := newOwnerChecker(testCase.binding)

			if !testCase.binding.Enabled() {
				require.Nil(t, checker, "no binding declared means no checker must be wired")
			}

			err := checker.check(evalInput)
			if testCase.expectedErr == nil {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.True(t, errors.Is(err, testCase.expectedErr),
				"expected error wrapping %v, got %v", testCase.expectedErr, err)

			// The 403/400 mapping must remain distinguishable for upper layers.
			switch testCase.expectedErr {
			case ErrOwnerInputInvalid:
				require.False(t, errors.Is(err, ErrOwnerMismatch))
				require.False(t, errors.Is(err, ErrOwnerNotFound))
			case ErrOwnerMismatch:
				require.False(t, errors.Is(err, ErrOwnerInputInvalid))
			case ErrOwnerNotFound:
				require.False(t, errors.Is(err, ErrOwnerInputInvalid))
			}
		})
	}
}

func TestOwnerCheckerDoesNotMutateSharedInput(t *testing.T) {
	t.Parallel()

	input := ownerInput("bob", nil, map[string]any{
		"resource": map[string]any{"owner": "alice"},
	}, nil)
	evalInput := mustBuildOwnerEvalInput(t, input)

	before := (*ast.Term)(evalInput).String()

	checker := newOwnerChecker(OwnerBinding{OwnerPath: "request.body.resource.owner"})
	err := checker.check(evalInput)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrOwnerMismatch))

	require.Equal(t, before, (*ast.Term)(evalInput).String(), "the shared parsed input must not be rewritten")
}

func TestOwnerBindingEnforcementInEvaluation(t *testing.T) {
	logger := logging.NewNoOpLogger()

	opaModule := MustNewOPAModuleConfig([]Module{
		{
			Name: "example.rego",
			Content: `package policies
			allow {
				true
			}
			`,
		},
	})

	partialEvaluators := PartialResultsEvaluators{}
	require.NoError(t, partialEvaluators.AddFromConfig(
		context.Background(),
		logger,
		opaModule,
		&RondConfig{RequestFlow: RequestFlow{PolicyName: "allow"}},
		nil,
	))

	testCases := []struct {
		name        string
		binding     OwnerBinding
		input       Input
		expectedErr error
	}{
		{
			name:    "owner check passes and rego evaluation runs",
			binding: OwnerBinding{OwnerPath: "request.body.owner"},
			input:   ownerInput("alice", nil, map[string]any{"owner": "alice"}, nil),
		},
		{
			name:        "cross owner short-circuits before rego",
			binding:     OwnerBinding{OwnerPath: "request.body.owner"},
			input:       ownerInput("mallory", nil, map[string]any{"owner": "alice"}, nil),
			expectedErr: ErrOwnerMismatch,
		},
		{
			name:        "declared binding with missing owner fails closed before rego",
			binding:     OwnerBinding{OwnerPath: "request.body.owner"},
			input:       ownerInput("alice", nil, map[string]any{"title": "no owner"}, nil),
			expectedErr: ErrOwnerNotFound,
		},
		{
			name:        "malformed input returns the 400-mappable error",
			binding:     OwnerBinding{OwnerPath: "request.body.owner.who"},
			input:       ownerInput("alice", nil, map[string]any{"owner": "alice"}, nil),
			expectedErr: ErrOwnerInputInvalid,
		},
		{
			name:    "admin override reaches rego even on mismatch",
			binding: OwnerBinding{OwnerPath: "request.body.owner", AdminGroups: []string{"administrators"}},
			input:   ownerInput("mallory", []string{"administrators"}, map[string]any{"owner": "alice"}, nil),
		},
		{
			name:    "no binding declared keeps legacy behavior",
			binding: OwnerBinding{},
			input:   ownerInput("mallory", nil, map[string]any{"owner": "alice"}, nil),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			evalInput := mustBuildOwnerEvalInput(t, testCase.input)
			evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(
				context.Background(),
				"allow",
				&OPAEvaluatorOptions{OwnerBinding: testCase.binding},
			)
			require.NoError(t, err)

			result, err := evaluator.Evaluate(logger, evalInput, nil)
			if testCase.expectedErr != nil {
				require.Error(t, err)
				require.True(t, errors.Is(err, testCase.expectedErr),
					"expected %v, got %v", testCase.expectedErr, err)
				return
			}
			require.NoError(t, err)
			require.Nil(t, result)
		})
	}

	t.Run("owner gate also runs on partial query evaluation", func(t *testing.T) {
		filterEvaluators := PartialResultsEvaluators{}
		require.NoError(t, filterEvaluators.AddFromConfig(
			context.Background(),
			logger,
			opaModule,
			&RondConfig{RequestFlow: RequestFlow{PolicyName: "allow", GenerateQuery: true}},
			nil,
		))

		evalInput := mustBuildOwnerEvalInput(t, ownerInput("mallory", nil, map[string]any{"owner": "alice"}, nil))
		evaluator, err := filterEvaluators.GetEvaluatorFromPolicy(
			context.Background(),
			"allow",
			&OPAEvaluatorOptions{OwnerBinding: OwnerBinding{OwnerPath: "request.body.owner"}},
		)
		require.NoError(t, err)

		_, _, err = evaluator.PolicyEvaluation(
			logger,
			evalInput,
			&PolicyEvaluationOptions{},
		)
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrOwnerMismatch))
	})
}
