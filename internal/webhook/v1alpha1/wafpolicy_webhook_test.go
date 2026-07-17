package v1alpha1

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gatewayprotectorkubewardeniov1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

type wafPolicyTestCase struct {
	name          string
	policy        *gatewayprotectorkubewardeniov1alpha1.WAFPolicy
	expectedError string
	expectedField string
}

func TestWAFPolicyDefaulter_Default(t *testing.T) {
	policy := &gatewayprotectorkubewardeniov1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shop-gateway-default",
			Namespace: "gateway-protector-system",
		},
		Spec: gatewayprotectorkubewardeniov1alpha1.WAFPolicySpec{
			TargetRef: gatewayprotectorkubewardeniov1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      "shared-gw",
				Namespace: "infra",
			},
			Engine: gatewayprotectorkubewardeniov1alpha1.WAFEngineSpec{
				Mode:        gatewayprotectorkubewardeniov1alpha1.WAFEngineModeBlocking,
				FailureMode: gatewayprotectorkubewardeniov1alpha1.FailureModeClosed,
			},
		},
	}
	before := policy.DeepCopy()

	defaulter := &WAFPolicyCustomDefaulter{
		logger: logr.Discard(),
	}

	err := defaulter.Default(t.Context(), policy)
	require.NoError(t, err)

	// TODO(user): Default currently doesn't change anything (see its doc
	// comment); this asserts that no-op explicitly so the test starts
	// failing - as a reminder to add real assertions here - the moment a
	// default gets added.
	assert.Equal(t, before, policy)
}

var wafPolicyTestCases = []wafPolicyTestCase{
	{
		name: "should admit a Gateway-level default policy",
		policy: &gatewayprotectorkubewardeniov1alpha1.WAFPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shop-gateway-default",
				Namespace: "gateway-protector-system",
			},
			Spec: gatewayprotectorkubewardeniov1alpha1.WAFPolicySpec{
				TargetRef: gatewayprotectorkubewardeniov1alpha1.PolicyTargetReference{
					Group:     gatewayv1.GroupName,
					Kind:      "Gateway",
					Name:      "shared-gw",
					Namespace: "infra",
				},
				Engine: gatewayprotectorkubewardeniov1alpha1.WAFEngineSpec{
					Mode:        gatewayprotectorkubewardeniov1alpha1.WAFEngineModeBlocking,
					FailureMode: gatewayprotectorkubewardeniov1alpha1.FailureModeClosed,
				},
			},
		},
	},
	{
		name: "should admit an HTTPRoute override targeting a single sectionName",
		policy: &gatewayprotectorkubewardeniov1alpha1.WAFPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "admin-portal-strict",
				Namespace: "gateway-protector-system",
			},
			Spec: gatewayprotectorkubewardeniov1alpha1.WAFPolicySpec{
				TargetRef: gatewayprotectorkubewardeniov1alpha1.PolicyTargetReference{
					Group:       gatewayv1.GroupName,
					Kind:        "HTTPRoute",
					Name:        "admin-portal",
					Namespace:   "team-shop",
					SectionName: ptr.To(gatewayv1.SectionName("admin")),
				},
				Engine: gatewayprotectorkubewardeniov1alpha1.WAFEngineSpec{
					Mode:        gatewayprotectorkubewardeniov1alpha1.WAFEngineModeBlocking,
					FailureMode: gatewayprotectorkubewardeniov1alpha1.FailureModeClosed,
				},
				ParanoiaLevel: 3,
			},
		},
	},
	{
		name: "should admit a route opting out via mode Off",
		policy: &gatewayprotectorkubewardeniov1alpha1.WAFPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "public-status-page-off",
				Namespace: "gateway-protector-system",
			},
			Spec: gatewayprotectorkubewardeniov1alpha1.WAFPolicySpec{
				TargetRef: gatewayprotectorkubewardeniov1alpha1.PolicyTargetReference{
					Group:     gatewayv1.GroupName,
					Kind:      "HTTPRoute",
					Name:      "public-status-page",
					Namespace: "team-shop",
				},
				Engine: gatewayprotectorkubewardeniov1alpha1.WAFEngineSpec{
					Mode:        gatewayprotectorkubewardeniov1alpha1.WAFEngineModeOff,
					FailureMode: gatewayprotectorkubewardeniov1alpha1.FailureModeOpen,
				},
			},
		},
	},
	// TODO(user): once ValidateCreate/ValidateUpdate implement real
	// validation (see their doc comments), add deny cases here, e.g.:
	//   - customRulesRefs referencing a WAFRuleSet that doesn't exist
	//   - a targetRef that duplicates another WAFPolicy's attachment point
	// each with expectedField/expectedError set to the corresponding
	// admission.Warnings/error the webhook is expected to return.
}

func TestWAFPolicyCustomValidator_ValidateCreate(t *testing.T) {
	for _, test := range wafPolicyTestCases {
		t.Run(test.name, func(t *testing.T) {
			validator := &WAFPolicyCustomValidator{
				logger: logr.Discard(),
			}

			ctx := admission.NewContextWithRequest(t.Context(), admission.Request{})
			warnings, err := validator.ValidateCreate(ctx, test.policy)

			if test.expectedError != "" {
				require.Error(t, err)
				statusErr, ok := err.(interface{ Status() metav1.Status })
				require.True(t, ok)
				details := statusErr.Status().Details
				require.NotNil(t, details)
				require.Len(t, details.Causes, 1)
				assert.Equal(t, test.expectedField, details.Causes[0].Field)
				assert.Contains(t, details.Causes[0].Message, test.expectedError)
			} else {
				require.NoError(t, err)
			}

			assert.Empty(t, warnings)
		})
	}
}

func TestWAFPolicyCustomValidator_ValidateUpdate(t *testing.T) {
	for _, test := range wafPolicyTestCases {
		t.Run(test.name, func(t *testing.T) {
			validator := &WAFPolicyCustomValidator{
				logger: logr.Discard(),
			}

			ctx := admission.NewContextWithRequest(t.Context(), admission.Request{})
			warnings, err := validator.ValidateUpdate(ctx, &gatewayprotectorkubewardeniov1alpha1.WAFPolicy{}, test.policy)

			if test.expectedError != "" {
				require.Error(t, err)
				statusErr, ok := err.(interface{ Status() metav1.Status })
				require.True(t, ok)
				details := statusErr.Status().Details
				require.NotNil(t, details)
				require.Len(t, details.Causes, 1)
				assert.Equal(t, test.expectedField, details.Causes[0].Field)
				assert.Contains(t, details.Causes[0].Message, test.expectedError)
			} else {
				require.NoError(t, err)
			}

			assert.Empty(t, warnings)
		})
	}
}

func TestWAFPolicyCustomValidator_ValidateDelete(t *testing.T) {
	validator := &WAFPolicyCustomValidator{
		logger: logr.Discard(),
	}

	policy := &gatewayprotectorkubewardeniov1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shop-gateway-default",
			Namespace: "gateway-protector-system",
		},
	}

	ctx := admission.NewContextWithRequest(t.Context(), admission.Request{})
	warnings, err := validator.ValidateDelete(ctx, policy)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}
