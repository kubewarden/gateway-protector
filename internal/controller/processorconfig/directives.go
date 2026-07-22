// Package processorconfig renders the processor's data-plane configuration
// (see internal/processor/config) from Accepted WAFPolicy objects, the
// WAFRuleSet objects they reference, and the Gateway/HTTPRoute objects they
// attach to.
//
// This package is pure: it never touches the Kubernetes API itself. Callers
// (see internal/controller/processor_config_reconciler.go) are responsible
// for listing the input objects and publishing the result.
package processorconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// engineKeyLength is the number of hex characters (from a sha256 digest)
// used as an engine key: short enough to stay readable in logs/ConfigMap
// diffs, long enough that an accidental collision between two genuinely
// different directive blocks is not a practical concern.
const engineKeyLength = 16

// offEngineDirectives is the directive block rendered for a WAFPolicy with
// spec.engine.mode: Off. It is rendered byte-for-byte identically for every
// such policy, so - like any other engine - they all share a single
// deduplicated entry via EngineKey (see docs/processor.md's
// "public-status-page-off" example, where an explicit "off" engine is what
// lets a route opt out of a broader default via longest-prefix-wins,
// instead of the route simply having no entry at all).
const offEngineDirectives = "SecRuleEngine Off\n"

// crsSetupOverridesRuleID is the SecRule id used for the SecAction rendered
// by writeCRSSetupOverrides. gateway-protector reserves the block
// 10000000-10000099 for its own generated directives - above every
// convention range a rule author might otherwise reach for (1-99999
// site-local, 900000-999999 OWASP Core Rule Set, 9500000-9599999 CRS
// plugins) - so this can never collide with a user-authored WAFRuleSet
// rule. WAFCustomRule.ID's CEL validation (see api/v1alpha1/wafruleset_types.go)
// enforces the site-local range for user rules and must be kept in sync
// with this reserved block: CEL rules can't reference Go constants, so
// there is no compiler-enforced link between the two.
const crsSetupOverridesRuleID = 10000001

// RenderDirectives composes the Coraza/SecLang directive block for policy,
// given the WAFRuleSet objects referenced by its spec.customRulesRefs
// (already resolved by the caller; see ResolveRuleSets). The rendering
// order follows OWASP Core Rule Set conventions:
//
//  1. Include @coraza.conf-recommended (skipped entirely for mode: Off)
//  2. SecRuleEngine On|DetectionOnly|Off
//  3. request/response body access directives (from requestBody/responseBody)
//  4. a SecAction setting tx.blocking_paranoia_level/tx.*_anomaly_score_threshold,
//     BEFORE crs-setup.conf.example so it honors the override
//  5. Include @crs-setup.conf.example
//  6. Include @owasp_crs/*.conf
//  7. every referenced WAFRuleSet's custom SecRule directives, in
//     namespace/name order (see writeCustomRules) - not spec.customRulesRefs
//     order, which is not semantically meaningful (see that doc comment)
//  8. SecRuleRemoveById/SecRuleRemoveByTag for spec.exclusions, canonicalized
//     (see writeExclusions) - must come after the rules they remove are
//     loaded
//
// Both 7 and 8 are canonicalized (deterministically ordered/deduplicated)
// rather than rendered in whatever order the spec happens to list things:
// two policies that are semantically equivalent - same rulesets, same
// exclusions, listed in a different order or split differently across
// WAFExclusion entries - render byte-for-byte identical directives and so
// share one compiled engine (see EngineKey), instead of needlessly
// compiling and shipping duplicate engines that only differ in
// non-meaningful ways.
//
// A mode: Off policy skips all of the above and renders only
// "SecRuleEngine Off", since there is nothing else to configure - see
// offEngineDirectives.
func RenderDirectives(policy *gwpv1alpha1.WAFPolicy, ruleSets []*gwpv1alpha1.WAFRuleSet) string {
	if policy.Spec.Engine.Mode == gwpv1alpha1.WAFEngineModeOff {
		return offEngineDirectives
	}

	var b strings.Builder

	b.WriteString("Include @coraza.conf-recommended\n")
	writeEngineMode(&b, policy.Spec.Engine.Mode)
	writeBodyAccess(&b, "SecRequestBodyAccess", "SecRequestBodyLimit", "SecRequestBodyInMemoryLimit", policy.Spec.RequestBody)
	writeBodyAccess(&b, "SecResponseBodyAccess", "SecResponseBodyLimit", "SecResponseBodyInMemoryLimit", policy.Spec.ResponseBody)
	writeCRSSetupOverrides(&b, policy.Spec.ParanoiaLevel, policy.Spec.AnomalyThreshold)

	b.WriteString("Include @crs-setup.conf.example\n")
	b.WriteString("Include @owasp_crs/*.conf\n")

	writeCustomRules(&b, ruleSets)
	writeExclusions(&b, policy.Spec.Exclusions)

	return b.String()
}

func writeEngineMode(b *strings.Builder, mode gwpv1alpha1.WAFEngineMode) {
	switch mode {
	case gwpv1alpha1.WAFEngineModeBlocking:
		b.WriteString("SecRuleEngine On\n")
	case gwpv1alpha1.WAFEngineModeDetection:
		b.WriteString("SecRuleEngine DetectionOnly\n")
	case gwpv1alpha1.WAFEngineModeOff:
		// Handled by RenderDirectives before writeEngineMode is ever
		// called; kept here only so the switch is exhaustive.
	}
}

// writeBodyAccess renders the SecLang directives for one
// WAFBodyInspectionSpec (requestBody or responseBody), using the given
// directive names for that phase. A nil spec means "let the Core Rule
// Set's own recommended defaults apply" and renders nothing.
func writeBodyAccess(b *strings.Builder, accessDirective, limitDirective, inMemoryLimitDirective string, spec *gwpv1alpha1.WAFBodyInspectionSpec) {
	if spec == nil {
		return
	}

	if !spec.Enabled {
		fmt.Fprintf(b, "%s Off\n", accessDirective)
		return
	}

	b.WriteString(accessDirective + " On\n")

	if spec.MaxSize != nil {
		limit := spec.MaxSize.Value()
		fmt.Fprintf(b, "%s %d\n", limitDirective, limit)
		fmt.Fprintf(b, "%s %d\n", inMemoryLimitDirective, limit)
	}
}

// writeCRSSetupOverrides renders the tx.blocking_paranoia_level and
// tx.*_anomaly_score_threshold overrides as a single SecAction, executed
// before @crs-setup.conf.example is included so the setup rules see - and
// keep - these values instead of falling back to their own defaults. Zero
// values mean "unset" (paranoiaLevel is validated Minimum=1 so 0 can only
// mean absent; anomalyThreshold's Inbound/Outbound are +optional int32
// with no minimum, so a genuine 0 threshold cannot be distinguished from
// unset - documented as a known limitation) and are omitted, letting the
// Core Rule Set's own defaults apply.
func writeCRSSetupOverrides(b *strings.Builder, paranoiaLevel int32, anomalyThreshold *gwpv1alpha1.WAFAnomalyThreshold) {
	var setVars []string

	if paranoiaLevel != 0 {
		setVars = append(setVars, fmt.Sprintf("setvar:tx.blocking_paranoia_level=%d", paranoiaLevel))
	}

	if anomalyThreshold != nil {
		if anomalyThreshold.Inbound != 0 {
			setVars = append(setVars, fmt.Sprintf("setvar:tx.inbound_anomaly_score_threshold=%d", anomalyThreshold.Inbound))
		}
		if anomalyThreshold.Outbound != 0 {
			setVars = append(setVars, fmt.Sprintf("setvar:tx.outbound_anomaly_score_threshold=%d", anomalyThreshold.Outbound))
		}
	}

	if len(setVars) == 0 {
		return
	}

	fmt.Fprintf(b, "SecAction \"id:%d,phase:1,pass,nolog,%s\"\n", crsSetupOverridesRuleID, strings.Join(setVars, ","))
}

// writeCustomRules appends every WAFRuleSet's raw SecRule directives,
// sorted by namespace/name rather than in spec.customRulesRefs order.
//
// spec.customRulesRefs is a listType=map (keyed by name): Kubernetes list
// semantics for such a list don't guarantee any particular order survives
// a server-side-apply merge, so treating "the order the refs were written
// in" as meaningful would be relying on behavior the API doesn't actually
// promise. Rendering in a canonical (namespace/name) order instead makes
// the output a pure function of *which* rulesets are referenced, not of
// how the list happened to be ordered when last written - which also means
// two policies referencing the same rulesets in a different order render
// identically and share one compiled engine (see RenderDirectives).
//
// Rules *within* a single WAFRuleSet are rendered in spec.rules order,
// which - unlike customRulesRefs - is an ordinary (atomic) list and so is
// preserved: any SecLang rules that depend on relative order (e.g. a
// skipAfter/ctl chain) must live together in one WAFRuleSet.
func writeCustomRules(b *strings.Builder, ruleSets []*gwpv1alpha1.WAFRuleSet) {
	sorted := slices.Clone(ruleSets)
	slices.SortFunc(sorted, func(a, bb *gwpv1alpha1.WAFRuleSet) int {
		if c := strings.Compare(a.Namespace, bb.Namespace); c != 0 {
			return c
		}

		return strings.Compare(a.Name, bb.Name)
	})

	for _, ruleSet := range sorted {
		for _, rule := range ruleSet.Spec.Rules {
			b.WriteString(rule.Directive)
			if !strings.HasSuffix(rule.Directive, "\n") {
				b.WriteString("\n")
			}
		}
	}
}

// writeExclusions renders SecRuleRemoveById/SecRuleRemoveByTag covering
// every spec.exclusions entry. These must come after the rules they remove
// are loaded (i.e. after the Core Rule Set include and any custom rules),
// which is why RenderDirectives calls this last.
//
// The ids across every WAFExclusion entry are pooled, deduplicated, and
// sorted numerically into a single SecRuleRemoveById line; tags are pooled,
// deduplicated, and sorted lexically into one SecRuleRemoveByTag line per
// tag. spec.exclusions has no ordering semantics of its own (removals are
// commutative - excluding rule A then B has the same effect as B then A),
// so canonicalizing means the same effective set of exclusions - however
// split across entries or ordered - always renders identically (see
// RenderDirectives).
func writeExclusions(b *strings.Builder, exclusions []gwpv1alpha1.WAFExclusion) {
	var ids []int32

	tagSet := make(map[string]struct{})

	for _, exclusion := range exclusions {
		ids = append(ids, exclusion.ByID...)

		for _, tag := range exclusion.ByTag {
			tagSet[tag] = struct{}{}
		}
	}

	if len(ids) > 0 {
		ids = slices.Compact(slices.Sorted(slices.Values(ids)))

		idStrings := make([]string, len(ids))
		for i, id := range ids {
			idStrings[i] = strconv.Itoa(int(id))
		}

		fmt.Fprintf(b, "SecRuleRemoveById %s\n", strings.Join(idStrings, " "))
	}

	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}

	slices.Sort(tags)

	for _, tag := range tags {
		fmt.Fprintf(b, "SecRuleRemoveByTag \"%s\"\n", tag)
	}
}

// EngineKey returns the deduplication key for a rendered directive block:
// identical directives (e.g. from two policies with byte-for-byte
// equivalent configuration) always produce the same key, so the processor
// compiles and holds a single engine for both (see
// internal/processor/config.Config.Directives).
func EngineKey(directives string) string {
	sum := sha256.Sum256([]byte(directives))

	return hex.EncodeToString(sum[:])[:engineKeyLength]
}
