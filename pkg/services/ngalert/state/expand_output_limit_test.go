package state

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/state/template"
)

// expansionAllocBudget is the heap one label or annotation expansion may use.
// It leaves room for a writer capped at DefaultMaxLabelValueSize and stays well
// below the full output of the doubling template these tests execute.
const expansionAllocBudget = 32 << 20

// doublingTemplate builds nested define blocks where each block emits the previous
// block twice. fullLen is the number of bytes a complete expansion writes.
func doublingTemplate(base string, doublings int) (tmpl string, fullLen int) {
	var b strings.Builder
	b.WriteString(`{{define "d0"}}`)
	b.WriteString(base)
	b.WriteString(`{{end}}`)
	for i := 1; i <= doublings; i++ {
		b.WriteString(`{{define "d`)
		b.WriteString(itoa(i))
		b.WriteString(`"}}{{template "d`)
		b.WriteString(itoa(i - 1))
		b.WriteString(`"}}{{template "d`)
		b.WriteString(itoa(i - 1))
		b.WriteString(`"}}{{end}}`)
	}
	b.WriteString(`{{template "d`)
	b.WriteString(itoa(doublings))
	b.WriteString(`"}}`)
	return b.String(), len(base) << doublings
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [8]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}

func heapAllocDuring(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestExpand_DoublingTemplateDoesNotMaterializeFullOutput(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	data := template.Data{}

	t.Run("output under the cap is expanded", func(t *testing.T) {
		base := strings.Repeat("ab", 16) // 32 bytes, no template metacharacters
		tmpl, fullLen := doublingTemplate(base, 2)
		require.Equal(t, len(base)*4, fullLen)
		require.Less(t, fullLen, DefaultMaxLabelValueSize)

		got, err := template.Expand(ctx, "summary", tmpl, data, nil, now)
		require.NoError(t, err)
		require.Equal(t, strings.Repeat(base, 4), got)
	})

	t.Run("output over the cap stops during generation", func(t *testing.T) {
		// 1 KiB doubled 16 times is 64 MiB. That is above both the 4 MiB label cap
		// and expansionAllocBudget, so a clamp applied only after Expand returns
		// still fails this test.
		base := strings.Repeat("A", 1024)
		tmpl, fullLen := doublingTemplate(base, 16)
		require.Greater(t, fullLen, DefaultMaxLabelValueSize)
		require.Greater(t, fullLen, expansionAllocBudget)
		require.Less(t, len(tmpl), 8<<10)

		var got string
		var err error
		alloc := heapAllocDuring(func() {
			got, err = template.Expand(ctx, "summary", tmpl, data, nil, now)
		})
		t.Logf("expand alloc=%d resultLen=%d err=%v", alloc, len(got), err)
		require.LessOrEqualf(t, alloc, uint64(expansionAllocBudget),
			"template expansion allocated %d bytes; full output is %d bytes and must be cut off while it is written", alloc, fullLen)
		require.LessOrEqual(t, len(got), DefaultMaxLabelValueSize)
	})
}

func TestProcessEvalResults_DoublingTemplateDoesNotMaterializeFullOutput(t *testing.T) {
	// schedule/alert_rule.go and backtesting/engine.go both pass the stored rule to
	// ProcessEvalResults. That method is what expands labels and annotations.
	base := strings.Repeat("B", 1024)
	tmpl, fullLen := doublingTemplate(base, 16)
	require.Greater(t, fullLen, DefaultMaxLabelValueSize)
	require.Greater(t, fullLen, expansionAllocBudget)

	cases := []struct {
		name        string
		labels      data.Labels
		annotations data.Labels
	}{
		{
			name:        "annotation",
			labels:      data.Labels{"plain": "ok"},
			annotations: data.Labels{"summary": tmpl},
		},
		{
			name:        "label",
			labels:      data.Labels{"note": tmpl},
			annotations: data.Labels{"summary": "ok"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := &models.AlertRule{
				OrgID:           1,
				UID:             "rule-uid",
				Title:           "doubling",
				NamespaceUID:    "folder-uid",
				RuleGroup:       "group",
				Condition:       "A",
				IntervalSeconds: 60,
				NoDataState:     models.NoData,
				ExecErrState:    models.ErrorErrState,
				Labels:          tc.labels,
				Annotations:     tc.annotations,
				For:             0,
			}
			mgr := NewManager(ManagerCfg{
				ExternalURL: nil,
				Images:      &NoopImageService{},
				Clock:       clock.New(),
				Tracer:      tracing.InitializeTracerForTest(),
				Log:         log.New("ngalert.state.manager"),
			}, NewNoopPersister())

			var transitions StateTransitions
			var err error
			alloc := heapAllocDuring(func() {
				transitions, err = mgr.ProcessEvalResults(context.Background(), time.Now(), rule, eval.Results{{
					Instance:    data.Labels{"instance": "1"},
					State:       eval.Normal,
					EvaluatedAt: time.Now(),
				}}, nil, nil)
			})
			require.NoError(t, err)
			require.NotEmpty(t, transitions)
			t.Logf("process alloc=%d", alloc)
			require.LessOrEqualf(t, alloc, uint64(expansionAllocBudget),
				"evaluation allocated %d bytes expanding a template whose full output is %d bytes", alloc, fullLen)
			for _, tr := range transitions {
				for key, val := range tr.Labels {
					require.LessOrEqualf(t, len(val), DefaultMaxLabelValueSize, "label %s", key)
				}
				for key, val := range tr.Annotations {
					require.LessOrEqualf(t, len(val), DefaultMaxLabelValueSize, "annotation %s", key)
				}
			}
		})
	}
}
