package template

import (
	"encoding/json"
	"errors"
	"fmt"
	html_template "html/template"
	"math"
	"net"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"text/template"
	"time"

	common_templates "github.com/prometheus/common/helpers/templates"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/timestamp"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type query struct {
	Datasource string `json:"datasource"`
	Expr       string `json:"expr"`
}

const (
	FilterLabelFuncName      = "filterLabels"
	FilterLabelReFuncName    = "filterLabelsRe"
	GraphLinkFuncName        = "graphLink"
	RemoveLabelsFuncName     = "removeLabels"
	RemoveLabelsReFuncName   = "removeLabelsRe"
	TableLinkFuncName        = "tableLink"
	MergeLabelValuesFuncName = "mergeLabelValues"
)

// graphLinkGrowth is more than the bytes graphLinkFunc and tableLinkFunc write for each byte of
// their argument: the datasource is escaped and quoted twice, and the expression once.
const graphLinkGrowth = 16

// A version of vector that's easier to use from templates.
type sample struct {
	Labels map[string]string
	Value  any
}

type queryResult []*sample

// newFuncMap returns the functions available to a template. They are the functions of the
// Prometheus template expander and Grafana's own, plus overrides of the text/template builtins
// that build strings. Functions that can return more than their arguments charge b.
func newFuncMap(b *budget, evaluatedAt time.Time, externalURL *url.URL) template.FuncMap {
	return template.FuncMap{
		"print":    b.formatFunc(1, fmt.Sprint),
		"println":  b.formatFunc(1, fmt.Sprintln),
		"printf":   b.printf,
		"html":     b.formatFunc(6, template.HTMLEscaper),
		"js":       b.formatFunc(6, template.JSEscaper),
		"urlquery": b.formatFunc(3, template.URLQueryEscaper),

		// query is a no-op as it is not supported in Grafana.
		"query": func(string) (queryResult, error) {
			return queryResult{}, nil
		},
		"first": func(v queryResult) (*sample, error) {
			if len(v) > 0 {
				return v[0], nil
			}
			return nil, errors.New("first() called on vector with no elements")
		},
		"label": func(label string, s *sample) string {
			return s.Labels[label]
		},
		"value": func(s *sample) any {
			return s.Value
		},
		"strvalue": func(s *sample) string {
			return s.Labels["__value__"]
		},
		"args":         b.args,
		"reReplaceAll": b.reReplaceAll,
		"safeHtml": func(text string) html_template.HTML {
			//nolint:gosec // marking text as safe HTML is what safeHtml is for
			return html_template.HTML(text)
		},
		"match": regexp.MatchString,
		"title": b.stringFunc(3, func(s string) string {
			return cases.Title(language.AmericanEnglish, cases.NoLower).String(s)
		}),
		"toUpper": b.stringFunc(3, strings.ToUpper),
		"toLower": b.stringFunc(3, strings.ToLower),
		"sortByLabel": func(label string, v queryResult) queryResult {
			sort.SliceStable(v, func(i, j int) bool {
				return v[i].Labels[label] < v[j].Labels[label]
			})
			return v
		},
		"stripPort":          b.stringFunc(1, stripPort),
		"stripDomain":        b.stringFunc(1, stripDomain),
		"humanize":           humanize,
		"humanize1024":       humanize1024,
		"humanizeDuration":   common_templates.HumanizeDuration,
		"humanizePercentage": humanizePercentage,
		"humanizeTimestamp":  common_templates.HumanizeTimestamp,
		"toTime": func(i any) (*boundedTime, error) {
			v, err := common_templates.ConvertToFloat(i)
			if err != nil {
				return nil, err
			}
			t, err := common_templates.FloatToTime(v)
			if err != nil {
				return nil, err
			}
			return &boundedTime{Time: *t, b: b}, nil
		},
		"toDuration": func(i any) (*time.Duration, error) {
			v, err := common_templates.ConvertToFloat(i)
			if err != nil {
				return nil, err
			}
			d := time.Duration(v * float64(time.Second))
			return &d, nil
		},
		"now": func() float64 {
			return float64(timestamp.FromTime(evaluatedAt)) / 1000.0
		},
		"pathPrefix": func() string {
			return externalURL.Path
		},
		"externalURL": func() string {
			return externalURL.String()
		},
		"parseDuration": func(d string) (float64, error) {
			v, err := model.ParseDurationAllowNegative(d)
			if err != nil {
				return 0, err
			}
			return float64(time.Duration(v)) / float64(time.Second), nil
		},
		"urlQueryEscape": b.stringFunc(3, url.QueryEscape),

		FilterLabelFuncName: func(m Labels, match string) (Labels, error) {
			return charge(b, filterLabelsFunc(m, match))
		},
		FilterLabelReFuncName: func(m Labels, pattern string) (Labels, error) {
			return charge(b, filterLabelsReFunc(m, pattern))
		},
		GraphLinkFuncName: b.stringFunc(graphLinkGrowth, graphLinkFunc),
		RemoveLabelsFuncName: func(m Labels, match string) (Labels, error) {
			return charge(b, removeLabelsFunc(m, match))
		},
		RemoveLabelsReFuncName: func(m Labels, pattern string) (Labels, error) {
			return charge(b, removeLabelsReFunc(m, pattern))
		},
		TableLinkFuncName: b.stringFunc(graphLinkGrowth, tableLinkFunc),
		MergeLabelValuesFuncName: func(values map[string]Value) (Labels, error) {
			return charge(b, mergeLabelValuesFunc(values))
		},
	}
}

func stripPort(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

func stripDomain(hostPort string) string {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return hostPort
	}
	host = strings.Split(host, ".")[0]
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	return host
}

func humanize(i any) (string, error) {
	v, err := common_templates.ConvertToFloat(i)
	if err != nil {
		return "", err
	}
	if v == 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Sprintf("%.4g", v), nil
	}
	if math.Abs(v) >= 1 {
		prefix := ""
		for _, p := range []string{"k", "M", "G", "T", "P", "E", "Z", "Y"} {
			if math.Abs(v) < 1000 {
				break
			}
			prefix = p
			v /= 1000
		}
		return fmt.Sprintf("%.4g%s", v, prefix), nil
	}
	prefix := ""
	for _, p := range []string{"m", "u", "n", "p", "f", "a", "z", "y"} {
		if math.Abs(v) >= 1 {
			break
		}
		prefix = p
		v *= 1000
	}
	return fmt.Sprintf("%.4g%s", v, prefix), nil
}

func humanize1024(i any) (string, error) {
	v, err := common_templates.ConvertToFloat(i)
	if err != nil {
		return "", err
	}
	if math.Abs(v) <= 1 || math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Sprintf("%.4g", v), nil
	}
	prefix := ""
	for _, p := range []string{"ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi"} {
		if math.Abs(v) < 1024 {
			break
		}
		prefix = p
		v /= 1024
	}
	return fmt.Sprintf("%.4g%s", v, prefix), nil
}

func humanizePercentage(i any) (string, error) {
	v, err := common_templates.ConvertToFloat(i)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%.4g%%", v*100), nil
}

// filterLabelsFunc removes all labels that do not match the string.
func filterLabelsFunc(m Labels, match string) Labels {
	res := make(Labels)
	for k, v := range m {
		if k == match {
			res[k] = v
		}
	}
	return res
}

// filterLabelsReFunc removes all labels that do not match the regex.
func filterLabelsReFunc(m Labels, pattern string) Labels {
	re := regexp.MustCompile(pattern)
	res := make(Labels)
	for k, v := range m {
		if re.MatchString(k) {
			res[k] = v
		}
	}
	return res
}

func graphLinkFunc(data string) string {
	var q query
	if err := json.Unmarshal([]byte(data), &q); err != nil {
		return ""
	}
	datasource := url.QueryEscape(q.Datasource)
	expr := url.QueryEscape(q.Expr)
	return fmt.Sprintf(`/explore?left={"datasource":%[1]q,"queries":[{"datasource":%[1]q,"expr":%q,"instant":false,"range":true,"refId":"A"}],"range":{"from":"now-1h","to":"now"}}`, datasource, expr)
}

// removeLabelsFunc removes all labels that match the string.
func removeLabelsFunc(m Labels, match string) Labels {
	res := make(Labels)
	for k, v := range m {
		if k != match {
			res[k] = v
		}
	}
	return res
}

// removeLabelsReFunc removes all labels that match the regex.
func removeLabelsReFunc(m Labels, pattern string) Labels {
	re := regexp.MustCompile(pattern)
	res := make(Labels)
	for k, v := range m {
		if !re.MatchString(k) {
			res[k] = v
		}
	}
	return res
}

func tableLinkFunc(data string) string {
	var q query
	if err := json.Unmarshal([]byte(data), &q); err != nil {
		return ""
	}
	datasource := url.QueryEscape(q.Datasource)
	expr := url.QueryEscape(q.Expr)
	return fmt.Sprintf(`/explore?left={"datasource":%[1]q,"queries":[{"datasource":%[1]q,"expr":%q,"instant":true,"range":false,"refId":"A"}],"range":{"from":"now-1h","to":"now"}}`, datasource, expr)
}

// mergeLabelValuesFunc returns a map of label keys to deduplicated and comma separated values.
func mergeLabelValuesFunc(values map[string]Value) Labels {
	type uniqueLabelVals map[string]struct{}

	labels := make(map[string]uniqueLabelVals)
	for _, value := range values {
		for k, v := range value.Labels {
			var ul uniqueLabelVals
			var ok bool
			if ul, ok = labels[k]; !ok {
				ul = uniqueLabelVals{}
				labels[k] = ul
			}
			ul[v] = struct{}{}
		}
	}

	res := make(Labels)
	for label, vals := range labels {
		keys := make([]string, 0, len(vals))
		for val := range vals {
			keys = append(keys, val)
		}
		slices.Sort(keys)
		res[label] = strings.Join(keys, ", ")
	}
	return res
}
