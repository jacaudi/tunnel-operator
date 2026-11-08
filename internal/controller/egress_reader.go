package controllers

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/resources"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// EgressReader reads the egress status of the gateway agent listening on podIP.
type EgressReader interface {
	Read(ctx context.Context, podIP string) (EgressReport, error)
}

// EgressReport is the body of the agent's GET /egress, whose keys the tags name: the agent's
// StatusHandler writes them, and TestHTTPEgressReaderDecodesTheAgentHandler feeds this decoder that
// handler's own output. Unknown values are zero.
type EgressReport struct {
	ExitIP                string                `json:"exitIP"`
	ForwardedPort         int32                 `json:"forwardedPort"`
	LastCycle             *v1alpha1.CycleResult `json:"lastCycle"`
	CycleInProgress       bool                  `json:"cycleInProgress"`
	LastHandledAnnotation string                `json:"lastHandledAnnotation"`
}

// HTTPEgressReader GETs http://<podIP>:8080/egress. Timeout bounds the whole request and must be positive.
type HTTPEgressReader struct {
	Timeout time.Duration

	baseURL string // tests only: stands in for http://<podIP>:8080
}

// Read returns the agent's report. A status other than 200 or a body that is not the report is an error.
func (h HTTPEgressReader) Read(ctx context.Context, podIP string) (EgressReport, error) {
	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	url := cmp.Or(h.baseURL, "http://"+net.JoinHostPort(podIP, strconv.Itoa(resources.HTTPPort))) + "/egress"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return EgressReport{}, fmt.Errorf("read egress status: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return EgressReport{}, fmt.Errorf("read egress status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return EgressReport{}, fmt.Errorf("read egress status: GET %s: status %d", url, resp.StatusCode)
	}
	var report EgressReport
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&report); err != nil {
		return EgressReport{}, fmt.Errorf("read egress status: decode %s: %w", url, err)
	}
	return report, nil
}

// gatewayPod returns the one pod of dep that is Ready and not terminating, found through r, which must
// not be the filtered Pod cache. ok is false when there are none or several, as during a rollout.
func gatewayPod(ctx context.Context, r client.Reader, dep *appsv1.Deployment) (pod *corev1.Pod, ok bool, err error) {
	sel, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil {
		return nil, false, fmt.Errorf("read the selector of Deployment %s/%s: %w", dep.Namespace, dep.Name, err)
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(dep.Namespace), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return nil, false, fmt.Errorf("list the pods of Deployment %s/%s: %w", dep.Namespace, dep.Name, err)
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if !p.DeletionTimestamp.IsZero() || !slices.ContainsFunc(p.Status.Conditions, podReady) {
			continue
		}
		if pod != nil {
			return nil, false, nil
		}
		pod = p
	}
	return pod, pod != nil, nil
}

func podReady(c corev1.PodCondition) bool {
	return c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue
}

// pollEgress reads the status of the agent of dep, the gateway's Ready Deployment. It returns nil, which
// leaves status.egress as it is, when there is no reader, when dep has not exactly one Ready pod, and when
// the read fails; a failure is logged here, not returned, because the poll is retried at the next requeue.
func (r *WireguardReconciler) pollEgress(ctx context.Context, dep *appsv1.Deployment) *EgressReport {
	if r.EgressReader == nil {
		return nil
	}
	log := ctrllog.FromContext(ctx)
	pod, ok, err := gatewayPod(ctx, r.APIReader, dep)
	if err != nil {
		log.Error(err, "Failed to find the gateway pod to poll; keeping status.egress")
		return nil
	}
	if !ok {
		return nil
	}
	report, err := r.EgressReader.Read(ctx, pod.Status.PodIP)
	if err != nil {
		log.Error(err, "Failed to read the gateway's egress status; keeping status.egress", "pod", pod.Name)
		return nil
	}
	return &report
}
