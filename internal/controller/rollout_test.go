//go:build integration

package controllers

import (
	"context"
	"reflect"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// heldPrefix marks a Deployment the fake rollout leaves alone, so a spec can drive its status by hand.
const heldPrefix = "held-"

// fakeRollout stands in for the kube-controller-manager envtest does not run: it reports every
// Deployment controlled by a Wireguard whose name does not start with heldPrefix as rolled out, with
// observedGeneration at its generation and spec.replicas updated, ready and available replicas. Other
// Deployments (apply_test.go's probes) are left alone: a status write would bump their resourceVersion
// and add a managedFields entry those specs assert on.
type fakeRollout struct{ client.Client }

func (f *fakeRollout) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	dep := &appsv1.Deployment{}
	if err := f.Get(ctx, req.NamespacedName, dep); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if owner := metav1.GetControllerOf(dep); owner == nil || owner.Kind != "Wireguard" || strings.HasPrefix(dep.Name, heldPrefix) {
		return ctrl.Result{}, nil
	}
	replicas := int32(1)
	if dep.Spec.Replicas != nil {
		replicas = *dep.Spec.Replicas
	}
	want := appsv1.DeploymentStatus{
		ObservedGeneration: dep.Generation,
		Replicas:           replicas,
		UpdatedReplicas:    replicas,
		ReadyReplicas:      replicas,
		AvailableReplicas:  replicas,
	}
	if reflect.DeepEqual(dep.Status, want) {
		return ctrl.Result{}, nil
	}
	dep.Status = want
	if err := f.Status().Update(ctx, dep); err != nil {
		// A conflict (the Deployment moved under us) falls through as the error: controller-runtime
		// requeues it with backoff, which is the retry this fake needs.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, nil
}
