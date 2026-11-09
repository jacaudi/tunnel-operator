package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	"github.com/jacaudi/tunnel-operator/internal/ipam"
	"github.com/jacaudi/tunnel-operator/internal/resources"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// A reconcile reads the Secret from the informer cache, which can lag a write the previous reconcile
// made. Replacing the Secret from that stale read must conflict, not overwrite the stored gluetun key.
func TestReplaceSecretConflictsOnAStaleRead(t *testing.T) {
	const keyName = "gluetun-api-key"
	name := types.NamespacedName{Name: "vpn", Namespace: "default"}

	tests := []struct {
		name           string
		writeAfterRead bool
		wantConflict   bool
		wantKey        string
	}{
		{name: "a read that is still current is replaced", wantKey: "K2"},
		{name: "a read another writer has since outdated is rejected and keeps the stored key", writeAfterRead: true, wantConflict: true, wantKey: "K1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithObjects(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: name.Namespace},
				Data:       map[string][]byte{"privateKey": []byte("p")},
			}).Build()

			// What the reconcile read: a Secret without the key.
			read := &corev1.Secret{}
			if err := c.Get(t.Context(), name, read); err != nil {
				t.Fatalf("get: %v", err)
			}
			if tt.writeAfterRead {
				// An earlier reconcile stores K1 after that read.
				stored := read.DeepCopy()
				stored.Data[keyName] = []byte("K1")
				if err := c.Update(t.Context(), stored); err != nil {
					t.Fatalf("store K1: %v", err)
				}
			}

			// The replacement built from the read: no ResourceVersion of its own, a fresh key.
			desired := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: name.Namespace},
				Data:       map[string][]byte{"privateKey": []byte("p"), keyName: []byte("K2")},
			}
			err := (&WireguardReconciler{Client: c}).replaceSecret(t.Context(), read, desired)

			if got := apierrors.IsConflict(err); got != tt.wantConflict {
				t.Errorf("replaceSecret error = %v, want conflict %v", err, tt.wantConflict)
			}
			stored := &corev1.Secret{}
			if err := c.Get(t.Context(), name, stored); err != nil {
				t.Fatalf("get: %v", err)
			}
			if got := string(stored.Data[keyName]); got != tt.wantKey {
				t.Errorf("stored %s = %q, want %q", keyName, got, tt.wantKey)
			}
		})
	}
}

// The Secret is read from the informer cache, which can still say NotFound after another reconcile
// created it. The create then fails AlreadyExists, which is the same stale read as a Conflict: the next
// reconcile sees the Secret, so it is a quiet requeue and not an error with its backoff.
func TestReconcileRequeuesWhenTheSecretAlreadyExists(t *testing.T) {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{v1alpha1.AddToScheme, corev1.AddToScheme, appsv1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatalf("add to the scheme: %v", err)
		}
	}
	wg := &v1alpha1.Wireguard{
		ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "default"},
		Spec:       v1alpha1.WireguardSpec{LocalCIDRs: []string{"10.96.0.0/12"}},
		Status:     v1alpha1.WireguardStatus{Status: v1alpha1.Pending},
	}
	// The fake assigns no ClusterIP, and the reconcile stops at a Service outside localCIDRs.
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "vpn-svc", Namespace: "default"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.10"},
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(wg, svc).WithStatusSubresource(wg).
		WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				return apierrors.NewAlreadyExists(corev1.Resource("secrets"), obj.GetName())
			}
			return cl.Create(ctx, obj, opts...)
		}}).Build()
	r := &WireguardReconciler{
		Client:         c,
		APIReader:      c,
		Scheme:         s,
		secretBuilder:  resources.NewSecretBuilder(s),
		serviceBuilder: resources.NewServiceBuilder(s),
		ipAllocator:    ipam.NewAllocator(),
	}

	got, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(wg)})

	if err != nil {
		t.Fatalf("Reconcile error = %v, want nil for a Secret that already exists", err)
	}
	if want := time.Second; got.RequeueAfter != want {
		t.Errorf("RequeueAfter = %v, want %v", got.RequeueAfter, want)
	}
}
