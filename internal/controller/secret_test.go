package controllers

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
