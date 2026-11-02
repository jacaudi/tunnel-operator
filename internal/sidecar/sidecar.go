package sidecar

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/jacaudi/wireguard-operator/api/v1alpha1"
	"github.com/jacaudi/wireguard-operator/internal/resources"
)

// datapath applies a Tunnel to the pod's network namespace.
type datapath interface {
	Apply(key wgtypes.Key, t Tunnel) error
}

// runner holds what one pass needs: the reader (the watch cache in Run), the writer (the API), the
// datapath, the configuration and the pod's private key.
type runner struct {
	r   ctrlclient.Reader
	w   ctrlclient.Writer
	dp  datapath
	cfg Config
	key wgtypes.Key
}

// step makes one pass: it registers the pod's WireguardPeer, reads the Wireguard and, once the operator
// has published everything the tunnel needs, applies it. While the operator is not done it returns an
// error wrapping errWaiting.
func (r *runner) step(ctx context.Context) error {
	peer, err := ensurePeer(ctx, r.r, r.w, r.cfg, r.key.PublicKey().String())
	if err != nil {
		return err
	}
	if peer == nil {
		return fmt.Errorf("%w: WireguardPeer %s/%s registered", errWaiting, r.cfg.PodNamespace, r.cfg.PodName)
	}

	wg := &v1alpha1.Wireguard{}
	if err := r.r.Get(ctx, types.NamespacedName{Namespace: r.cfg.PodNamespace, Name: r.cfg.Wireguard}, wg); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%w: Wireguard %s/%s not found", errWaiting, r.cfg.PodNamespace, r.cfg.Wireguard)
		}
		return fmt.Errorf("get Wireguard %s/%s: %w", r.cfg.PodNamespace, r.cfg.Wireguard, err)
	}

	t, err := desiredTunnel(peer, wg)
	if err != nil {
		return err
	}
	return r.dp.Apply(r.key, t)
}

// Run registers the pod and keeps its tunnel configured until ctx is done: after every change to the
// pod's WireguardPeer or the Wireguard, and every resources.ReassertInterval. It returns nil when ctx
// is done, and an error when the key, the API config, the client or the cache cannot be created.
// Without list and watch access (no RoleBinding) the watch never syncs: Run then waits, logging
// nothing of its own, until ctx is done, and the pod's startup probe fails.
func Run(ctx context.Context, cfg Config, logger logr.Logger) error {
	ctrllog.SetLogger(logger)

	key, err := LoadOrCreateKey(cfg.KeyPath)
	if err != nil {
		return fmt.Errorf("load the private key: %w", err)
	}
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster API config: %w", err)
	}
	s := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(s); err != nil {
		return fmt.Errorf("add v1alpha1 to the scheme: %w", err)
	}
	writeClient, err := ctrlclient.New(restCfg, ctrlclient.Options{Scheme: s})
	if err != nil {
		return fmt.Errorf("create the API client: %w", err)
	}

	kick := make(chan struct{}, 1)
	c, err := startWatch(ctx, restCfg, s, cfg, kick, logger)
	if err != nil {
		return fmt.Errorf("start the watch cache: %w", err)
	}
	if c == nil {
		return nil
	}

	loop(ctx, &runner{r: c, w: writeClient, dp: podDatapath{}, cfg: cfg, key: key}, kick, logger)
	return nil
}

// startWatch starts a cache that watches only the pod's WireguardPeer and the Wireguard cfg names, in
// the pod's namespace, and makes a non-blocking send on kick on every add, update and delete of
// either. It returns the cache once it has synced, and (nil, nil) when ctx is done before then.
func startWatch(ctx context.Context, restCfg *rest.Config, s *runtime.Scheme, cfg Config, kick chan<- struct{}, logger logr.Logger) (cache.Cache, error) {
	c, err := cache.New(restCfg, cache.Options{
		Scheme:            s,
		DefaultNamespaces: map[string]cache.Config{cfg.PodNamespace: {}},
		ByObject: map[ctrlclient.Object]cache.ByObject{
			&v1alpha1.WireguardPeer{}: {Field: fields.OneTermEqualSelector("metadata.name", cfg.PodName)},
			&v1alpha1.Wireguard{}:     {Field: fields.OneTermEqualSelector("metadata.name", cfg.Wireguard)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create the cache: %w", err)
	}

	notify := func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	handler := toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { notify() },
		UpdateFunc: func(_, _ any) { notify() },
		DeleteFunc: func(any) { notify() },
	}
	for _, obj := range []ctrlclient.Object{&v1alpha1.WireguardPeer{}, &v1alpha1.Wireguard{}} {
		inf, err := c.GetInformer(ctx, obj)
		if err != nil {
			return nil, fmt.Errorf("get the %T informer: %w", obj, err)
		}
		if _, err := inf.AddEventHandler(handler); err != nil {
			return nil, fmt.Errorf("watch %T: %w", obj, err)
		}
	}

	// c.Start returns when ctx is done, which is this goroutine's shutdown path.
	go func() {
		if err := c.Start(ctx); err != nil {
			logger.Error(err, "watch cache stopped")
		}
	}()
	if !c.WaitForCacheSync(ctx) {
		if ctx.Err() != nil {
			return nil, nil
		}
		return nil, errors.New("the watch on the WireguardPeer and the Wireguard did not sync")
	}
	return c, nil
}

// loop runs rn.step at once, then after every kick and every resources.ReassertInterval, until ctx
// is done, logging each pass's outcome. It returns before the first pass when ctx is already done.
func loop(ctx context.Context, rn *runner, kick <-chan struct{}, logger logr.Logger) {
	ticker := time.NewTicker(resources.ReassertInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		switch err := rn.step(ctx); {
		case err == nil:
			logger.V(1).Info("tunnel applied")
		case errors.Is(err, errWaiting):
			logger.Info(err.Error())
		default:
			logger.Error(err, "client pass failed")
		}
		select {
		case <-ctx.Done():
		case <-kick:
		case <-ticker.C:
		}
	}
}
