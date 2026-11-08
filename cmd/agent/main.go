package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
	"github.com/jacaudi/tunnel-operator/internal/agent"
	"github.com/jacaudi/tunnel-operator/internal/agent/egress"
	"github.com/jacaudi/tunnel-operator/internal/datapath"
	"github.com/jacaudi/tunnel-operator/internal/ipam"
	"github.com/jacaudi/tunnel-operator/internal/resources"
	"github.com/jacaudi/tunnel-operator/internal/sidecar"
	"github.com/jacaudi/tunnel-operator/internal/wireguard"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "client" {
		os.Exit(runClient(os.Args[2:]))
	}

	var configFilePath string
	var iface string
	var verbosity int
	var wgUserspaceImplementationFallback string
	var wireguardListenPort int
	flag.StringVar(&configFilePath, "state", "./state.json", "The location of the file that states the desired state")
	flag.StringVar(&iface, "wg-iface", resources.WgInterface, "the wg device name. Default is wg0")
	flag.StringVar(&wgUserspaceImplementationFallback, "wg-userspace-implementation-fallback", resources.UserspaceImplementation, "The userspace implementation of wireguard to fallback to")
	flag.IntVar(&wireguardListenPort, "wg-listen-port", 51820, "the UDP port wireguard is listening on")
	flag.IntVar(&verbosity, "v", 1, "the verbosity level")
	flag.Parse()

	println(fmt.Sprintf(
		`	
               .:::::::::::::::::::::::::...::::::::::::::::::::.               
             .::::::::::::::::::::.:^7J5PBGY!^::::::::::::::::::::.             
            :::::::::::::::::::::~?J??5&@@@@@&G!~~~::::::::::::::::.      WG Agent Configuration      
           ::::::::::::::::::::::^7&@@@@@@@@@@@@&&&G^:::::::::::::::.     ------------------------------------------       
          .::::::::::::::::::::::!J#@@@@@@@BBBGPPG7:::::::::::::::::.     wg-iface: %s      
          .:::::::::::::::::::::^?Y5#@@@@@@5^...:::::::::::::::::::::     state: %s      
          .::::::::::::::::::::::..:!7Y#@@@@@#Y~:.::::::::::::::::::.     wg-listen-port: %d      
          .:::::::::::::::::::.:^!?JYYJ?JG&@@@@@#7::::::::::::::::::.
          .:::::::::::::::::.^J#@@@@@@@@@&#B&@@@@@G:::::::::::::::::.     wg-userspace-implementation-fallback: %s           
          .:::::::::::::::::J@@@@@@@@@@@@@@@&G@@@@@J.:::::::::::::::.           
          .::::::::::::::::5@@@@@#?~~~7P@@@@@&B@@@@P.:::::::::::::::.           
          .:::::::::::::::^@@@@@P..::::.~@@@@B&@@@@!::::::::::::::::.           
          .:::::::::::::::~@@@@@J.::::::^@@@#&@@@@P:::::::::::::::::.           
          .::::::::::::::::B@@@@@P!^:.:~G&&&@@@@@5::::::::::::::::::.           
          .:::::::::::::::::G@@@@@&#BB&@@@@@@@@B~.::::::::::::::::::.           
          .::::::::::::::::..~G&&&@@@@@@@@@&&&&&P^.:::::::::::::::::.           
          .::::::::::::::.:~YGGY&@@@@@&GY7JB@@@@@@7:::::::::::::::::.           
          .::::::::::::::?&@@@B&@@@@#!:..:::~B@@@@@~::::::::::::::::.           
          .:::::::::::::J&#P5?5@@@@@:.::::::::&@@@@5.:::::::::::::::.           
          .:::::::::::::^:....J@@@@@~.::::::.^@@@@@5.::::::::::::::::           
          .::::::::::::::::::::&@@@@@Y~::::^J&@@@@&^::::::::::::::::.           
           ::::::::::::::::::::^B@@@@@@&##&@@@@@@#~:::::::::::::::::.           
            :::::::::::::::::::::7B@@@@@@@@@@@@#?::::::::::::::::::.            
             .::::::::::::::::::::.^7YGB##BGY7^:.:::::::::::::::::.             
               .:::::::::::::::::::::..::::..::::::::::::::::::..               
                  .....:...............................:.....                   

	/  \    /  \/  _____/       /  _  \   / ___\  ____   _____/  |_  
	\   \/\/   /   \  ___      /  /_\  \ / /_/  _/ __ \ /    \   __\ 
	 \        /\    \_\  \    /    |    \\___  /\  ___/|   |  |  |   
	  \__/\  /  \______  /    \____|__  /_____/  \___  |___|  |__|   
		   \/          \/             \/             \/     \/
`, iface, configFilePath, wireguardListenPort, wgUserspaceImplementationFallback))

	stdr.SetVerbosity(verbosity)
	log := stdr.NewWithOptions(log.New(os.Stderr, "", log.LstdFlags), stdr.Options{LogCaller: stdr.All})
	log = log.WithName("agent")
	// The egress engine logs through slog's default logger.
	slog.SetDefault(slog.New(logr.ToSlogHandler(log)))

	wg := wireguard.Wireguard{
		Logger:                            log.WithName("wireguard"),
		Iface:                             iface,
		ListenPort:                        wireguardListenPort,
		WgUserspaceImplementationFallback: wgUserspaceImplementationFallback,
	}

	// Bind the health port before the first pass: that pass applies state and can take a while, and
	// the kubelet's TCP liveness probe on this port kills the agent when nothing accepts. The
	// kernel queues connections until Serve runs below.
	healthLn, err := net.Listen("tcp", ":8080") //nolint:gosec // G102: the kubelet and the operator reach this by pod IP
	if err != nil {
		log.Error(err, "Error while binding the health port")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	dp := datapath.New()

	// An empty key is not fatal: the API still serves, and every cycle fails as GluetunError.
	gluetunAPIKey := os.Getenv("GLUETUN_API_KEY")
	if gluetunAPIKey == "" {
		log.Info("GLUETUN_API_KEY is empty: every VPN cycle will fail as GluetunError")
	}
	engine := &egress.Engine{
		// No client-wide timeout: every call carries its own context, bounded by the engine.
		G:        &egress.Gluetun{BaseURL: "http://" + resources.GluetunControlAddress, APIKey: gluetunAPIKey, HTTP: &http.Client{}},
		Deadline: resources.CycleDeadline,
		Cooldown: resources.CycleCooldown,
	}
	httpLog := log.WithName("http")
	peerState := func() agent.State {
		state, _, err := agent.GetDesiredState(configFilePath)
		if err != nil {
			httpLog.Error(err, "egress API cannot read the server state; refusing every caller")
		}
		return state
	}
	peers := &egress.PeerListener{Handler: egress.PeerAPIHandler(engine, peerState), Port: resources.EgressAPIPort}

	// assertLocal re-asserts what the agent owns on this pod: the datapath, the egress rules and
	// the egress API listener. It never calls gluetun, so applying a state and the 10 s reassert
	// never wait on it. Failures are logged and retried on the next pass; the datapath ones also
	// hold /health NotReady through dp.Err.
	assertLocal := func(state agent.State) {
		if err := dp.Ensure(ctx, agent.PeerCIDR(state)); err != nil {
			log.Error(err, "Error while asserting the datapath")
		}

		var tunnelAddr netip.Addr
		prefix, err := netip.ParsePrefix(agent.PeerCIDR(state))
		if err == nil {
			tunnelAddr, err = ipam.ServerAddress(prefix)
		}
		if err != nil {
			log.Error(err, "Error while deriving the server tunnel address")
		}
		// A bad holder means no forwarding rules, which fails closed.
		holder, err := netip.ParseAddr(state.Egress.ForwardedPortPeer)
		if err != nil && state.Egress.ForwardedPortPeer != "" {
			log.Error(err, "Ignoring an invalid forwarded port holder", "holder", state.Egress.ForwardedPortPeer)
		}
		rules := datapath.EgressRules{TunnelAddr: tunnelAddr, Holder: holder, Port: engine.Snapshot().ForwardedPort}
		if err := dp.EnsureEgress(ctx, rules); err != nil {
			log.Error(err, "Error while asserting the egress rules")
		}

		// The listener binds only the tunnel address, which exists once wg.Sync has assigned it to
		// wg0; until then the bind fails and the next pass retries.
		if tunnelAddr.IsValid() {
			if err := peers.Ensure(tunnelAddr); err != nil {
				log.Error(err, "Error while binding the egress API")
			}
		}
	}
	// syncGluetun refreshes the engine's cache, restarts a stopped gluetun and starts a cycle the
	// annotation asks for. It waits on gluetun, so it runs on its own loop below.
	syncGluetun := func(state agent.State) {
		engine.Refresh(ctx, state.Egress.StaticPort)
		engine.SelfHeal(ctx)
		engine.HandleAnnotation(state.Egress.CycleRequestedAt, state.Egress.LastHandledAnnotation)
	}
	// reading runs f on the state file's current content.
	reading := func(f func(agent.State)) func() {
		return func() {
			state, _, err := agent.GetDesiredState(configFilePath)
			if err != nil {
				log.Error(err, "Error while reading the state to re-assert")
				return
			}
			f(state)
		}
	}

	stopWatching, err := agent.OnStateChange(configFilePath, log.WithName("onStateChange"), func(state agent.State) {
		log.Info("Received a new state")
		err := wg.Sync(state)
		if err != nil {
			log.Error(err, "Error while sycncing wireguard")
			return
		}
		assertLocal(state)
	})

	if err != nil {
		log.Error(err, "Error while watching changes")
		os.Exit(1)
	}

	defer stopWatching()

	gluetunClient := &http.Client{Timeout: 2 * time.Second}
	gluetunHealthURL := "http://" + resources.GluetunHealthAddress + "/"

	// A gluetun restart can flush the iptables rules, so the local pass repeats every tick.
	go onTick(ctx, reading(assertLocal))
	// The gluetun loop also runs once now, without blocking anything.
	go func() {
		syncState := reading(syncGluetun)
		syncState()
		onTick(ctx, syncState)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		state, _, err := agent.GetDesiredState(configFilePath)

		if err != nil {
			httpLog.Error(err, "agent is not ready as it cannot get server state")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		err = agent.IsStateValid(state)

		if err != nil {
			httpLog.Error(err, "agent is not ready as server state not valid")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		err = wg.Sync(state)

		if err != nil {
			httpLog.Error(err, "agent is not ready as it cannot sync wireguard")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		if err := dp.Err(); err != nil {
			httpLog.Error(err, "agent is not ready as the datapath is not asserted")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		// During a VPN cycle gluetun is down on purpose and the peer path may be too. Skipping these
		// two checks keeps the pod Ready, so the Service keeps its endpoint and handshakes survive.
		// Egress stays closed meanwhile: the killswitch and the blackhole rule remain in place.
		if !engine.Snapshot().CycleInProgress {
			if err := datapath.CheckPeerPath(agent.PeerCIDR(state)); err != nil {
				httpLog.Error(err, "agent is not ready as peer traffic would not reach the tunnel")
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}

			if err := agent.GluetunHealthy(r.Context(), gluetunClient, gluetunHealthURL); err != nil {
				httpLog.Error(err, "agent is not ready as gluetun is not healthy")
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}

		httpLog.V(2).Info("agent is ready")

		w.WriteHeader(http.StatusOK)
	})

	mux.Handle("GET /egress", egress.StatusHandler(engine))

	// This listener answers the kubelet's health probes and the operator's egress poll.
	srv := egress.NewServer(healthLn.Addr().String(), mux)
	shutdown := make(chan struct{})
	go func() {
		defer close(shutdown)
		<-ctx.Done()
		log.Info("Shutting down agent")
		_ = srv.Shutdown(context.Background())
		if err := peers.Close(context.Background()); err != nil {
			log.Error(err, "Error while shutting down the egress API")
		}
	}()

	if err := srv.Serve(healthLn); err != http.ErrServerClosed {
		log.Error(err, "Health server error")
		return
	}
	// Serve returns as soon as Shutdown is called; wait for the shutdown to finish.
	<-shutdown
}

// onTick calls f every resources.ReassertInterval until ctx is done.
func onTick(ctx context.Context, f func()) {
	ticker := time.NewTicker(resources.ReassertInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f()
		}
	}
}

// runClient runs `agent client`: the startup check with --check, otherwise the client sidecar. It
// returns the process exit code: 0 on success or a clean shutdown, 1 on failure, 2 on a usage error.
func runClient(args []string) int {
	var wireguardName string
	var check bool
	var verbosity int
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.StringVar(&wireguardName, "wireguard", "", "the Wireguard to attach to: a name in this pod's namespace, or namespace/name")
	fs.BoolVar(&check, "check", false, "run the startup check and exit")
	fs.IntVar(&verbosity, "v", 0, "the verbosity level; 1 also logs every applied pass")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	stdr.SetVerbosity(verbosity)
	logger := stdr.NewWithOptions(log.New(os.Stderr, "", log.LstdFlags), stdr.Options{LogCaller: stdr.All}).WithName("client")

	if check {
		if err := sidecar.Check(resources.WgInterface); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}

	cfg, err := sidecar.ConfigFromEnv(wireguardName, sidecar.DefaultKeyPath, os.Getenv)
	if err != nil {
		logger.Error(err, "invalid configuration")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := sidecar.Run(ctx, cfg, logger); err != nil {
		logger.Error(err, "client stopped")
		return 1
	}
	return 0
}
