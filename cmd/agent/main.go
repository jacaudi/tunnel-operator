package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
	"github.com/jacaudi/wireguard-operator/internal/agent"
	"github.com/jacaudi/wireguard-operator/internal/datapath"
	"github.com/jacaudi/wireguard-operator/internal/resources"
	"github.com/jacaudi/wireguard-operator/internal/wireguard"
)

func main() {
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

	wg := wireguard.Wireguard{
		Logger:                            log.WithName("wireguard"),
		Iface:                             iface,
		ListenPort:                        wireguardListenPort,
		WgUserspaceImplementationFallback: wgUserspaceImplementationFallback,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	dp := datapath.New()

	close, err := agent.OnStateChange(configFilePath, log.WithName("onStateChange"), func(state agent.State) {
		log.Info("Received a new state")
		err := wg.Sync(state)
		if err != nil {
			log.Error(err, "Error while sycncing wireguard")
			return
		}
		if err := dp.Ensure(ctx, agent.PeerCIDR(state)); err != nil {
			log.Error(err, "Error while asserting the datapath")
		}
	})

	if err != nil {
		log.Error(err, "Error while watching changes")
		os.Exit(1)
	}

	defer close()

	gluetunClient := &http.Client{Timeout: 2 * time.Second}
	gluetunHealthURL := "http://" + resources.GluetunHealthAddress + "/"

	go reassert(ctx, dp, configFilePath, log)

	httpLog := log.WithName("http")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
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

		if err := agent.GluetunHealthy(r.Context(), gluetunClient, gluetunHealthURL); err != nil {
			httpLog.Error(err, "agent is not ready as gluetun is not healthy")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		httpLog.V(2).Info("agent is ready")

		w.WriteHeader(http.StatusOK)
	})

	// Timeouts are not optional here. This listener answers the kubelet's health
	// probes, and with no ReadHeaderTimeout a client that opens a connection and
	// dribbles header bytes holds a goroutine open indefinitely (Slowloris) —
	// enough of them and the probe endpoint stops answering, which the kubelet
	// reads as an unhealthy pod and restarts the tunnel.
	srv := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		log.Info("Shutting down agent")
		_ = srv.Shutdown(context.Background())
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Error(err, "Health server error")
	}
}

// reassert re-asserts the datapath for the current state every resources.ReassertInterval until ctx
// is done; a gluetun restart can flush the iptables rules.
func reassert(ctx context.Context, dp *datapath.Datapath, statePath string, logger logr.Logger) {
	ticker := time.NewTicker(resources.ReassertInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		state, _, err := agent.GetDesiredState(statePath)
		if err != nil {
			logger.Error(err, "Error while reading the state to re-assert the datapath")
			continue
		}
		if err := dp.Ensure(ctx, agent.PeerCIDR(state)); err != nil {
			logger.Error(err, "Error while re-asserting the datapath")
		}
	}
}
