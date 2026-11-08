# Changelog

## 0.1.0 (2026-11-08)


### ⚠ BREAKING CHANGES

* **deps:** the minimum supported Kubernetes version is now 1.34, with the MutatingAdmissionPolicy beta enabled on 1.34 and 1.35 (--feature-gates=MutatingAdmissionPolicy=true and --runtime-config=admissionregistration.k8s.io/v1beta1=true).
* **api:** Wireguard now requires spec.localCIDRs (at least one IPv4 CIDR) and spec.gluetun; a Wireguard with spec: {} is rejected by the CRD.
* **api:** a publicKey that is not a canonical 32-byte base64 WireGuard key is now rejected at admission, and a peerCIDR with host bits set, an IPv6 prefix or a prefix longer than /30 now reports Degraded/InvalidPeerCIDR instead of being used.
* **api:** WireguardPeer spec.address is removed. Existing peers are allocated afresh into status.address, so a peer's address can change once on upgrade.
* **controller:** WireguardPeers are no longer given an ownerReference to their Wireguard, so deleting a Wireguard no longer deletes its peers. The pending 'Waiting for wireguard peer to be created', the 'Waiting for <wireguard> to be ready' and the 'Duplicate address' peer statuses are gone. A peer whose Wireguard does not exist now reads pending instead of error.
* spec.useWgUserspaceImplementation, spec.enableIpForwardOnPodInit and the agent flag --wg-use-userspace-implementation are removed; the server pod always runs a privileged sysctl init container.
* spec.serviceType, spec.port, spec.address, spec.externalAddress, spec.serviceAnnotations, status.address, status.port, status.uniqueIdentifier and status.resources are removed; `<name>-svc` is always ClusterIP.
* spec.mtu, spec.dns, spec.dnsSearchDomain, spec.persistentKeepalive, status.dns and WireguardPeer spec.privateKeyRef, allowedIPs, dns and dnsSearchDomain are removed; the `<name>-peer-configs` and `<peer>-peer` Secrets are no longer written; peers must supply spec.publicKey.
* spec.peerCIDRv6, spec.ipv6Only and WireguardPeer spec.addressV6, disabled, egressNetworkPolicies, downloadSpeed and uploadSpeed are removed.
* spec.tunnel, status.tunnel and the wstunnel sidecar and Service port are removed.
* spec.metric, the `<name>-metrics-svc` Service and the agent's :9586 metrics port are removed.
* **agent:** the server no longer NATs peer traffic or enforces per-peer egress policy, so peers have no internet egress until M4 routes it through gluetun.

### Features

* add PersistentKeepalive to generated peer configs ([f3de393](https://github.com/jacaudi/tunnel-operator/commit/f3de393c6ab845025cb2b2e819dc97d69e306a06)), closes [#4](https://github.com/jacaudi/tunnel-operator/issues/4)
* **agent:** assert the fail-closed datapath and poll gluetun's health ([b0c535b](https://github.com/jacaudi/tunnel-operator/commit/b0c535bac86f5f746b40a4b7b537da724fed0446))
* **agent:** configure the client from its peer's status ([4529745](https://github.com/jacaudi/tunnel-operator/commit/45297451b6098fdf6c9384baec39802bdb5d0b96))
* **agent:** configure the client's tunnel from the server's status ([770dfb8](https://github.com/jacaudi/tunnel-operator/commit/770dfb818913709d948a27f86a9f979e5b41fdca))
* **agent:** register an application pod as its own WireguardPeer ([996404c](https://github.com/jacaudi/tunnel-operator/commit/996404c529ecb90f4296192b5ee8bbe7b9c469c4))
* **agent:** route the client pod's internet traffic through wg0 ([7f151ed](https://github.com/jacaudi/tunnel-operator/commit/7f151edd6b0323b6cbd3ab14cb47b3890cec5f6f))
* **agent:** run the WireGuard client sidecar as agent client ([10fff07](https://github.com/jacaudi/tunnel-operator/commit/10fff070883eed8efd59f57c22b07a879ee29fb7))
* **agent:** say in the sidecar log why the operator has not admitted the peer ([d89a37e](https://github.com/jacaudi/tunnel-operator/commit/d89a37ea3f3d5cae565d8f492420c29da5b39848))
* **agent:** set wg0's MTU and keep exactly one address on it ([26f4aec](https://github.com/jacaudi/tunnel-operator/commit/26f4aecf0d18318d241be84aac82b196d2159487))
* **api:** add spec.localCIDRs and spec.gluetun to Wireguard ([ff37fcb](https://github.com/jacaudi/tunnel-operator/commit/ff37fcbe9d70512aceee82fe388265fe5efb8842))
* **api:** let a WireguardPeer reference a Wireguard in another namespace ([37ff4e6](https://github.com/jacaudi/tunnel-operator/commit/37ff4e6ae5d629f328a086a7198aa4ec3a2c73a9))
* **api:** move the allocated peer address to status.address ([9438f14](https://github.com/jacaudi/tunnel-operator/commit/9438f14b22b6f13909808f1f1470e7022501387d))
* **api:** publish the server endpoint and public key in Wireguard status ([bca286e](https://github.com/jacaudi/tunnel-operator/commit/bca286e9e27ab589528f790b1ed6b9241c7820aa))
* **api:** validate peer public keys and the peer CIDR ([6a03304](https://github.com/jacaudi/tunnel-operator/commit/6a033041b632bdd2b02be8a76fbb8c3d85f42135))
* **chart:** add the chart skeleton with the manager Deployment ([3ad146f](https://github.com/jacaudi/tunnel-operator/commit/3ad146f1a9c469b11479ca462370e4a257646ffa))
* **chart:** generate CRDs, admission policy and RBAC from config ([3f803ef](https://github.com/jacaudi/tunnel-operator/commit/3f803ef0d38b2599b174c0debf747f60b745af24))
* **controller:** keep the client RoleBinding in namespaces with labelled pods ([dda1e17](https://github.com/jacaudi/tunnel-operator/commit/dda1e1718687cf13a1956cc26fb7442a9d7e3dd8))
* **controller:** label gateway and operator pods and read gateway pods uncached ([b0b99ad](https://github.com/jacaudi/tunnel-operator/commit/b0b99ad440d762ea1adea6b4c3c5ff4221c63e7a))
* **controller:** reconcile peers from the Wireguard controller alone ([b9dbfd6](https://github.com/jacaudi/tunnel-operator/commit/b9dbfd64da35b766f34e328888c531b1e661c7fa))
* **controller:** report Ready only once the server Deployment has rolled out ([7458fdc](https://github.com/jacaudi/tunnel-operator/commit/7458fdc7295d5b3b39159c9e0dd2a23dfb550a78))
* **controller:** run gluetun beside the agent in the server pod ([668131b](https://github.com/jacaudi/tunnel-operator/commit/668131bb02c11009512a2670b2f4e02ac0e55a7a))
* **controller:** validate localCIDRs, the ClusterIP and reserved gluetun variables ([d40d9c3](https://github.com/jacaudi/tunnel-operator/commit/d40d9c32c52f27dea4bef50ab7a15bc22f7661f2))
* **injection:** inject the client sidecar into labelled pods ([e40aba8](https://github.com/jacaudi/tunnel-operator/commit/e40aba85f63eaad797a863d704a281c6c6cd5777))
* **injection:** reject labelled pods that were not injected ([baa0616](https://github.com/jacaudi/tunnel-operator/commit/baa0616133ee7469fddaf5a5886a0d4d14ada5a4))
* **rbac:** add the wireguard-operator-client ClusterRole and a client example ([aa31ee0](https://github.com/jacaudi/tunnel-operator/commit/aa31ee08e2c10cae7f776a9b245e6badecf79970))


### Bug Fixes

* **agent:** close the wgctrl client and stop a malformed peer address from panicking ([f2d73a9](https://github.com/jacaudi/tunnel-operator/commit/f2d73a9e2868c410f76acf2cc16d14bad77506a3)), closes [#37](https://github.com/jacaudi/tunnel-operator/issues/37)
* **agent:** ignore a missing IPv6 stack when deleting IPv6 default routes ([5f861ed](https://github.com/jacaudi/tunnel-operator/commit/5f861edab6cf2feba84c20292d0900aa90b9b55d))
* **agent:** report NotReady when wg0 traffic would not reach tun0 ([372df84](https://github.com/jacaudi/tunnel-operator/commit/372df84074c2ffd7a55e52e2eba9b1fb283713f1)), closes [#72](https://github.com/jacaudi/tunnel-operator/issues/72)
* clear Degraded on success; cover removal, drift, adoption, failure ([5fd49b4](https://github.com/jacaudi/tunnel-operator/commit/5fd49b4c4ad8bef1108c8e50504dc3bead66a686)), closes [#2](https://github.com/jacaudi/tunnel-operator/issues/2)
* **controller:** hand a new peer to the server in the reconcile that allocates it ([f7f2c41](https://github.com/jacaudi/tunnel-operator/commit/f7f2c41076abd395459b78652565ec485247ce4a))
* **controller:** heal the client RoleBinding by watching it ([8681a53](https://github.com/jacaudi/tunnel-operator/commit/8681a53905c9031455f087bf287e39b4215ae8d4))
* **controller:** keep allocating peers after one peer's status conflict ([2b9243d](https://github.com/jacaudi/tunnel-operator/commit/2b9243d718a29b464dfd2029c5fa9185593c02d4)), closes [#37](https://github.com/jacaudi/tunnel-operator/issues/37)
* **controller:** keep two peers from sharing an address ([900bbe6](https://github.com/jacaudi/tunnel-operator/commit/900bbe6b818be2923318cda161084c1f14b2be02))
* **controller:** let the current holder keep a public key against a newer claim ([fea2c65](https://github.com/jacaudi/tunnel-operator/commit/fea2c65d4a9a613d9cf56835636823ee1e0f9a4b))
* **controller:** nudge only server pods in the Wireguard's namespace ([1e95d8b](https://github.com/jacaudi/tunnel-operator/commit/1e95d8b0b116b593298424c5e4c1190c395c8911))
* **controller:** re-check a ClusterIP outside localCIDRs every minute ([a788270](https://github.com/jacaudi/tunnel-operator/commit/a78827027759f57e957dba587811fbc0abfc7654))
* **controller:** re-check the served admission policy version periodically ([d86b09c](https://github.com/jacaudi/tunnel-operator/commit/d86b09c6ef6aba2b024a073531ce0b392e870ebb))
* **controller:** read the current key holders before writing any peer status ([d9bb43b](https://github.com/jacaudi/tunnel-operator/commit/d9bb43b8a9eed4fe0172a4182c6551a4b40edd1d)), closes [#37](https://github.com/jacaudi/tunnel-operator/issues/37)
* **controller:** refuse a peer whose public key another peer of the gateway holds ([f5ff549](https://github.com/jacaudi/tunnel-operator/commit/f5ff54933367b11e54c52c672ea092b17437f07d))
* **controller:** report Degraded when localCIDRs contains the probe address ([8404741](https://github.com/jacaudi/tunnel-operator/commit/84047411b92c01bd7cf183ef8d9f202b1ebca6ec)), closes [#72](https://github.com/jacaudi/tunnel-operator/issues/72)
* **controller:** report Degraded when peerCIDR contains the probe address ([f7c76e5](https://github.com/jacaudi/tunnel-operator/commit/f7c76e5957cd61fa8be8d50ca5ee6f680ad9a24c)), closes [#72](https://github.com/jacaudi/tunnel-operator/issues/72)
* **controller:** skip a peer whose status write fails validation at every write site ([43b8fb6](https://github.com/jacaudi/tunnel-operator/commit/43b8fb66d11f2800e0c0de1589a35919ff30077b))
* **controller:** stamp the generation the reconcile rendered ([c500efa](https://github.com/jacaudi/tunnel-operator/commit/c500efab813fb174fc2f6ad66df3bc7c160cad08))
* **deps:** bump x/net, grpc, otel and the Go toolchain to clear reachable vulnerabilities ([9dbe485](https://github.com/jacaudi/tunnel-operator/commit/9dbe4859b2844f985bb1f12092ffbd5cfab85452)), closes [#2](https://github.com/jacaudi/tunnel-operator/issues/2)
* give the linter the history its ratchet needs, and say so ([b89f552](https://github.com/jacaudi/tunnel-operator/commit/b89f5526614fed6862bbcb04a92d3c37175e7040)), closes [#37](https://github.com/jacaudi/tunnel-operator/issues/37)
* keep the envtest suite running in the Makefile test targets ([7a638d7](https://github.com/jacaudi/tunnel-operator/commit/7a638d7e87aa9c2f622fc768bdacf8d5baa3da0e)), closes [#37](https://github.com/jacaudi/tunnel-operator/issues/37)
* make the hand-written YAML and Dockerfiles pass the new gates ([3b4b9ed](https://github.com/jacaudi/tunnel-operator/commit/3b4b9ed96d0827e399fb4a62c82254db5f0f8eeb)), closes [#37](https://github.com/jacaudi/tunnel-operator/issues/37)
* **rbac:** grant the operator only the RoleBinding and policy names it manages ([269ee81](https://github.com/jacaudi/tunnel-operator/commit/269ee81159bed9edd05eb18032e1d0aec216f7c9))
* reconcile both Services declaratively via Server-Side Apply ([3589a0c](https://github.com/jacaudi/tunnel-operator/commit/3589a0c0b6ddcb36eb14f8fde6f346388c57b5bf)), closes [#2](https://github.com/jacaudi/tunnel-operator/issues/2)
* reconcile the Deployment declaratively via Server-Side Apply ([21af595](https://github.com/jacaudi/tunnel-operator/commit/21af59527d26521f45b10be5d0a31fd6fd41b73a)), closes [#2](https://github.com/jacaudi/tunnel-operator/issues/2)
* resolve every gosec finding the new lint baseline reports ([99d1cf4](https://github.com/jacaudi/tunnel-operator/commit/99d1cf4ea75a42b016aa48d7e515a36f73af2d0e)), closes [#37](https://github.com/jacaudi/tunnel-operator/issues/37)
* stop the Makefile reinstalling tools and eating uncommitted config ([25ba292](https://github.com/jacaudi/tunnel-operator/commit/25ba292844d54f1db085ee4dddd00f220c51a724))


### Dependencies

* bump the transitive dependencies carrying reachable vulnerabilities ([31f33e0](https://github.com/jacaudi/tunnel-operator/commit/31f33e0045851cdd5175e4417807e53d623feec5)), closes [#40](https://github.com/jacaudi/tunnel-operator/issues/40) [#37](https://github.com/jacaudi/tunnel-operator/issues/37)


### Miscellaneous Chores

* **chart:** align task ci with ci-lint and correct stale comments and docs ([a83d23a](https://github.com/jacaudi/tunnel-operator/commit/a83d23ab819bf79507ff1d190742ca69630bb3b2))
* ignore the session handoff prompts directory ([a0414d7](https://github.com/jacaudi/tunnel-operator/commit/a0414d77700e3f0c265e04f613f4485f1e4623b8))
* release main ([b2eab9d](https://github.com/jacaudi/tunnel-operator/commit/b2eab9dce7a7c5d3db7724e1538b3f0b8be59965))
* remove dead scaffolding and stale comments ([66bd490](https://github.com/jacaudi/tunnel-operator/commit/66bd490eb2759334baea4d302b833a9a8283e8de)), closes [#37](https://github.com/jacaudi/tunnel-operator/issues/37)
* rename Go module path to github.com/jacaudi/wireguard-operator ([e380e0e](https://github.com/jacaudi/tunnel-operator/commit/e380e0ef6656535193f238ef095ac120a3060ba5)), closes [#36](https://github.com/jacaudi/tunnel-operator/issues/36)
* rename Go module path to jacaudi and complete fork housekeeping ([be6d4e4](https://github.com/jacaudi/tunnel-operator/commit/be6d4e439816a51b31ebaccc3dcc979e142de23e))
* rename labels, literal names, field manager and lease to tunnel-operator ([bbe9071](https://github.com/jacaudi/tunnel-operator/commit/bbe9071a9f03fd000dd3f5f7cb7c2cf074bc90b5))
* rename the API group to vpn.tunnel-operator.io ([765166a](https://github.com/jacaudi/tunnel-operator/commit/765166ac50f2f997ef8d487cc6f4472273209fe0))


### Code Refactoring

* **agent:** delete the iptables sync that flushes the pod's rules ([172d3a4](https://github.com/jacaudi/tunnel-operator/commit/172d3a4fc01e24e8f5b0c75e6f5f1dceb92a92bc))
* delete IPv6 and the per-peer policy fields ([14c52c5](https://github.com/jacaudi/tunnel-operator/commit/14c52c5d9ca4d917c1de52e1a2215810660d6c61))
* delete peer config rendering and peer key minting ([0789c2e](https://github.com/jacaudi/tunnel-operator/commit/0789c2e98e4454497b2861018d018371d08f2124))
* delete the agent metrics exporter ([f25455f](https://github.com/jacaudi/tunnel-operator/commit/f25455f31e08222784816b246e9ce964ad5eda6e))
* delete the one-value knobs and the vestigial ConfigMap ([464884b](https://github.com/jacaudi/tunnel-operator/commit/464884b96896fbe697b724e7fa372a5af452561e))
* delete the wstunnel sidecar ([d46d94d](https://github.com/jacaudi/tunnel-operator/commit/d46d94dea0c6192b3d85ab565afda2ac095fba1d))
* make the server Service always ClusterIP ([79f6b37](https://github.com/jacaudi/tunnel-operator/commit/79f6b371b603e11612897968fed295e84baef1d7))


### Build System

* **deps:** upgrade controller-runtime to v0.25 and Kubernetes libraries to v0.37 ([945cf49](https://github.com/jacaudi/tunnel-operator/commit/945cf4970c6534505a5a764ef1e2e961ab95abe9)), closes [#37](https://github.com/jacaudi/tunnel-operator/issues/37)
