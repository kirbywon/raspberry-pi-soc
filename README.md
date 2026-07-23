# Section 1: System Overview & Architecture

### 1.1 Project Objectives & Scope

* **Primary Motivation & Origin:** 
  * Started as a simple local DNS project (Pi-hole) to block ads and network tracking while gaining foundational hands-on cybersecurity experience.
  * Evolved iteratively through continuous homelab expansion—adding recursive DNS privacy, containerized NIDS packet inspection, full-stack log aggregation, and system telemetry as learning progressed.
  * Serves as a hands-on sandbox for practical threat monitoring, SIEM log parsing, and container orchestration.

* **Primary Operational Objectives:**
  * **Recursive DNS & Network Privacy:** Eliminate reliance on third-party upstream DNS resolvers and block malicious/tracking domains at the perimeter.
  * **Intrusion & Threat Detection:** Inspect raw network traffic for malicious signatures, anomalies, and unauthorized lateral movement.
  * **Unified Telemetry & Observability:** Aggregate system metrics, container performance, and security logs into centralized, queryable dashboards.

* **Scope of Coverage:**
  * **Monitored Subnet:** 100% of primary home LAN and Wi-Fi network traffic routed through the stack.
  * **Covered Assets:** Personal endpoints, smart home / IoT devices, and containerized home services.
  * **Remote Coverage:** Secured remote access and DNS filtering provided via Tailscale mesh integration.

---

### 1.2 Hardware Specs & Network Topology

* **Hardware Specs:**
  * **Host System:** Raspberry Pi 5 (ARM64 / `aarch64` Cortex-A76)
  * **Memory:** 8 GB LPDDR4x RAM (7.9 GiB total available)
  * **Storage:** 128 GB NVMe SSD via PCIe M.2 HAT (`/dev/nvme0n1p2`) for high-speed I/O and database performance (Loki / Prometheus)
  * **Hostname:** `PieSOC`

* **Network Interfaces & Connectivity:**
  * **Primary Interface (`eth0`):** Gigabit Ethernet hardwired to main router (`192.168.1.40/24`)
  * **Wireless Interface (`wlan0`):** Dual-band Wi-Fi backup (`192.168.1.97/24`)
  * **Overlay VPN (`tailscale0`):** Integrated Tailscale mesh node (`100.89.94.112/32`) for secure remote management and zero-trust access
  * **Container Networking:** Isolated Docker custom bridge networks (`br-*`) facilitating microsegmentation between security, telemetry, and web UI stacks

---

### 1.3 Software Architecture & Container Decomposition

The platform is orchestrated via Docker Compose, segmented into functional microservice layers using a hybrid networking model (`host` networking for low-latency security tools, isolated `bridge` networks for Web UI/Management services).

| Functional Layer | Container Name | Image Source | Network Mode | Key Purpose & Functionality |
| :--- | :--- | :--- | :--- | :--- |
| **Network Intrusion Detection (NIDS)** | `suricata-ips` | `jasonish/suricata:latest` | `host` | Deep Packet Inspection (DPI) inspecting raw interfaces for signature-based threats and malicious traffic. |
| **Perimeter DNS & Filtering** | `pihole` | `pihole/pihole:2024.07.0` | `host` | Primary local DNS server providing network-wide ad, telemetry, and malware domain blocking. |
| **Recursive DNS Resolution** | `unbound` | `klutchell/unbound:latest` | `host` | Local recursive DNS resolver handling root-level queries to bypass third-party upstream logging. |
| **Log Ingestion & Indexing** | `loki` | `grafana/loki:latest` | `host` | High-performance log aggregation engine storing NIDS, system, and container logs. |
| **Log Collection Agent** | `promtail` | `grafana/promtail:latest` | `plg_plg` | Scrapes system `/var/log` files and Docker container outputs, pushing parsed events into Loki. |
| **Metrics Collection Engine** | `prometheus` | `prom/prometheus` | `host` | Time-series database storing hardware, network, and container resource metrics. |
| **System Telemetry Exporter** | `node-exporter` | `prom/node-exporter:latest` | `host` | Collects host-level system metrics (CPU, RAM, NVMe I/O, network bandwidth). |
| **Container Metrics Exporter** | `cadvisor` | `gcr.io/cadvisor/cadvisor:latest` | `prometheus_default` | Monitors real-time resource utilization (CPU/Memory) across all active Docker containers. |
| **Central Telemetry Dashboard** | `grafana` | `grafana/grafana-oss:latest` | `plg_plg` | Centralized SOC dashboard visualizing Suricata alerts, DNS metrics, and system health (`:3001`). |
| **Mesh VPN (Active)** | `tailscale0` | *Native Host Daemon* | `host` | Primary mesh VPN providing secure, zero-trust remote access and encrypted overlay networking. |
| **Legacy VPN (Deprecating)** | `wg-easy` | `weejewel/wg-easy` | `wireguard_default` | Legacy WireGuard server; retained in standby during full migration to Tailscale overlay mesh. |
| **Container Management** | `portainer` | `portainer/portainer-ce:latest` | `portainer_default` | Web UI management console for Docker stack lifecycle and volume inspection (`:9443`). |
| **Application Gateway / Portal** | `homepage` | `ghcr.io/gethomepage/homepage:latest` | `homepage_default` | Unified dashboard for service health monitoring and quick application navigation (`:3000`). |
| **Data Synchronization** | `syncthing` | `syncthing/syncthing:latest` | `bridge` | Decentralized, encrypted file synchronization for notes, configs, and backup data (`:8384`). |
| **API / Automation Gateway** | `openclaw-gateway` | `ghcr.io/openclaw/openclaw:latest` | `common-bridge` | Containerized API gateway integration handling external webhooks/automation (`:18789`). |

# Section 2: Network Traffic & Data Pipelines

### 2.1 Local DNS Filtering & Telemetry Pipeline

> [!NOTE] ⚠️ Active Implementation Note (To Be Updated)
> **Current State:** Pi-hole is currently utilizing Cloudflare (`1.1.1.1` / `1.0.0.1`) for upstream DNS resolution. 
> **Pending Update:** Once Pi-hole is reconfigured to forward queries internally to `unbound` (`127.0.0.1#5335`), update this section to reflect root-level recursive DNS resolution.

* **Inbound Query Resolution & Perimeter Protection:**
  * Endpoint DNS queries originating from local LAN devices or Tailscale mesh nodes (`kali-laptop`, `nx779j`) are directed to Pi-hole on port `53`.
  * Pi-hole evaluates inbound requests against configured blocklists, dropping ad, tracking, and telemetry domains at the perimeter.
  * Allowed queries are forwarded to upstream resolvers (`1.1.1.1` / `1.0.0.1`).

* **Log Aggregation & Ingestion:**
  * DNS query activity is logged locally to `/var/log/pihole/pihole.log`.
  * **Promtail** streams the log file in real time, parsing timestamps, query types, domain targets, client IPs, and block/allow status via structured regex.
  * Extracted log batches are pushed to **Loki** on port `3100` for indexed storage and search capability inside Grafana dashboards.

* **Encrypted Overlay Mesh (Tailscale):**
  * Remote endpoints connect back to `PieSOC` (`100.89.94.112`) over an encrypted Tailscale mesh network.
  * Admin Web UIs and telemetry dashboards remain completely unexposed to the public internet, accessible strictly via authenticated Tailscale paths.

---

### 2.2 Intrusion Detection & System Telemetry Flow

* **NIDS Packet Inspection:**
  * **Suricata** runs in `host` network mode, providing raw socket access to inspect incoming and outgoing traffic on interface `eth0`.
  * Packet headers and payloads are checked against active threat signatures in real time.
  * Detected alerts and anomalies write directly to `/var/log/suricata/eve.json` for ingestion into Loki.

* **System & Container Health Ingestion:**
  * **Node-Exporter** collects host health metrics (CPU load, 8GB RAM footprint, NVMe read/write I/O).
  * **cAdvisor** monitors container-level resource utilization across all active microservices.
  * **Prometheus** scrapes metric endpoints every 15 seconds, storing time-series telemetry for visualization in Grafana.
    

# Section 3: Container Stack & Service Deep-Dive

### 3.1 Network Gateway & Recursive DNS (Pi-hole + Unbound)

* **Pi-hole Setup:**
  * **Upstream Configuration:** Currently configured with Cloudflare DNS (`1.1.1.1` / `1.0.0.1`) as primary resolvers.
  * **Blocklist Selection:** Configured with default StevenBlack blocklists supplemented with targeted telemetry-blocking lists for smart home / IoT noise reduction.
  * **Local DNS Records:** Enforces static local resolution (`.home.arpa` / `.internal`) mapping friendly hostnames directly to local container/service IP addresses.

* **Unbound Configuration:**
  * **Recursion Parameters:** Provisioned in container stack (`klutchell/unbound`) on internal port `5335`.
  * **Privacy & Validation:** Configured for strict DNSSEC validation, hardened against cache poisoning, and enforcing `qname-minimization: yes` to minimize query leakage during root resolution.

---

### 3.2 Network Intrusion Detection (Suricata NIDS)

* **Capture Engine:**
  * **Interface Binding:** Bound directly to primary Ethernet interface (`eth0`) using `host` network mode.
  * **AF_PACKET Settings:** Configured with high-performance `AF_PACKET` socket interface, using multi-threaded packet processing tuned for the Raspberry Pi 5's Cortex-A76 core layout.

* **Rule Management:**
  * **Rulesets Enabled:** Active rulesets include Emerging Threats (ET) Open ruleset covering malware C2 traffic, active exploit attempts, and suspicious outbound connections.
  * **Update Routine:** Automated rule downloads executed via `suricata-update` cron triggers.

* **Noise Reduction:**
  * **Suppression Rules:** Configured thresholding rules in `threshold.config` to silence high-volume benign broadcasts (mDNS, SSDP, local Chromecast/smart home discovery packets).

---

### 3.3 Centralized Logging & Telemetry (Loki + Promtail + Grafana)

* **Log Ingestion:**
  * **Target Sources:** Scrapes `/var/log/pihole/pihole.log` (DNS), `/var/log/suricata/eve.json` (NIDS events), and Docker container stdout/stderr output.
  * **Parsing Pipelines:** Promtail uses custom regex and JSON stages to extract dynamic fields (`src_ip`, `dest_port`, `event_type`, `domain`, `action`) before pushing to Loki.

* **Storage & Retention:**
  * **Engine & Mount:** Utilizes Loki TSDB storage mounted directly on the high-speed 128GB NVMe SSD (`/dev/nvme0n1p2`) to withstand high IOPS without SD card wear.
  * **Retention Policy:** Enforces a rolling 14-day log retention window in `loki-config.yaml` to prevent disk bloat.

* **Dashboards Built:**
  * **SOC Security Overview:** Real-time Suricata alert severity breakdown, high-risk signature matches, and top target internal IPs.
  * **Perimeter DNS Analytics:** Query velocity graphs, block ratios, top allowed/blocked domains, and client query rates.
  * **Host & Container Telemetry:** Real-time CPU, RAM, NVMe temperature, and individual container resource consumption (cAdvisor).

---

### 3.4 Remote Access Gateway & Mesh

* **Tailscale Overlay Mesh (Active):**
  * Provides zero-trust mesh routing connecting `PieSOC` (`100.89.94.112`) to remote endpoints (`kali-laptop`, `nx779j`).
  * Enforces strict administrative isolation—Web UIs (Grafana, Portainer, Pi-hole) are bound to local LAN and Tailscale interfaces only.

* **WireGuard (`wg-easy`) (Legacy / Standby):**
  * Retained as a fallback split-tunnel VPN gateway operating on custom UDP ports.
    

# Section 4: Operational Insights & 6-Month Learnings

### 4.1 Resource Realities on ARM Architecture

* **Performance Baseline:**
  * **Normal Operational Load:** Across all 14 active microservices, baseline memory footprint sits comfortably at **~2.8 GiB to 3.2 GiB** out of 7.9 GiB available RAM (~35–40% total utilization).
  * **CPU Behavior:** Idle load stays under 5% across the Cortex-A76 cores. Promtail and Suricata show temporary CPU spikes (up to 25–35%) during high network throughput bursts or rapid log ingestion sequences.
  * **Peak Load Scenarios:** Simultaneous Grafana dashboard re-renders with heavy Loki LogQL query ranges (e.g., 7-day log aggregates) combined with full Suricata rule reloads push CPU load briefly to 60–70%, but system stability remains rock-solid without thermal throttling.

* **Thermal & Storage Impact:**
  * **Thermal Performance:** Operating inside an actively cooled case, `PieSOC` maintains stable idle temperatures of **38°C–42°C**, peaking around **55°C** under heavy LogQL query processing.
  * **SSD vs. SD Card Durability:** Migrating the Docker root data directory, Loki chunks, and Suricata `eve.json` logs to the **128 GB NVMe SSD (via PCIe M.2 HAT)** was the single most critical stability upgrade. It completely eliminated the I/O write bottlenecks and flash degradation risks inherent to running log-heavy stacks on standard MicroSD cards.

---

### 4.2 Signal-to-Noise Tuning

* **False Positive Reduction:**
  * **Smart Home Broadcast Noise:** Initial Suricata deployments generated substantial alert volume from benign local network protocols (mDNS on port 5353, SSDP/UPnP discovery, and frequent IoT keep-alive pings).
  * **Tuning Applied:** Implemented custom suppression rules in `threshold.config` and silenced low-priority Emerging Threats (ET) Info signatures for internal subnet ranges (`192.168.1.0/24`), reducing raw alert noise by ~85%.

* **Real Anomalies & Telemetry Insights:**
  * **Outbound Telemetry Auditing:** Pi-hole query logs revealed high-frequency background phone-home attempts from smart TVs and IoT appliances, which were promptly isolated using custom domain blocklists.
  * **Port Scan Detection:** Suricata successfully flagged and logged multiple external port sweeps and automated recon probes originating from public WAN interfaces prior to perimeter firewall drops.
    

# Section 5: Maintenance & Disaster Recovery Playbook

### 5.1 Backup Strategy & Config Exports

To protect against data loss, configuration drift, or host corruption, critical container volumes, service configurations, and system configurations are systematically backed up.

* **Volume & Config Backup Execution:**

  # Stop services writing active databases/logs to avoid state corruption
  docker compose down

  # Archive persistent docker volumes and config directories to NVMe backup target
  sudo tar -cvzf /mnt/nvme/backups/piesoc_configs_$(date +%Y%m%d).tar.gz \
    /etc/pihole \
    /etc/suricata \
    ./docker-compose.yml \
    ./grafana \
    ./loki \
    ./promtail \
    ./unbound

  # Restart microservice stack
  docker compose up -d

* **Pi-hole Teleporter & Grafana Dashboard Exports:**
  * **Pi-hole:** Settings export executed via Web UI (Settings > Teleporter > Export) or CLI (pihole -a -t) to preserve custom local DNS records (.home.arpa) and white/blocklists.
  * **Grafana Dashboards:** Custom SOC overview and system telemetry dashboards exported directly as JSON definitions and stored in source control (git).
---
### 5.2 Update Strategy & Patching Workflow

System maintenance follows a routine patching cycle to ensure security updates are applied without breaking running services.

* **Container Image Update Routine:**

  # Navigate to compose directory
  cd ~/homelab

  # Pull latest images defined in compose file
  docker compose pull

  # Re-create containers with updated images in detached mode
  docker compose up -d --remove-orphans

  # Prune dangling/unused images to reclaim NVMe storage
  docker image prune -f

* **OS Patching & Kernel Updates (Raspberry Pi OS / ARM64):**

  # Update package repositories and upgrade installed packages
  sudo apt update && sudo apt full-upgrade -y

  # Clean up orphaned dependencies
  sudo apt autoremove -y && sudo apt clean

  # Reboot system if kernel or core system libraries were updated
  sudo reboot
---
### 5.3 Disaster Recovery & Cold-Start Rebuild

In the event of total drive failure or OS corruption, the entire SOC stack can be restored onto fresh media using the following recovery sequence:

1. **Host OS Provisioning:** Flash fresh Raspberry Pi OS 64-bit to drive, configure hostname (PieSOC), static IP (192.168.1.40/24), and enable SSH/PCIe HAT support for NVMe.
2. **Prerequisites Installation:** Install Docker Engine, Docker Compose plugin, and Tailscale daemon.
3. **Restore Configs:** Extract the backup archive (piesoc_configs_*.tar.gz) back into working directories.
4. **Authenticate Tailscale:** Re-authenticate node (tailscale up) to re-establish secure mesh IP (100.89.94.112).
5. **Bring Up Stack:** Run docker compose up -d to pull images, initialize volumes, and restore full NIDS/DNS/Telemetry operations.
	
# Section 6: Future Roadmap

* [ ] **Migrate Pi-hole Upstream to Unbound:** Switch Pi-hole primary upstream DNS from Cloudflare (`1.1.1.1`) to the local `unbound` container (`127.0.0.1#5335`) to complete root-level recursive DNS resolution and strict DNSSEC enforcement.
* [ ] **Decommission `wg-easy` Stack:** Complete full client transition to Tailscale mesh, then spin down and remove the standalone `wg-easy` container stack to free background resources.
* [ ] **Enable NIDS Promiscuous Mode:** Configure `eth0` in promiscuous mode (`ip link set eth0 promisc`) or configure a mirrored port (SPAN) on the network switch to expand Suricata visibility to inter-device lateral LAN traffic.
* [ ] **Refine Suricata Noise Thresholds:** Tune `threshold.config` and disable non-critical ET rules to further eliminate false-positive alerts triggered by local smart home device broadcasts.
