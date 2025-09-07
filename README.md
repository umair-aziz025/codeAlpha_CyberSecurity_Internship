# codeAlpha_CyberSecurity_Internship
Here's the consolidated guide for setting up Snort IDS on Kali, with all the steps, explanations, and code. I've also added the log rotation configuration as a valuable addition.

---

# 🛡️ Step-by-Step: Setting Up Snort IDS on Kali

This comprehensive guide will walk you through setting up Snort 3 on Kali Linux, from installation to advanced features like automated blocking and a web-based dashboard, ensuring a robust Intrusion Detection System.

---

## 1. Install & Update System

It's crucial to start by updating your Kali Linux system to ensure you have the latest packages and security patches. Then, install Snort 3, which is available directly from the Kali repositories.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install snort -y
```

Verify the installation by checking the Snort version. This confirms Snort is correctly installed and ready for configuration.

```bash
snort -V
```
`

---

## 2. Verify Network Interfaces

Identify the network interface that connects your Kali machine to the network you intend to monitor. This is typically the interface that shares the same subnet as your target systems (e.g., your Windows host).

```bash
ip addr show
```

For our example:
*   Kali `eth1` has the IP address `10.55.97.29`
*   Windows host has the IP address `10.55.97.119`

We will configure Snort to monitor `eth1`.

---

## 3. Run Snort (Packet Capture Mode)

Before diving into complex rule sets, perform a quick test to ensure Snort can capture packets from your chosen interface. This verifies basic functionality.

```bash
sudo snort -i eth1 -c /etc/snort/snort.lua
```

From your Windows host, `ping 10.55.97.29`. You should observe Snort printing captured ICMP packets in the terminal, confirming it's actively monitoring `eth1`.

---

## 4. Add Custom Rule

Custom rules are the heart of Snort's detection capabilities. Create a new file for your local rules to keep them separate from default Snort rules, making management easier.

```bash
sudo nano /etc/snort/rules/local.rules
```

Add the following ICMP detection rule to `local.rules`. This rule will trigger an alert whenever an ICMP packet is detected, which is useful for identifying basic network reconnaissance like ping sweeps.

```snort
alert icmp any any -> any any (msg:"ICMP Detected - Possible Ping"; sid:1000001; rev:1;)
```

---

## 5. Enable Rule in Configuration

For Snort to utilize your custom rules, you must explicitly include your `local.rules` file in the main Snort configuration file (`snort.lua`).

```bash
sudo nano /etc/snort/snort.lua
```

Ensure the following line is present and uncommented within `snort.lua`. This tells Snort where to find your custom rule definitions.

```lua
include = RULE_PATH .. "/local.rules"
```
`

---

## 6. Configure Output (Write Alerts to Disk)

To store Snort alerts persistently, configure the output module to write alerts to a file. This is essential for review, analysis, and integration with other tools.

Still inside `snort.lua`, locate the `outputs` section and add the `alert_fast` configuration:

```lua
alert_fast = { file = true }
```

With this setting, Snort will now write its alerts to `/var/log/snort/alert_fast.txt`, providing a chronological log of detected events.

---

## 7. Run Snort with Rules and Output

Now, run Snort with your custom rules enabled and configured to log alerts to a file. We'll also ensure the log directory has the correct permissions.

```bash
sudo pkill -f snort || true # Kills any existing Snort processes
sudo mkdir -p /var/log/snort # Ensure log directory exists
sudo chown root:root /var/log/snort # Set ownership
sudo chmod 0755 /var/log/snort # Set permissions

sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -i eth1 -A alert_fast -l /var/log/snort
```

Open a new terminal and monitor the alert file:

```bash
tail -f /var/log/snort/alert_fast.txt
```

Ping your Kali machine (`10.55.97.29`) from your Windows host again. You should now see detailed alerts appearing in the `alert_fast.txt` file. ✅

---

## 8. Automated Response (Optional)

Automated response allows Snort to take action (like blocking an IP address) when a malicious activity is detected. This script monitors the alert log and uses `iptables` to block the source IP of an alert.

**File**: `/usr/local/bin/block_on_alert.sh`

```bash
sudo tee /usr/local/bin/block_on_alert.sh > /dev/null <<'EOF'
#!/usr/bin/env bash
LOG="/var/log/snort/alert_fast.txt"
BLOCKED_FILE="/var/run/snort_blocked_ips.txt"
DRY_RUN=true   # set false to actually apply rules
WHITELIST=("10.55.97.29" "127.0.0.1")

# Ensure the blocked IPs file exists
touch "$BLOCKED_FILE"

# Tail the log file and process new lines
tail -Fn0 "$LOG" | while read -r line; do
  # Extract IP address from the log line
  ip=$(echo "$line" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -n1)
  
  # Skip if no IP found or if IP is whitelisted
  [ -z "$ip" ] && continue
  for wl_ip in "${WHITELIST[@]}"; do
    if [ "$ip" = "$wl_ip" ]; then continue 2; fi # Skip to next line if whitelisted
  done

  # Check if IP is already blocked
  if grep -qx "$ip" "$BLOCKED_FILE"; then continue; fi

  # Apply blocking rule or perform dry run
  if [ "$DRY_RUN" = true ]; then
    echo "DRY RUN: Would block $ip. Command: sudo iptables -I INPUT -s $ip -j DROP"
  else
    # Check if rule exists before adding to avoid duplicates
    sudo iptables -C INPUT -s "$ip" -j DROP 2>/dev/null || sudo iptables -I INPUT -s "$ip" -j DROP
    echo "$ip" >> "$BLOCKED_FILE"
    echo "Blocked $ip at $(date)"
  fi
done
EOF

sudo chmod +x /usr/local/bin/block_on_alert.sh
```

Initially, run it in DRY RUN mode to observe its behavior without actually modifying your firewall rules:

```bash
sudo /usr/local/bin/block_on_alert.sh
```

Once you are confident in its operation, edit the script and change `DRY_RUN=true` to `DRY_RUN=false` to enable actual blocking.

---

## 9. Local Dashboard (Flask + Chart.js)

A visual dashboard provides an intuitive way to monitor Snort alerts, offering insights into source IPs and alert types. This simple Flask application serves a web page with charts powered by Chart.js.

**File**: `/usr/local/bin/snort_dashboard.py`

```bash
sudo tee /usr/local/bin/snort_dashboard.py > /dev/null <<'PY'
#!/usr/bin/env python3
from flask import Flask, render_template_string
from collections import Counter
import re
import os

ALERT_FILE = '/var/log/snort/alert_fast.txt'
MAX_LINES = 500 # Max lines to read from the alert file for performance
app = Flask(__name__)

# Regex to parse the alert lines
line_re = re.compile(r'^(?P<ts>\S+)\s+.*?"(?P<msg>.*?)".*\{(?P<proto>\S+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)')

# HTML template for the dashboard
TEMPLATE = """
<!doctype html>
<html>
<head>
  <title>Snort Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <meta http-equiv="refresh" content="30"> <!-- Auto-refresh every 30 seconds -->
  <style>
    body { font-family: sans-serif; margin: 20px; }
    h2 { color: #333; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    .chart-container {
        display: flex;
        flex-wrap: wrap; /* Allows charts to wrap on smaller screens */
        gap: 40px;
        justify-content: center; /* Center charts when space allows */
        margin-bottom: 20px;
    }
    canvas {
        background-color: #fff;
        padding: 10px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
  </style>
</head>
<body>
<h2>Snort Dashboard</h2>
<p>Displaying last {{count}} alerts. Last updated: {{ current_time }}</p>
<div class="chart-container">
  <div><canvas id="barChart" width="450" height="250"></canvas></div>
  <div><canvas id="pieChart" width="300" height="300"></canvas></div>
</div>
<h3>Recent Alerts</h3>
<table border=1 cellpadding=4>
<tr><th>Time</th><th>Proto</th><th>Src</th><th>Dst</th><th>Message</th></tr>
{% for a in alerts %}
<tr><td>{{a.ts}}</td><td>{{a.proto}}</td><td>{{a.src}}</td><td>{{a.dst}}</td><td>{{a.msg}}</td></tr>
{% endfor %}
</table>
<script>
// Bar chart for top source IPs
new Chart(document.getElementById('barChart'), {
  type:'bar',
  data:{labels:{{ top_src|map(attribute=0)|list|tojson }},
        datasets:[{label:'Alerts by Source IP', data:{{ top_src|map(attribute=1)|list|tojson }},
                   backgroundColor:'rgba(54,162,235,0.7)',
                   borderColor:'rgba(54,162,235,1)',
                   borderWidth:1}]},
  options:{
      responsive:false,
      plugins:{legend:{display:false, position: 'top'}, title: {display: true, text: 'Top 10 Alerting Source IPs'}},
      scales: {
          y: { beginAtZero: true, title: { display: true, text: 'Number of Alerts' } },
          x: { title: { display: true, text: 'Source IP Address' } }
      }
  }
});
// Pie chart for protocols
new Chart(document.getElementById('pieChart'), {
  type:'pie',
  data:{labels:{{ proto_labels|tojson }},
        datasets:[{data:{{ proto_counts|tojson }},
                   backgroundColor:['#FF6384','#36A2EB','#FFCE56','#4BC0C0','#9966FF', '#FF9F40'],
                   hoverOffset: 4}]},
  options:{
      responsive:false,
      plugins:{legend:{position:'right'}, title: {display: true, text: 'Alerts by Protocol'}}
  }
});
</script>
</body>
</html>
"""

# Function to safely tail a file
def tail_file(path, n=MAX_LINES):
    try:
        if not os.path.exists(path):
            return []
        with open(path, 'r') as f:
            return f.read().splitlines()[-n:]
    except Exception as e:
        print(f"Error reading alert file: {e}")
        return []

# Function to parse alert lines
def parse_alerts(lines):
    parsed, srcs, protos = [], [], []
    for L in lines:
        m = line_re.search(L)
        if m:
            d = m.groupdict()
            parsed.append(d)
            srcs.append(d['src'])
            protos.append(d['proto'])
    return parsed, srcs, protos

@app.route('/')
def index():
    lines = tail_file(ALERT_FILE)
    parsed, srcs, protos = parse_alerts(lines)
    
    # Get top 10 source IPs
    top = Counter(srcs).most_common(10)
    
    # Get protocol counts
    proto_counts = Counter(protos)
    
    # Get current time for display
    from datetime import datetime
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return render_template_string(TEMPLATE,
        alerts=reversed(parsed), # Display newest alerts first in the table
        top_src=top,
        proto_labels=list(proto_counts.keys()),
        proto_counts=list(proto_counts.values()),
        count=len(parsed),
        current_time=current_time)

if __name__=="__main__":
    # Listen on 0.0.0.0 to be accessible from other hosts (e.g., your Windows machine if firewalled)
    # For local access only, use 127.0.0.1
    app.run(host="0.0.0.0", port=8080, debug=False) # Set debug=True for development
PY

sudo chmod +x /usr/local/bin/snort_dashboard.py
```

Install Flask and its dependencies:

```bash
sudo apt install python3-pip -y
sudo pip3 install flask
```

Run the dashboard application:

```bash
sudo /usr/local/bin/snort_dashboard.py
```

Now, open your web browser and navigate to: `http://127.0.0.1:8080` (or your Kali's IP address like `http://10.55.97.29:8080` if you changed the host to `0.0.0.0` in the script). 🚀

---

## 10. Configure Log Rotation (Optional but Recommended)

Log files, especially alert logs, can grow very large over time, consuming disk space and potentially impacting system performance. Log rotation is essential to manage these files by automatically compressing, deleting, or archiving them.

Create a new log rotate configuration file for Snort:

```bash
sudo nano /etc/logrotate.d/snort
```

Add the following configuration. This setup will rotate the `alert_fast.txt` file daily, compress old logs, keep them for 7 days, and create new log files after rotation.

```
/var/log/snort/alert_fast.txt {
    daily
    missingok
    rotate 7
    compress
    notifempty
    create 0640 root root
    postrotate
        # No specific action needed for Snort alerts after rotation,
        # as Snort will simply write to the new file.
        # If Snort were writing to a specific inode, we might need to restart it.
    endscript
}
```

---

## 11. (Optional) Run as Systemd Services

For production environments or persistent monitoring, it's best to run Snort, the auto-blocker, and the dashboard as systemd services. This ensures they start automatically at boot and can be easily managed.

**11.1. Snort Service: `/etc/systemd/system/snort.service`**

```bash
sudo tee /etc/systemd/system/snort.service > /dev/null <<'EOF'
[Unit]
Description=Snort 3 IDS
After=network.target

[Service]
ExecStartPre=/bin/mkdir -p /var/log/snort
ExecStartPre=/bin/chown root:root /var/log/snort
ExecStartPre=/bin/chmod 0755 /var/log/snort
ExecStart=/usr/bin/snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -i eth1 -A alert_fast -l /var/log/snort
Restart=on-failure
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
```

**11.2. Snort Blocker Service: `/etc/systemd/system/snort-blocker.service`**

```bash
sudo tee /etc/systemd/system/snort-blocker.service > /dev/null <<'EOF'
[Unit]
Description=Snort IP Blocker
After=snort.service
Requires=snort.service

[Service]
ExecStart=/usr/local/bin/block_on_alert.sh
Restart=on-failure
User=root # Needs root for iptables
Group=root

[Install]
WantedBy=multi-user.target
EOF
```

**11.3. Snort Dashboard Service: `/etc/systemd/system/snort-dashboard.service`**

```bash
sudo tee /etc/systemd/system/snort-dashboard.service > /dev/null <<'EOF'
[Unit]
Description=Snort Dashboard
After=network.target

[Service]
ExecStart=/usr/local/bin/snort_dashboard.py
Restart=on-failure
User=kali # Or your non-root user for the dashboard
Group=kali # Or your non-root user group

[Install]
WantedBy=multi-user.target
EOF
```

After creating these service files, reload the systemd manager configuration and enable them to start on boot:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now snort.service snort-blocker.service snort-dashboard.service
```

You can check the status of each service with `sudo systemctl status snort.service`, `sudo systemctl status snort-blocker.service`, and `sudo systemctl status snort-dashboard.service`.

---

✅ At this point you have a complete Snort IDS setup, including:

*   Snort 3 installed and running with custom rules
*   Alerts being written to a disk file (`/var/log/snort/alert_fast.txt`)
*   An automated IP blocker (in dry-run mode, ready for activation)
*   A local web-based dashboard with bar and pie charts for visual alert analysis
*   Proper log rotation configured to manage alert file growth
*   All components configured to run as persistent systemd services

This comprehensive guide should provide you with a powerful and manageable Snort IDS on your Kali Linux system!
