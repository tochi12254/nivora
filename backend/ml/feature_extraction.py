import math

def safe_get(d, *keys, default=None):
    """Safely get nested dictionary values."""
    for key in keys:
        if isinstance(d, dict) and key in d:
            d = d[key]
        else:
            return default
    return d

def extract_http_features(packet):
    return {
        "missing_csp": int(safe_get(packet, "header_analysis", "security_headers", "missing_csp", default=False)),
        "rapid_requests": int(safe_get(packet, "behavioral_indicators", "unusual_timing", "rapid_requests", default=False)),
        "unusual_casing": int(safe_get(packet, "header_analysis", "header_manipulation", "unusual_casing", default=False)),
        "invalid_format": int(safe_get(packet, "header_analysis", "header_manipulation", "invalid_format", default=False)),
        "entropy": safe_get(packet, "payload_characteristics", "entropy", default=0.0),
        "packet_size": safe_get(packet, "network_metrics", "packet_size", default=0),
        "inter_arrival_time": safe_get(packet, "network_metrics", "inter_arrival_time", default=0.0),
        "window_ratio": safe_get(packet, "tcp_metrics", "seq_analysis", "window_ratio", default=0.0),
        "tcp_flags_ack": int(safe_get(packet, "tcp_metrics", "flags", "ack", default=False)),
        "tcp_flags_syn": int(safe_get(packet, "tcp_metrics", "flags", "syn", default=False)),
        "tcp_flags_fin": int(safe_get(packet, "tcp_metrics", "flags", "fin", default=False)),
        "http_method_null": int(packet.get("method") is None),
        "host_null": int(packet.get("host") is None),
        "path_null": int(packet.get("path") is None),
        "threat_score": safe_get(packet, "threat_analysis", "threat_score", default=0),
    }

def extract_system_features(telemetry):
    cpu_usage = safe_get(telemetry, "cpu", "usage", default=0.0)
    mem_percent = safe_get(telemetry, "memory", "percent", default=0.0)
    swap_percent = safe_get(telemetry, "memory", "swap", "percent", default=0.0)
    disk_read = safe_get(telemetry, "disk", "io", "read_bytes", default=0)
    disk_write = safe_get(telemetry, "disk", "io", "write_bytes", default=0)
    net_recv = safe_get(telemetry, "network", "io", "bytes_recv", default=0)
    net_sent = safe_get(telemetry, "network", "io", "bytes_sent", default=0)
    
    return {
        "cpu_usage": cpu_usage,
        "mem_percent": mem_percent,
        "swap_percent": swap_percent,
        "disk_read_mb": disk_read / (1024 ** 2),
        "disk_write_mb": disk_write / (1024 ** 2),
        "net_recv_mb": net_recv / (1024 ** 2),
        "net_sent_mb": net_sent / (1024 ** 2),
        "arp_count": len(safe_get(telemetry, "network", "arp_table", default=[])),
        "established_conns": sum(1 for c in safe_get(telemetry, "network", "connections", default=[]) if c.get("status") == "ESTABLISHED"),
        "interface_count": len(safe_get(telemetry, "network", "interfaces", default=[])),
    }

def extract_process_features(telemetry):
    processes = telemetry.get("processes", [])
    top_cpu = sorted(processes, key=lambda p: p.get("cpu", 0), reverse=True)[:3]
    top_mem = sorted(processes, key=lambda p: p.get("memory", 0), reverse=True)[:3]

    return {
        "top_cpu_1": top_cpu[0]["cpu"] if len(top_cpu) > 0 else 0,
        "top_cpu_2": top_cpu[1]["cpu"] if len(top_cpu) > 1 else 0,
        "top_cpu_3": top_cpu[2]["cpu"] if len(top_cpu) > 2 else 0,
        "top_mem_1": top_mem[0]["memory"] if len(top_mem) > 0 else 0,
        "top_mem_2": top_mem[1]["memory"] if len(top_mem) > 1 else 0,
        "top_mem_3": top_mem[2]["memory"] if len(top_mem) > 2 else 0,
        "suspicious_proc_count": sum(1 for p in processes if p.get("suspicious", False)),
        "unsigned_proc_count": sum(1 for p in processes if not p.get("signed", True)),
    }

def extract_features_from_all(data: dict) -> dict:
    """
    Central extraction dispatcher for telemetry + packet data.
    Assumes keys like 'type': 'http_activity' or 'system_telemetry'.
    """
    kind = data.get("type")

    if kind == "http_activity":
        return extract_http_features(data)
    elif kind == "system_telemetry":
        sys_features = extract_system_features(data)
        proc_features = extract_process_features(data)
        return {**sys_features, **proc_features}
    else:
        return {}  # Unknown type


from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.preprocessing import StandardScaler, MinMaxScaler
import numpy as np
import pandas as pd

# ====================
# Custom Transformers
# ====================


class SystemMetricsExtractor(BaseEstimator, TransformerMixin):
    """Extract core system metrics"""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = {
            # CPU Features
            "cpu_usage": X["cpu"]["usage"],
            "cpu_load_1min": X["cpu"]["load_avg"][0] if X["cpu"]["load_avg"] else 0,
            "cpu_user_time": X["cpu"]["times"]["user"],
            # Memory Features
            "mem_used_pct": X["memory"]["percent"],
            "swap_used_pct": X["memory"]["swap"]["percent"],
            # Disk Features
            "disk_io_read": X["disk"]["io"]["read_bytes"],
            "disk_io_write": X["disk"]["io"]["write_bytes"],
            "disk_used_pct": X["disk"]["partitions"][0]["percent"],
            # Network Features
            "net_connections": len(X["network"]["connections"]),
            "net_bytes_sent": X["network"]["io"]["bytes_sent"],
            "dns_cache_size": len(X["network"]["dns_cache"]),
        }
        return pd.DataFrame([features])


class ProcessMetricsExtractor(BaseEstimator, TransformerMixin):
    """Extract process-related features"""

    def __init__(self, top_n=5):
        self.top_n = top_n

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        procs = X["processes"]

        # Process statistics
        features = {
            "proc_count": len(procs),
            "suspicious_procs": sum(p["suspicious"] for p in procs),
            "unsigned_binaries": sum(1 for p in procs if not p["signed"]),
            # Top memory consumers
            "top_mem_procs": ",".join(
                [
                    p["name"]
                    for p in sorted(procs, key=lambda x: x["memory"], reverse=True)[
                        : self.top_n
                    ]
                ]
            ),
            # CPU utilization distribution
            "cpu_util_q90": np.quantile([p["cpu"] for p in procs], 0.9),
        }
        return pd.DataFrame([features])


class SecurityFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extract security-related features"""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        sec = X["security"]
        return pd.DataFrame(
            [
                {
                    "firewall_active": sec["firewall"],
                    "pending_updates": sec["updates"],
                    "anomaly_count": len(X["anomalies"]),
                }
            ]
        )


class TemporalFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extract time-based features"""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return pd.DataFrame(
            [
                {
                    "uptime_hours": X["system"]["uptime"] / 3600,
                    "hours_since_boot": (
                        pd.Timestamp.now() - pd.to_datetime(X["system"]["boot_time"])
                    ).total_seconds()
                    / 3600,
                }
            ]
        )


# ====================
# Pipeline Assembly
# ====================

feature_pipeline = Pipeline(
    [
        (
            "feature_union",
            FeatureUnion(
                [
                    ("system", SystemMetricsExtractor()),
                    ("process", ProcessMetricsExtractor()),
                    ("security", SecurityFeatureExtractor()),
                    ("temporal", TemporalFeatureExtractor()),
                ]
            ),
        ),
        (
            "post_processing",
            Pipeline(
                [
                    ("imputer", SimpleImputer(strategy="constant", fill_value=0)),
                    ("scaler", MinMaxScaler(feature_range=(0, 1))),
                ]
            ),
        ),
    ]
)

# ====================
# Example Usage
# ====================

if __name__ == "__main__":
    # Sample input data structure (using your provided format)
    sample_data = {...}  # Your monitoring data here

    # Transform data
    features = feature_pipeline.fit_transform(sample_data)

    # Get feature names
    feature_names = feature_pipeline.named_steps[
        "feature_union"
    ].get_feature_names_out()

    # Create DataFrame
    df = pd.DataFrame(features, columns=feature_names)
    print(df.head())

# ====================
# Feature Documentation
# ====================
"""
Generated Features:
1. System Metrics:
   - cpu_usage: Current CPU utilization percentage
   - cpu_load_1min: 1-minute load average
   - cpu_user_time: User-space CPU time
   - mem_used_pct: Memory usage percentage
   - swap_used_pct: Swap space usage percentage
   - disk_io_read: Bytes read from disk
   - disk_io_write: Bytes written to disk
   - disk_used_pct: Main partition usage
   - net_connections: Active network connections
   - net_bytes_sent: Network bytes sent
   - dns_cache_size: DNS cache entries

2. Process Metrics:
   - proc_count: Total running processes
   - suspicious_procs: Known suspicious processes
   - unsigned_binaries: Unsigned executables
   - top_mem_procs: Top 5 memory-consuming processes
   - cpu_util_q90: 90th percentile CPU usage

3. Security Features:
   - firewall_active: Firewall status
   - pending_updates: Available system updates
   - anomaly_count: Active anomalies

4. Temporal Features:
   - uptime_hours: System uptime duration
   - hours_since_boot: Time since last boot
"""
