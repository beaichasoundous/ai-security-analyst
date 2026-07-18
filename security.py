DANGEROUS_PHRASES = [
    "ignore previous instructions",
    "forget your instructions",
    "you are now",
    "disregard your rules",
    "pretend you are",
    "bypass security",
    "ignore all rules"
]

def sanitize_input(log):
    log_lower = log.lower()
    for phrase in DANGEROUS_PHRASES:
        if phrase in log_lower:
            return None
    return log

def get_severity_score(analysis):
    analysis_upper = analysis.upper()
    if "CRITICAL" in analysis_upper:
        return {"level": "CRITICAL", "score": 10, "color": "🔴"}
    elif "HIGH" in analysis_upper:
        return {"level": "HIGH", "score": 7, "color": "🟠"}
    elif "MEDIUM" in analysis_upper:
        return {"level": "MEDIUM", "score": 4, "color": "🟡"}
    else:
        return {"level": "LOW", "score": 1, "color": "🟢"}
    
def detect_log_type(log):
    log_lower = log.lower()
    
    if "ssh" in log_lower:
        return "SSH"
    elif "http" in log_lower:
        return "HTTP"
    elif "firewall" in log_lower:
        return "FIREWALL"
    elif "drop table" in log_lower:
        return "SQL"
    else:
        return "UNKNOWN"