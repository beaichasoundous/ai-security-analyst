import os
import ollama
from dotenv import load_dotenv
from security import sanitize_input, get_severity_score, detect_log_type
from mcpServer import read_log_file, search_web, lookup_ip, write_report
from rag import search_threats, add_threat

load_dotenv()

chat_history = []

LOG_PROMPTS = {
    "SSH": "Focus on brute force attacks, failed login attempts, and unauthorized access",
    "HTTP": "Focus on too many requests from same IP, suspicious URLs, web attacks, weird headers and DDoS patterns",
    "SQL": "Watch for SQL commands like DROP TABLE, UNION SELECT, and any commands that can lead to data theft or unauthorized access",
    "FIREWALL": "Scan for port scanning activity, blocked connections, suspicious IPs and unauthorized ports"
}


system_prompt = """
You are an expert network security analyst with 10 years of experience.
When given a network log you must:
1. Identify any threats or suspicious activity
2. Rate the severity (LOW, MEDIUM, HIGH, CRITICAL)
3. Explain what the threat is in simple terms
4. Give concrete recommendations to fix it

CRITICAL SEVERITY RULES - follow these exactly:
- if log shows successful login after failed attempts → CRITICAL
- if attacker gained root access → CRITICAL
- if data was stolen or accessed → CRITICAL
- if system was compromised → CRITICAL

HIGH SEVERITY RULES:
- multiple failed login attempts without success → HIGH
- port scanning detected → HIGH
- DDoS attack detected → HIGH

MEDIUM SEVERITY RULES:
- single suspicious request → MEDIUM
- unusual traffic pattern → MEDIUM

LOW SEVERITY RULES:
- single failed login → LOW
- minor suspicious activity → LOW

Always structure your response like this:
⚠️ THREAT LEVEL: [level]
🔍 WHAT I FOUND: [explanation]
🛡️ RECOMMENDATIONS: [action steps]

"""

def analyze(log):
    try:
        log_type = detect_log_type(log)
        extra = LOG_PROMPTS.get(log_type, "")

        # search RAG for similar past threats
        rag_results = search_threats(log)
        similar_threats = rag_results['documents'][0]
        rag_context = "\n".join(similar_threats)

        # build enhanced prompt with RAG context
        enhanced_prompt = system_prompt + f"""
\n\nLog Type: {log_type}
Extra Focus: {extra}

Similar past threats from our database:
{rag_context}

Use these similar threats as context for your analysis.
"""
        chat_history.append({
            "role": "user",
            "content": f"Analyze this network log:\n{log}"
        })

        # use Ollama instead of Groq
        response = ollama.chat(
            model="llama3.2:3b",
            messages=[
                {"role": "system", "content": enhanced_prompt}
            ] + chat_history
        )

        result = response['message']['content']

        chat_history.append({
            "role": "assistant",
            "content": result
        })

        # save to RAG database
        add_threat([log], [f"threat_{len(chat_history)}"])

        return result

    except Exception as e:
        print(f"Error analyzing log: {e}")
        return None


def analyze_with_tools(message):
    if ".log" in message or ".txt" in message:
        words = message.split()
        file_path = None
        for word in words:
            if ".log" in word or ".txt" in word:
                file_path = word
                break
        content = read_log_file(file_path)
        return analyze(content)

    elif "ip" in message.lower():
        words = message.split()
        for word in words:
            if word.count(".") == 3:
                result = lookup_ip(word)
                print("lookup result:", result)
                ip_report = f"""
Analyze this IP address threat intelligence report:

IP Address: {result.get('ip')}
Abuse Confidence Score: {result.get('abuse_score')}/100
Country: {result.get('country')}
ISP: {result.get('isp', 'Unknown')}
Total Reports: {result.get('total_reports')}
Is Tor Exit Node: {result.get('is_tor')}
Hostnames: {result.get('hostname')}
Last Reported: {result.get('last_reported')}

Based on this real threat intelligence data, provide a detailed security analysis.
"""
                return analyze(ip_report)

    else:
        return analyze(message)


def reset_memory():
    chat_history.clear()