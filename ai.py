import os
from groq import Groq
from dotenv import load_dotenv
from security import sanitize_input, get_severity_score, detect_log_type

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

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

Always structure your response like this:
⚠️ THREAT LEVEL: [level]
🔍 WHAT I FOUND: [explanation]
🛡️ RECOMMENDATIONS: [action steps]
"""

def analyze(log):
    try:
        
        log_type = detect_log_type(log)

        extra = LOG_PROMPTS.get(log_type,"")

        enhanced_prompt = system_prompt + "\n\nLog type:" + log_type + "\nExtra Focus: " + extra
        
        chat_history.append({
            "role": "user",
            "content": f"Analyze this network log:\n{log}"
        })

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": enhanced_prompt}
            ] + chat_history
        )

        result = response.choices[0].message.content

        chat_history.append({
            "role": "assistant",
            "content": result
        })
        
        return result
    
        

    except Exception as e:
        print(f"Error analyzing log: {e}")
        return None

def reset_memory():
    chat_history.clear()

