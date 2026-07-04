import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

THREATS_FILE = os.path.join(os.path.expanduser("~"), "threats.json")

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

def save_threat(log, analysis):
    threat = {
        "timestamp": str(datetime.now()),
        "log": log,
        "analysis": analysis
    }
    with open(THREATS_FILE, "a") as f:
        f.write(json.dumps(threat) + "\n")

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

# serve frontend
@app.route('/')
def home():
    return render_template('index.html')

def analyze_log():
    data = request.json
    log = data.get("log", "")

    if not log:
        return jsonify({"error": "No log provided"}), 400

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this network log:\n{log}"}
        ]
    )

    result = response.choices[0].message.content
    save_threat(log, result)
    return jsonify({"analysis": result})

@app.route('/analyze', methods=['POST'])
def analyze_log():
    data = request.json
    log = data.get("log", "")

    if not log:
        return jsonify({"error": "No log provided"}), 400

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this network log:\n{log}"}
        ]
    )

    result = response.choices[0].message.content
    severity = get_severity_score(result)
    save_threat(log, result)

    return jsonify({
        "analysis": result,
        "severity": severity
    })

if __name__ == '__main__':
    app.run(port=5000, debug=True)