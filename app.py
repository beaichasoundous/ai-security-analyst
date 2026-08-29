from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from ai import analyze,reset_memory ,analyze_with_tools
from storage import save_threat, get_all_threats
from security import sanitize_input, get_severity_score


app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────
# PAGE ROUTES
# ─────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/history-page')
def history_page():
    return render_template('history.html')

# ─────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────

@app.route('/api/analyze', methods=['POST'])
def analyze_log():
    data = request.json
    log = data.get("log", "")

    if not log:
        return jsonify({
            "success": False,
            "error": "No log provided"
        }), 400

    clean_log = sanitize_input(log)
    if clean_log is None:
        return jsonify({
            "success": False,
            "error": "⚠️ Prompt injection attempt detected and blocked!"
        }), 400

    result = analyze_with_tools(clean_log)
    severity = get_severity_score(result)
    save_threat(log, result, severity)

    return jsonify({
        "success": True,
        "analysis": result,
        "severity": severity
    })


@app.route('/api/history', methods=['GET'])
def history():
    threats = get_all_threats()
    return jsonify({
        "success": True,
        "count": len(threats),
        "threats": threats
    })


@app.route('/api/reset', methods=['POST'])
def reset():
    reset_memory()
    return jsonify({
        "success": True,
        "message": "Memory cleared ✓"
    })


if __name__ == '__main__':
    app.run(port=5000, debug=True)