import os
from unittest import expectedFailure, result
from flask import request
from datetime import datetime
import requests

from dotenv import load_dotenv

load_dotenv()
def read_log_file(file_path):
   if not os.path.exists(file_path):
    raise fileNotFoundedError(f"file{file_path} does not exists")

   with open(file_path, 'r') as file :
    return file.read()

def search_web(query):
    try:
        url = "https://api.duckduckgo.com/"
        params = {
            "q": query,
            "format": "json"
        }
        response = requests.get(url, params=params)
        data = response.json()
        
        results = []

        if data.get("AbstractText"):
            results.append(data["AbstractText"])

        for topic in data.get("RelatedTopics", []):
            if "Text" in topic:
                results.append(topic["Text"])

        
        if results:
            return "\n".join(results)
        else:
            return "No results found"
        
        return data
    except Exception as e:
        print(f"Error searching web: {e}")
        return None

def lookup_ip(ip_address):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check"
        method = GET
        headers = {
            "Key": os.getenv("ABUSEIPDB_KEY"),
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }

        request = request.get(url, headers=headers, params=params)
        data = request.json()
        result = data.get("data", {})
        return {
            "ip": ip,
            "abuse_score": result.get(data.abuse_score),
            "isp": result.get("isp"), 
            "country": result.get(data.country),
            "total_reports": result.get(data.total_reports)
        }
    except Exception as e:
        print(f"Error looking up IP: {e}")
        return None


def lookup_ip(ip_address):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": os.getenv("ABUSEIPDB_KEY"),
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }

        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        print("AbuseIPDB response:", data) 
        result = data.get("data", {})
        
        return {
            "ip": ip_address,
            "abuse_score": result.get("abuseConfidenceScore"),
            "country": result.get("countryCode"),
            "total_reports": result.get("totalReports")
        }
    except Exception as e:
        print(f"Error looking up IP: {e}")
        return None

def write_report(report_content, file_name="security_report.txt"):
    try:
        timestamp=datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        full_content= f"Security Report - {timestamp}\n\n{report_content}\n"
        path = os.path.join("reports", file_name)
        with open(path, "w") as file:
            file.write(full_content)
            return f"Report saved to {path}"
    except Exception as e:
        return(f"Erooro writing report: {e}")
        