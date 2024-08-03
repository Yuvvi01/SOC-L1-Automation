import os
import spacy
import re
import requests
from openai import OpenAI
from fpdf import FPDF
from transformers import AutoTokenizer, AutoModelForCausalLM
from typing import List, Dict, Tuple
from sklearn.metrics import precision_score, recall_score, f1_score
import hashlib
from collections import defaultdict

# Load OpenAI API key from environment variable
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("Missing OpenAI API key. Please set the 'OPENAI_API_KEY' environment variable.")

client = OpenAI(api_key=api_key)

# Initialize spaCy English model
nlp = spacy.load("en_core_web_sm")

# Simulated feedback storage and metrics data
feedback_data = []
metrics_data = []

# Define general, security-specific, and other log-related keywords
GENERAL_KEYWORDS = ["timestamp", "log_level", "message", "source", "event_id", "user_id", "session_id", "host", "process_id", "thread_id", "status"]
COMPUTER_LOGS_KEYWORDS = ["cpu_usage", "memory_usage", "disk_usage", "network_activity", "application_name", "file_path", "registry_key", "error_code"]
CLOUD_LOGS_KEYWORDS = ["cloud_provider", "service_name", "region", "resource_id", "api_call", "response_time", "request_id", "account_id"]
O365_LOGS_KEYWORDS = ["operation", "workload", "client_ip", "user_agent", "organization_id", "object_id", "result_status", "affected_user"]
SECURITY_KEYWORDS = ["alert_id", "threat_level", "indicator_type", "indicator_value", "action_taken", "source_ip", "destination_ip", "protocol", "port"]

# Aggregate all keywords into one list for easier processing
ALL_KEYWORDS = GENERAL_KEYWORDS + COMPUTER_LOGS_KEYWORDS + CLOUD_LOGS_KEYWORDS + O365_LOGS_KEYWORDS + SECURITY_KEYWORDS

# Dynamic Severity Assessment
def assess_severity(alert_content: Dict) -> str:
    if "Administrator" in alert_content['Alert']:
        return "High"
    elif "Failed Login" in alert_content['Alert']:
        return "Medium"
    else:
        return "Low"

# Context-Aware Analysis
def analyze_security_log(alert_content: Dict, model: str) -> Dict:
    severity = assess_severity(alert_content)
    alert_decision = "Actionable" if severity in ["High", "Medium"] else "Non-Actionable"
    
    analyst_comments = [
        f"- This alert indicates {severity} severity, suggesting a potential security risk.",
        f"- The event was triggered from IP address {alert_content['Source IP']} targeting {alert_content['Destination IP']}.",
        "Immediate action is recommended." if alert_decision == "Actionable" else "Further investigation is recommended."
    ]
    
    return {
        "alert_name": alert_content['Alert'],
        "severity": severity,
        "alert_decision": alert_decision,
        "endpoint_name": alert_content['Hostname'],
        "short_description": f"{alert_content['Alert']} detected from {alert_content['Source IP']} to {alert_content['Destination IP']}.",
        "analyst_comments": "\n".join(analyst_comments),
        "verifications_required": "Check server logs for unauthorized access or misconfiguration.",
        "next_steps": "Investigate further and apply necessary mitigations." if alert_decision == "Actionable" else "Monitor the situation.",
        "team_name": "SOC Team"
    }

# Hybrid Model Integration
def process_alert_with_hybrid_model(alert_content: Dict) -> Dict:
    gpt4_result = process_alert_with_gpt4(alert_content)
    llama3_result = process_alert_with_llama3_local(alert_content)
    
    # Combine the insights
    combined_result = {
        "alert_name": gpt4_result["alert_name"],
        "severity": max(gpt4_result["severity"], llama3_result["severity"]),
        "alert_decision": gpt4_result["alert_decision"] if gpt4_result["alert_decision"] == "Actionable" else llama3_result["alert_decision"],
        "endpoint_name": gpt4_result["endpoint_name"],
        "short_description": gpt4_result["short_description"],
        "analyst_comments": gpt4_result["analyst_comments"] + "\n\n" + llama3_result["analyst_comments"],
        "verifications_required": gpt4_result["verifications_required"],
        "next_steps": gpt4_result["next_steps"],
        "team_name": gpt4_result["team_name"]
    }
    
    return combined_result

# GPT-4 Processing Function
def process_alert_with_gpt4(alert_content: Dict) -> Dict:
    response = client.Completions.create(
        model="gpt-4",
        prompt=f"Analyze the following alert: {alert_content}",
        max_tokens=500
    )
    generated_text = response.choices[0].text.strip()

    return {
        "alert_name": alert_content['Alert'],
        "severity": "High",
        "alert_decision": "Actionable",
        "endpoint_name": alert_content['Hostname'],
        "short_description": generated_text,
        "analyst_comments": f"Generated using GPT-4 analysis.\n{generated_text}",
        "verifications_required": "Check server logs for unauthorized access or misconfiguration.",
        "next_steps": "Investigate further and apply necessary mitigations.",
        "team_name": "SOC Team"
    }

# GPT-3.5 Processing Function
def process_alert_with_gpt35(alert_content: Dict) -> Dict:
    response = client.Completions.create(
        model="gpt-3.5-turbo",
        prompt=f"Analyze the following alert: {alert_content}",
        max_tokens=500
    )
    generated_text = response.choices[0].text.strip()

    return {
        "alert_name": alert_content['Alert'],
        "severity": "Medium",
        "alert_decision": "Non-Actionable",
        "endpoint_name": alert_content['Hostname'],
        "short_description": generated_text,
        "analyst_comments": f"Generated using GPT-3.5 analysis.\n{generated_text}",
        "verifications_required": "Review logs for anomalies and potential misconfigurations.",
        "next_steps": "Monitor the situation and ensure task disabling was intentional.",
        "team_name": "SOC Team"
    }

# LLaMA-3 Processing Function
def process_alert_with_llama3_local(alert_content: Dict) -> Dict:
    tokenizer = AutoTokenizer.from_pretrained("meta/llama-3")
    model = AutoModelForCausalLM.from_pretrained("meta/llama-3")

    inputs = tokenizer(alert_content['Alert'], return_tensors="pt")
    outputs = model.generate(**inputs)
    generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)

    return {
        "alert_name": alert_content['Alert'],
        "severity": "High",
        "alert_decision": "Actionable",
        "endpoint_name": alert_content['Hostname'],
        "short_description": generated_text,
        "analyst_comments": f"Generated using LLaMA-3 analysis.\n{generated_text}",
        "verifications_required": "Investigate network traffic logs and check for unauthorized access.",
        "next_steps": "Isolate affected systems and conduct a thorough investigation.",
        "team_name": "SOC Team"
    }

# Continuous Learning with Feedback Loop
def update_model_with_feedback(feedback: List[Dict]):
    for item in feedback:
        if item['correct_decision'].lower() == 'no':
            print(f"Model {item['model']} needs adjustment for alert {item['alert_id']}.")
            # Add logic to update model parameters or retrain here
        else:
            print(f"Model {item['model']} performed well for alert {item['alert_id']}.")

# Perform Advanced Analytics
def perform_advanced_analytics(results: List[tuple]):
    y_true = []
    y_pred = []
    for model, alert_info in results:
        true_label = "Actionable"  # This would be the actual label from SOC
        predicted_label = alert_info["alert_decision"]
        y_true.append(true_label)
        y_pred.append(predicted_label)

    precision = precision_score(y_true, y_pred, pos_label="Actionable")
    recall = recall_score(y_true, y_pred, pos_label="Actionable")
    f1 = f1_score(y_true, y_pred, pos_label="Actionable")

    metrics = {
        "model": model,
        "precision": precision,
        "recall": recall,
        "f1_score": f1
    }
    metrics_data.append(metrics)

    print(f"Advanced Analytics for {model}:")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    print(f"F1-Score: {f1:.2f}\n")

# Generate PDF Report
def generate_pdf_report(results: List[tuple]):
    for model, alert_info in results:
        pdf = FPDF()
        pdf.add_page()

        # Subject line: [Alert Name] | [Severity] | [Actionable/ Non-Actionable] | [Endpoint Name]
        alert_name = alert_info.get("alert_name", "Unknown Alert")
        severity = alert_info.get("severity", "Unknown Severity")
        actionability = alert_info.get("alert_decision", "Unknown Decision")
        endpoint_name = alert_info.get("endpoint_name", "Unknown Endpoint")
                subject_line = f"Subject: {alert_name} | {severity} | {actionability} | {endpoint_name}"

        # Short description
        short_description = alert_info.get("short_description", "No description available.")

        # Security Alert Details
        soc_analyst_comments = alert_info.get("analyst_comments", "No comments provided.")
        verifications_required = alert_info.get("verifications_required", "No verifications listed.")
        recommended_next_steps = alert_info.get("next_steps", "No recommendations provided.")
        team_name = alert_info.get("team_name", "SOC Team")

        # Add content to PDF
        pdf.set_font("Helvetica", size=12)
        pdf.multi_cell(0, 10, subject_line, align="L")
        pdf.ln(10)

        pdf.cell(0, 10, "Hi Team,", ln=True, align="L")
        pdf.ln(5)
        pdf.multi_cell(0, 10, short_description, align="L")
        pdf.ln(10)

        pdf.cell(0, 10, "Security Alert Details:", ln=True, align="L")
        pdf.ln(5)

        pdf.cell(0, 10, "SOC Analyst Triage Comments:", ln=True, align="L")
        pdf.multi_cell(0, 10, soc_analyst_comments, align="L")
        pdf.ln(5)

        pdf.cell(0, 10, "Verifications Required:", ln=True, align="L")
        pdf.multi_cell(0, 10, verifications_required, align="L")
        pdf.ln(5)

        pdf.cell(0, 10, "Recommended Next Steps:", ln=True, align="L")
        pdf.multi_cell(0, 10, recommended_next_steps, align="L")
        pdf.ln(10)

        # Check for hallucination warnings and add to the report
        if "hallucination_warning" in alert_info:
            pdf.set_text_color(255, 0, 0)
            pdf.multi_cell(0, 10, f"Warning: {alert_info['hallucination_warning']}", align="L")
            pdf.set_text_color(0, 0, 0)
            pdf.ln(10)

        pdf.multi_cell(0, 10, f"Sincerely,\n{team_name}", align="L")
        pdf.ln(10)

        # Write the PDF to a file
        pdf_output_path = f"report_{model}.pdf"
        pdf.output(pdf_output_path)
        print(f"PDF report generated successfully at {pdf_output_path}")

# Collect Feedback
def collect_feedback(results: List[tuple]) -> List[Dict]:
    feedback = []
    for model, alert_info in results:
        feedback_item = {
            "model": model,
            "alert_id": alert_info.get("alert_name"),
            "correct_decision": input(f"Was the alert decision '{alert_info['alert_decision']}' by {model} correct? (yes/no): "),
            "comments": input(f"Any additional comments on the alert processed by {model}? ")
        }
        feedback.append(feedback_item)
    return feedback

# Analyze the sampled logs using the models
def analyze_logs(sampled_logs):
    reports = []
    for _, log in sampled_logs.iterrows():
        processed_info_hybrid = process_alert_with_hybrid_model(log)
        reports.append(processed_info_hybrid)
    return reports

# Run the analysis on sampled logs
def main():
    # Assume `security_logs` is already loaded and we sample 10 logs for analysis
    sampled_logs = security_logs.sample(10, random_state=42)
    detailed_reports = analyze_logs(sampled_logs)

    # Generate and save PDF reports
    for report in detailed_reports:
        generate_pdf_report([(report['alert_name'], report)])

    # Collect feedback from SOC analysts
    feedback = collect_feedback([(report['alert_name'], report) for report in detailed_reports])
    update_model_with_feedback(feedback)

    # Perform advanced analytics on the results
    perform_advanced_analytics([(report['alert_name'], report) for report in detailed_reports])

# Run the main function
if __name__ == "__main__":
    main()

