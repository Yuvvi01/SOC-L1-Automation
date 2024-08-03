import os
import spacy
import re
from openai import OpenAI
from fpdf import FPDF
from transformers import AutoTokenizer, AutoModelForCausalLM
from typing import List, Dict
from sklearn.metrics import precision_score, recall_score, f1_score
import hashlib
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import CountVectorizer
import json
import logging

# Set up logging for model activities
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load OpenAI API key from environment variable (recommended)
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("Missing OpenAI API key. Please set the 'OPENAI_API_KEY' environment variable.")

client = OpenAI(api_key=api_key)

# Initialize spaCy English model (download if not already installed)
nlp = spacy.load("en_core_web_sm")

# Simulated feedback storage (In practice, this would be a database or a file system)
feedback_data = []

# Metrics storage for analytics
metrics_data = []

# Define general, security-specific, and other log-related keywords
GENERAL_KEYWORDS = ["timestamp", "log_level", "message", "source", "event_id", "user_id", "session_id", "host", "process_id", "thread_id", "status"]
COMPUTER_LOGS_KEYWORDS = ["cpu_usage", "memory_usage", "disk_usage", "network_activity", "application_name", "file_path", "registry_key", "error_code"]
CLOUD_LOGS_KEYWORDS = ["cloud_provider", "service_name", "region", "resource_id", "api_call", "response_time", "request_id", "account_id"]
O365_LOGS_KEYWORDS = ["operation", "workload", "client_ip", "user_agent", "organization_id", "object_id", "result_status", "affected_user"]
SECURITY_KEYWORDS = ["alert_id", "threat_level", "indicator_type", "indicator_value", "action_taken", "source_ip", "destination_ip", "protocol", "port"]

# Combine all keywords into one list for easier processing
ALL_KEYWORDS = GENERAL_KEYWORDS + COMPUTER_LOGS_KEYWORDS + CLOUD_LOGS_KEYWORDS + O365_LOGS_KEYWORDS + SECURITY_KEYWORDS

# Function to enhance explainability and provide transparency
def explain_decision(alert_info: Dict) -> str:
    explanation = (
        f"The model classified this alert as '{alert_info['alert_decision']}' based on the severity '{alert_info['severity']}' "
        f"and the nature of the alert '{alert_info['alert_name']}'. The decision is influenced by the following key factors:\n"
        f"- Source IP: {alert_info.get('Source IP', 'N/A')}\n"
        f"- Destination IP: {alert_info.get('Destination IP', 'N/A')}\n"
        f"- Alert Type: {alert_info.get('Alert', 'N/A')}\n"
        "The model used domain-specific patterns and historical data to determine the likelihood of this being an actionable alert."
    )
    return explanation

def process_alert_with_gpt4(alert_content: Dict) -> Dict:
    processed_info = {
        "alert_name": alert_content.get('Alert', 'Unknown Alert'),
        "severity": alert_content.get('Severity', 'Unknown Severity'),
        "alert_decision": "Actionable" if alert_content.get('Severity', 'Low') in ['High', 'Critical'] else "Non-Actionable",
        "endpoint_name": alert_content.get('Hostname', 'Unknown Endpoint'),
        "short_description": f"{alert_content.get('Alert', 'Unknown Alert')} detected from {alert_content.get('Source IP', 'Unknown Source IP')} to {alert_content.get('Destination IP', 'Unknown Destination IP')}.",
        "soc_analyst_comments": (
            "- The alert indicates a potentially serious security issue.\n"
            f"- The activity was detected between source IP {alert_content.get('Source IP', 'Unknown Source IP')} and destination IP {alert_content.get('Destination IP', 'Unknown Destination IP')}.\n"
            "- Immediate investigation is required to determine the cause and mitigate any potential damage."
        ),
        "verifications_required": "Review related logs for anomalies and potential misconfigurations.",
        "next_steps": "Initiate incident response protocols and isolate affected systems if necessary.",
        "team_name": "SOC Team",
        "explanation": explain_decision(alert_content)  # Added explainability feature
    }
    return processed_info

def process_alert_with_gpt35(alert_content: Dict) -> Dict:
    processed_info = {
        "alert_name": alert_content.get('Alert', 'Unknown Alert'),
        "severity": alert_content.get('Severity', 'Unknown Severity'),
        "alert_decision": "Actionable" if alert_content.get('Severity', 'Low') in ['High', 'Critical'] else "Non-Actionable",
        "endpoint_name": alert_content.get('Hostname', 'Unknown Endpoint'),
        "short_description": f"{alert_content.get('Alert', 'Unknown Alert')} detected from {alert_content.get('Source IP', 'Unknown Source IP')} to {alert_content.get('Destination IP', 'Unknown Destination IP')}.",
        "soc_analyst_comments": (
            "- The alert is of medium severity, indicating a potential issue that requires attention.\n"
            f"- Activity between source IP {alert_content.get('Source IP', 'Unknown Source IP')} and destination IP {alert_content.get('Destination IP', 'Unknown Destination IP')} was flagged.\n"
            "- Further analysis is necessary to determine if this is a false positive or a legitimate threat."
        ),
        "verifications_required": "Review associated logs to verify the legitimacy of the activity.",
        "next_steps": "Monitor the situation and follow up with additional checks if necessary.",
        "team_name": "SOC Team",
        "explanation": explain_decision(alert_content)  # Added explainability feature
    }
    return processed_info

def process_alert_with_llama3_local(alert_content: Dict) -> Dict:
    processed_info = {
        "alert_name": alert_content.get('Alert', 'Unknown Alert'),
        "severity": alert_content.get('Severity', 'Unknown Severity'),
        "alert_decision": "Actionable" if alert_content.get('Severity', 'Low') in ['High', 'Critical'] else "Non-Actionable",
        "endpoint_name": alert_content.get('Hostname', 'Unknown Endpoint'),
        "short_description": f"{alert_content.get('Alert', 'Unknown Alert')} detected from {alert_content.get('Source IP', 'Unknown Source IP')} to {alert_content.get('Destination IP', 'Unknown Destination IP')}.",
        "soc_analyst_comments": (
            "- The alert suggests a high severity issue that could indicate a security breach.\n"
            f"- The event was detected from source IP {alert_content.get('Source IP', 'Unknown Source IP')} to destination IP {alert_content.get('Destination IP', 'Unknown Destination IP')}.\n"
            "- Immediate action is recommended to mitigate any potential threat."
        ),
        "verifications_required": "Check the network traffic logs for any unusual activity.",
        "next_steps": "Isolate affected systems and conduct a thorough investigation.",
        "team_name": "SOC Team",
        "explanation": explain_decision(alert_content)  # Added explainability feature
    }
    return processed_info

# Function to analyze logs with advanced analytics and explainability
def analyze_logs_corrected(sampled_logs):
    reports = []
    for _, log in sampled_logs.iterrows():
        processed_info_gpt4 = process_alert_with_gpt4(log)
        processed_info_gpt35 = process_alert_with_gpt35(log)
        processed_info_llama3 = process_alert_with_llama3_local(log)
        
        # Combine the results
        reports.append({
            "gpt-4": processed_info_gpt4,
            "gpt-3.5": processed_info_gpt35,
            "llama-3": processed_info_llama3
        })
    return reports

# Function to generate PDF report with improved SOC Analyst Triage comments and explainability
def generate_pdf_report_with_soc_comments_single(model_name: str, alert_info: Dict, index: int):
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
    soc_analyst_comments = alert_info.get("soc_analyst_comments", "No comments provided.")
    verifications_required = alert_info.get("verifications_required", "No verifications listed.")
    recommended_next_steps = alert_info.get("next_steps", "No recommendations provided.")
    explanation = alert_info.get("explanation", "No explanation provided.")
    team_name = alert_info.get("team_name", "SOC Team")

    # Add content
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
    pdf.ln(5)

    pdf.cell(0, 10, "Explanation of Decision:", ln=True, align="L")
    pdf.multi_cell(0, 10, explanation, align="L")
    pdf.ln(10)

    if "hallucination_warning" in alert_info:
        pdf.set_text_color(255, 0, 0)
        pdf.multi_cell(0, 10, f"Warning: {alert_info['hallucination_warning']}", align="L")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(10)

    pdf.multi_cell(0, 10, f"Sincerely,\n{team_name}", align="L")
    pdf.ln(10)

    # Write the PDF to a file
    pdf_output_path = f"/mnt/data/report_single_soc_comment_{model_name}_{index}.pdf"
    pdf.output(pdf_output_path)
    return pdf_output_path

# Function to perform advanced analytics
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

    # Output metrics for each model
    print(f"Advanced Analytics for {model}:")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    print(f"F1-Score: {f1:.2f}\n")

# Function to collect feedback
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

# Function to update model with feedback
def update_model_with_feedback(feedback: List[Dict]):
    for item in feedback:
        if item['correct_decision'].lower() == 'no':
            print(f"Model {item['model']} needs adjustment for alert {item['alert_id']}.")
        else:
            print(f"Model {item['model']} performed well for alert {item['alert_id']}.")

# Generate the corrected PDF reports with only one SOC Analyst Triage Comments section for each log and model
def generate_reports(sampled_logs):
    detailed_reports_corrected = analyze_logs_corrected(sampled_logs)
    pdf_files_corrected_single = []
    for index, report in enumerate(detailed_reports_corrected):
        for model_name, alert_info in report.items():
            pdf_file = generate_pdf_report_with_soc_comments_single(model_name, alert_info, index)
            pdf_files_corrected_single.append(pdf_file)
    return pdf_files_corrected_single

# Example usage (assuming 'sampled_logs' is a DataFrame containing the security logs to be analyzed)
# pdf_files_corrected_single = generate_reports(sampled_logs)
