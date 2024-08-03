import os
import spacy
import re
import requests  # For hypothetical LLaMA-3 API integration
from openai import OpenAI
from fpdf import FPDF
from transformers import AutoTokenizer, AutoModelForCausalLM  # For local LLaMA-3 integration
from typing import List, Dict
from sklearn.metrics import precision_score, recall_score, f1_score
import hashlib

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

def analyze_alerts(alert_files: List[str], models: List[str]):
    try:
        for alert_file_path in alert_files:
            # Open the alert file and read its content
            with open(alert_file_path, "r") as alert_file:
                alert_content = alert_file.read()

            # Process the alert with each LLM model
            results = []
            for model in models:
                if model == "gpt-4":
                    processed_alert_info = process_alert_with_gpt4(alert_content)
                elif model == "gpt-3.5":
                    processed_alert_info = process_alert_with_gpt35(alert_content)
                elif model == "llama-3":
                    processed_alert_info = process_alert_with_llama3_local(alert_content)
                else:
                    processed_alert_info = {"error": "Model not supported"}
                results.append((model, processed_alert_info))

            # Generate and save PDF report for each alert
            generate_pdf_report(results)

            # Perform advanced analytics
            perform_advanced_analytics(results)

            # Collect feedback from SOC analysts (simulated here)
            feedback = collect_feedback(results)
            feedback_data.append(feedback)

            # Use feedback to improve the model (simulated update function)
            update_model_with_feedback(feedback)

    except Exception as e:
        print(f"Error analyzing alerts: {e}")
    finally:
        # Cleanup resources if necessary
        pass

def process_alert_with_gpt4(alert_content: str) -> Dict:
    """
    Process alert content with GPT-4 using OpenAI API.
    """
    response = client.Completions.create(
        model="gpt-4",
        prompt=f"Analyze the following alert: {alert_content}",
        max_tokens=500
    )
    generated_text = response.choices[0].text.strip()

    processed_info = {
        "alert_name": "Suspicious Activity Detected",
        "severity": "High",
        "alert_decision": "Actionable",
        "endpoint_name": "Server123",
        "short_description": generated_text,
        "analyst_comments": "Generated using GPT-4.",
        "verifications_required": "Check server logs.",
        "next_steps": "Investigate further.",
        "team_name": "SOC Team"
    }
    return processed_info

def process_alert_with_gpt35(alert_content: str) -> Dict:
    """
    Process alert content with GPT-3.5 using OpenAI API.
    """
    response = client.Completions.create(
        model="gpt-3.5-turbo",
        prompt=f"Analyze the following alert: {alert_content}",
        max_tokens=500
    )
    generated_text = response.choices[0].text.strip()

    processed_info = {
        "alert_name": "Suspicious Activity Detected",
        "severity": "Medium",
        "alert_decision": "Non-Actionable",
        "endpoint_name": "Server456",
        "short_description": generated_text,
        "analyst_comments": "Generated using GPT-3.5.",
        "verifications_required": "Review logs for anomalies.",
        "next_steps": "Monitor the situation.",
        "team_name": "SOC Team"
    }
    return processed_info

def process_alert_with_llama3_local(alert_content: str) -> Dict:
    """
    Process alert content with a locally hosted LLaMA-3 model.
    """
    tokenizer = AutoTokenizer.from_pretrained("meta/llama-3")
    model = AutoModelForCausalLM.from_pretrained("meta/llama-3")

    inputs = tokenizer(alert_content, return_tensors="pt")
    outputs = model.generate(**inputs)
    generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)

    processed_info = {
        "alert_name": "Unusual Network Activity",
        "severity": "High",
        "alert_decision": "Actionable",
        "endpoint_name": "Server789",
        "short_description": generated_text,
        "analyst_comments": "Generated using LLaMA-3.",
        "verifications_required": "Investigate network traffic logs.",
        "next_steps": "Isolate affected systems.",
        "team_name": "SOC Team"
    }
    return processed_info

def detect_hallucinations(alert_info: Dict, extracted_keywords: List[str]) -> Dict:
    """
    Detect potential hallucinations by checking consistency against known data or rules.
    """
    # Example: Simple check against expected keywords (In practice, more complex checks)
    if alert_info["alert_decision"] == "Actionable" and not set(extracted_keywords).intersection(SECURITY_KEYWORDS):
        alert_info["hallucination_warning"] = "Possible hallucination detected. Verify the accuracy of this alert."

    return alert_info

def anonymize_data(alert_info: Dict) -> Dict:
    """
    Anonymize sensitive data to mitigate privacy risks.
    """
    # Example: Hash the endpoint name to anonymize it
    if "endpoint_name" in alert_info:
        alert_info["endpoint_name"] = hashlib.sha256(alert_info["endpoint_name"].encode()).hexdigest()

    return alert_info

def generate_pdf_report(results: List[tuple]):
    """
    Generate a PDF report for each alert and LLM model evaluation.
    """
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

def collect_feedback(results: List[tuple]) -> List[Dict]:
    """
    Simulate feedback collection from SOC analysts. In practice, this would be a form or interface.
    """
    feedback = []
    for model, alert_info in results:
        # Simulate analyst feedback
        feedback_item = {
            "model": model,
            "alert_id": alert_info.get("alert_name"),
            "correct_decision": input(f"Was the alert decision '{alert_info['alert_decision']}' by {model} correct? (yes/no): "),
            "comments": input(f"Any additional comments on the alert processed by {model}? ")
        }
        feedback.append(feedback_item)
    return feedback

def update_model_with_feedback(feedback: List[Dict]):
    """
    Simulate model update based on feedback. In practice, this would involve retraining or fine-tuning.
    """
    for item in feedback:
        if item['correct_decision'].lower() == 'no':
            print(f"Model {item['model']} needs adjustment for alert {item['alert_id']}.")
            # Add logic to update model parameters or retrain here
        else:
            print(f"Model {item['model']} performed well for alert {item['alert_id']}.")

def perform_advanced_analytics(results: List[tuple]):
    """
    Perform advanced analytics on model performance and alert processing.
    """
    y_true = []
    y_pred = []
    for model, alert_info in results:
        # Simulate true labels and predictions (In practice, these would come from actual alert data and model outputs)
        true_label = "Actionable"  # This would be the actual label from SOC
        predicted_label = alert_info["alert_decision"]
        y_true.append(true_label)
        y_pred.append(predicted_label)

    # Calculate and store precision, recall, F1-score
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

def extract_keywords(alert_description: str) -> List[str]:
    """
    Extract relevant keywords from the alert description using predefined keywords and NER.
    """
    keywords = []

    # Use spaCy NER to identify entities
    doc = nlp(alert_description)
    for entity in doc.ents:
        if entity.label_ in ("PERSON", "ORG", "FAC", "LOC", "GPE", "PRODUCT"):
            keywords.append(entity.text)

    # Use regular expressions to match predefined keywords in the alert description
    for keyword in ALL_KEYWORDS:
        if re.search(rf"\b{keyword}\b", alert_description):
            keywords.append(keyword)

    return keywords

def build_log_query(keywords: List[str]) -> str:
    """
    Build a log query string using the extracted keywords.
    """
    # Escape special characters in keywords for safe query building
    escaped_keywords = [re.escape(keyword) for keyword in keywords]

    # Adapt query based on your log system (replace with your specific logic)
    log_query_template = "search logs where (message contains any of: '{keywords}')"
    log_query = log_query_template.format(keywords=" OR ".join(escaped_keywords))

    return log_query

# List of alert files to analyze
alert_files = [
    r"path_to_your_alert_file_here1.log",
    r"path_to_your_alert_file_here2.log"
]

# List of LLM models to evaluate
models = ["gpt-4", "gpt-3.5", "llama-3"]

# Analyze the alerts using the specified models
analyze_alerts(alert_files, models)
