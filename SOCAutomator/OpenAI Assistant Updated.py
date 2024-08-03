import os
from openai import OpenAI
from fpdf import FPDF

# Load OpenAI API key from environment variable (recommended)
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("Missing OpenAI API key. Please set the 'OPENAI_API_KEY' environment variable.")

client = OpenAI(api_key=api_key)

def analyze_alert(alert_file_path):
    try:
        # Create a vector store named "Alert"
        vector_store = client.beta.vector_stores.create(name="Alert")

        # Open the alert file and upload it to the vector store
        with open(alert_file_path, "rb") as alert_file:
            file_streams = [alert_file]
            file_batch = client.beta.vector_stores.file_batches.upload_and_poll(
                vector_store_id=vector_store.id, files=file_streams
            )
            print(f"File upload status: {file_batch.status}")
            print(f"File counts: {file_batch.file_counts}")

        # Define assistant and tool resources
        assistant = client.beta.assistants.create(
            name="Tier 1 SOC Analyst",
            instructions='''You are an experienced tier 1 SOC analyst. Review the SIEM alerts and decide which alerts are interesting or not interesting. An interesting alert indicates a potential incident that needs to be investigated further. A non-interesting alert is either informational or a false positive. Make this decision based on the details in the alert and respond with your decision.''',
            tools=[{"type": "file_search"}],
            model="gpt-4o",  # Check OpenAI documentation for available models
        )
        assistant.client.beta.assistants.update(
            assistant_id=assistant.id,
            tool_resources={"file_search": {"vector_store_ids": [vector_store.id]}},
        )

        # Upload the alert file to OpenAI
        message_file = client.files.create(file=open(alert_file_path, "rb"), purpose="assistants")

        # Create a thread with the attached file
        thread = client.beta.threads.create(
            messages=[
                {
                    "role": "user",
                    "content": (
                        "There is 1 Wazuh alert in the file. Please review the alert and indicate whether it is "
                        "'interesting' or 'not-interesting'. Your message should use the following format:\n"
                        "alert_id:\nalert_description:\nalert_decision:\nreason:"
                    ),
                    "attachments": [{"file_id": message_file.id, "tools": [{"type": "file_search"}]}],
                }
            ]
        )

        # Run the assistant and retrieve results
        run = client.beta.threads.runs.create_and_poll(thread_id=thread.id, assistant_id=assistant.id)
        messages_list = client.beta.threads.messages.list(thread_id=thread.id, run_id=run.id)
        message_content = messages_list[0].content[0].text

        # Parse the alert information
        alert_info = {}
        for line in message_content.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                alert_info[key.strip()] = value.strip()

        # Check for missing data and handle gracefully
        if not all(key in alert_info for key in ["alert_id", "alert_description", "alert_decision", "reason"]):
            raise ValueError("Alert information incomplete. Please check the SIEM alert format.")

        # Generate and export PDF report
        alert_description = alert_info["alert_description"]
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", size=11)
        pdf.cell(200, 10, txt="SIEM Alert Analysis Report", align="C")
        pdf.ln(10)
        for key, value in alert_info.items():
            pdf.cell(50, 6, f"{key.capitalize()}:", align="L")
            pdf.cell(0, 6, f"{value}", align="L")
            pdf.ln(5)
    except Exception as e:
        print(f"An error occurred: {e}")

# Path to the log file
log_file_path = r"C:\Users\Yuvra\OneDrive\Desktop\PYTHON SCRIPTING\SOCAutomator\alert.log"

# Analyze the alert
analyze_alert(log_file_path)
