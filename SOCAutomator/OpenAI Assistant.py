from openai import OpenAI

client = OpenAI(api_key="$API_KEY")
assistant = client.beta.assistants.create(
    name="Tier 1 SOC Analyst",
    instructions='''You are an experienced tier 1 SOC analyst. Review the SIEM alerts and decide which alerts are interesting or not interesting. An interesting alert indicates a potential incident that needs to be investigated further. A non-interesting alert is either informational or a false positive. Make this decision based on the details in the alert and respond with your decision.''',
    tools=[{"type": "file_search"}],
    model="gpt-40"
)
########################################################3
# Create a vector store named "Alert"
vector_store = client.beta.vector_stores.create(name="Alert")

# Define the file path and stream
file_paths = ["alert.json"]
file_streams = [open(path, "rb") for path in file_paths]

# Upload the files to the vector store and poll for completion
file_batch = client.beta.vector_stores.file_batches.upload_and_poll(
    vector_store_id=vector_store.id,
    files=file_streams
)

# Print the status and file counts of the batch
print(file_batch.status)
print(file_batch.file_counts)

# Update the assistant with the relevant tool resources
assistant.client.beta.assistants.update(
    assistant_id=assistant.id,
    tool_resources={"file_search": {"vector_store_ids": [vector_store.id]}},
)

# Upload the user-provided file to OpenAI
message_file = client.files.create(file=open("alert.json", "rb"), purpose="assistants")
#############################################################################################

# Create a thread and attach the file to the message
thread = client.beta.threads.create(
    messages=[
        {
            "role": "user",
            "content": (
                "There is 1 Wazuh alert in the file. Please review the alert and indicate whether it is "
                "'interesting' or 'not-interesting'. Your message should use the following format:\n"
                "alert_id:\nalert_description:\nalert_decision:\nreason:"
            ),
            # Attach the new file to the message.
            "attachments": [{"file_id": message_file.id, "tools": [{"type": "file_search"}]}],
        }
    ]
)

# The thread now has a vector store with that file in its tool resources.
print(thread.tool_resources.file_search)

# Use the create and poll SDK helper to create a run and poll the status of the run until it's in a terminal state.
run = client.beta.threads.runs.create_and_poll(thread_id=thread.id, assistant_id=assistant.id)

# Retrieve messages list
messages_list = client.beta.threads.messages.list(thread_id=thread.id, run_id=run.id)
message_content = messages_list[0].content[0].text
annotations = message_content.annotations
citations = []

for index, annotation in enumerate(annotations):
    message_content.value = message_content.value.replace(annotation.text, f"[{index}]")
    if getattr(annotation, "file_citation", None):
        cited_file = client.files.retrieve(annotation.file_citation.file_id)
        citations.append(f"[{index}] {cited_file.filename}")

print(message_content.value)
print("\n".join(citations))

