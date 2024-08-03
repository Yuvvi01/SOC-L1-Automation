# LLM-Enhanced SOC Triage Model

## Overview

This repository contains a sophisticated model that integrates Large Language Models (LLMs) such as GPT-4, GPT-3.5, and LLaMA-3 with Security Information and Event Management (SIEM) systems to enhance the triage process in Security Operations Centers (SOCs). This model automates alert analysis, provides detailed SOC Analyst Triage comments, and generates comprehensive PDF reports, all aimed at improving the efficiency and accuracy of SOC operations.

## Features

- **Multi-Model Integration**: Utilizes GPT-4, GPT-3.5, and LLaMA-3 for alert analysis and decision-making.
- **Automated Triage**: Classifies alerts as Actionable or Non-Actionable based on severity and context.
- **SOC Analyst Triage Comments**: Generates detailed comments that explain the context and importance of each alert.
- **Explainability**: Provides clear explanations for the model's decisions, enhancing transparency.
- **Advanced Analytics**: Includes precision, recall, and F1-score metrics for evaluating model performance.
- **Feedback Loop**: Allows SOC analysts to provide feedback, enabling continuous improvement of the model.
- **Comprehensive Reporting**: Generates detailed PDF reports for each analyzed alert, including SOC triage comments and recommended next steps.
- **Logging and Monitoring**: Built-in logging for better tracking and monitoring of model operations.

## Installation

To use this model, follow these steps:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Yuvvi01/SOC-L1-Automation
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Set up your environment:**
   - Set the `OPENAI_API_KEY` environment variable with your OpenAI API key.
   - Ensure all necessary libraries and tools are installed (e.g., `spaCy`, `transformers`, `FPDF`).

## Usage

### Analyzing Logs

1. **Prepare your log files** in CSV format.
2. **Run the analysis**:
   ```python
   from model import analyze_logs_corrected, generate_reports

   # Load your log files
   logs_df = pd.read_csv('path_to_your_log_file.csv')

   # Analyze and generate reports
   pdf_reports = generate_reports(logs_df)
   ```
3. **Access the reports**:
   - Generated PDF reports will be saved in the `/mnt/data/` directory.

### Customization

- **SOC Analyst Triage Comments**: Modify the `process_alert_with_gpt4`, `process_alert_with_gpt35`, and `process_alert_with_llama3_local` functions to customize the content of the SOC Analyst Triage Comments.
- **Feedback and Model Update**: Use the `collect_feedback` and `update_model_with_feedback` functions to iteratively improve the model based on analyst input.

## Contributing

We welcome contributions! Please fork the repository and submit a pull request with your proposed changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions, please open an issue on this repository or contact the project maintainer at [yuvrajsingh3440@gmail.com](mailto:yuvrajsingh3440@gmail.com).
