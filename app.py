import os
import json
import tempfile
import shutil
import ast
import re
from flask import Flask, render_template, request, jsonify, session
from werkzeug.utils import secure_filename
import threading
import uuid

# Import the threat modeling functionality
from main import perform_textual_analysis, perform_whitebox_analysis, build_threat_model
# Import llmConfig to get available models
from llm import llmConfig

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = os.path.join(tempfile.gettempdir(), 'threat_model_uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Store ongoing analysis tasks
analysis_tasks = {}

def format_error_message(error_message):
    """
    Format error messages to make them more readable, especially for lists of feedback items.
    """
    # FIX: correct regex to capture [...] lists
    list_pattern = r'\[.*?\]'
    match = re.search(list_pattern, error_message, flags=re.DOTALL)

    if match:
        try:
            # Extract the list portion and convert it to a Python list
            list_str = match.group(0)
            feedback_items = ast.literal_eval(list_str)

            if isinstance(feedback_items, list):
                # Format the list items as HTML bullet points
                formatted_items = "<ul>" + "".join([f"<li>{item}</li>" for item in feedback_items]) + "</ul>"
                # Replace the original list representation with the formatted version
                formatted_message = error_message.replace(list_str, formatted_items)
                return formatted_message
        except (SyntaxError, ValueError):
            # If there's any error parsing the list, return the original message
            pass

    return error_message

def _safe_model(_selected):
    """Single-model mode; always return the configured llama model."""
    return llmConfig.DEFAULT_MODEL

@app.route('/')
def index():
    model_options = [{"value": llmConfig.DEFAULT_MODEL, "label": llmConfig.DEFAULT_MODEL}]
    return render_template('index.html', model_options=model_options, default_model=llmConfig.DEFAULT_MODEL)

@app.route('/analyze_description', methods=['POST'])
def analyze_description():
    description = request.form.get('description', '')
    model = _safe_model(request.form.get('model', llmConfig.DEFAULT_MODEL))

    if not description:
        return jsonify({'error': 'No description provided'}), 400

    # Generate a unique task ID
    task_id = str(uuid.uuid4())

    # Create a thread to run the analysis
    def run_analysis():
        try:
            # We set use_parallel to False by default, modify if necessary
            threat_model = perform_textual_analysis(description, use_parallel=False, model=model)
            analysis_tasks[task_id] = {'status': 'completed', 'result': threat_model}
        except Exception as e:
            error_message = str(e)
            # Format the error message if it contains feedback items
            formatted_error = format_error_message(error_message)
            analysis_tasks[task_id] = {'status': 'failed', 'error': formatted_error}

    # Store the task status
    analysis_tasks[task_id] = {'status': 'in_progress'}

    # Start the analysis in a background thread
    thread = threading.Thread(target=run_analysis)
    thread.daemon = True
    thread.start()

    return jsonify({'task_id': task_id})

@app.route('/analyze_codebase', methods=['POST'])
def analyze_codebase():
    if 'codebase' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['codebase']
    model = _safe_model(request.form.get('model', llmConfig.DEFAULT_MODEL))
    repo_url = request.form.get('repo_url', '')

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Generate a unique task ID and create a dedicated folder
    task_id = str(uuid.uuid4())
    task_dir = os.path.join(app.config['UPLOAD_FOLDER'], task_id)
    os.makedirs(task_dir, exist_ok=True)

    # Handle scan report uploads
    scan_files = {}
    scan_report_types = ['sonarqube_report', 'qualys_report', 'netsparker_report', 'generic_scan_report']
    
    for report_type in scan_report_types:
        if report_type in request.files:
            report_file = request.files[report_type]
            if report_file and report_file.filename != '':
                scan_path = os.path.join(task_dir, f"{report_type}_{secure_filename(report_file.filename)}")
                report_file.save(scan_path)
                scan_files[report_type] = scan_path

    # Handle zip file upload - save and extract
    try:
        zip_path = os.path.join(task_dir, secure_filename(file.filename))
        file.save(zip_path)

        # Extract if it's a zip file
        if zip_path.endswith('.zip'):
            import zipfile
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(task_dir)

        # Create a thread to run the enhanced analysis
        def run_enhanced_analysis():
            try:
                # Process scan reports if any were uploaded
                scan_results = {}
                if scan_files:
                    from scan_parsers import process_scan_reports
                    scan_results = process_scan_reports(
                        sonarqube_file=scan_files.get('sonarqube_report'),
                        qualys_file=scan_files.get('qualys_report'),
                        netsparker_file=scan_files.get('netsparker_report'),
                        generic_file=scan_files.get('generic_scan_report')
                    )

                # Run standard threat model analysis
                threat_model = perform_whitebox_analysis(task_dir, model=model)
                
                # Enhance result with scan data if available
                if scan_results and scan_results.get('summary', {}).get('total_findings', 0) > 0:
                    threat_model['scan_integration'] = {
                        'scan_results': scan_results,
                        'correlation_available': len(scan_results.get('correlation_analysis', [])) > 0,
                        'total_scan_findings': scan_results['summary']['total_findings'],
                        'sast_findings': scan_results['summary']['sast_findings'],
                        'dast_findings': scan_results['summary']['dast_findings'],
                        'scan_summary': f"Integrated {scan_results['summary']['total_findings']} security findings from uploaded scan reports"
                    }
                    
                    # Add scan context to threat model description
                    if 'description' in threat_model:
                        threat_model['description'] += f"\n\n**Security Scan Integration:**\n"
                        threat_model['description'] += f"- Total scan findings: {scan_results['summary']['total_findings']}\n"
                        threat_model['description'] += f"- SAST findings: {scan_results['summary']['sast_findings']}\n"
                        threat_model['description'] += f"- DAST findings: {scan_results['summary']['dast_findings']}\n"
                        if scan_results.get('correlation_analysis'):
                            threat_model['description'] += f"- Correlated vulnerability patterns: {len(scan_results['correlation_analysis'])}\n"

                # Add repository context if provided
                if repo_url:
                    if 'metadata' not in threat_model:
                        threat_model['metadata'] = {}
                    threat_model['metadata']['repository_url'] = repo_url

                analysis_tasks[task_id] = {'status': 'completed', 'result': threat_model}
                
            except Exception as e:
                error_message = str(e)
                # Format the error message if it contains feedback items
                formatted_error = format_error_message(error_message)
                analysis_tasks[task_id] = {'status': 'failed', 'error': formatted_error}
            finally:
                # Clean up temporary directory
                if os.path.exists(task_dir):
                    shutil.rmtree(task_dir)

        # Store the task status
        analysis_tasks[task_id] = {'status': 'in_progress'}

        # Start the analysis in a background thread
        thread = threading.Thread(target=run_enhanced_analysis)
        thread.daemon = True
        thread.start()

        return jsonify({'task_id': task_id})

    except Exception as e:
        # Clean up on error
        if os.path.exists(task_dir):
            shutil.rmtree(task_dir)
        return jsonify({'error': str(e)}), 500

# ---------- NEW: Suggestions endpoint ----------
SUGGESTION_SYSTEM_PROMPT = (
    "You are a senior security architect and product strategist. "
    "Given an application context, produce market-aligned, up-to-date suggestions for improving the "
    "architecture and the textual description for STRIDE threat modeling. "
    "Base your advice on widely adopted, current best practices (e.g., OWASP ASVS/Top10, NIST SSDF, SLSA, "
    "CIS Benchmarks, PCI DSS 4.0, Zero Trust). "
    "Do NOT invent prices or unverifiable statistics. If a specific market figure is unknown, say 'N/A'. "
    "Output clear, actionable items suitable for immediate backlog intake."
)

SUGGESTION_USER_TEMPLATE = """\
Context:
{context}

Produce the following, concisely:
1) Missing details to add (components, assets, data flows, trust boundaries, environment, controls) — bullet list.
2) Risk hotspots & likely STRIDE categories to expect — bullet list.
3) Market-aligned improvements (why it matters, how to implement, quick wins vs. strategic) — bullet list.
4) A short, improved description template the user can paste back into the tool to get better results.

Keep it practical and specific to the given context. Avoid generic filler.
"""

@app.route('/suggest', methods=['POST'])
def suggest():
    context = request.form.get('context', '').strip()
    model = _safe_model(request.form.get('model', llmConfig.DEFAULT_MODEL))

    if not context:
        return jsonify({'error': 'No context provided'}), 400

    task_id = str(uuid.uuid4())

    def run_suggestion():
        try:
            prompt = SUGGESTION_USER_TEMPLATE.format(context=context)
            text = llmConfig.get_llm_response(
                prompt=prompt,
                system_message=SUGGESTION_SYSTEM_PROMPT,
                temperature=0.2,
                model=model
            )
            # Store markdown as result; frontend will render it
            analysis_tasks[task_id] = {'status': 'completed', 'result': {'suggestions_md': text}}
        except Exception as e:
            analysis_tasks[task_id] = {'status': 'failed', 'error': format_error_message(str(e))}

    analysis_tasks[task_id] = {'status': 'in_progress'}
    thread = threading.Thread(target=run_suggestion)
    thread.daemon = True
    thread.start()

    return jsonify({'task_id': task_id})

@app.route('/task_status/<task_id>', methods=['GET'])
def task_status(task_id):
    task = analysis_tasks.get(task_id)
    if not task:
        return jsonify({'status': 'not_found'}), 404

    status_data = {'status': task['status']}

    if task['status'] == 'completed':
        status_data['result'] = task['result']
    elif task['status'] == 'failed':
        status_data['error'] = task['error']

    return jsonify(status_data)

@app.route('/visualize/<task_id>')
def visualize(task_id):
    task = analysis_tasks.get(task_id)
    if not task or task['status'] != 'completed':
        return render_template('error.html', message='Analysis task not found or incomplete')

    return render_template('graph.html', task_id=task_id)

@app.route('/get_task_data/<task_id>')
def get_task_data(task_id):
    task = analysis_tasks.get(task_id)
    if not task or task['status'] != 'completed':
        return jsonify({'error': 'Task not found or incomplete'}), 404

    return jsonify(task['result'])

# Optional: expose models to the UI if needed
@app.route('/models', methods=['GET'])
def list_models():
    return jsonify({"models": llmConfig.AVAILABLE_MODELS, "default": llmConfig.DEFAULT_MODEL})

# Clean up old tasks
@app.before_request
def cleanup_old_tasks():
    tasks_to_remove = []
    for task_id, task in list(analysis_tasks.items()):
        if task.get('status') in ('completed', 'failed') and len(analysis_tasks) > 100:
            tasks_to_remove.append(task_id)

    for task_id in tasks_to_remove[:max(0, len(analysis_tasks) - 50)]:  # Keep the 50 most recent
        analysis_tasks.pop(task_id, None)

if __name__ == '__main__':
    app.run(debug=True)
