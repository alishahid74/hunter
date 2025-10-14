#!/usr/bin/env python3
"""
SymbolicHunter Web Dashboard
Interactive web interface for binary analysis
"""

from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_socketio import SocketIO, emit
import os
import sys
import json
import threading
import queue
import time
from datetime import datetime
from werkzeug.utils import secure_filename
import subprocess

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from modules.utils import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'symbolic-hunter-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

socketio = SocketIO(app, cors_allowed_origins="*")

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('output', exist_ok=True)

# Global storage for analysis jobs
active_jobs = {}
completed_jobs = {}
log_queues = {}


def construct_results_from_output(output_dir):
    """Construct results dict from output files if analysis.json doesn't exist"""
    results = {
        'statistics': {},
        'vulnerabilities': {},
        'dangerous_functions': [],
        'taint_analysis': {}
    }

    # Try to load memory analysis
    mem_file = os.path.join(output_dir, 'memory_analysis.json')
    if os.path.exists(mem_file):
        try:
            with open(mem_file, 'r') as f:
                results['memory_analysis'] = json.load(f)
        except:
            pass

    # Try to load any JSON files
    for file in os.listdir(output_dir):
        if file.endswith('.json') and file != 'memory_analysis.json':
            try:
                with open(os.path.join(output_dir, file), 'r') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        results.update(data)
            except:
                pass

    return results


class AnalysisJob:
    """Represents an analysis job"""
    def __init__(self, job_id, binary_path, options):
        self.job_id = job_id
        self.binary_path = binary_path
        self.options = options
        self.status = 'pending'
        self.progress = 0
        self.start_time = None
        self.end_time = None
        self.result = None
        self.error = None
        self.output_dir = None

    def to_dict(self):
        return {
            'job_id': self.job_id,
            'binary_path': os.path.basename(self.binary_path),
            'status': self.status,
            'progress': self.progress,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'output_dir': self.output_dir,
            'options': self.options
        }


def run_analysis(job_id):
    """Run analysis in background thread"""
    job = active_jobs.get(job_id)
    if not job:
        return

    try:
        job.status = 'running'
        job.start_time = datetime.now()
        log_queue = queue.Queue()
        log_queues[job_id] = log_queue

        # Emit status update
        socketio.emit('job_update', job.to_dict(), namespace='/analysis')

        # Build command
        cmd = [
            'python', 'symbolic_hunter_complete.py',
            job.binary_path
        ]

        if job.options.get('verbose'):
            cmd.append('-v')
        if job.options.get('all_features'):
            cmd.append('--all')
        if job.options.get('html_report'):
            cmd.extend(['--html-report', f'output/{job_id}_report.html'])
        if job.options.get('test_exploits'):
            cmd.append('--test-exploits')
        if job.options.get('generate_signatures'):
            cmd.append('--generate-signatures')
        if job.options.get('memory_analysis'):
            cmd.append('--memory-analysis')

        cmd.extend(['--max-states', str(job.options.get('max_states', 1000))])
        cmd.extend(['--timeout', str(job.options.get('timeout', 300))])
        cmd.extend(['--output-dir', f'output/{job_id}'])

        job.output_dir = f'output/{job_id}'

        # Run the analysis
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )

        # Stream output
        for line in process.stdout:
            log_queue.put(line.strip())
            socketio.emit('log_message', {
                'job_id': job_id,
                'message': line.strip()
            }, namespace='/analysis')

            # Update progress based on output
            if 'Step' in line:
                try:
                    parts = line.split('Step')[1].split(':')[0].strip()
                    current = int(parts.split('/')[0])
                    total = job.options.get('max_states', 1000)
                    job.progress = min(100, int((current / total) * 100))
                    socketio.emit('job_update', job.to_dict(), namespace='/analysis')
                except:
                    pass

        process.wait()

        # Load results
        result_file = os.path.join(job.output_dir, 'analysis.json')
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                job.result = json.load(f)
        else:
            # Try to construct results from output files
            job.result = construct_results_from_output(job.output_dir)

        job.status = 'completed'
        job.progress = 100
        job.end_time = datetime.now()

        # Move to completed jobs
        completed_jobs[job_id] = job
        del active_jobs[job_id]

    except Exception as e:
        job.status = 'failed'
        job.error = str(e)
        job.end_time = datetime.now()
        completed_jobs[job_id] = job
        if job_id in active_jobs:
            del active_jobs[job_id]

    finally:
        socketio.emit('job_update', job.to_dict(), namespace='/analysis')


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file upload"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Save file
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Get file info
    file_info = get_file_info(filepath)

    return jsonify({
        'success': True,
        'filepath': filepath,
        'file_info': file_info
    })


@app.route('/api/analyze', methods=['POST'])
def start_analysis():
    """Start a new analysis"""
    data = request.json
    binary_path = data.get('binary_path')

    if not binary_path or not os.path.exists(binary_path):
        return jsonify({'error': 'Invalid binary path'}), 400

    # Create job
    job_id = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    job = AnalysisJob(job_id, binary_path, data.get('options', {}))
    active_jobs[job_id] = job

    # Start analysis in background
    thread = threading.Thread(target=run_analysis, args=(job_id,))
    thread.daemon = True
    thread.start()

    return jsonify({
        'success': True,
        'job_id': job_id,
        'job': job.to_dict()
    })


@app.route('/api/jobs')
def get_jobs():
    """Get all jobs"""
    all_jobs = {}
    all_jobs.update({k: v.to_dict() for k, v in active_jobs.items()})
    all_jobs.update({k: v.to_dict() for k, v in completed_jobs.items()})

    return jsonify(all_jobs)


@app.route('/api/job/<job_id>')
def get_job(job_id):
    """Get specific job details"""
    job = active_jobs.get(job_id) or completed_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    return jsonify(job.to_dict())


@app.route('/api/job/<job_id>/results')
def get_job_results(job_id):
    """Get job results"""
    job = active_jobs.get(job_id) or completed_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    if not job.result:
        return jsonify({'error': 'Results not available'}), 404

    return jsonify(job.result)


@app.route('/api/job/<job_id>/report')
def get_job_report(job_id):
    """Get HTML report"""
    job = active_jobs.get(job_id) or completed_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    # Try multiple possible locations for the report
    report_paths = [
        os.path.join(job.output_dir, 'report.html'),
        os.path.join(job.output_dir, f'{job_id}_report.html'),
        f'output/{job_id}_report.html'
    ]

    for report_file in report_paths:
        if os.path.exists(report_file):
            return send_file(report_file)

    return jsonify({'error': 'Report not found', 'checked_paths': report_paths}), 404


@app.route('/api/job/<job_id>/download/<path:filename>')
def download_file(job_id, filename):
    """Download generated files"""
    job = active_jobs.get(job_id) or completed_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    # Try multiple possible locations
    possible_paths = [
        os.path.join(job.output_dir, filename),
        os.path.join(job.output_dir, 'signatures', filename),
        os.path.join(job.output_dir, 'signatures', os.path.basename(filename))
    ]

    for file_path in possible_paths:
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)

    return jsonify({'error': 'File not found', 'tried': possible_paths}), 404


@app.route('/api/job/<job_id>/cancel', methods=['POST'])
def cancel_job(job_id):
    """Cancel running job"""
    job = active_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    job.status = 'cancelled'
    job.end_time = datetime.now()
    completed_jobs[job_id] = job
    del active_jobs[job_id]

    socketio.emit('job_update', job.to_dict(), namespace='/analysis')

    return jsonify({'success': True})


@app.route('/api/job/<job_id>/files')
def list_job_files(job_id):
    """List all files in job output directory"""
    job = active_jobs.get(job_id) or completed_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    if not job.output_dir or not os.path.exists(job.output_dir):
        return jsonify({'error': 'Output directory not found', 'path': job.output_dir}), 404

    files = {}
    for root, dirs, filenames in os.walk(job.output_dir):
        for filename in filenames:
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, job.output_dir)
            files[rel_path] = {
                'size': os.path.getsize(full_path),
                'path': full_path
            }

    return jsonify({
        'output_dir': job.output_dir,
        'files': files
    })


@app.route('/api/stats')
def get_stats():
    """Get dashboard statistics"""
    total_jobs = len(active_jobs) + len(completed_jobs)
    active_count = len(active_jobs)
    completed_count = len([j for j in completed_jobs.values() if j.status == 'completed'])
    failed_count = len([j for j in completed_jobs.values() if j.status == 'failed'])

    return jsonify({
        'total_jobs': total_jobs,
        'active_jobs': active_count,
        'completed_jobs': completed_count,
        'failed_jobs': failed_count
    })


@socketio.on('connect', namespace='/analysis')
def handle_connect():
    """Handle WebSocket connection"""
    emit('connected', {'status': 'connected'})


@socketio.on('subscribe_job', namespace='/analysis')
def handle_subscribe(data):
    """Subscribe to job updates"""
    job_id = data.get('job_id')
    emit('subscribed', {'job_id': job_id})


if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════╗
║       SymbolicHunter Web Dashboard Starting...            ║
╚═══════════════════════════════════════════════════════════╝

🌐 Dashboard will be available at: http://localhost:5000
📊 Interactive analysis interface
🔍 Real-time monitoring
📈 Beautiful visualizations

Press Ctrl+C to stop the server.
    """)

    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
