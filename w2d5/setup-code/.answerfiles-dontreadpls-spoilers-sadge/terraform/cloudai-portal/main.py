from flask import Flask, render_template, request, jsonify
import os
import requests
import json
from datetime import datetime
import google.auth
from google.auth.transport.requests import Request
from pathlib import Path

app = Flask(__name__)

# Environment variables
PROJECT_ID = os.environ.get('PROJECT_ID', 'your-project-id')
REGION = os.environ.get('REGION', 'us-east1')
MONITORING_FUNCTION_URL = os.environ.get('MONITORING_FUNCTION_URL', '')

# API Keys (intentionally vulnerable)
API_KEY = os.environ.get('CLOUDAI_API_KEY', 'dev-key-12345')
ADMIN_KEY = os.environ.get('CLOUDAI_ADMIN_KEY', 'admin-secret-key')

# Flag values from environment
FLAGS = {
    'FLAG1': os.environ.get('FLAG1', 'flag{nope-not-here}'),
    'FLAG2': os.environ.get('FLAG2', 'flag{nice-try}'),
    'FLAG3': os.environ.get('FLAG3', 'flag{im-sadge-you-got-to-this-point}'),
    'FLAG4': os.environ.get('FLAG4', 'flag{ask-for-a-hint-cmon-:p}')
}

# Flag gating functions
def init_flag_dir():
    """Initialize flag progress directory"""
    flag_dir = Path('/tmp/flag_progress')
    flag_dir.mkdir(exist_ok=True)
    return flag_dir

def check_module_unlocked(module_num):
    """Check if a module is unlocked"""
    # Module 1 is always unlocked
    if module_num == 1:
        return True
    
    flag_dir = Path('/tmp/flag_progress')
    flag_file = flag_dir / f'module_{module_num}_unlocked'
    return flag_file.exists()

def unlock_module(module_num):
    """Unlock a module by creating the flag file"""
    flag_dir = Path('/tmp/flag_progress')
    flag_file = flag_dir / f'module_{module_num}_unlocked'
    
    timestamp = datetime.now().isoformat()
    flag_file.write_text(f'Unlocked at: {timestamp}\n')

def get_progress():
    """Get current module unlock progress"""
    return {
        'module1': check_module_unlocked(1),
        'module2': check_module_unlocked(2),
        'module3': check_module_unlocked(3),
        'module4': check_module_unlocked(4)
    }

def get_identity_token():
    """Get identity token for service-to-service auth"""
    try:
        credentials, project = google.auth.default()
        auth_req = Request()
        credentials.refresh(auth_req)
        return credentials.token
    except:
        return None

@app.route('/')
def index():
    """CloudAI Labs homepage"""
    return render_template('index.html', 
        project_id=PROJECT_ID,
        region=REGION
    )

@app.route('/submit-flag', methods=['POST'])
def submit_flag():
    """Handle flag submission"""
    submitted_flag = request.form.get('flag', '').strip()
    
    if not submitted_flag:
        return jsonify({
            'success': False,
            'message': 'Please enter a flag'
        }), 400
    
    # Check FLAG1 (unlocks module 2)
    if submitted_flag == FLAGS['FLAG1']:
        unlock_module(2)
        return jsonify({
            'success': True,
            'message': 'Correct! Module 2 (System Status) is now unlocked.',
            'module_unlocked': 2
        })
    
    # Check FLAG2 (unlocks module 3)
    elif submitted_flag == FLAGS['FLAG2']:
        unlock_module(3)
        return jsonify({
            'success': True,
            'message': 'Correct! Module 3 (Monitoring) is now unlocked.',
            'module_unlocked': 3
        })

    # Check FLAG3 (unlocks module 4)
    elif submitted_flag == FLAGS['FLAG3']:
        unlock_module(4)
        return jsonify({
            'success': True,
            'message': 'Correct! Module 4 (Admin) is now unlocked.',
            'module_unlocked': 4
        })

    # Check FLAG4 (unlocks module 5)
    elif submitted_flag == FLAGS['FLAG4']:
        unlock_module(5)
        return jsonify({
            'success': True,
            'message': 'Correct! Module 5 (gpt6) is now unlocked.',
            'module_unlocked': 5
        })
    
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid flag. Please try again.'
        }), 400

@app.route('/progress')
def progress():
    """Return current module unlock status"""
    return jsonify(get_progress())

@app.route('/docs')
def developer_docs():
    """Module 1 entry point - Model downloads"""
    return render_template('1-model-downloads.html', 
        project_id=PROJECT_ID,
        region=REGION,
        api_endpoint=f'https://{REGION}-{PROJECT_ID}.cloudfunctions.net/cloudai-portal/api/v1/'
    )

@app.route('/api/v1/models')
def list_models():
    """Module 1 - API endpoint revealing model information"""
    api_key = request.headers.get('X-API-Key', '')
    
    response = {
        'status': 'success',
        'models': {
            'dev': ['sentiment-test', 'nlp-experiment', 'gpt5-benchmark-leaked'],
            'prod': []
        }
    }
    
    if api_key == API_KEY:
        response['models']['prod'] = ['sentiment-v1', 'translation-v2']
        response['note'] = 'Production models loaded'
    elif api_key == ADMIN_KEY:
        response['models']['prod'] = ['sentiment-v1', 'translation-v2', 'gpt5-production']
        response['admin'] = True
        response['note'] = 'Admin access granted'
    else:
        response['note'] = 'Public access only. Use API key for production models.'
        
    return jsonify(response)

@app.route('/api/v1/predict', methods=['POST'])
def predict():
    """Simple prediction endpoint"""
    api_key = request.headers.get('X-API-Key', '')
    
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
        
    data = request.get_json()
    model = data.get('model', 'sentiment-v1')
    text = data.get('text', '')
    
    # Simple mock prediction
    if 'good' in text.lower() or 'great' in text.lower():
        sentiment = 'positive'
    elif 'bad' in text.lower() or 'terrible' in text.lower():
        sentiment = 'negative'
    else:
        sentiment = 'neutral'
        
    return jsonify({
        'model': model,
        'prediction': sentiment,
        'confidence': 0.85
    })

@app.route('/status')
def deployment_status():
    """Module 2 entry point - System status page"""
    # Check if module 2 is unlocked
    if not check_module_unlocked(2):
        return render_template('locked.html',
            module_num=2,
            module_name='System Status',
            hint='Find the flag from the previous module.'
        )
    
    deployments = [{
        'id': 'deploy-2024-01-15',
        'timestamp': '2024-01-15 14:23:11',
        'status': 'completed',
        'deployed_by': 'terraform-pipeline@{}.iam.gserviceaccount.com'.format(PROJECT_ID),
        'artifacts': {
            'logs': f'gs://modeldata-prod-{PROJECT_ID}/deploy-logs.txt',
            'state': f'gs://modeldata-prod-{PROJECT_ID}/terraform.tfstate',
            'backup': f'gs://modeldata-prod-{PROJECT_ID}/terraform.tfstate.backup'
        }
    }]
    
    return render_template('2-system-status.html',
        deployments=deployments,
        project_id=PROJECT_ID
    )

@app.route('/monitoring')
def monitoring_dashboard():
    """Module 3 entry point - Monitoring dashboard"""
    # Check if module 3 is unlocked
    if not check_module_unlocked(3):
        return render_template('locked.html',
            module_num=3,
            module_name='Monitoring Dashboard',
            hint='Find the previous flag to unlock this module'
        )
    
    return render_template('3-monitoring.html',
        project_id=PROJECT_ID,
        region=REGION
    )

@app.route('/monitoring/check', methods=['POST'])
def monitoring_check():
    """Module 3 - Web wrapper for monitoring function"""
    metadata_param = request.form.get('metadata', 'email')
    
    # Check if this is the monitoring function endpoint
    if not MONITORING_FUNCTION_URL:
        return jsonify({
            'error': 'Monitoring function not configured',
            'hint': 'The monitoring-function Cloud Function must be deployed'
        }), 503
    
    try:
        # Call the vulnerable monitoring function
        token = get_identity_token()
        headers = {}
        if token:
            headers['Authorization'] = f'Bearer {token}'
            
        response = requests.post(
            MONITORING_FUNCTION_URL,
            json={'metadata': metadata_param},
            headers=headers,
            timeout=5
        )
        
        return jsonify(response.json())
    except Exception as e:
        return jsonify({
            'error': 'Failed to call monitoring function',
            'details': str(e),
            'hint': 'Try using "token" as the metadata parameter'
        }), 500

@app.route('/admin')
def admin_console():
    """Module 4 entry point - Admin console"""
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '') if auth_header else None
    
    if not check_module_unlocked(4):
        return render_template('locked.html',
            module_num=4,
            module_name='Admin Login',
            hint='Find the previous flag to unlock this module'
        )

    elif not token:
        return render_template('4-admin_login.html',
            hint='Use the token obtained from the monitoring function'
        )
    
    # Mock service account data
    service_accounts = [
        {
            'email': f'{PROJECT_ID}-compute@developer.gserviceaccount.com',
            'description': 'Default compute service account',
            'roles': ['Editor', 'ServiceAccountTokenCreator']
        },
        {
            'email': f'terraform-pipeline@{PROJECT_ID}.iam.gserviceaccount.com',
            'description': 'Terraform deployment pipeline',
            'roles': ['TerraformPipelineProjectAdmin']
        },
        {
            'email': f'monitoring-function@{PROJECT_ID}.iam.gserviceaccount.com',
            'description': 'Monitoring function service account',
            'roles': ['Editor']
        }
    ]
    
    return render_template('admin.html',
        service_accounts=service_accounts,
        project_id=PROJECT_ID,
        token_preview=token[:20] + '...' if len(token) > 20 else token
    )

@app.route('/admin/test-permissions', methods=['POST'])
def test_permissions():
    """Module 4 - Test service account permissions"""
    sa_email = request.form.get('service_account', '')
    
    # Mock response showing impersonation possibilities
    if 'compute' in sa_email and 'terraform-pipeline' in request.form.get('target', ''):
        return jsonify({
            'can_impersonate': True,
            'reason': 'compute service account has ServiceAccountTokenCreator role',
            'command': f'gcloud projects add-iam-policy-binding {PROJECT_ID} --member=user:YOUR_EMAIL --role=roles/viewer --impersonate-service-account={sa_email}',
            'next_step': 'Use this command with the terraform-pipeline service account to gain project access'
        })
    
    return jsonify({
        'can_impersonate': False,
        'hint': 'Check which service accounts have token creator permissions'
    })

# Handle Cloud Functions entry point
def cloudai_portal(request):
    """Cloud Function entry point"""
    with app.test_request_context(
        path=request.path,
        method=request.method,
        headers=dict(request.headers),
        data=request.get_data(),
        query_string=request.query_string
    ):
        try:
            rv = app.preprocess_request()
            if rv is None:
                rv = app.dispatch_request()
        except Exception as e:
            rv = app.handle_user_exception(e)
        response = app.make_response(rv)
        return app.process_response(response)

# Initialize flag directory on startup
init_flag_dir()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
