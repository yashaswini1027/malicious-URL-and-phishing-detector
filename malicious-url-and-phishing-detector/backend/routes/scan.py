from flask import Blueprint, request, jsonify
from threat_analyzer import analyze_url_content

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/scan', methods=['POST'])
def scan():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'Request body must be valid JSON'}), 400

    url = data.get('url', '').strip()
    content = data.get('content', '').strip()

    if not url and not content:
        return jsonify({'error': 'Either URL or content is required'}), 400

    # Perform local analysis using the threat analyzer
    try:
        analysis_result = analyze_url_content(url, content)
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {e}'}), 500

    return jsonify(analysis_result)