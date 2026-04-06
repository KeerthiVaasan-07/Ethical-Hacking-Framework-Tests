from flask import Flask, jsonify, request
from flask_cors import CORS
from core.config import Config
from core.llm_client import LLMClient
from detectors.prompt_injection import PromptInjectionTester
from detectors.image_injection import ImageInjectionTester
from detectors.vector_attack import VectorAttackTester
from detectors.api_attack import APIAttackTester
from detectors.unlimited_prompt import UnlimitedPromptTester
from detectors.vector_embed_attack import VectorEmbedAttackTester
import os

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "LLM Security Testing API is running!"})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

@app.route('/run-scan', methods=['POST'])
def run_scan():
    try:
        data = request.json

        # Get config from dashboard request
        api_key = data.get('api_key') or os.getenv('LLM_API_KEY')
        provider = data.get('provider', 'openai')
        model = data.get('model', 'gpt-3.5-turbo')
        base_url = data.get('base_url', None)
        system_prompt = data.get('system_prompt', None)
        tests = data.get('tests', 'prompt')

        if not api_key:
            return jsonify({"error": "No API key provided"}), 400

        # Initialize LLM client
        llm_client = LLMClient(
            provider=provider,
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout=30,
            max_tokens=1000
        )

        # Test connection first
        test_response = llm_client.send_message("Hello")
        if test_response.error:
            return jsonify({"error": f"Connection failed: {test_response.error}"}), 400

        # Run selected tests
        reports = []

        if tests in ['prompt', 'all']:
            tester = PromptInjectionTester(llm_client, None)
            reports.append(tester.run_tests(system_prompt=system_prompt))

        if tests in ['api', 'all']:
            tester = APIAttackTester(llm_client, None)
            reports.append(tester.run_tests(system_prompt=system_prompt))

        if tests in ['unlimited', 'all']:
            tester = UnlimitedPromptTester(llm_client, None)
            reports.append(tester.run_tests(system_prompt=system_prompt))

        if tests in ['image', 'all']:
            tester = ImageInjectionTester(llm_client, None)
            reports.append(tester.run_tests(system_prompt=system_prompt))

        if tests in ['vector', 'all']:
            tester = VectorAttackTester(llm_client, None)
            reports.append(tester.run_tests(system_prompt=system_prompt))

        if tests in ['vectors', 'all']:
            tester = VectorEmbedAttackTester(llm_client, None)
            reports.append(tester.run_tests(system_prompt=system_prompt))

        # Build response
        results = []
        for report in reports:
            for r in report.test_results:
                results.append({
                    "category": report.category,
                    "test_name": r.test_name,
                    "vulnerable": r.vulnerable,
                    "severity": r.severity,
                    "confidence": r.confidence,
                    "attack_payload": r.attack_payload,
                    "llm_response": r.llm_response,
                    "evidence": r.evidence,
                    "description": r.description,
                    "mitigation": r.mitigation,
                    "response_time": r.response_time
                })

        summary = {
            "total_tests": sum(r.total_tests for r in reports),
            "vulnerabilities_found": sum(r.vulnerabilities_found for r in reports),
            "risk_score": max([r.overall_risk_score for r in reports]) if reports else 0
        }

        return jsonify({
            "summary": summary,
            "results": results
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
