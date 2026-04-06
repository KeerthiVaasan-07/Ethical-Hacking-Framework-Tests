"""
View detailed test results
"""
from core.config import Config
from core.llm_client import LLMClient
from detectors.prompt_injection import PromptInjectionTester

# Load config
config = Config()
llm_client = LLMClient(
    provider=config.llm_config.provider,
    api_key=config.llm_config.api_key,
    model=config.llm_config.model,
    base_url=config.llm_config.base_url,
    timeout=config.llm_config.timeout,
    max_tokens=config.llm_config.max_tokens
)

# Run tests
tester = PromptInjectionTester(llm_client, config)
report = tester.run_tests()

# Print vulnerable results
print("\n" + "="*70)
print("VULNERABILITIES FOUND")
print("="*70)

for result in report.test_results:
    if result.vulnerable:
        print(f"\n{'='*70}")
        print(f"TEST: {result.test_name}")
        print(f"SEVERITY: {result.severity.upper()}")
        print(f"CONFIDENCE: {result.confidence * 100}%")
        print(f"{'='*70}")
        
        print(f"\n>>> ATTACK PAYLOAD:")
        print(result.attack_payload)
        
        print(f"\n>>> MISTRAL'S RESPONSE:")
        print(result.llm_response)
        
        print(f"\n>>> WHY IT'S VULNERABLE:")
        print(result.evidence)
        
        print(f"\n>>> DESCRIPTION:")
        print(result.description)
        
        print(f"\n>>> HOW TO FIX:")
        print(result.mitigation)
        
        print("\n" + "-"*70)