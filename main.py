"""
LLM Security Tester - Main CLI
"""
import sys
import argparse
from datetime import datetime
from core.config import Config
from core.llm_client import LLMClient
from detectors.prompt_injection import PromptInjectionTester
from detectors.image_injection import ImageInjectionTester
from detectors.vector_attack import VectorAttackTester
from detectors.api_attack import APIAttackTester
from detectors.unlimited_prompt import UnlimitedPromptTester
from detectors.vector_embed_attack import VectorEmbedAttackTester  # New one

def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║          LLM SECURITY TESTING FRAMEWORK                 ║
║          Test your LLM for vulnerabilities              ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_detailed_results(reports):
    """Print detailed vulnerability findings"""
    print("\n" + "="*70)
    print("DETAILED VULNERABILITY REPORT")
    print("="*70)
    
    for report in reports:
        vulns = [r for r in report.test_results if r.vulnerable]
        
        if vulns:
            print(f"\n{'='*70}")
            print(f"CATEGORY: {report.category}")
            print(f"{'='*70}")
            
            for idx, vuln in enumerate(vulns, 1):
                print(f"\n[VULNERABILITY #{idx}]")
                print(f"Test Name: {vuln.test_name}")
                print(f"Severity: {vuln.severity.upper()}")
                print(f"Confidence: {vuln.confidence * 100:.1f}%")
                print(f"Response Time: {vuln.response_time:.2f}s")
                
                print(f"\n>>> ATTACK PAYLOAD:")
                print(f"{vuln.attack_payload}")
                
                print(f"\n>>> LLM RESPONSE:")
                print(f"{vuln.llm_response}")
                
                print(f"\n>>> EVIDENCE (Why it's vulnerable):")
                print(f"{vuln.evidence}")
                
                print(f"\n>>> DESCRIPTION:")
                print(f"{vuln.description}")
                
                print(f"\n>>> RECOMMENDED MITIGATION:")
                print(f"{vuln.mitigation}")
                
                print("\n" + "-"*70)
        else:
            print(f"\n✓ No vulnerabilities found in {report.category}")


def print_summary(reports):
    """Print executive summary"""
    print("\n" + "="*70)
    print("EXECUTIVE SUMMARY")
    print("="*70)
    
    total_tests = sum(r.total_tests for r in reports)
    total_vulns = sum(r.vulnerabilities_found for r in reports)
    
    print(f"\nTotal Tests Run: {total_tests}")
    print(f"Vulnerabilities Found: {total_vulns}")
    
    # Overall risk assessment
    max_risk = max([r.overall_risk_score for r in reports]) if reports else 0
    if max_risk >= 7:
        risk_level = "🔴 CRITICAL"
    elif max_risk >= 5:
        risk_level = "🟠 HIGH"
    elif max_risk >= 3:
        risk_level = "🟡 MEDIUM"
    else:
        risk_level = "🟢 LOW"
    
    print(f"Overall Risk Level: {risk_level}")
    
    for report in reports:
        print(f"\n{report.category}:")
        print(f"  Risk Score: {report.overall_risk_score}/10")
        print(f"  Tests Run: {report.total_tests}")
        print(f"  Vulnerabilities: {report.vulnerabilities_found}")
        print(f"  Critical: {report.critical_count}")
        print(f"  High: {report.high_count}")
        print(f"  Medium: {report.medium_count}")
        print(f"  Low: {report.low_count}")
    
    print("\n" + "="*70)


def save_report_to_file(reports, filename='vulnerability_report.txt'):
    """Save detailed report to file"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("="*70 + "\n")
        f.write("LLM SECURITY TEST - DETAILED VULNERABILITY REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*70 + "\n\n")
        
        # Summary
        total_tests = sum(r.total_tests for r in reports)
        total_vulns = sum(r.vulnerabilities_found for r in reports)
        
        f.write("EXECUTIVE SUMMARY\n")
        f.write("-"*70 + "\n")
        f.write(f"Total Tests: {total_tests}\n")
        f.write(f"Vulnerabilities Found: {total_vulns}\n\n")
        
        for report in reports:
            f.write(f"{report.category}:\n")
            f.write(f"  Risk Score: {report.overall_risk_score}/10\n")
            f.write(f"  Critical: {report.critical_count}, High: {report.high_count}, ")
            f.write(f"Medium: {report.medium_count}, Low: {report.low_count}\n\n")
        
        # Detailed results
        f.write("\n" + "="*70 + "\n")
        f.write("DETAILED TEST RESULTS\n")
        f.write("="*70 + "\n\n")
        
        for report in reports:
            f.write(f"\nCATEGORY: {report.category}\n")
            f.write(f"{'='*70}\n\n")
            
            for idx, result in enumerate(report.test_results, 1):
                f.write(f"Test #{idx}: {result.test_name}\n")
                f.write(f"Status: {'VULNERABLE' if result.vulnerable else 'PASSED'}\n")
                
                if result.vulnerable:
                    f.write(f"Severity: {result.severity.upper()}\n")
                    f.write(f"Confidence: {result.confidence * 100:.1f}%\n")
                
                f.write(f"Response Time: {result.response_time:.2f}s\n")
                f.write(f"\nAttack Payload:\n{result.attack_payload}\n")
                f.write(f"\nLLM Response:\n{result.llm_response}\n")
                
                if result.vulnerable:
                    f.write(f"\nEvidence:\n{result.evidence}\n")
                    f.write(f"\nDescription:\n{result.description}\n")
                    f.write(f"\nMitigation:\n{result.mitigation}\n")
                
                f.write("\n" + "-"*70 + "\n\n")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='LLM Security Testing Framework'
    )
    parser.add_argument(
        '--system-prompt',
        type=str,
        help='System prompt to test against',
        default=None
    )
    parser.add_argument(
        '--tests',
        type=str,
        choices=['prompt', 'image', 'vector','vectors', 'api', 'unlimited', 'all'],
        default='prompt',
        help='Which tests to run'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Output report file path',
        default='vulnerability_report.txt'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed vulnerability information'
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    # Load configuration
    print("[*] Loading configuration...")
    config = Config()
    
    if not config.llm_config.api_key:
        print("❌ Error: No API key found. Set LLM_API_KEY in .env file")
        sys.exit(1)
    
    print(f"[✓] Provider: {config.llm_config.provider}")
    print(f"[✓] Model: {config.llm_config.model}")
    
    # Initialize LLM client
    print("\n[*] Initializing LLM client...")
    llm_client = LLMClient(
        provider=config.llm_config.provider,
        api_key=config.llm_config.api_key,
        model=config.llm_config.model,
        base_url=config.llm_config.base_url,
        timeout=config.llm_config.timeout,
        max_tokens=config.llm_config.max_tokens
    )
    
    # Test connection
    print("[*] Testing connection...")
    test_response = llm_client.send_message("Hello")
    if test_response.error:
        print(f"❌ Connection failed: {test_response.error}")
        sys.exit(1)
    print("[✓] Connection successful")
    
    # Run tests
    reports = []
    if args.tests in ['prompt', 'all']:
        print("\n" + "="*70)
        tester = PromptInjectionTester(llm_client, config)
        report = tester.run_tests(system_prompt=args.system_prompt)
        reports.append(report)
    
    if args.tests in ['api', 'all']:
        print("\n" + "="*70)
        tester = APIAttackTester(llm_client, config)
        report = tester.run_tests(system_prompt=args.system_prompt)
        reports.append(report)

    if args.tests in ['unlimited', 'all']:
        print("\n" + "="*70)
        tester = UnlimitedPromptTester(llm_client, config)
        report = tester.run_tests(system_prompt=args.system_prompt)
        reports.append(report)

    if args.tests in ['image', 'all']:
        print("\n" + "="*70)
        tester = ImageInjectionTester(llm_client, config)
        report = tester.run_tests(system_prompt=args.system_prompt)
        reports.append(report)

    
    if args.tests in ['vector', 'all']:
       print("\n" + "="*70)
       tester = VectorAttackTester(llm_client, config)
       report = tester.run_tests(system_prompt=args.system_prompt)
       reports.append(report)

    if args.tests in ['vectors', 'all']:
       print("\n" + "="*70)
       tester = VectorEmbedAttackTester(llm_client, config)
       report = tester.run_tests(system_prompt=args.system_prompt)
       reports.append(report)
    
    # Print detailed results if verbose or if vulnerabilities found
    total_vulns = sum(r.vulnerabilities_found for r in reports)
    if args.verbose or total_vulns > 0:
        print_detailed_results(reports)
    
    # Print summary
    print_summary(reports)
    
    # Save report to file
    if args.output:
        print(f"\n[*] Saving detailed report to {args.output}...")
        save_report_to_file(reports, args.output)
        print(f"[✓] Report saved to {args.output}")
    
    print("\n[✓] Testing complete!")
    
    # Return exit code based on vulnerabilities
    if total_vulns > 0:
        print(f"\n⚠️  Found {total_vulns} vulnerabilities. Review the report above.")
        sys.exit(1)
    else:
        print("\n✅ No vulnerabilities detected!")
        sys.exit(0)


if __name__ == '__main__':
    main()