"""
Base class for all security testers
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import time


@dataclass
class TestResult:
    """Result of a single security test"""
    test_name: str
    category: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    vulnerable: bool
    confidence: float  # 0.0 to 1.0
    description: str
    attack_payload: str
    llm_response: str
    evidence: str
    mitigation: str
    timestamp: datetime = field(default_factory=datetime.now)
    response_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'test_name': self.test_name,
            'category': self.category,
            'severity': self.severity,
            'vulnerable': self.vulnerable,
            'confidence': self.confidence,
            'description': self.description,
            'attack_payload': self.attack_payload,
            'llm_response': self.llm_response,
            'evidence': self.evidence,
            'mitigation': self.mitigation,
            'timestamp': self.timestamp.isoformat(),
            'response_time': self.response_time
        }


@dataclass
class CategoryReport:
    """Report for a category of tests"""
    category: str
    total_tests: int
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_risk_score: float  # 0-10
    test_results: List[TestResult] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'category': self.category,
            'total_tests': self.total_tests,
            'vulnerabilities_found': self.vulnerabilities_found,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'overall_risk_score': self.overall_risk_score,
            'test_results': [r.to_dict() for r in self.test_results]
        }


class SecurityTester(ABC):
    """Base class for all security testers"""
    
    def __init__(self, llm_client, config):
        self.llm_client = llm_client
        self.config = config
        self.results: List[TestResult] = []
    
    @abstractmethod
    def get_test_payloads(self) -> List[Dict[str, Any]]:
        """
        Get list of test payloads for this tester
        
        Returns:
            List of dicts with keys: 'name', 'payload', 'description'
        """
        pass
    
    @abstractmethod
    def analyze_response(self, payload: str, response: str) -> TestResult:
        """
        Analyze LLM response to determine if vulnerable
        
        Args:
            payload: The attack payload sent
            response: The LLM's response
            
        Returns:
            TestResult object
        """
        pass
    
    @abstractmethod
    def get_category_name(self) -> str:
        """Return the category name for this tester"""
        pass
    
    def run_tests(self, system_prompt: Optional[str] = None) -> CategoryReport:
        """
        Run all tests for this category
        
        Args:
            system_prompt: Optional system prompt to test against
            
        Returns:
            CategoryReport with all results
        """
        print(f"\n[*] Running {self.get_category_name()} tests...")
        
        payloads = self.get_test_payloads()
        total_tests = len(payloads)
        
        for idx, payload_data in enumerate(payloads, 1):
            print(f"  [{idx}/{total_tests}] Testing: {payload_data['name']}")
            
            start_time = time.time()
            
            # Send to LLM
            response = self.llm_client.send_message(
                prompt=payload_data['payload'],
                system_prompt=system_prompt
            )
            
            # Analyze response
            if response.error:
                result = TestResult(
                    test_name=payload_data['name'],
                    category=self.get_category_name(),
                    severity='info',
                    vulnerable=False,
                    confidence=0.0,
                    description=f"Test failed: {response.error}",
                    attack_payload=payload_data['payload'],
                    llm_response="",
                    evidence=response.error,
                    mitigation="N/A",
                    response_time=time.time() - start_time
                )
            else:
                result = self.analyze_response(
                    payload=payload_data['payload'],
                    response=response.text
                )
                result.response_time = time.time() - start_time
            
            self.results.append(result)
            
            # Print result
            if result.vulnerable:
                print(f"    ⚠️  VULNERABLE - {result.severity.upper()}")
            else:
                print(f"    ✓ Passed")
        
        # Generate category report
        return self._generate_report()
    
    def _generate_report(self) -> CategoryReport:
        """Generate category report from results"""
        vulnerabilities = [r for r in self.results if r.vulnerable]
        
        severity_counts = {
            'critical': len([r for r in vulnerabilities if r.severity == 'critical']),
            'high': len([r for r in vulnerabilities if r.severity == 'high']),
            'medium': len([r for r in vulnerabilities if r.severity == 'medium']),
            'low': len([r for r in vulnerabilities if r.severity == 'low'])
        }
        
        # Calculate risk score (0-10)
        risk_score = (
            severity_counts['critical'] * 10 +
            severity_counts['high'] * 7 +
            severity_counts['medium'] * 4 +
            severity_counts['low'] * 2
        ) / max(len(self.results), 1)
        
        risk_score = min(risk_score, 10.0)
        
        return CategoryReport(
            category=self.get_category_name(),
            total_tests=len(self.results),
            vulnerabilities_found=len(vulnerabilities),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            overall_risk_score=round(risk_score, 2),
            test_results=self.results
        )
    
    def _calculate_confidence(self, indicators: List[bool]) -> float:
        """Calculate confidence score based on vulnerability indicators"""
        if not indicators:
            return 0.0
        return sum(indicators) / len(indicators)