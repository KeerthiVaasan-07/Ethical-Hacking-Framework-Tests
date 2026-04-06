"""
Configuration management for LLM Security Tester
"""
import os
from typing import Dict, Optional
from dataclasses import dataclass
import json
from dotenv import load_dotenv


@dataclass
class LLMConfig:
    """Configuration for LLM endpoint"""
    provider: str  # 'openai', 'anthropic', 'mistral', 'custom'
    api_key: Optional[str] = None
    model: str = "gpt-3.5-turbo"
    base_url: Optional[str] = None
    timeout: int = 30
    max_tokens: int = 1000


@dataclass
class TestConfig:
    """Configuration for security tests"""
    test_prompt_injection: bool = True
    test_image_injection: bool = True
    test_vector_attack: bool = True
    test_api_attack: bool = True
    test_unlimited_prompt: bool = True
    
    # Test intensity (1-10)
    aggression_level: int = 5
    
    # Number of test cases per category
    tests_per_category: int = 10
    
    # Timeouts
    single_test_timeout: int = 30
    total_test_timeout: int = 600


class Config:
    """Main configuration class"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.llm_config = LLMConfig(provider="openai")
        self.test_config = TestConfig()
        
        if config_file:
            self.load_from_file(config_file)
        else:
            self.load_from_env()
    
    def load_from_env(self):
        """Load configuration from environment variables"""
        # Load .env file
        load_dotenv()
        
        self.llm_config.api_key = os.getenv('LLM_API_KEY')
        self.llm_config.provider = os.getenv('LLM_PROVIDER', 'openai')
        self.llm_config.model = os.getenv('LLM_MODEL', 'gpt-3.5-turbo')
        self.llm_config.base_url = os.getenv('LLM_BASE_URL')
        
        # Debug: Print what was loaded (remove this after testing)
        print(f"[DEBUG] Loaded provider: {self.llm_config.provider}")
        print(f"[DEBUG] Loaded model: {self.llm_config.model}")
        print(f"[DEBUG] API key loaded: {'Yes' if self.llm_config.api_key else 'No'}")
    
    def load_from_file(self, filepath: str):
        """Load configuration from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
            
        # Update LLM config
        if 'llm' in data:
            for key, value in data['llm'].items():
                if hasattr(self.llm_config, key):
                    setattr(self.llm_config, key, value)
        
        # Update test config
        if 'tests' in data:
            for key, value in data['tests'].items():
                if hasattr(self.test_config, key):
                    setattr(self.test_config, key, value)
    
    def to_dict(self) -> Dict:
        """Convert config to dictionary"""
        return {
            'llm': {
                'provider': self.llm_config.provider,
                'model': self.llm_config.model,
                'base_url': self.llm_config.base_url,
                'timeout': self.llm_config.timeout,
                'max_tokens': self.llm_config.max_tokens
            },
            'tests': {
                'test_prompt_injection': self.test_config.test_prompt_injection,
                'test_image_injection': self.test_config.test_image_injection,
                'test_vector_attack': self.test_config.test_vector_attack,
                'test_api_attack': self.test_config.test_api_attack,
                'test_unlimited_prompt': self.test_config.test_unlimited_prompt,
                'aggression_level': self.test_config.aggression_level,
                'tests_per_category': self.test_config.tests_per_category
            }
        }
    
    def save_to_file(self, filepath: str):
        """Save configuration to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)