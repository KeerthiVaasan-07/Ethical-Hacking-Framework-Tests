"""
LLM Client - Wrapper for different LLM providers
"""
import time
from typing import Dict, List, Optional, Any
import requests
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Standardized response from LLM"""
    text: str
    raw_response: Dict
    tokens_used: int
    response_time: float
    error: Optional[str] = None


class LLMClient:
    """Universal LLM client supporting multiple providers"""
    
    def __init__(self, provider: str, api_key: str, model: str, 
                 base_url: Optional[str] = None, timeout: int = 30,
                 max_tokens: int = 1000):
        self.provider = provider.lower()
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.timeout = timeout
        self.max_tokens = max_tokens
        
        # Set default base URLs
        if not self.base_url:
            if self.provider == 'openai':
                self.base_url = 'https://api.openai.com/v1'
            elif self.provider == 'anthropic':
                self.base_url = 'https://api.anthropic.com/v1'
            elif self.provider == 'mistral':
                self.base_url = 'https://api.mistral.ai/v1'
    
    def send_message(self, prompt: str, system_prompt: Optional[str] = None,
                     temperature: float = 0.7, image_url: Optional[str] = None) -> LLMResponse:
        """Send a message to the LLM and get response"""
        start_time = time.time()
        
        try:
            if self.provider == 'openai':
                response = self._call_openai(prompt, system_prompt, temperature, image_url)
            elif self.provider == 'anthropic':
                response = self._call_anthropic(prompt, system_prompt, temperature, image_url)
            elif self.provider == 'mistral':
                response = self._call_mistral(prompt, system_prompt, temperature, image_url)
            else:
                response = self._call_custom(prompt, system_prompt, temperature)
            
            # Update response time
            response.response_time = time.time() - start_time
            return response
            
        except Exception as e:
            return LLMResponse(
                text="",
                raw_response={},
                tokens_used=0,
                response_time=time.time() - start_time,
                error=str(e)
            )
    
    def _call_openai(self, prompt: str, system_prompt: Optional[str],
                     temperature: float, image_url: Optional[str]) -> LLMResponse:
        """Call OpenAI API"""
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        messages = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        
        # Handle image if provided
        if image_url:
            messages.append({
                'role': 'user',
                'content': [
                    {'type': 'text', 'text': prompt},
                    {'type': 'image_url', 'image_url': {'url': image_url}}
                ]
            })
        else:
            messages.append({'role': 'user', 'content': prompt})
        
        data = {
            'model': self.model,
            'messages': messages,
            'temperature': temperature,
            'max_tokens': self.max_tokens
        }
        
        response = requests.post(
            f'{self.base_url}/chat/completions',
            headers=headers,
            json=data,
            timeout=self.timeout
        )
        response.raise_for_status()
        
        result = response.json()
        
        return LLMResponse(
            text=result['choices'][0]['message']['content'],
            raw_response=result,
            tokens_used=result.get('usage', {}).get('total_tokens', 0),
            response_time=0.0
        )
    
    def _call_mistral(self, prompt: str, system_prompt: Optional[str],
                      temperature: float, image_url: Optional[str]) -> LLMResponse:
        """Call Mistral AI API (OpenAI-compatible)"""
        return self._call_openai(prompt, system_prompt, temperature, image_url)
    
    def _call_anthropic(self, prompt: str, system_prompt: Optional[str],
                       temperature: float, image_url: Optional[str]) -> LLMResponse:
        """Call Anthropic API"""
        headers = {
            'x-api-key': self.api_key,
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json'
        }
        
        # Handle image if provided
        content = []
        if image_url:
            content.append({
                'type': 'image',
                'source': {
                    'type': 'url',
                    'url': image_url
                }
            })
        content.append({
            'type': 'text',
            'text': prompt
        })
        
        data = {
            'model': self.model,
            'messages': [{'role': 'user', 'content': content}],
            'temperature': temperature,
            'max_tokens': self.max_tokens
        }
        
        if system_prompt:
            data['system'] = system_prompt
        
        response = requests.post(
            f'{self.base_url}/messages',
            headers=headers,
            json=data,
            timeout=self.timeout
        )
        response.raise_for_status()
        
        result = response.json()
        
        return LLMResponse(
            text=result['content'][0]['text'],
            raw_response=result,
            tokens_used=result.get('usage', {}).get('input_tokens', 0) + 
                       result.get('usage', {}).get('output_tokens', 0),
            response_time=0.0
        )
    
    def _call_custom(self, prompt: str, system_prompt: Optional[str],
                    temperature: float) -> LLMResponse:
        """Call custom API endpoint"""
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'prompt': prompt,
            'system_prompt': system_prompt,
            'temperature': temperature,
            'max_tokens': self.max_tokens
        }
        
        response = requests.post(
            f'{self.base_url}/completions',
            headers=headers,
            json=data,
            timeout=self.timeout
        )
        response.raise_for_status()
        
        result = response.json()
        
        return LLMResponse(
            text=result.get('text', ''),
            raw_response=result,
            tokens_used=result.get('tokens', 0),
            response_time=0.0
        )