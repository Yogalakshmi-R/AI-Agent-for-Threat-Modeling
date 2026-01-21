# Debug script to test API endpoints
import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

def test_llama_api():
    """Test Llama 3.1 API connection"""
    try:
        url = os.getenv('OLLAMA_API_URL')
        api_key = os.getenv('OLLAMA_API_KEY')
        
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        test_payload = {
            "model": "llama3.1:8b",
            "messages": [{"role": "user", "content": "Hello, test message"}],
            "max_tokens": 100
        }
        
        print(f"Testing Llama API: {url}")
        response = requests.post(url, headers=headers, json=test_payload, timeout=30)
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Content: {response.text[:500]}")
        
        return response.status_code == 200
        
    except Exception as e:
        print(f"Llama API Error: {str(e)}")
        return False

def test_azure_openai_api():
    """Test Azure OpenAI API connection"""
    try:
        endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
        api_key = os.getenv('AZURE_OPENAI_API_KEY')
        deployment = os.getenv('AZURE_OPENAI_DEPLOYMENT')
        api_version = os.getenv('AZURE_OPENAI_API_VERSION')
        
        url = f"{endpoint}openai/deployments/{deployment}/chat/completions?api-version={api_version}"
        
        headers = {
            'api-key': api_key,
            'Content-Type': 'application/json'
        }
        
        test_payload = {
            "messages": [{"role": "user", "content": "Hello, test message"}],
            "max_tokens": 100
        }
        
        print(f"Testing Azure OpenAI API: {url}")
        response = requests.post(url, headers=headers, json=test_payload, timeout=30)
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Content: {response.text[:500]}")
        
        return response.status_code == 200
        
    except Exception as e:
        print(f"Azure OpenAI API Error: {str(e)}")
        return False

if __name__ == "__main__":
    print("=== API Connection Tests ===")
    print("\n1. Testing Llama 3.1 API...")
    llama_success = test_llama_api()
    
    print("\n2. Testing Azure OpenAI API...")
    azure_success = test_azure_openai_api()
    
    print(f"\n=== Results ===")
    print(f"Llama 3.1: {'✅ Success' if llama_success else '❌ Failed'}")
    print(f"Azure OpenAI: {'✅ Success' if azure_success else '❌ Failed'}")