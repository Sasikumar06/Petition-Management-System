from datetime import datetime, timezone
import os
import requests
import json
import re

def get_current_utc():
    """Return current datetime in UTC."""
    return datetime.now(timezone.utc)

def analyze_petition(petition_text, petition_title, language='en', api_key=None):
    """Analyze petition text to determine department, priority and tags."""
    # First try AI-based analysis if API key is available
    if api_key:
        try:
            result = analyze_with_ai(petition_text, petition_title, language, api_key)
            if result:
                return result
        except Exception as e:
            print(f"AI analysis error: {e}")
            
    # Fall back to keyword-based analysis
    return keyword_based_analysis(petition_text, petition_title)

def analyze_with_ai(text, title, language, api_key):
    """Use AI to analyze petition content."""
    from googletrans import Translator
    
    # Translate if not in English
    if language != 'en':
        try:
            translator = Translator()
            translated_title = translator.translate(title, dest='en').text
            translated_text = translator.translate(text[:1500], dest='en').text
        except:
            translated_title = title
            translated_text = text[:1500]
    else:
        translated_title = title
        translated_text = text[:1500]
    
    # Make API request
    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        json={
            "model": "qwen/qwq-32b:free",
            "messages": [
                {"role": "system", "content": "You are an AI that categorizes petitions."},
                {"role": "user", "content": f"""
                Analyze this petition and provide a JSON response with:
                1. department_name: One of [Education, Health, Infrastructure, Environment, Public Safety, Housing, Social Welfare, Transportation, Employment, Community Development, General]
                2. priority: low, normal, or high
                3. tags: 3-5 relevant keywords as an array
                4. analysis: Brief 1-2 sentence summary
                
                Title: {translated_title}
                Content: {translated_text}
                """}
            ],
            "response_format": {"type": "json_object"}
        }
    )
    
    if response.status_code == 200:
        try:
            content = response.json()["choices"][0]["message"]["content"]
            result = json.loads(content)
            
            # Map priorities
            priority_map = {
                "low": "Low", 
                "normal": "Normal", 
                "medium": "Normal", 
                "high": "High", 
                "urgent": "High"
            }
            
            return {
                "department_name": result.get("department_name", "General"),
                "priority": priority_map.get(result.get("priority", "").lower(), "Normal"),
                "tags": result.get("tags", []),
                "analysis": result.get("analysis", "No analysis provided.")
            }
        except:
            pass
    
    return None

def keyword_based_analysis(text, title):
    """Simple keyword-based categorization."""
    # Keywords for departments
    department_keywords = {
        "Education": ["school", "education", "student", "teacher", "curriculum", "பள்ளி", "கல்வி", "மாணவர்"],
        "Health": ["health", "hospital", "doctor", "healthcare", "medical", "மருத்துவமனை", "மருத்துவர்", "சுகாதாரம்"],
        "Infrastructure": ["road", "bridge", "pavement", "construction", "infrastructure", "சாலை", "பாலம்"],
        "Environment": ["pollution", "waste", "climate", "environment", "conservation", "மாசு", "சுற்றுச்சூழல்"],
        "Public Safety": ["police", "crime", "safety", "emergency", "security", "காவல்", "பாதுகாப்பு"],
        "Housing": ["housing", "home", "rent", "shelter", "eviction", "வீடு", "குடியிருப்பு"],
        "Social Welfare": ["welfare", "benefit", "aid", "support", "assistance", "நலன்", "உதவி"],
        "Transportation": ["transport", "bus", "train", "commuting", "traffic", "போக்குவரத்து", "பேருந்து"],
        "Employment": ["job", "employment", "work", "salary", "unemployment", "வேலை", "வேலைவாய்ப்பு"],
        "Community Development": ["community", "development", "revitalization", "neighborhood", "சமூகம்"]
    }
    
    combined_text = (text + " " + title).lower()
    
    # Find department based on keywords
    department = "General"
    max_matches = 0
    for dept, keywords in department_keywords.items():
        matches = sum(1 for keyword in keywords if keyword.lower() in combined_text)
        if matches > max_matches:
            max_matches = matches
            department = dept
    
    # Determine priority
    priority = "Normal"
    if any(word in combined_text for word in ["urgent", "immediately", "emergency", "critical", "அவசரம்", "உடனடி"]):
        priority = "High"
    elif any(word in combined_text for word in ["minor", "small", "eventually", "சிறிய", "சிறு"]):
        priority = "Low"
    
    # Extract tags
    words = re.findall(r'\b\w+\b', combined_text)
    common_words = ["the", "and", "a", "an", "in", "of", "to", "for", "with", "that", "this", "ஒரு", "மற்றும்"]
    potential_tags = [w for w in words if len(w) > 3 and w not in common_words]
    tag_count = {}
    for tag in potential_tags:
        tag_count[tag] = tag_count.get(tag, 0) + 1
    tags = [tag for tag, count in sorted(tag_count.items(), key=lambda x: x[1], reverse=True)[:5]]
    
    return {
        "department_name": department,
        "priority": priority,
        "tags": tags,
        "analysis": "Automatic categorization based on keywords."
    }