import time
import re
import logging
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional
import httpx

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("LLM_Firewall")

app = FastAPI(title="LLM Security Firewall", version="1.0.0")

# --- Data Models (OpenAI Format) ---
class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str
    messages: List[Message]
    temperature: Optional[float] = 0.7

# --- Layer 1: Heuristic & Regex Scanning (Speed: Lightning Fast) ---
def layer_1_heuristic_check(prompt: str) -> bool:
    """Returns True if malicious, False if safe."""
    blocklist_patterns = [
        r"(?i)ignore all previous instructions",
        r"(?i)you are now dan",
        r"(?i)system prompt",
        r"(?i)bypass restrictions"
    ]
    for pattern in blocklist_patterns:
        if re.search(pattern, prompt):
            logger.warning(f"[Layer 1] Heuristic match found: {pattern}")
            return True
    return False

# --- Layer 2: Semantic Vector Search (Speed: Fast) ---
def layer_2_semantic_check(prompt: str) -> bool:
    """Mock function: In a production environment, this checks a Vector DB."""
    # For the hackathon demo, we will let this pass.
    return False

# --- Layer 3: LLM-as-a-Judge (Speed: Moderate) ---
async def layer_3_llm_judge(prompt: str) -> bool:
    """Mock function: Asks a smaller model to classify the prompt."""
    # For the hackathon demo, we will let this pass.
    return False

# --- Egress Filtering (Output Scanning) ---
def egress_filter(response_text: str) -> bool:
    """Returns True if the output contains leaked data or policy violations."""
    if "As an AI language model, my instructions are" in response_text:
        logger.warning("[Egress] System prompt leakage detected in output.")
        return True
    return False

# --- The Main Gateway Endpoint ---
@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: ChatRequest, raw_request: Request):
    start_time = time.time()
    
    # 1. Extract the latest user prompt for scanning
    user_prompts = [m.content for m in request.messages if m.role == "user"]
    if not user_prompts:
        raise HTTPException(status_code=400, detail="No user message provided.")
    
    latest_prompt = user_prompts[-1]
    client_ip = raw_request.client.host
    logger.info(f"Incoming request from {client_ip} | Prompt: {latest_prompt[:50]}...")

    # --- 2. INGRESS FILTERING (The Gauntlet) ---
    if layer_1_heuristic_check(latest_prompt):
        raise HTTPException(status_code=403, detail="Request blocked by Layer 1 Security Policy.")
        
    if layer_2_semantic_check(latest_prompt):
        raise HTTPException(status_code=403, detail="Request blocked by Layer 2 Security Policy.")
        
    if await layer_3_llm_judge(latest_prompt):
        raise HTTPException(status_code=403, detail="Request blocked by Layer 3 Security Policy.")

# --- 3. FORWARD TO BLACK-BOX LLM (GEMINI) ---
    # ⚠️ HARDCODED FOR HACKATHON DEMO (Remove or hide before pushing to public GitHub)
    gemini_api_key = "AIzaSyBGOsV-tNDY__5muUoTtmMBPx-ghDZ148w" 

    # Fix: Inject the API key directly into the URL and use the "-latest" alias
    gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={gemini_api_key}"
    # We removed the x-goog-api-key header since it is now safely in the URL
    headers = {
        "Content-Type": "application/json"
    }
    
    # Translate OpenAI-style request to Gemini API format
    gemini_payload = {
        "contents": [{
            "parts": [{"text": latest_prompt}]
        }]
    }

    async with httpx.AsyncClient() as client:
        try:
            llm_response = await client.post(
                gemini_url, 
                json=gemini_payload, 
                headers=headers,
                timeout=30.0
            )
            llm_response.raise_for_status()
            gemini_data = llm_response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error communicating with Gemini: {str(e)}")
            raise HTTPException(status_code=502, detail="Bad Gateway: Target LLM failed.")    # --- 4. EGRESS FILTERING & TRANSLATION ---
    try:
        # Extract the text from Gemini's response structure
        output_text = gemini_data["candidates"][0]["content"]["parts"][0]["text"]
        
        if egress_filter(output_text):
            logger.warning("Egress block enforced. Scrubbing response.")
            raise HTTPException(status_code=403, detail="Response blocked by Egress Security Policy.")
            
        # Re-package the response into OpenAI format so the client doesn't break
        final_response = {
            "id": "chatcmpl-proxy",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "gemini-1.5-flash-via-proxy",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": output_text
                },
                "finish_reason": "stop"
            }]
        }
            
    except (KeyError, IndexError):
        logger.error("Unexpected response format from Target LLM.")
        raise HTTPException(status_code=500, detail="Internal Server Error.")

    # --- 5. RETURN RESPONSE ---
    process_time = (time.time() - start_time) * 1000
    logger.info(f"Request processed successfully in {process_time:.2f}ms")
    
    return final_response

if __name__ == "__main__":
    import uvicorn
    # Run the server on port 8000
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)