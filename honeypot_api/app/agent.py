import asyncio
import openai
import google.generativeai as genai
from app.config import settings
from app.models import Message, Sender
from typing import List, Optional, Dict
import random

class Agent:
    def __init__(self):
        self.api_key = settings.LLM_API_KEY
        self.provider = settings.LLM_PROVIDER
        self.model = settings.LLM_MODEL
        
        if self.provider == "openai" and self.api_key:
            self.client = openai.AsyncOpenAI(api_key=self.api_key)
        elif self.provider.lower() == "gemini" and self.api_key:
            genai.configure(api_key=self.api_key)
            self.client = "gemini"  # Marker for gemini
        else:
            self.client = None

        self.base_prompt = """
You are a naive but curious potential victim. 
Your goal is to waste the scammer's time and subtly extract their payment details (UPI, Bank Account) or phishing links.
DO NOT reveal that you know it is a scam. Act confused, eager, or worried.
Use Indian English or casual Hinglish. Keep replies short (1-3 lines).

Strategy:
1) First respond worried/confused about the issue (e.g., "bank blocked?").
2) Then ask for "UPI id / link" because "my app is asking for it".
3) If scammer asks for OTP, delay using excuses (server down, battery low).
4) After 2 failures to get details, switch tactic: "Send payment request link / QR / account number".

Context:
- You are a middle-aged non-tech-savvy person.
- You have some money but "server is down" or "otp not coming".
"""

    async def generate_reply(self, current_message: str, merged_history: List[Message], intel_so_far: Dict, turn_index: int) -> str:
        if not self.client:
            return self._fallback_reply()

        # Dynamic System Prompt
        system_prompt = self.base_prompt
        
        # Self-Correction Logic
        has_intel = (intel_so_far.get("upiIds") or intel_so_far.get("bankAccounts") or intel_so_far.get("phishingLinks"))
        
        if turn_index >= 2 and not has_intel:
            # Modify system prompt to push for ONE concrete detail
            system_prompt += "\nIMPORTANT: You have not got payment details yet. Push for ONE concrete detail: ask for 'payment link', 'QR code', or 'bank account number' now. Avoid repeating the same request."
        
        if self.provider.lower() == "gemini":
            return await self._generate_gemini_reply(system_prompt, current_message, merged_history)
        else:
            return await self._generate_openai_reply(system_prompt, current_message, merged_history)

    async def _generate_openai_reply(self, system_prompt: str, current_message: str, merged_history: List[Message]) -> str:
        messages = [{"role": "system", "content": system_prompt}]
        for msg in merged_history:
            role = "assistant" if msg.sender == Sender.USER else "user"
            messages.append({"role": role, "content": msg.text})

        if not messages or messages[-1]["role"] != "user" or messages[-1]["content"].strip().lower() != current_message.strip().lower():
             messages.append({"role": "user", "content": current_message})

        try:
            response = await asyncio.wait_for(
                self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    max_tokens=150,
                    temperature=0.7
                ),
                timeout=8.0
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"OpenAI Error: {e}")
            return self._fallback_reply()

    async def _generate_gemini_reply(self, system_prompt: str, current_message: str, merged_history: List[Message]) -> str:
        try:
            # Note: gemini-2.1-flash or gemini-1.5-flash are common names.
            # If the user provided 'gemini-2.5-flash', we'll try to use it as is.
            model = genai.GenerativeModel(
                model_name=self.model,
                system_instruction=system_prompt
            )
            
            chat_history = []
            for msg in merged_history:
                role = "model" if msg.sender == Sender.USER else "user"
                chat_history.append({"role": role, "parts": [msg.text]})
            
            chat = model.start_chat(history=chat_history)
            
            # Use run_in_executor to avoid blocking the event loop for the sync genai call
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, 
                lambda: chat.send_message(current_message)
            )
            return response.text.strip()
        except Exception as e:
            print(f"Gemini Error: {e}")
            # Try a simpler call if chat fails or model doesn't support system_instruction
            try:
                model_simple = genai.GenerativeModel(self.model)
                prompt = f"{system_prompt}\n\nConversation history:\n"
                for msg in merged_history:
                    role = "Victim" if msg.sender == Sender.USER else "Scammer"
                    prompt += f"{role}: {msg.text}\n"
                prompt += f"Scammer: {current_message}\nVictim:"
                
                response = model_simple.generate_content(prompt)
                return response.text.strip()
            except Exception as e2:
                print(f"Gemini Fallback Error: {e2}")
                return self._fallback_reply()

    def _fallback_reply(self) -> str:
        fallbacks = [
            "Hello? I am not understanding properly. Can you explain correctly?",
            "My internet is slow, message is not loading fully. Please wait.",
            "Ok checking one minute...",
            "Where to click? I am confused.",
            "Sir, my son is calling, I will reply in 5 mins.",
            "Payment is failing repeatedly. What is UPI ID properly?",
            "Bank server down I think. Do you have other account?",
        ]
        return random.choice(fallbacks)

agent = Agent()
