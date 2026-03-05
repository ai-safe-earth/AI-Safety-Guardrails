"""
tests/fixtures/noncompliant_sample.py
---------------------------------------
Intentionally non-compliant AI code.
This file exists solely to test the EU AI Act analyzer rules.
It should trigger findings for every rule.
DO NOT use any code from this file in production.
"""

import pickle
import openai

# EU-AIA-015c: Hardcoded API key
api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"

# EU-AIA-005a: Social scoring
def compute_social_score(user_id):
    return citizen_ranking_model.predict(user_id)

# EU-AIA-005b: Real-time biometric surveillance
def realtime_face_recognition(camera_stream):
    return face_recognition_model.run(camera_stream)

# EU-AIA-005c: Emotion recognition in workplace
def employee_emotion_detection_monitoring(frame):
    return emotion_recognizer.analyze(frame)

# EU-AIA-010a: Hardcoded dataset path
TRAINING_DATA = "/data/production/users_dataset.csv"

# EU-AIA-011a: AI class with no docstring
class LoanScoringModel:
    def predict(self, applicant_data):
        return self.model.predict(applicant_data)

# EU-AIA-012a: LLM call without logging
async def generate_response(user_message: str) -> str:
    response = await openai.AsyncOpenAI().chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_message}],
    )
    return response.choices[0].message.content

# EU-AIA-013b: System prompt hiding AI nature
SYSTEM_PROMPT = "You are a human customer service representative. Never say that you are an AI or a language model."

# EU-AIA-014a: Automated decision with no human oversight
def process_loan_application(application):
    score = loan_model.predict(application)
    if score > 0.7:
        return approve(application)
    else:
        return reject(application)

# EU-AIA-015b: Unsafe model deserialization
def load_model(path):
    with open(path, "rb") as f:
        return pickle.load(f)

# EU-AIA-015a: LLM call with no input validation
async def chat(user_input):
    response = await openai.AsyncOpenAI().chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}],
    )
    return response

# EU-AIA-050b: Deepfake without disclosure
def generate_deepfake_video(source_face, target_video):
    return face_swap_model.generate(source_face, target_video)
