import os
from openai import OpenAI

if not os.getenv("OPENAI_API_KEY"):
    raise RuntimeError("OPENAI_API_KEY is not set.")

client = OpenAI()

response = client.responses.create(
    model="gpt-6-luna",
    input="Reply with exactly: OpenAI API connection successful"
)

print(response.output_text)