import openai

# 1) Point the OpenAI client at Deepseek
openai.api_key  = "sk-6ca8c3ad4f534f35a90a816601afaa94"
openai.api_base = "https://api.deepseek.com/v1"

def list_deepseek_models():
    try:
        # This calls GET https://api.deepseek.com/v1/models
        response = openai.Model.list()
    except Exception as e:
        print("Error listing models:", e)
        return

    data = response.get("data", [])
    if not data:
        print("No models found. Check your API key and base URL.")
        return

    print("Available models on Deepseek:")
    for entry in data:
        # Each entry typically has keys "id", "object", etc.
        print("  ", entry.get("id"))

if __name__ == "__main__":
    list_deepseek_models()
