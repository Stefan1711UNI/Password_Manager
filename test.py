import openai

#AI API TEST
#replace the key below with your actual Deepseek API key.
openai.api_key  = "sk-6ca8c3ad4f534f35a90a816601afaa94"
openai.api_base = "https://api.deepseek.com/v1"


class PasswordSuggester:
    """
    Uses the OpenAI‐compatible endpoint (Deepseek) to generate one memorable
    password. Make sure openai.api_key and openai.api_base are set first.
    """

    def __init__(self, model_name="deepseek-chat"):
        self.model_name = model_name

    def generate(self):
        prompt = (
            "Generate one secure but memorable password that follows normal speech patterns. "
            "Use capital letters, some digits, and combine words so that a human can remember it. "
            "Do NOT insert random symbols like # or $. "
            "For example: TheBLuE45RabbIT\n\n"
            "Password:"
        )

        try:
            response = openai.ChatCompletion.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an assistant that creates secure and memorable passwords."
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=16,
                temperature=0.8,
                n=1
            )
        except Exception as e:
            raise RuntimeError(f"AI API error: {e}")

        text = response.choices[0].message.content.strip()
        # Strip any leading “Password:” or quotes
        cleaned = text.strip().strip('"').strip("'")
        if cleaned.lower().startswith("password:"):
            cleaned = cleaned.split(":", 1)[1].strip()
        return cleaned


if __name__ == "__main__":
    suggester = PasswordSuggester(model_name="deepseek-chat")
    try:
        generated_password = suggester.generate()
        print("Generated password:", generated_password)
    except RuntimeError as err:
        print("Error generating password:", err)
