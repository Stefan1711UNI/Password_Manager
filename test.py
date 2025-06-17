from groq import Groq

MODEL_NAME = "compound-beta"
api_key = "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"

class PasswordSuggester:
    """
    Provides exactly 1 memorable password.
    """

    def __init__(self, model_name=MODEL_NAME, api_key=api_key):
        self.model_name = model_name

    def generate(self):
        prompt = (
            "You are a password‑making assistant. "
            "Generate **one** secure, memorable password by:  \n"
            "  1. Choosing three real English words that form a vivid mental image (e.g. 'SilverFoxMoon').  \n"
            "  2. Inserting 2–3 digits at the end (e.g. '123') for entropy.  \n"
            "Do **not** include symbols other than the capital letters and digits.  \n"
            "Return **exactly** the password, with no labels or extra text."
        )

        try:
            client = Groq(api_key=api_key)
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    # 1) System message tells the model who it *is*
                    {
                        "role": "system",
                        "content": "You are an assistant that creates secure and memorable passwords."
                    },
                    # 2) User message tells the model what we *want right now*
                    {
                        "role": "user",
                        "content": prompt
                    },
                ],
                max_tokens=8,
                temperature=0.8,
                top_p=1.0,
                # Stop at first newline so we only get a single line
                stop=["\n"]
            )
        except Exception as e:
            raise RuntimeError(f"AI API error: {e}")

        password = response.choices[0].message.content.strip()

        password = password.lstrip('"\' ').removeprefix("Password:").strip()

        return password


if __name__ == "__main__":
    suggester = PasswordSuggester()
    try:
        generated_password = suggester.generate()
        print("Generated password:", generated_password)
    except RuntimeError as err:
        print("Error generating password:", err)
