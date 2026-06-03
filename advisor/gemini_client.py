class GeminiClient:
    def __init__(self, api_key: str):
        self._api_key = api_key

    def generate(self, prompt: str) -> str:
        try:
            import google.generativeai as genai
        except ImportError:
            raise RuntimeError(
                "google-generativeai is not installed. Run: pip install google-generativeai"
            )
        try:
            genai.configure(api_key=self._api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(prompt)
            return response.text
        except Exception as exc:
            raise RuntimeError(str(exc)) from exc
