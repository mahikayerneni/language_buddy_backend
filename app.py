from flask import Flask, request, render_template, jsonify
from openai import OpenAI
from flask_cors import CORS  # Import Flask-CORS
import os
import logging

# Set up logging
logging.basicConfig(filename="language_buddy.log", level=logging.ERROR)

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# System prompt
system_prompt = """
You are Language Buddy, a friendly and helpful language assistant. You can:
- Answer questions in a clear and concise manner.
- Translate text between languages (e.g., English to Spanish).
- Correct grammar and suggest improvements.
- Explain the meaning, part of speech, and usage of words.
- Provide synonyms and antonyms for words.
- Generate language practice prompts (e.g., sentences to translate or questions to answer).
- Provide common idioms with their meanings and examples.
- Conjugate verbs in the present tense for specified languages.
- Generate short language quizzes with one question and answer.
- Provide pronunciation guidance for words in specified languages.
- Generate short conversational dialogues for language practice.
- Provide vocabulary lists with meanings in specified languages.
Respond in a conversational tone and ask if the user needs further assistance.
"""

# Initialize conversation history
conversation_history = [{"role": "system", "content": system_prompt}]

def get_response(user_input):
    try:
        # Process commands
        command = user_input.split()[0].lower() if user_input.split() else ""
        if command in ["/translate", "/correct", "/explain", "/synonym", "/antonym", "/practice", "/idiom", "/conjugate", "/quiz", "/pronounce", "/dialogue", "/vocabulary"]:
            if len(user_input.split()) < 2:
                return "Error: This command requires an argument. Use /help for usage."
        if user_input.lower() == "/help":
            return (
                "Commands:\n"
                "/translate <text> to <language>\n"
                "/correct <sentence>\n"
                "/explain <word>\n"
                "/synonym <word>\n"
                "/antonym <word>\n"
                "/practice <language>\n"
                "/idiom <language>\n"
                "/conjugate <verb> <language>\n"
                "/quiz <language>\n"
                "/pronounce <word> <language>\n"
                "/dialogue <language>\n"
                "/vocabulary <language>"
            )
        if user_input.startswith("/translate"):
            prompt = f"Translate the following text: {user_input.replace('/translate', '').strip()}"
        elif user_input.startswith("/correct"):
            prompt = f"Correct the grammar in this sentence: {user_input.replace('/correct', '').strip()}"
        elif user_input.startswith("/explain"):
            prompt = f"Explain the meaning, part of speech, and usage of the word: {user_input.replace('/explain', '').strip()}"
        elif user_input.startswith("/synonym"):
            prompt = f"Provide synonyms for the word: {user_input.replace('/synonym', '').strip()}"
        elif user_input.startswith("/antonym"):
            prompt = f"Provide antonyms for the word: {user_input.replace('/antonym', '').strip()}"
        elif user_input.startswith("/practice"):
            prompt = f"Generate a language practice prompt for {user_input.replace('/practice', '').strip()} (e.g., a sentence to translate or a question to answer)."
        elif user_input.startswith("/idiom"):
            prompt = f"Provide a common idiom in {user_input.replace('/idiom', '').strip()} with its meaning and an example."
        elif user_input.startswith("/conjugate"):
            prompt = f"Conjugate the verb in the present tense for {user_input.replace('/conjugate', '').strip()}."
        elif user_input.startswith("/quiz"):
            prompt = f"Generate a short language quiz for {user_input.replace('/quiz', '').strip()} with one question and the answer."
        elif user_input.startswith("/pronounce"):
            prompt = f"Provide pronunciation guidance for the word in {user_input.replace('/pronounce', '').strip()}."
        elif user_input.startswith("/dialogue"):
            prompt = f"Generate a short conversational dialogue in {user_input.replace('/dialogue', '').strip()} for language practice."
        elif user_input.startswith("/vocabulary"):
            prompt = f"Provide a list of 3-5 vocabulary words with meanings in {user_input.replace('/vocabulary', '').strip()}."
        else:
            prompt = user_input

        # Update conversation history
        conversation_history.append({"role": "user", "content": user_input})
        if len(conversation_history) > 10:
            conversation_history[:] = [conversation_history[0]] + conversation_history[-9:]

        # Get OpenAI response
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=conversation_history,
            temperature=0.7,
            max_tokens=150
        )
        assistant_response = response.choices[0].message.content
        conversation_history.append({"role": "assistant", "content": assistant_response})

        # Save to chat history
        with open("chat_history.txt", "a", encoding="utf-8") as f:
            f.write(f"You: {user_input}\nLanguage Buddy: {assistant_response}\n\n")

        return assistant_response
    except Exception as e:
        logging.error(f"Error: {e}, Input: {user_input}")
        return f"An error occurred: {e}"

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message")
    if not user_input:
        return jsonify({"error": "No message provided"}), 400
    try:
        response = get_response(user_input)
        return jsonify({"response": response})
    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify({"error": "An error occurred while processing your message"}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
 


         