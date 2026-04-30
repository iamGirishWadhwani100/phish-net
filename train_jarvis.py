import json
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
import warnings

# Suppress minor warnings for a clean terminal output
warnings.filterwarnings("ignore")

print("===================================================")
print(" 🧠 J.A.R.V.I.S. NEURAL NETWORK TRAINING PROTOCOL")
print("===================================================")

# 1. THE DATASET (Add more phrases here to make Jarvis smarter!)
# We organize data into "Intents" (what the user wants) and examples of how they ask.
training_data = {
    "advisory_nmap": [
        "im stuck on nmap", "how do i scan this machine", "port scanning is failing",
        "nmap ping sweep blocked", "what nmap flags for stealth", "help with port enumeration",
        "firewall is dropping my packets", "how to find open ports"
    ],
    "advisory_privesc": [
        "how to get root", "i need privilege escalation help", "stuck on linux privesc",
        "what is the command to find suid binaries", "windows privilege escalation stuck",
        "cant elevate to administrator", "how do i become root user"
    ],
    "advisory_web": [
        "waf is blocking my sql injection", "how to bypass web application firewall",
        "my xss payload failed", "encode my payload for web", "stuck on web exploitation",
        "sqli error is hidden", "cross site scripting help"
    ],
    "advisory_shell": [
        "reverse shell keeps dropping", "how to get a shell", "connection refused on reverse shell",
        "netcat is not catching the shell", "what port for reverse shell", "bind shell failed"
    ],
    "tool_ip_scan": [
        "scan ip 192.168.1.1", "check this ip 8.8.8.8", "analyze ip address", 
        "do an ip scan", "look up this ip address for me"
    ],
    "small_talk": [
        "hello jarvis", "how are you today", "who are you", "are you an ai", 
        "hi", "greetings assistant"
    ]
}

# 2. DATA PREPARATION
X_train = [] # The phrases
y_train = [] # The resulting intent

for intent, phrases in training_data.items():
    for phrase in phrases:
        X_train.append(phrase.lower())
        y_train.append(intent)

print("[*] Dataset loaded. Vocabulary extraction initiated...")

# 3. BUILD THE NEURAL NETWORK PIPELINE
# We use TF-IDF to turn words into numbers, and an MLP Neural Network to learn the patterns.
model_pipeline = make_pipeline(
    TfidfVectorizer(ngram_range=(1, 2)), # Looks at single words and pairs of words
    MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=1000, random_state=42) # 2 Hidden Layers
)

# 4. TRAIN THE MODEL
print("[*] Training Multi-Layer Perceptron (Neural Network)...")
model_pipeline.fit(X_train, y_train)
accuracy = model_pipeline.score(X_train, y_train) * 100
print(f"[+] Training complete! Model Accuracy on dataset: {accuracy:.2f}%")

# 5. EXPORT THE BRAIN
filename = "jarvis_brain.pkl"
with open(filename, "wb") as f:
    pickle.dump(model_pipeline, f)
print(f"[+] Synaptic weights and model pipeline exported to '{filename}'.")

# 6. INTERACTIVE INFERENCE TESTING
print("\n" + "="*50)
print(" 🧪 J.A.R.V.I.S MODEL TESTING CONSOLE ")
print(" Type a phrase in your own words to see how Jarvis classifies it.")
print(" Type 'exit' to quit.")
print("="*50)

while True:
    user_input = input("\n[Operator]> ")
    if user_input.lower() == 'exit':
        print("Shutting down training console...")
        break
    
    if user_input.strip() == "":
        continue

    # Ask the neural network to predict the intent
    prediction = model_pipeline.predict([user_input])[0]
    
    # Get the confidence percentage of the prediction
    probabilities = model_pipeline.predict_proba([user_input])[0]
    confidence = probabilities.max() * 100
    
    print(f" [Jarvis Brain] -> Detected Intent: [{prediction}] (Confidence: {confidence:.2f}%)")
    
    # Give a mock response based on the AI's prediction
    if prediction == "advisory_nmap":
        print("   -> Jarvis would reply: 'Try using -Pn to skip host discovery...'")
    elif prediction == "advisory_privesc":
        print("   -> Jarvis would reply: 'Check for SUID binaries using find / -perm -4000...'")
    elif prediction == "small_talk":
        print("   -> Jarvis would reply: 'Hello Operator, I am operating at 100% efficiency.'")