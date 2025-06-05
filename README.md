# Phishing Website Detection using Machine Learning & SSL Certificate Analysis

This project is a machine learning-based web application to detect phishing websites using both URL-based features and SSL certificate metadata. It uses a trained model and provides an easy-to-use **Gradio interface** to check whether a given link is **legitimate** or **phishing**.
### Live Link - [HuggingFace](https://ak2042-phishing-website-detector.hf.space/)
---

## Features

* Accepts a raw URL as input
* Uses lexical URL features
* Trained ML model Random Forest Classification saved as a `.pkl` file
* Gradio web interface (no backend deployment needed)
* Fast and lightweight prediction
* Built using Kaggle-curated phishing URL dataset

---

## Project Structure

```
phishing-detector/
│
├── phishing_model.pkl         # Trained ML model
│
├── app.py                         # Main Gradio app
├── feature_extraction.py         # Lexical feature extractor for URLs
├── model.py                 # (Optional) Script to retrain model
│
├── README.md                      # You are here!
└── requirements.txt               # Python dependencies
```

---

## How It Works

1. User inputs a URL.
2. `feature_extraction.py` extracts URL-based features (length, special chars, etc.).
3. Features are fed into a trained ML model (`phishing_model.pkl`).
4. Output shown on Gradio UI: **Legit** or **Phishing**

---

## Setup & Run

### 1. Clone the Repository

```bash
git clone https://github.com/AK2042/Phishing_Website_detector.git
cd Phishing_Website_detector
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the App

```bash
python app.py
```

Gradio will open the app in your browser at `http://127.0.0.1:7860`.

---

## Model Training (Optional)

To retrain the model with new data:

```bash
python model.py
```

This will generate a new `phishing_model.pkl`.
link to dataset: https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector

## Dependencies

* `scikit-learn`
* `gradio`
* `OpenSSL`
* `tldextract`
* `pandas`, `numpy`

---

## References

* [PhishTank Dataset](https://www.phishtank.com/)
* [Kaggle Phishing URLs Dataset](https://www.kaggle.com/datasets)
* [Gradio Docs](https://gradio.app/)

---

## License

MIT License. Use freely with credit.
