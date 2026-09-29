# Machine Learning Models Documentation

This directory contains the machine learning models used in the Malicious URL and Phishing Detector project. The models are designed to analyze URL patterns, structural heuristics, and page metadata for potential security threats.

## Model Overview

1. **Lightweight Classifier**: 
   - A fine-tuned machine learning classifier that operates locally to provide instant threat analysis without requiring an internet connection.
   - It is optimized for performance and accuracy, ensuring low latency during predictions.

2. **Transformer Model**:
   - A transformer-based model that leverages advanced natural language processing techniques to analyze page contents and metadata.
   - This model is designed to enhance the detection of phishing attempts by understanding the context of the content.

## Training and Fine-Tuning

- The models can be trained and fine-tuned using the `scripts/train_classifier.py` script.
- Ensure that the training dataset is properly preprocessed and formatted according to the requirements of the models.
- After training, the models are saved in a format compatible with the backend application for easy loading and inference.

## Usage

- The models are loaded in the `backend/threat_analyzer.py` file, where they are utilized to perform predictions based on the extracted features from URLs and page contents.
- The results of the predictions are returned to the frontend through the API endpoints defined in `backend/app.py`.

## Future Improvements

- Consider expanding the dataset for training to improve model robustness.
- Explore additional features that can be extracted from URLs and page contents to enhance detection capabilities.
- Regularly update the models with new data to adapt to evolving phishing techniques.