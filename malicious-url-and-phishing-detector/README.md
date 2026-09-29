# Malicious URL and Phishing Detector

This project is a comprehensive solution for detecting malicious URLs and phishing threats using machine learning techniques. It consists of a backend Flask application that analyzes URLs and page contents, and a frontend user interface built with React.

## Project Structure

```
malicious-url-and-phishing-detector
├── backend
│   ├── app.py                  # Main entry point for the Flask web application
│   ├── feature_extractor.py     # Extracts features from URLs for analysis
│   ├── threat_analyzer.py       # Implements the lightweight ML classifier for local analysis
│   ├── models
│   │   └── README.md            # Documentation for machine learning models
│   ├── routes
│   │   └── scan.py              # Defines the route for scanning URLs and page contents
│   ├── tests
│   │   └── test_scan.py         # Unit tests for the scan route and threat analysis
│   └── requirements.txt         # Python dependencies for the backend application
├── frontend
│   ├── src
│   │   ├── components           # React components for the frontend UI
│   │   └── services             # Service files for API calls to the backend
│   └── package.json             # Configuration file for the frontend application
├── scripts
│   └── train_classifier.py      # Responsible for training the lightweight ML classifier
└── README.md                    # Documentation for the entire project
```

## Features

- **URL Prediction**: The backend provides an API endpoint to analyze URLs for phishing threats.
- **Local Analysis**: A lightweight machine learning classifier performs instant threat analysis without requiring an internet connection.
- **Feature Extraction**: Relevant features are extracted from URLs to enhance the accuracy of threat detection.
- **User Interface**: A React-based frontend allows users to input URLs and view scan results easily.

## Setup Instructions

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/malicious-url-and-phishing-detector.git
   cd malicious-url-and-phishing-detector
   ```

2. Install backend dependencies:
   ```
   cd backend
   pip install -r requirements.txt
   ```

3. Train the classifier (if necessary):
   ```
   python ../scripts/train_classifier.py
   ```

4. Run the backend server:
   ```
   python app.py
   ```

5. In a new terminal, navigate to the frontend directory and install dependencies:
   ```
   cd frontend
   npm install
   ```

6. Start the frontend application:
   ```
   npm start
   ```

## Usage

- Access the frontend application at `http://localhost:3000`.
- Input a URL in the provided field and submit to receive an analysis of potential threats.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.