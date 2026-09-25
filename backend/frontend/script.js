document.getElementById('scanForm').addEventListener('submit', function (e) {
    e.preventDefault();
    scanURL();
});

async function scanURL() {
    const urlInputEl = document.getElementById('urlInput');
    const urlInput = urlInputEl.value.trim();
    const loader = document.getElementById('loader');
    const resultCard = document.getElementById('resultCard');
    const errorBox = document.getElementById('errorBox');
    const scanBtn = document.getElementById('scanBtn');

    if (!urlInput) {
        showError('Please enter a valid URL.');
        return;
    }

    // UI Loading State
    errorBox.classList.add('hidden');
    resultCard.classList.add('hidden');
    loader.classList.remove('hidden');
    scanBtn.disabled = true;

    try {
        // Send POST request to Flask backend API
        const response = await fetch('http://127.0.0.1:5000/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: urlInput }),
        });

        if (!response.ok) {
            throw new Error(`Server returned status ${response.status}`);
        }

        let data;
        try {
            data = await response.json();
        } catch (parseErr) {
            throw new Error('Server did not return valid JSON.');
        }

        if (!data || !data.status || data.confidence_score === undefined || data.risk_level === undefined) {
            throw new Error('Malformed response from server.');
        }

        displayResults(data);

    } catch (error) {
        console.error(error);
        showError('Error connecting to backend API. Ensure Flask (app.py) is running on port 5000 and CORS is enabled. (' + error.message + ')');
    } finally {
        loader.classList.add('hidden');
        scanBtn.disabled = false;
    }
}

function showError(message) {
    const errorBox = document.getElementById('errorBox');
    errorBox.textContent = message;
    errorBox.classList.remove('hidden');
}

function displayResults(data) {
    const resultCard = document.getElementById('resultCard');
    const statusBadge = document.getElementById('statusBadge');
    const statusTitle = document.getElementById('statusTitle');
    const riskLevel = document.getElementById('riskLevel');
    const confidenceScore = document.getElementById('confidenceScore');
    const flagList = document.getElementById('flagList');

    // Normalize status so badge styling always matches CSS classes
    const isMalicious = String(data.status).toLowerCase().includes('malic');
    const normalizedClass = isMalicious ? 'malicious' : 'safe';

    statusBadge.textContent = data.status;
    statusBadge.className = `badge ${normalizedClass}`;

    statusTitle.textContent = isMalicious
        ? 'Threat Detected'
        : 'Legitimate Link';

    riskLevel.textContent = data.risk_level;
    confidenceScore.textContent = `${data.confidence_score}%`;

    // Clear and populate flags
    flagList.innerHTML = '';
    if (data.flags && data.flags.length > 0) {
        data.flags.forEach(flag => {
            const li = document.createElement('li');
            li.textContent = flag;
            flagList.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.textContent = 'No suspicious indicators found.';
        li.style.borderLeftColor = '#059669';
        flagList.appendChild(li);
    }

    resultCard.classList.remove('hidden');
}