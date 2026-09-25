async function scanURL() {
    const urlInput = document.getElementById('urlInput').value.trim();
    const loader = document.getElementById('loader');
    const resultCard = document.getElementById('resultCard');
    const scanBtn = document.getElementById('scanBtn');

    if (!urlInput) {
        alert('Please enter a valid URL.');
        return;
    }

    // UI Loading State
    loader.classList.remove('hidden');
    resultCard.classList.add('hidden');
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
            throw new Error('Server returned an error');
        }

        const data = await response.json();
        displayResults(data);

    } catch (error) {
        alert('Error connecting to backend API. Ensure Flask (app.py) is running on port 5000.');
        console.error(error);
    } finally {
        loader.classList.add('hidden');
        scanBtn.disabled = false;
    }
}

function displayResults(data) {
    const resultCard = document.getElementById('resultCard');
    const statusBadge = document.getElementById('statusBadge');
    const statusTitle = document.getElementById('statusTitle');
    const riskLevel = document.getElementById('riskLevel');
    const confidenceScore = document.getElementById('confidenceScore');
    const flagList = document.getElementById('flagList');

    // Populate data
    statusBadge.textContent = data.status;
    statusBadge.className = `badge ${data.status.toLowerCase()}`;
    
    statusTitle.textContent = data.status === 'Malicious' 
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