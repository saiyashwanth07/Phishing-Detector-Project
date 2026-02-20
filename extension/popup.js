document.addEventListener('DOMContentLoaded', function() {
  // DOM Elements
  const urlInput = document.getElementById('urlInput');
  const checkBtn = document.getElementById('checkBtn');
  const checkCurrentBtn = document.getElementById('checkCurrentBtn');
  const clearBtn = document.getElementById('clearBtn');
  const ignoreBtn = document.getElementById('ignoreBtn');
  const loadingSpinner = document.getElementById('loadingSpinner');
  const errorMessage = document.getElementById('errorMessage');
  const resultSection = document.getElementById('resultSection');
  const resultTitle = document.getElementById('resultTitle');
  const resultText = document.getElementById('resultText');
  const confidenceBar = document.getElementById('confidenceBar');
  const confidenceText = document.getElementById('confidenceText');
  const historyList = document.getElementById('historyList');
  
  // Initialize
  loadHistory();
  loadCurrentTabUrl();
  
  // Event Listeners
  checkBtn.addEventListener('click', checkUrlInput);
  checkCurrentBtn.addEventListener('click', checkCurrentPage);
  clearBtn.addEventListener('click', clearHistory);
  ignoreBtn.addEventListener('click', ignoreCurrentDomain);
  
  urlInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') checkUrlInput();
  });
  
  // Check URL from input
  async function checkUrlInput() {
    const url = urlInput.value.trim();
    
    if (!url) {
      showError('Please enter a URL');
      return;
    }
    
    if (!isValidUrl(url)) {
      showError('Please enter a valid URL (include http:// or https://)');
      return;
    }
    
    await analyzeUrl(url);
  }
  
  // Check current page
  async function checkCurrentPage() {
    loadingSpinner.classList.add('visible');
    hideResult();
    hideError();
    
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      if (tab && tab.url) {
        urlInput.value = tab.url;
        await analyzeUrl(tab.url);
      } else {
        showError('Unable to get current page URL');
      }
    } catch (error) {
      showError('Error accessing current page: ' + error.message);
    } finally {
      loadingSpinner.classList.remove('visible');
    }
  }
  
  // Analyze URL
  async function analyzeUrl(url) {
    loadingSpinner.classList.add('visible');
    hideResult();
    hideError();
    
    try {
      const result = await chrome.runtime.sendMessage({
        action: 'checkURL',
        url: url
      });
      
      if (result.error) {
        showError('Analysis failed: ' + result.error);
        return;
      }
      
      displayResult(result);
      loadHistory();
    } catch (error) {
      showError('Connection error: ' + error.message);
    } finally {
      loadingSpinner.classList.remove('visible');
    }
  }
  
  // Display result
  function displayResult(result) {
    const prediction = result.prediction || 'unknown';
    const confidence = result.confidence || 0;
    
    // Set result class
    resultSection.className = 'result visible';
    
    if (prediction === 'phishing') {
      if (confidence > 80) {
        resultSection.classList.add('danger');
        resultTitle.textContent = '⚠️ PHISHING DETECTED';
        resultText.textContent = 'This URL appears to be a phishing attempt. Do not enter personal information.';
      } else {
        resultSection.classList.add('warning');
        resultTitle.textContent = '⚠️ SUSPICIOUS URL';
        resultText.textContent = 'This URL shows some suspicious characteristics. Proceed with caution.';
      }
    } else {
      resultSection.classList.add('safe');
      resultTitle.textContent = '✅ SAFE URL';
      resultText.textContent = 'This URL appears to be legitimate.';
    }
    
    // Update confidence bar
    confidenceBar.className = 'confidence-fill ' + (prediction === 'phishing' ? 'danger' : 'safe');
    confidenceBar.style.width = confidence + '%';
    
    // Update confidence text
    confidenceText.textContent = `Confidence: ${confidence.toFixed(1)}%`;
    
    // Scroll to result
    resultSection.scrollIntoView({ behavior: 'smooth' });
  }
  
  // Ignore current domain
  async function ignoreCurrentDomain() {
    const url = urlInput.value.trim();
    if (!url) {
      showError('No URL to ignore');
      return;
    }
    
    try {
      const result = await chrome.runtime.sendMessage({
        action: 'ignoreDomain',
        url: url
      });
      
      if (result.success) {
        alert('Domain added to ignore list. You won\'t see warnings for this site.');
      } else {
        showError('Failed to ignore domain');
      }
    } catch (error) {
      showError('Error: ' + error.message);
    }
  }
  
  // Hide result
  function hideResult() {
    resultSection.classList.remove('visible');
  }
  
  // Show error
  function showError(message) {
    errorMessage.textContent = message;
    errorMessage.classList.add('visible');
    hideResult();
  }
  
  // Hide error
  function hideError() {
    errorMessage.classList.remove('visible');
  }
  
  // Load history
  async function loadHistory() {
    try {
      const history = await chrome.runtime.sendMessage({ action: 'getHistory' });
      displayHistory(history);
    } catch (error) {
      console.error('Failed to load history:', error);
    }
  }
  
  // Display history
  function displayHistory(history) {
    historyList.innerHTML = '';
    
    if (!history || history.length === 0) {
      historyList.innerHTML = '<div class="history-item">No checks yet</div>';
      return;
    }
    
    history.slice(0, 5).forEach(item => {
      const historyItem = document.createElement('div');
      historyItem.className = 'history-item';
      
      const urlSpan = document.createElement('span');
      urlSpan.className = 'history-url';
      urlSpan.title = item.url;
      
      try {
        const urlObj = new URL(item.url);
        urlSpan.textContent = urlObj.hostname;
      } catch {
        urlSpan.textContent = item.url.substring(0, 30) + '...';
      }
      
      const badge = document.createElement('span');
      badge.className = 'history-prediction ' + 
        (item.prediction === 'phishing' ? 'phishing-badge' : 'legitimate-badge');
      badge.textContent = item.prediction === 'phishing' ? 'PHISHING' : 'SAFE';
      
      historyItem.appendChild(urlSpan);
      historyItem.appendChild(badge);
      
      // Click to re-check
      historyItem.addEventListener('click', () => {
        urlInput.value = item.url;
        analyzeUrl(item.url);
      });
      
      historyList.appendChild(historyItem);
    });
  }
  
  // Clear history
  async function clearHistory() {
    if (confirm('Clear all check history?')) {
      await chrome.runtime.sendMessage({ action: 'clearHistory' });
      loadHistory();
    }
  }
  
  // Validate URL
  function isValidUrl(string) {
    try {
      const url = new URL(string);
      return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
      return false;
    }
  }
  
  // Load current tab URL when popup opens
  async function loadCurrentTabUrl() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url && tab.url.startsWith('http')) {
        urlInput.value = tab.url;
      }
    } catch (error) {
      console.log('Could not load current tab URL:', error.message);
    }
  }
});