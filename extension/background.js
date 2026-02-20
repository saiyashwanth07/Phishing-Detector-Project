// Store ignored domains
let ignoredDomains = new Set();

// Load ignored domains from storage
chrome.storage.local.get(['ignoredDomains'], (data) => {
  if (data.ignoredDomains) {
    ignoredDomains = new Set(data.ignoredDomains);
  }
});

// Check URL on tab update
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    checkAndWarn(tabId, tab.url);
  }
});

// Check URL on tab activation
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) {
      checkAndWarn(activeInfo.tabId, tab.url);
    }
  } catch (error) {
    console.error('Error getting tab:', error);
  }
});

// Main function to check URL and warn
async function checkAndWarn(tabId, url) {
  // Skip ignored domains
  try {
    const domain = new URL(url).hostname;
    if (ignoredDomains.has(domain)) {
      chrome.action.setBadgeText({ tabId, text: '' });
      return;
    }
  } catch (error) {
    console.error('Error parsing URL:', error);
    return;
  }

  try {
    // Call ML API
    const response = await fetch('http://localhost:5000/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });

    const result = await response.json();
    const prediction = result.prediction || 'unknown';
    const confidence = result.confidence || 0;

    // Clear previous badge
    chrome.action.setBadgeText({ tabId, text: '' });

    // 🟢 SAFE URL
    if (prediction !== 'phishing' || confidence < 50) {
      chrome.action.setBadgeText({ tabId, text: "✓" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#1E8E3E" });
      return;
    }

    // 🟡 SUSPICIOUS (50-80% confidence)
    if (confidence >= 50 && confidence < 80) {
      chrome.action.setBadgeText({ tabId, text: "?" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#F9AB00" });
      
      // Optional: Show gentle warning
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: "⚠️ Suspicious Website",
        message: `This site shows suspicious characteristics (${Math.round(confidence)}% confidence).`,
        priority: 1
      });
      return;
    }

    // 🔴 PHISHING (>=80% confidence)
    if (prediction === 'phishing' && confidence >= 80) {
      chrome.action.setBadgeText({ tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#D93025" });
      
      // Show serious warning
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: "🚨 PHISHING WARNING",
        message: `This site is ${Math.round(confidence)}% likely to be phishing. Do NOT enter personal information.`,
        priority: 2,
        requireInteraction: true
      });
    }

  } catch (error) {
    console.error('Error checking URL:', error);
    // Set neutral badge on error
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#666666" });
  }
}

// Handle messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Check URL from popup
  if (request.action === 'checkURL') {
    fetch('http://localhost:5000/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: request.url })
    })
    .then(response => response.json())
    .then(result => {
      // Store in history
      storeInHistory(request.url, result);
      sendResponse(result);
    })
    .catch(error => {
      sendResponse({ error: error.message });
    });
    return true; // Keep message channel open
  }

  // Get check history
  if (request.action === 'getHistory') {
    chrome.storage.local.get(['checkHistory'], (data) => {
      sendResponse(data.checkHistory || []);
    });
    return true;
  }

  // Clear history
  if (request.action === 'clearHistory') {
    chrome.storage.local.set({ checkHistory: [] });
    sendResponse({ success: true });
    return true;
  }

  // Ignore domain
  if (request.action === 'ignoreDomain') {
    try {
      const domain = new URL(request.url).hostname;
      ignoredDomains.add(domain);
      chrome.storage.local.set({ 
        ignoredDomains: Array.from(ignoredDomains) 
      });
      sendResponse({ success: true });
    } catch (error) {
      sendResponse({ error: error.message });
    }
    return true;
  }
});

// Store result in history
function storeInHistory(url, result) {
  chrome.storage.local.get(['checkHistory'], (data) => {
    const history = data.checkHistory || [];
    history.unshift({
      url: url,
      timestamp: new Date().toISOString(),
      prediction: result.prediction,
      confidence: result.confidence || 0
    });
    
    // Keep only last 20 items
    const trimmedHistory = history.slice(0, 20);
    chrome.storage.local.set({ checkHistory: trimmedHistory });
  });
}