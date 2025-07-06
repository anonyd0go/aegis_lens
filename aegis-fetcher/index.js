/**
 * Cloudflare Worker to securely fetch HTML using the Browserless.io service.
 * IMPROVED: Better handling of phishing sites and error detection
 */

export default {
  async fetch(request, env, ctx) {
    // --- Step 1: Basic Request Validation ---
    if (request.method !== 'POST') {
      return new Response('Expected POST request', { status: 405 });
    }

    if (request.headers.get('Content-Type') !== 'application/json') {
      return new Response('Expected Content-Type: application/json', { status: 415 });
    }

    try {
      // --- Step 2: Get Target URL from Request Body ---
      const { url } = await request.json();

      if (!url) {
        return new Response(JSON.stringify({ error: 'URL is required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // --- Step 3: Call the Browserless.io API with improved options ---
      const apiKey = env.BROWSERLESS_API_KEY;

      if (!apiKey) {
        return new Response(JSON.stringify({ error: 'Worker is not configured. Missing Browserless API Key.' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const browserlessApiUrl = `https://production-sfo.browserless.io/content?token=${apiKey}`;

      // Make the secure call to the Browserless API with better options
      const response = await fetch(browserlessApiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          "url": url,
          "gotoOptions": {
            "waitUntil": "networkidle0",
            "timeout": 30000 // 30 seconds
          },
          // Add viewport to mimic real browser
          "viewport": {
            "width": 1366,
            "height": 768
          },
          // Set a real user agent
          "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
          // Don't block any resources - we want to see everything
          "blockResourceTypes": [],
          // Follow redirects
          "followRedirect": true
        }),
      });

      // --- Step 4: Process the API Response ---
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Error from Browserless API: ${errorText}`);
        return new Response(JSON.stringify({ 
          error: 'Failed to fetch content via Browserless', 
          details: errorText,
          statusCode: response.status 
        }), {
          status: response.status,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // The HTML content is the body of the successful response
      const html = await response.text();
      
      // Check if we got an error page
      const errorIndicators = [
        'This site can\'t be reached',
        'DNS_PROBE_FINISHED',
        '404 Not Found',
        'Page not found',
        'Domain for sale',
        'Account Suspended'
      ];
      
      const isErrorPage = errorIndicators.some(indicator => 
        html.toLowerCase().includes(indicator.toLowerCase())
      );

      // --- Step 5: Return the HTML to the Original Caller ---
      return new Response(JSON.stringify({ 
        html: html,
        isErrorPage: isErrorPage,
        contentLength: html.length,
        url: url
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      console.error('Error processing request:', error);
      return new Response(JSON.stringify({ 
        error: 'Failed to process request', 
        details: error.message 
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  },
};
