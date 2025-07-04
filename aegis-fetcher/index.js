/**
 * Cloudflare Worker to securely fetch HTML using the Browserless.io service.
 * This acts as a secure proxy to hide our Browserless.io API key.
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

      // --- Step 3: Call the Browserless.io API ---
      // The BROWSERLESS_API_KEY secret must be set in the worker's settings.
      const apiKey = env.BROWSERLESS_API_KEY;

      if (!apiKey) {
        return new Response(JSON.stringify({ error: 'Worker is not configured. Missing Browserless API Key.' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Construct the Browserless.io API endpoint URL
      const browserlessApiUrl = `https://production-sfo.browserless.io/content?token=${apiKey}`;

      // Make the secure call to the Browserless API
      const response = await fetch(browserlessApiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          "url": url,
          "gotoOptions": {
            "waitUntil": "networkidle0" // Wait until the page is fully loaded
          }
        }),
      });

      // --- Step 4: Process the API Response ---
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Error from Browserless API: ${errorText}`);
        return new Response(JSON.stringify({ error: 'Failed to fetch content via Browserless', details: errorText }), {
          status: response.status,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // The HTML content is the body of the successful response
      const html = await response.text();

      // --- Step 5: Return the HTML to the Original Caller ---
      return new Response(JSON.stringify({ html: html }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      console.error('Error processing request:', error);
      return new Response(JSON.stringify({ error: 'Failed to process request', details: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  },
};

