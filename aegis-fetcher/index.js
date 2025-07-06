/**
 * Cloudflare Worker to securely fetch HTML using the Browserless.io service.
 * IMPROVED: Better handling of phishing sites and error detection
 */

export default {
  async fetch(request, env, ctx) {
    // Enable CORS
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // --- Step 1: Basic Request Validation ---
    if (request.method !== 'POST') {
      return new Response('Expected POST request', { 
        status: 405,
        headers: corsHeaders 
      });
    }

    let requestBody;
    try {
      requestBody = await request.json();
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Invalid JSON in request body' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          ...corsHeaders 
        },
      });
    }

    const { url } = requestBody;

    if (!url) {
      return new Response(JSON.stringify({ error: 'URL is required' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          ...corsHeaders 
        },
      });
    }

    try {
      // --- Step 2: Call the Browserless.io API ---
      const apiKey = env.BROWSERLESS_API_KEY;

      if (!apiKey) {
        return new Response(JSON.stringify({ 
          error: 'Worker is not configured. Missing Browserless API Key.' 
        }), {
          status: 500,
          headers: { 
            'Content-Type': 'application/json',
            ...corsHeaders 
          },
        });
      }

      // Construct the Browserless.io API endpoint URL
      const browserlessApiUrl = `https://production-sfo.browserless.io/content?token=${apiKey}`;

      // Make the request to Browserless - using their documented format
      const browserlessResponse = await fetch(browserlessApiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url,
          gotoOptions: {
            waitUntil: 'networkidle0',
            timeout: 30000
          }
        }),
      });

      // --- Step 3: Process the API Response ---
      if (!browserlessResponse.ok) {
        const errorText = await browserlessResponse.text();
        console.error(`Browserless API error: ${browserlessResponse.status} - ${errorText}`);
        
        return new Response(JSON.stringify({ 
          error: 'Failed to fetch content via Browserless',
          details: errorText,
          status: browserlessResponse.status
        }), {
          status: 502, // Bad Gateway - upstream service error
          headers: { 
            'Content-Type': 'application/json',
            ...corsHeaders 
          },
        });
      }

      // Get the HTML content
      const html = await browserlessResponse.text();

      // Basic error page detection
      const lowerHtml = html.toLowerCase();
      const isErrorPage = 
        lowerHtml.includes('this site can\'t be reached') ||
        lowerHtml.includes('dns_probe') ||
        lowerHtml.includes('404 not found') ||
        lowerHtml.includes('page not found') ||
        lowerHtml.includes('account suspended') ||
        (lowerHtml.includes('error') && html.length < 1000);

      // --- Step 4: Return the HTML to the caller ---
      return new Response(JSON.stringify({ 
        html: html,
        isErrorPage: isErrorPage,
        contentLength: html.length
      }), {
        status: 200,
        headers: { 
          'Content-Type': 'application/json',
          ...corsHeaders 
        },
      });

    } catch (error) {
      console.error('Worker error:', error.message, error.stack);
      
      return new Response(JSON.stringify({ 
        error: 'Worker processing failed',
        details: error.message,
        stack: error.stack
      }), {
        status: 500,
        headers: { 
          'Content-Type': 'application/json',
          ...corsHeaders 
        },
      });
    }
  },
};
