// Import AWS SDK v3 clients
import {
    SecretsManagerClient,
    GetSecretValueCommand,
  } from "@aws-sdk/client-secrets-manager";
  
  // Node.js built-in fetch for HTTP requests (available in Node.js 18+)
  // No external dependency needed for basic fetch
  
  // --- AWS Client Initialization ---
  const secretsManagerClient = new SecretsManagerClient({}); // Configures based on Lambda execution environment
  
  // --- CONFIGURATION ---
  // Retrieve Secret ARN from environment variable (Set this in Lambda config!)
  const nvdApiSecretArn = process.env.NVD_API_SECRET_ARN;
  // Allowed origin for CORS - Hardcoded for production
  const allowedOrigin = "https://vulnerametrics.com";
  // NVD API Endpoint
  const NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
  // Basic CVE ID format validation regex
  const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;
  // --- END CONFIGURATION ---
  
  // --- Simple In-Memory Cache for Secret ---
  let cachedApiKey = null;
  let cacheExpiry = null;
  const CACHE_DURATION_MS = 5 * 60 * 1000; // Cache for 5 minutes
  
  // --- Helper Function to Get NVD API Key ---
  async function getNvdApiKey() {
    const now = Date.now();
    if (cachedApiKey && cacheExpiry && now < cacheExpiry) {
      console.log("Returning cached NVD API Key.");
      return cachedApiKey;
    }
  
    if (!nvdApiSecretArn) {
      console.error("ERROR: NVD_API_SECRET_ARN environment variable not set.");
      throw new Error("NVD API Key secret configuration error.");
    }
  
    console.log("Fetching NVD API Key from Secrets Manager:", nvdApiSecretArn);
    try {
      const command = new GetSecretValueCommand({ SecretId: nvdApiSecretArn });
      const data = await secretsManagerClient.send(command);
  
      if (data.SecretString) {
        const secret = JSON.parse(data.SecretString);
        if (!secret.apiKey) {
          console.error("ERROR: 'apiKey' key not found within the secret JSON.");
          throw new Error("Invalid secret format.");
        }
        console.log("NVD API Key successfully retrieved from Secrets Manager.");
        cachedApiKey = secret.apiKey;
        cacheExpiry = now + CACHE_DURATION_MS;
        return cachedApiKey;
      } else if (data.SecretBinary) {
        // Handle binary secret if needed, though we expect JSON string
        console.error("ERROR: Secret returned in unexpected binary format.");
        throw new Error("Unexpected secret format (binary).");
      }
      console.error("ERROR: Secret value not found.");
      throw new Error("Secret value not found.");
    } catch (error) {
      console.error("ERROR retrieving secret from Secrets Manager:", error);
      // Invalidate cache on error
      cachedApiKey = null;
      cacheExpiry = null;
      throw new Error("Failed to retrieve NVD API Key.");
    }
  }
  
  // --- Main Lambda Handler ---
  export const handler = async (event) => {
    console.log("EVENT RECEIVED:", JSON.stringify(event));
  
    // Prepare CORS headers
    const headers = {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Headers": "Content-Type,Authorization", // Allow Authorization header
      "Access-Control-Allow-Methods": "GET,OPTIONS", // Allow GET and OPTIONS
      "Access-Control-Allow-Credentials": "true",
    };
  
    // Handle OPTIONS request for CORS preflight
    if (event.httpMethod === "OPTIONS") {
      console.log("Responding to OPTIONS preflight request");
      return {
        statusCode: 204, // No Content
        headers: headers,
        body: "",
      };
    }
  
    let cveId;
    try {
      // Extract CVE ID from path parameters (assuming /cve/{id})
      cveId = event.pathParameters?.id;
  
      if (!cveId) {
        console.error("CVE ID not found in path parameters.");
        return {
          statusCode: 400, // Bad Request
          headers: headers,
          body: JSON.stringify({
            message: "Bad Request: Missing CVE ID in path.",
          }),
        };
      }
  
      // Validate CVE ID format
      if (!CVE_REGEX.test(cveId)) {
        console.error(`Invalid CVE ID format received: ${cveId}`);
        return {
          statusCode: 400, // Bad Request
          headers: headers,
          body: JSON.stringify({
            message:
              "Bad Request: Invalid CVE ID format. Expected format: CVE-YYYY-NNNN...",
          }),
        };
      }
      // Normalize CVE ID to uppercase for consistency
      cveId = cveId.toUpperCase();
  
      console.log(`Processing request for CVE ID: ${cveId}`);
  
      // --- Get NVD API Key ---
      const apiKey = await getNvdApiKey(); // Handles caching internally
  
      // --- Call NVD API ---
      const nvdUrl = `${NVD_API_BASE_URL}?cveId=${cveId}`;
      console.log(`Calling NVD API: ${nvdUrl}`);
  
      const nvdResponse = await fetch(nvdUrl, {
        method: "GET",
        headers: {
          apiKey: apiKey, // Include the API key header
          "User-Agent": "Vulnerametrics/1.0", // Optional: Good practice User-Agent
        },
      });
  
      console.log(`NVD API Response Status: ${nvdResponse.status}`);
  
      if (!nvdResponse.ok) {
        // Handle non-successful responses (e.g., 403 Forbidden, 404 Not Found, 429 Rate Limit, 5xx Server Errors)
        const errorBody = await nvdResponse.text(); // Read body for potential error details
        console.error(
          `NVD API Error: Status ${nvdResponse.status}, Body: ${errorBody}`
        );
        let userMessage = `Error fetching data from NVD API. Status: ${nvdResponse.status}.`;
        if (nvdResponse.status === 403)
          userMessage =
            "NVD API request forbidden. Check API Key validity or permissions.";
        if (nvdResponse.status === 404)
          userMessage = `CVE ID ${cveId} not found in NVD database.`;
        if (nvdResponse.status === 429)
          userMessage = "NVD API rate limit exceeded. Please try again later.";
        if (nvdResponse.status >= 500)
          userMessage =
            "NVD API is experiencing internal issues. Please try again later.";
  
        return {
          statusCode: nvdResponse.status === 404 ? 404 : 502, // Return 404 if NVD says not found, else 502 Bad Gateway
          headers: headers,
          body: JSON.stringify({ message: userMessage }),
        };
      }
  
      // --- Process Successful NVD Response ---
      const nvdData = await nvdResponse.json();
  
      if (
        !nvdData ||
        !nvdData.vulnerabilities ||
        nvdData.vulnerabilities.length === 0
      ) {
        console.log(
          `NVD API returned success status but no vulnerability data found for ${cveId}.`
        );
        return {
          statusCode: 404, // Not Found
          headers: headers,
          body: JSON.stringify({
            message: `CVE ID ${cveId} data not found in NVD database, though the API responded.`,
          }),
        };
      }
  
      // Extract the first vulnerability object (NVD API returns an array even for single CVE query)
      const vulnerability = nvdData.vulnerabilities[0].cve;
      console.log(`Successfully retrieved data for ${cveId}`);
  
      // --- Return Successful Response ---
      // We can return the whole 'vulnerability' object or select specific fields later if needed
      return {
        statusCode: 200,
        headers: headers,
        body: JSON.stringify(vulnerability), // Return the core CVE details
      };
    } catch (error) {
      console.error("ERROR processing request:", error);
  
      // Return generic server error response for unexpected errors (e.g., Secrets Manager failure)
      return {
        statusCode: 500,
        headers: headers,
        body: JSON.stringify({
          message: "Internal Server Error.",
          error: error.message,
        }),
      };
    }
  };
  