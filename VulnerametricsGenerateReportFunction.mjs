// Import AWS SDK v3 clients
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import {
  BedrockRuntimeClient,
  InvokeModelCommand,
} from "@aws-sdk/client-bedrock-runtime";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

// Import pdf-lib and Node.js modules
import { PDFDocument, StandardFonts, rgb, PageSizes } from "pdf-lib";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url"; // Needed for reliable path in ES Modules

// --- Constants and Configuration ---
const AWS_REGION = process.env.AWS_REGION || "us-east-1";
const USER_CREDITS_TABLE_NAME = process.env.USER_CREDITS_TABLE_NAME;
const NVD_API_SECRET_ARN = process.env.NVD_API_SECRET_ARN;
const BEDROCK_MODEL_ID = process.env.BEDROCK_MODEL_ID;
const S3_REPORT_BUCKET = process.env.S3_REPORT_BUCKET;
const ALLOWED_ORIGIN = "https://vulnerametrics.com";
const NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;
const REPORT_S3_PREFIX = "generated-reports/";
const LOGO_FILE_NAME = "vulnerametrics-logo-bw.png"; // Keep logo as requested

const DISCLAIMER_TEXT = `Disclaimer: The information provided herein may be wrong and is for educational, research, and defensive purposes only. Any attempt to exploit vulnerabilities without proper authorization is illegal and unethical.`;
const FOOTER_TEXT =
  "vulnerametrics.com was made by Miguel Cordero Pamphile => miguelcorderopamphile@gmail.com";
const NVD_RETRY_ATTEMPTS = 3;
const NVD_RETRY_DELAY_MS = 500;
const CACHE_DURATION_MS = 5 * 60 * 1000;

// --- B&W PDF Styling Constants (Refined for No Boxes) ---
const PDF_PAGE_MARGIN = 50;
const PDF_CONTENT_WIDTH = PageSizes.Letter[0] - 2 * PDF_PAGE_MARGIN;
const PDF_LINE_HEIGHT_MULTIPLIER = 1.35; // Line spacing
const PDF_LIST_ITEM_INDENT = 18;
const PDF_KEY_VALUE_INDENT = 150; // Indent for values in key-value lists
const PDF_SECTION_TITLE_LINE_THICKNESS = 0.5; // Thickness of line below section title
const BLACK_COLOR = rgb(0, 0, 0);
const PDF_FONT_SIZE_NORMAL = 10;
const PDF_FONT_SIZE_SMALL = 8;
const PDF_FONT_SIZE_TITLE = 14;
const PDF_FONT_SIZE_SECTION_HEADER = 11;
const PDF_TEXT_COLOR_NORMAL = BLACK_COLOR;
const PDF_TEXT_COLOR_HEADER = BLACK_COLOR;
const PDF_TEXT_COLOR_SECONDARY = BLACK_COLOR; // Was gray, now black for B&W
const PDF_TEXT_COLOR_FOOTER = BLACK_COLOR;
const PDF_TEXT_COLOR_BULLET = BLACK_COLOR;
const PDF_TEXT_COLOR_ERROR = BLACK_COLOR; // Keep error text black

// New Spacing Constants (Adjusted for No Boxes)
const SPACE_AFTER_MAIN_TITLE_LINE = 15; // Space below main report title line
const SPACE_BEFORE_SECTION = 18; // Space above a section title
const SPACE_AFTER_SECTION_TITLE_LINE = 10; // Space below the line under a section title
const SPACE_BETWEEN_LIST_ITEMS = 4;
const SPACE_BETWEEN_PARA = 5; // Base space between paragraphs/lines
const SPACE_BETWEEN_KEY_VALUE = 5; // Space between key-value pairs
const SPACE_BEFORE_DISCLAIMER = 25;
const FOOTER_MARGIN_DIVIDER = 2.5;

// CVSS Severity Thresholds (Used for extracting severity text, not color)
// Note: V2 thresholds are no longer strictly needed but kept for context if getSeverity is reused elsewhere.
const SEVERITY_THRESHOLDS = { CRITICAL: 9.0, HIGH: 7.0, MEDIUM: 4.0, LOW: 0.1 };

const BEDROCK_MAX_TOKENS = 4096;
const BEDROCK_ANTHROPIC_VERSION = "bedrock-2023-05-31";

// --- AWS Client Initialization ---
const ddbClient = new DynamoDBClient({ region: AWS_REGION });
const ddbDocClient = DynamoDBDocumentClient.from(ddbClient);
const secretsManagerClient = new SecretsManagerClient({ region: AWS_REGION });
const bedrockClient = new BedrockRuntimeClient({ region: AWS_REGION });
const s3Client = new S3Client({ region: AWS_REGION });

// --- Cache ---
let cachedNvdApiKey = null;
let cacheNvdExpiry = null;

// --- Helper Functions ---

function validateEnvironmentVariables() {
  console.log("--- Validating Environment Variables ---");
  const requiredVars = {
    USER_CREDITS_TABLE_NAME,
    NVD_API_SECRET_ARN,
    BEDROCK_MODEL_ID,
    S3_REPORT_BUCKET,
  };
  const missingVars = Object.entries(requiredVars)
    .filter(([key, value]) => !value)
    .map(([key]) => key);

  if (missingVars.length > 0) {
    const message = `Missing required environment variables: ${missingVars.join(
      ", "
    )}`;
    console.error("ERROR:", message);
    throw new Error(`Server configuration error: ${message}`);
  }
  console.log("Environment variables validated successfully.");
}

async function getNvdApiKey() {
  const now = Date.now();
  if (cachedNvdApiKey && cacheNvdExpiry && now < cacheNvdExpiry) {
    console.log("Using cached NVD API Key.");
    return cachedNvdApiKey;
  }
  if (!NVD_API_SECRET_ARN)
    throw new Error("NVD_API_SECRET_ARN environment variable not configured.");
  console.log("Fetching NVD API Key from Secrets Manager:", NVD_API_SECRET_ARN);
  try {
    const command = new GetSecretValueCommand({ SecretId: NVD_API_SECRET_ARN });
    const data = await secretsManagerClient.send(command);
    if (data.SecretString) {
      const secret = JSON.parse(data.SecretString);
      if (!secret.apiKey)
        throw new Error(
          "Invalid secret format in Secrets Manager ('apiKey' key missing)."
        );
      console.log("NVD API Key retrieved successfully.");
      cachedNvdApiKey = secret.apiKey;
      cacheNvdExpiry = now + CACHE_DURATION_MS;
      return cachedNvdApiKey;
    } else {
      throw new Error(
        "Secret value retrieved from Secrets Manager is not a string."
      );
    }
  } catch (error) {
    console.error("ERROR retrieving NVD secret:", error);
    cachedNvdApiKey = null;
    cacheNvdExpiry = null;
    throw new Error("Failed to retrieve NVD API Key from Secrets Manager.");
  }
}

async function fetchWithRetries(
  url,
  options,
  maxAttempts = NVD_RETRY_ATTEMPTS,
  initialDelay = NVD_RETRY_DELAY_MS
) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      console.log(`Attempt ${attempt} to fetch ${url}`);
      const response = await fetch(url, options);
      if (response.ok) {
        console.log(`Workspace successful for ${url} on attempt ${attempt}.`);
        return response;
      }
      if (
        (response.status === 429 || response.status >= 500) &&
        attempt < maxAttempts
      ) {
        const delay = initialDelay * Math.pow(2, attempt - 1);
        console.warn(
          `Workspace failed with status ${response.status}. Retrying attempt ${
            attempt + 1
          } after ${delay}ms...`
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }
      console.error(
        `Workspace failed with status ${response.status} after ${attempt} attempts.`
      );
      return response; // Return the failed response object
    } catch (error) {
      console.error(`Workspace attempt ${attempt} failed with error:`, error);
      if (attempt < maxAttempts) {
        const delay = initialDelay * Math.pow(2, attempt - 1);
        console.warn(
          `Retrying attempt ${attempt + 1} after ${delay}ms due to error...`
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
      } else {
        console.error("Fetch failed after all retry attempts due to error.");
        throw error;
      }
    }
  }
  // Should not be reachable if maxAttempts >= 1
  throw new Error("Fetch failed unexpectedly after all retry attempts.");
}

async function fetchNvdData(cveId, apiKey) {
  console.log(`Calling NVD API for ${cveId}`);
  const nvdUrl = `${NVD_API_BASE_URL}?cveId=${cveId}`;
  const nvdResponse = await fetchWithRetries(nvdUrl, {
    method: "GET",
    headers: { apiKey: apiKey, "User-Agent": "Vulnerametrics/1.0" },
  });
  console.log(`NVD API Final Status Code: ${nvdResponse.status}`);
  if (!nvdResponse.ok) {
    const errorBody = await nvdResponse
      .text()
      .catch(() => "Could not read error body");
    console.error(
      `NVD API Error: Status ${nvdResponse.status}, Body: ${errorBody}`
    );
    const statusCode = nvdResponse.status === 404 ? 404 : 502; // Treat other errors as Bad Gateway
    const message =
      nvdResponse.status === 404
        ? `CVE ID ${cveId} not found in NVD.`
        : `NVD API Error (${nvdResponse.status}). Check NVD service status or API key.`;
    throw { statusCode, message };
  }
  const nvdJson = await nvdResponse.json();
  if (!nvdJson?.vulnerabilities?.length || !nvdJson.vulnerabilities[0].cve) {
    console.error(
      `NVD API response for ${cveId} lacks expected vulnerability data structure.`
    );
    throw {
      statusCode: 404, // Or perhaps 502 if the structure is wrong despite 200 OK
      message: `Valid response received, but CVE ID ${cveId} data structure is unexpected or empty.`,
    };
  }
  console.log(`Successfully retrieved NVD data for ${cveId}`);
  // console.log(`Raw Vulnerability Data for ${cveId}:`, JSON.stringify(nvdJson.vulnerabilities[0].cve, null, 2)); // Log full CVE object if needed
  return nvdJson.vulnerabilities[0].cve;
}

/**
 * Extracts relevant data, focusing ONLY on CVSS v3.x.
 */
function extractRelevantNvdData(vulnerabilityData) {
  console.log("Extracting relevant NVD data points (Focusing on CVSS v3)...");
  // console.log("Raw NVD Metrics Data received:", JSON.stringify(vulnerabilityData.metrics, null, 2)); // Keep logging for debugging

  /**
   * Finds the best CVSS v3.x metric data from an array of metrics.
   * Prioritizes v3.1 with cvssData, then v3.0 with cvssData.
   */
  const getCvssV3Data = (metricsV31Array, metricsV30Array) => {
    const combinedMetrics = [
      ...(metricsV31Array || []),
      ...(metricsV30Array || []),
    ];

    if (combinedMetrics.length === 0) {
      // console.log("getCvssV3Data: No CVSS v3.1 or v3.0 metrics arrays provided.");
      return null;
    }

    // ----- START FIX -----
    // Prioritize v3.1 with cvssData, remove format check
    let metric = combinedMetrics.find(
      (m) =>
        // m.format === "CVSS" && // <<< REMOVED condition
        m.cvssData?.version?.startsWith("3.1") && m.cvssData // Ensure cvssData object exists
    );

    // Fallback to v3.0 with cvssData, remove format check
    if (!metric) {
      metric = combinedMetrics.find(
        (m) =>
          // m.format === "CVSS" && // <<< REMOVED condition
          m.cvssData?.version?.startsWith("3.0") && m.cvssData // Ensure cvssData object exists
      );
    }
    // ----- END FIX -----

    if (!metric?.cvssData) {
      // console.warn("getCvssV3Data: Could not find a v3.1 or v3.0 metric WITH a cvssData object in:", JSON.stringify(combinedMetrics));
      return null;
    }

    // console.log("getCvssV3Data: Found metric object:", JSON.stringify(metric));

    const { cvssData } = metric;

    const getSeverity = (score) => {
      // Only needs score for V3
      if (score == null) return "N/A";
      if (score >= SEVERITY_THRESHOLDS.CRITICAL) return "CRITICAL";
      if (score >= SEVERITY_THRESHOLDS.HIGH) return "HIGH";
      if (score >= SEVERITY_THRESHOLDS.MEDIUM) return "MEDIUM";
      if (score >= SEVERITY_THRESHOLDS.LOW) return "LOW"; // >= 0.1
      return "NONE"; // 0.0
    };

    const baseScore = cvssData.baseScore ?? null;
    const version = cvssData.version; // Should be 3.1 or 3.0
    const calculatedSeverity = getSeverity(baseScore);
    // Use NVD provided severity if available, otherwise calculate it
    const cvssSeverity = cvssData.baseSeverity || calculatedSeverity;

    // Extract ONLY V3 fields
    return {
      version: version || "N/A", // Should exist if metric.cvssData exists
      vectorString: cvssData.vectorString || "N/A",
      attackVector: cvssData.attackVector || null,
      attackComplexity: cvssData.attackComplexity || null,
      privilegesRequired: cvssData.privilegesRequired || null,
      userInteraction: cvssData.userInteraction || null,
      scope: cvssData.scope || null,
      confidentialityImpact: cvssData.confidentialityImpact || null,
      integrityImpact: cvssData.integrityImpact || null,
      availabilityImpact: cvssData.availabilityImpact || null,
      baseScore: baseScore,
      baseSeverity: cvssSeverity,
      // NO V2 fields (accessVector, accessComplexity, authentication)
    };
  };

  // Call the dedicated V3 extractor
  const cvssV3 = getCvssV3Data(
    vulnerabilityData.metrics?.cvssMetricV31,
    vulnerabilityData.metrics?.cvssMetricV30
  );

  // console.log("Extracted CVSSv3:", JSON.stringify(cvssV3, null, 2));
  // CVSSv2 is no longer extracted or used.

  const cweIds =
    vulnerabilityData.weaknesses?.flatMap((w) =>
      w.description
        ?.filter((d) => d.lang === "en" && d.value?.startsWith("CWE-"))
        .map((d) => d.value.match(/CWE-\d+/)?.[0] || d.value)
        .filter((id) => id)
    ) || [];
  const uniqueCweIds = [...new Set(cweIds)];

  const relevantData = {
    id: vulnerabilityData.id,
    sourceIdentifier: vulnerabilityData.sourceIdentifier || "N/A",
    published: vulnerabilityData.published
      ? new Date(vulnerabilityData.published).toLocaleDateString("en-US", {
          year: "numeric",
          month: "numeric",
          day: "numeric",
        })
      : "N/A",
    lastModified: vulnerabilityData.lastModified
      ? new Date(vulnerabilityData.lastModified).toLocaleDateString("en-US", {
          year: "numeric",
          month: "numeric",
          day: "numeric",
        })
      : "N/A",
    vulnStatus: vulnerabilityData.vulnStatus || "N/A",
    description:
      vulnerabilityData.descriptions?.find((d) => d.lang === "en")?.value ||
      "No English description available.",
    cvssV3: cvssV3, // Contains only V3 data object or null
    // cvssV2: undefined, // Explicitly removed
    cwe: uniqueCweIds.length > 0 ? uniqueCweIds : ["N/A"],
    references:
      vulnerabilityData.references?.map((ref) => ({
        url: ref.url,
        source: ref.source || "N/A",
        tags: ref.tags || [],
      })) || [],
    cisaKnownExploited: !!vulnerabilityData.cisaExploitAdd,
    cisaActionDue: vulnerabilityData.cisaActionDue || null,
    cisaRequiredAction: vulnerabilityData.cisaRequiredAction || null,
    cisaVulnerabilityName: vulnerabilityData.cisaVulnerabilityName || null,
  };

  console.log("Relevant NVD data extracted (CVSSv3 focus).");
  return relevantData;
}

/**
 * Prepares Bedrock prompt, now excluding CVSS v2 info.
 */
function prepareBedrockPrompt(relevantNvdData) {
  console.log("Preparing prompt for Bedrock (Focusing on CVSS v3)...");

  // Construct summary, EXCLUDING cvssV2
  const nvdSummaryForPrompt = {
    id: relevantNvdData.id,
    description: relevantNvdData.description,
    published: relevantNvdData.published,
    lastModified: relevantNvdData.lastModified,
    status: relevantNvdData.vulnStatus,
    cvssV3: relevantNvdData.cvssV3 // Only include V3 data if present
      ? {
          score: relevantNvdData.cvssV3.baseScore,
          severity: relevantNvdData.cvssV3.baseSeverity,
          vector: relevantNvdData.cvssV3.vectorString,
        }
      : null, // Explicitly null if no V3 data
    // cvssV2 field removed
    cwe: relevantNvdData.cwe,
    cisaKnownExploited: relevantNvdData.cisaKnownExploited,
  };

  const desiredJsonStructure = `{
"vulnerability_analysis": "string",
"vulnerability_exploitation": "string",
"vulnerability_mitigation": "string",
"cwe_implications": "string",
"blind_spots": "string"
}`;

  const bedrockPrompt = `You are a specialized AI cybersecurity agent. Your task is to analyze the provided National Vulnerability Database (NVD) summary for ${
    relevantNvdData.id
  } and generate a comprehensive, objective, critical, and coherent vulnerability report. Focus on providing professional, actionable insights.

Analyze the following NVD summary:
\`\`\`json
${JSON.stringify(nvdSummaryForPrompt, null, 2)}
\`\`\`

Generate a response conforming *exactly* to the JSON structure specified below. Populate each field with detailed, professional-level text suitable for a cybersecurity report. Ensure the exploitation and mitigation sections are objective and describe general mechanisms rather than providing direct exploit code or overly specific commands.

Desired JSON structure:
\`\`\`json
${desiredJsonStructure}
\`\`\`

Respond ONLY with the valid JSON object conforming strictly to the structure requested above. Do not include any introductory text, explanations, apologies, or formatting markers like \`\`\`json before or after the JSON object itself.`;

  return bedrockPrompt;
}

// --- Bedrock Invocation (No changes needed here) ---
async function invokeBedrockAnalysis(prompt) {
  console.log(`Invoking Bedrock model: ${BEDROCK_MODEL_ID}`);
  const bedrockPayload = {
    anthropic_version: BEDROCK_ANTHROPIC_VERSION,
    max_tokens: BEDROCK_MAX_TOKENS,
    messages: [{ role: "user", content: [{ type: "text", text: prompt }] }],
  };
  const invokeCommand = new InvokeModelCommand({
    contentType: "application/json",
    accept: "application/json",
    modelId: BEDROCK_MODEL_ID,
    body: JSON.stringify(bedrockPayload),
  });

  let rawBedrockOutput;
  let textContent;
  try {
    const bedrockResult = await bedrockClient.send(invokeCommand);
    rawBedrockOutput = Buffer.from(bedrockResult.body).toString("utf-8");
    console.log("Bedrock invocation successful.");

    const parsedBody = JSON.parse(rawBedrockOutput);
    textContent = parsedBody.content?.[0]?.text;

    if (!textContent) {
      console.error(
        "Could not find 'content[0].text' in Bedrock response:",
        parsedBody
      );
      throw new Error(
        "Bedrock response structure unexpected: Missing text content."
      );
    }

    console.log("Attempting to parse Bedrock response text as JSON.");
    const jsonRegex = /^\s*\{[\s\S]*\}\s*$/;
    if (jsonRegex.test(textContent.trim())) {
      console.log("Response appears to be JSON-like.");
      textContent = textContent.trim();
    } else {
      console.warn(
        "Response may not be raw JSON. Attempting to extract from potential fences."
      );
      const fenceMatch = textContent.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
      if (fenceMatch && fenceMatch[1]) {
        textContent = fenceMatch[1].trim();
        console.log("Extracted content from Markdown fences.");
      } else {
        console.error(
          "Could not extract valid JSON from Bedrock response. Raw text:",
          textContent
        );
        throw new Error(
          "Bedrock response was not in the expected JSON format."
        );
      }
    }

    const bedrockJsonResponse = JSON.parse(textContent);

    const validatedResponse = {
      vulnerability_analysis:
        bedrockJsonResponse.vulnerability_analysis || "N/A",
      vulnerability_exploitation:
        bedrockJsonResponse.vulnerability_exploitation || "N/A",
      vulnerability_mitigation:
        bedrockJsonResponse.vulnerability_mitigation || "N/A",
      cwe_implications: bedrockJsonResponse.cwe_implications || "N/A",
      blind_spots: bedrockJsonResponse.blind_spots || "N/A",
    };

    console.log("Bedrock JSON parsed and validated successfully.");
    return validatedResponse;
  } catch (error) {
    console.error("ERROR invoking Bedrock or parsing response:", error);
    if (error instanceof SyntaxError) {
      console.error("Failed to parse Bedrock response as JSON.");
      console.error("Text content that failed parsing:", textContent);
      throw new Error(
        `Failed to parse structured response from Bedrock. Content received: ${textContent.substring(
          0,
          200
        )}...`
      );
    }
    const errorMessage = `Bedrock invocation/parsing failed: ${error.message}${
      rawBedrockOutput
        ? ` | Raw Response: ${rawBedrockOutput.substring(0, 500)}...`
        : ""
    }`;
    throw new Error(errorMessage);
  }
}

// --- PDF Generation Functions ---

// wrapText (No changes needed)
function wrapText(text, font, fontSize, maxWidth) {
  if (!text || typeof font.widthOfTextAtSize !== "function") {
    // console.warn("wrapText called with invalid text or font object.");
    return [text || ""];
  }
  const cleanedText = String(text)
    .trim()
    .replace(/\s*\n\s*/g, " ")
    .replace(/^- /gm, "")
    .replace(/ +/g, " ");

  if (!cleanedText) {
    return [""];
  }

  const words = cleanedText.split(" ");
  const lines = [];
  let currentLine = "";

  for (const word of words) {
    if (!word) continue;

    const testLine = currentLine ? `${currentLine} ${word}` : word;
    let testWidth;

    try {
      testWidth = font.widthOfTextAtSize(testLine, fontSize);
    } catch (e) {
      // console.warn(`Could not calculate width for text segment: "${testLine.substring(0, 50)}..."`, e);
      testWidth = maxWidth + 1;
    }

    if (testWidth <= maxWidth) {
      currentLine = testLine;
    } else {
      if (currentLine) {
        lines.push(currentLine);
      }
      let tempWord = word;
      while (true) {
        let currentWordWidth;
        try {
          currentWordWidth = font.widthOfTextAtSize(tempWord, fontSize);
        } catch (e) {
          // console.warn(`Could not calculate width for word part: "${tempWord.substring(0, 50)}..."`, e);
          currentWordWidth = maxWidth + 1;
        }

        if (currentWordWidth <= maxWidth) {
          currentLine = tempWord;
          break;
        }

        let splitPoint = 0;
        for (let i = 1; i < tempWord.length; i++) {
          let subWidth;
          try {
            subWidth = font.widthOfTextAtSize(
              tempWord.substring(0, i),
              fontSize
            );
          } catch (e) {
            // console.warn(`Could not calculate width during split check: "${tempWord.substring(0, i)}..."`, e);
            subWidth = maxWidth + 1;
          }
          if (subWidth > maxWidth) {
            break;
          }
          splitPoint = i;
        }
        splitPoint = Math.max(1, splitPoint > 1 ? splitPoint - 1 : splitPoint);
        lines.push(tempWord.substring(0, splitPoint));
        tempWord = tempWord.substring(splitPoint);
        try {
          if (font.widthOfTextAtSize(tempWord, fontSize) <= maxWidth) {
            currentLine = tempWord;
            break;
          }
        } catch (e) {
          // console.warn(`Could not calculate width for remaining part: "${tempWord.substring(0, 50)}..."`, e);
          lines.push(tempWord);
          currentLine = "";
          break;
        }
      }
    }
  }
  if (currentLine) {
    lines.push(currentLine);
  }
  return lines.length > 0 ? lines : [""];
}

// addFooterToAllPages (No changes needed)
async function addFooterToAllPages(pdfDoc, font, text, fontSize) {
  const pages = pdfDoc.getPages();
  const footerY = PDF_PAGE_MARGIN / FOOTER_MARGIN_DIVIDER;

  for (let i = 0; i < pages.length; i++) {
    const page = pages[i];
    const { width } = page.getSize();
    const pageNumText = `Page ${i + 1} of ${pages.length}`;
    let textWidth = 0;
    let pageNumWidth = 0;

    try {
      textWidth = font.widthOfTextAtSize(text, fontSize);
    } catch (e) {
      textWidth = 200;
    }
    try {
      pageNumWidth = font.widthOfTextAtSize(pageNumText, fontSize);
    } catch (e) {
      pageNumWidth = 50;
    }

    page.drawText(text, {
      x: (width - textWidth) / 2,
      y: footerY,
      size: fontSize,
      font: font,
      color: PDF_TEXT_COLOR_FOOTER,
    });
    page.drawText(pageNumText, {
      x: width - PDF_PAGE_MARGIN - pageNumWidth,
      y: footerY,
      size: fontSize,
      font: font,
      color: PDF_TEXT_COLOR_FOOTER,
    });
  }
}

// calculateEstimatedContentHeight (No changes needed structurally, but relies on correct inputs)
function calculateEstimatedContentHeight(
  content,
  contentType,
  fonts,
  fontSize,
  maxWidth,
  lineHeightMultiplier,
  dataObject = null
) {
  if (
    (content === null || content === "") &&
    contentType !== "keyValueList" &&
    !dataObject
  )
    return 0;
  const lineHeight = fontSize * lineHeightMultiplier;
  let totalHeight = 0;
  const font = fonts.regular;
  try {
    switch (contentType) {
      case "paragraph":
      case "references":
        if (!content) {
          totalHeight = 0;
          break;
        }
        const paraLines = wrapText(content, font, fontSize, maxWidth);
        totalHeight += paraLines.length * lineHeight;
        break;
      case "list":
        const listItems = Array.isArray(content)
          ? content
              .map((item) => String(item || "").trim())
              .filter((item) => item)
          : [];
        if (listItems.length === 0) {
          totalHeight += lineHeight;
        } else {
          listItems.forEach((item) => {
            if (!item) return;
            const itemLines = wrapText(
              item,
              font,
              fontSize,
              maxWidth - PDF_LIST_ITEM_INDENT
            );
            totalHeight +=
              itemLines.length * lineHeight + SPACE_BETWEEN_LIST_ITEMS;
          });
        }
        break;
      case "keyValueList":
        const items = dataObject || {};
        const keys = Object.keys(items);
        if (keys.length === 0) {
          totalHeight += lineHeight;
        } else {
          keys.forEach((key) => {
            const value = items[key];
            const valueText =
              value === null || value === undefined
                ? "N/A"
                : Array.isArray(value)
                ? value.length > 0
                  ? value.join(", ")
                  : "N/A"
                : String(value);
            if (valueText && valueText !== "N/A") {
              const valueLines = wrapText(
                valueText,
                font,
                fontSize,
                maxWidth - PDF_KEY_VALUE_INDENT
              );
              totalHeight +=
                Math.max(1, valueLines.length) * lineHeight +
                SPACE_BETWEEN_KEY_VALUE;
            } else {
              totalHeight += lineHeight + SPACE_BETWEEN_KEY_VALUE;
            }
          });
        }
        break;
      default:
        const defaultLines = wrapText(
          String(content || ""),
          font,
          fontSize,
          maxWidth
        );
        totalHeight += defaultLines.length * lineHeight;
    }
  } catch (e) {
    console.error(
      `Error calculating estimated height for contentType='${contentType}':`,
      e
    );
    totalHeight += 5 * lineHeight;
  }
  if (isNaN(totalHeight) || totalHeight < 0) {
    console.error(
      `Height calculation invalid (${totalHeight}) for contentType='${contentType}'.`
    );
    totalHeight = 3 * lineHeight;
  }
  return totalHeight;
}

/**
 * Gets CVSS metric values, now excluding V2-specific cases.
 */
function getCvssValue(cvssData, label) {
  if (!cvssData) return "N/A";
  switch (label) {
    case "Vector:":
      return cvssData.vectorString || "N/A";
    case "Score:":
      return cvssData.baseScore !== null ? `${cvssData.baseScore}` : "N/A";
    case "Severity:":
      return cvssData.baseSeverity || "N/A";
    // V3 specific
    case "Attack Vector:":
      return cvssData.attackVector || "N/A";
    case "Attack Complexity:":
      return cvssData.attackComplexity || "N/A";
    case "Privileges Required:":
      return cvssData.privilegesRequired || "N/A";
    case "User Interaction:":
      return cvssData.userInteraction || "N/A";
    case "Scope:":
      return cvssData.scope || "N/A";
    // V2 specific cases REMOVED
    // case "Access Vector:": return cvssData.accessVector || "N/A";
    // case "Access Complexity:": return cvssData.accessComplexity || "N/A";
    // case "Authentication:": return cvssData.authentication || "N/A";
    // Common
    case "Confidentiality:":
      return cvssData.confidentialityImpact || "N/A";
    case "Integrity:":
      return cvssData.integrityImpact || "N/A";
    case "Availability:":
      return cvssData.availabilityImpact || "N/A";
    default:
      console.warn(`Unknown or V2-specific CVSS label requested: ${label}`);
      return "N/A"; // Return N/A for unknown or removed labels
  }
}

// drawKeyValueList (No changes needed structurally)
async function drawKeyValueList(context, dataObject, options = {}) {
  const { fonts, contentWidth, addNewPage, pageHeight } = context;
  let localCurrentY = context.y;
  const fontSize = options.fontSize || PDF_FONT_SIZE_NORMAL;
  const keyFont = options.keyFont || fonts.bold;
  const valueFont = options.valueFont || fonts.regular;
  const keyColor = options.keyColor || PDF_TEXT_COLOR_NORMAL;
  const valueColor = options.valueColor || PDF_TEXT_COLOR_SECONDARY; // Default value color
  const itemIndent = options.itemIndent || 0;
  const valueIndent = options.valueIndent || PDF_KEY_VALUE_INDENT;
  const lineHeight = fontSize * PDF_LINE_HEIGHT_MULTIPLIER;
  const startX = PDF_PAGE_MARGIN + itemIndent;
  const valueStartX = startX + valueIndent;
  const valueMaxWidth = contentWidth - valueIndent - itemIndent;
  const keys = Object.keys(dataObject || {});

  if (keys.length === 0 && options.showNoResultsMessage) {
    if (localCurrentY - lineHeight < PDF_PAGE_MARGIN) {
      context.page = addNewPage();
      localCurrentY = pageHeight - PDF_PAGE_MARGIN;
    }
    context.pdfPage.drawText(options.noResultsMessage || "No data available.", {
      x: startX,
      y: localCurrentY,
      font: valueFont,
      size: fontSize,
      color: valueColor,
    });
    localCurrentY -= lineHeight + SPACE_BETWEEN_KEY_VALUE;
    context.y = localCurrentY;
    return;
  }

  for (const key of keys) {
    const value = dataObject[key];
    let valueText;
    if (value === null || value === undefined) {
      valueText = "N/A";
    } else if (Array.isArray(value)) {
      valueText = value.length > 0 ? value.join(", ") : "N/A";
    } else {
      valueText = String(value);
    }

    const valueLines = wrapText(valueText, valueFont, fontSize, valueMaxWidth);
    const requiredHeight =
      Math.max(1, valueLines.length) * lineHeight + SPACE_BETWEEN_KEY_VALUE;

    if (localCurrentY - requiredHeight < PDF_PAGE_MARGIN) {
      context.page = addNewPage();
      localCurrentY = pageHeight - PDF_PAGE_MARGIN;
    }

    context.pdfPage.drawText(key + ":", {
      x: startX,
      y: localCurrentY,
      font: keyFont,
      size: fontSize,
      color: keyColor,
    });

    let valueLineY = localCurrentY;
    valueLines.forEach((line, index) => {
      if (valueLineY - lineHeight < PDF_PAGE_MARGIN) {
        context.page = addNewPage();
        localCurrentY = pageHeight - PDF_PAGE_MARGIN;
        valueLineY = localCurrentY;
        context.pdfPage.drawText(key + ": (cont.)", {
          x: startX,
          y: localCurrentY,
          font: keyFont,
          size: fontSize - 1,
          color: keyColor,
        });
      }
      context.pdfPage.drawText(line, {
        x: valueStartX,
        y: valueLineY,
        font: valueFont,
        size: fontSize,
        color: options.valueColor || PDF_TEXT_COLOR_SECONDARY,
      }); // Use specified or default value color
      valueLineY -= lineHeight;
    });

    localCurrentY = valueLineY - SPACE_BETWEEN_KEY_VALUE; // Apply space AFTER the pair
  }
  context.y = localCurrentY;
}

// drawSection (No changes needed structurally)
async function drawSection(context, title, content, contentType) {
  const { fonts, contentWidth, addNewPage, pageHeight } = context;
  let localCurrentY = context.y;
  const titleFontSize = PDF_FONT_SIZE_SECTION_HEADER;
  const contentFontSize = PDF_FONT_SIZE_NORMAL;
  const font = fonts.regular;
  const boldFont = fonts.bold;
  const lineHeight = contentFontSize * PDF_LINE_HEIGHT_MULTIPLIER;
  const titleLineHeight = titleFontSize * PDF_LINE_HEIGHT_MULTIPLIER;
  const contentMaxWidth = contentWidth;

  const estimatedContentHeight = calculateEstimatedContentHeight(
    content,
    contentType,
    fonts,
    contentFontSize,
    contentMaxWidth,
    PDF_LINE_HEIGHT_MULTIPLIER,
    null
  );
  const spaceNeededForHeader =
    SPACE_BEFORE_SECTION +
    titleLineHeight +
    PDF_SECTION_TITLE_LINE_THICKNESS +
    SPACE_AFTER_SECTION_TITLE_LINE;

  if (localCurrentY - spaceNeededForHeader < PDF_PAGE_MARGIN) {
    context.page = addNewPage();
    localCurrentY = pageHeight - PDF_PAGE_MARGIN;
  }
  localCurrentY -= SPACE_BEFORE_SECTION;

  context.pdfPage.drawText(title, {
    x: PDF_PAGE_MARGIN,
    y: localCurrentY,
    font: boldFont,
    size: titleFontSize,
    color: PDF_TEXT_COLOR_HEADER,
  });
  localCurrentY -= titleLineHeight;

  const lineY = localCurrentY + 2;
  if (lineY > PDF_PAGE_MARGIN) {
    context.pdfPage.drawLine({
      start: { x: PDF_PAGE_MARGIN, y: lineY },
      end: { x: PDF_PAGE_MARGIN + contentWidth, y: lineY },
      thickness: PDF_SECTION_TITLE_LINE_THICKNESS,
      color: BLACK_COLOR,
    });
  }
  localCurrentY -=
    PDF_SECTION_TITLE_LINE_THICKNESS + SPACE_AFTER_SECTION_TITLE_LINE;

  const contentStartX = PDF_PAGE_MARGIN;
  const checkSpaceAndAddPageIfNeeded = (requiredHeight) => {
    if (localCurrentY - requiredHeight < PDF_PAGE_MARGIN) {
      context.page = addNewPage();
      localCurrentY = pageHeight - PDF_PAGE_MARGIN;
      return true;
    }
    return false;
  };

  let contentDrawn = false;
  if (
    contentType !== "keyValueList" &&
    content !== null &&
    content !== undefined &&
    !(Array.isArray(content) && content.length === 0) &&
    content !== ""
  ) {
    try {
      if (
        estimatedContentHeight > 0 &&
        localCurrentY - lineHeight < PDF_PAGE_MARGIN
      ) {
        checkSpaceAndAddPageIfNeeded(lineHeight);
      }
      switch (contentType) {
        case "paragraph":
        case "references":
          const paraLines = wrapText(
            String(content),
            font,
            contentFontSize,
            contentMaxWidth
          );
          paraLines.forEach((line) => {
            checkSpaceAndAddPageIfNeeded(lineHeight);
            context.pdfPage.drawText(line, {
              x: contentStartX,
              y: localCurrentY,
              font,
              size: contentFontSize,
              color: PDF_TEXT_COLOR_NORMAL,
            });
            localCurrentY -= lineHeight;
          });
          contentDrawn = true;
          break;
        case "list":
          const listItems = Array.isArray(content)
            ? content
                .map((item) => String(item || "").trim())
                .filter((item) => item)
            : [];
          if (listItems.length > 0) {
            listItems.forEach((item) => {
              if (!item) return;
              const itemLines = wrapText(
                item,
                font,
                contentFontSize,
                contentMaxWidth - PDF_LIST_ITEM_INDENT
              );
              let firstLine = true;
              itemLines.forEach((line) => {
                checkSpaceAndAddPageIfNeeded(lineHeight);
                if (firstLine) {
                  context.pdfPage.drawText("\u2022", {
                    x: contentStartX,
                    y: localCurrentY,
                    font: boldFont,
                    size: contentFontSize + 2,
                    color: PDF_TEXT_COLOR_BULLET,
                  });
                }
                context.pdfPage.drawText(line, {
                  x: contentStartX + PDF_LIST_ITEM_INDENT,
                  y: localCurrentY,
                  font,
                  size: contentFontSize,
                  color: PDF_TEXT_COLOR_NORMAL,
                });
                localCurrentY -= lineHeight;
                firstLine = false;
              });
              localCurrentY -= SPACE_BETWEEN_LIST_ITEMS;
            });
            contentDrawn = true;
          }
          break;
        default:
          console.warn(
            `Unsupported content type for drawSection content: ${contentType}`
          );
          /* Fallback logic */ break;
      }
    } catch (drawError) {
      console.error(
        `Error drawing content for section "${title}" (type: ${contentType}):`,
        drawError
      );
      /* Error drawing logic */ contentDrawn = true;
    }
  }

  if (
    !contentDrawn &&
    (contentType === "paragraph" ||
      contentType === "list" ||
      contentType === "references")
  ) {
    checkSpaceAndAddPageIfNeeded(lineHeight);
    context.pdfPage.drawText("N/A", {
      x: contentStartX,
      y: localCurrentY,
      font,
      size: contentFontSize,
      color: PDF_TEXT_COLOR_SECONDARY,
    });
    localCurrentY -= lineHeight;
  }
  context.y = localCurrentY;
}

/**
 * Generates the PDF report, focusing only on CVSS v3.x.
 */
async function generatePdfReport(bedrockAnalysisData, cveId, relevantNvdData) {
  console.log("Generating PDF document (Focusing on CVSS v3)...");
  try {
    const pdfDoc = await PDFDocument.create();
    const contentWidth = PDF_CONTENT_WIDTH;
    const helveticaFont = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const helveticaBoldFont = await pdfDoc.embedFont(
      StandardFonts.HelveticaBold
    );

    let currentPage = pdfDoc.addPage(PageSizes.Letter);
    const pageHeight = currentPage.getHeight();
    let currentY = pageHeight - PDF_PAGE_MARGIN;

    const addNewPage = () => {
      currentPage = pdfDoc.addPage(PageSizes.Letter);
      currentY = pageHeight - PDF_PAGE_MARGIN;
      pdfContext.pdfPage = currentPage;
      return currentPage;
    };

    const pdfContext = {
      pdfDoc,
      pdfPage: currentPage,
      fonts: { regular: helveticaFont, bold: helveticaBoldFont },
      contentWidth,
      pageHeight,
      addNewPage,
      set y(newY) {
        currentY = newY;
      },
      get y() {
        return currentY;
      },
      set page(newPage) {
        currentPage = newPage;
        this.pdfPage = newPage;
      },
      get page() {
        return currentPage;
      },
    };

    // --- Header Elements (Same as before) ---
    let logoHeight = 0;
    let logoWidth = 0;
    const logoScale = 0.1;
    try {
      const __filename = fileURLToPath(import.meta.url);
      const __dirname = path.dirname(__filename);
      const logoPath = path.resolve(
        process.env.LAMBDA_TASK_ROOT || __dirname,
        LOGO_FILE_NAME
      );
      const logoBytes = await fs.readFile(logoPath);
      const logoImage = await pdfDoc.embedPng(logoBytes);
      const logoDims = logoImage.scale(logoScale);
      logoHeight = logoDims.height;
      logoWidth = logoDims.width;
      const logoX = pdfContext.page.getWidth() - PDF_PAGE_MARGIN - logoWidth;
      const logoBottomY = pageHeight - PDF_PAGE_MARGIN - logoHeight;
      if (currentY < logoBottomY + 10) {
        currentY = logoBottomY - 10;
      }
      pdfContext.page.drawImage(logoImage, {
        x: logoX,
        y: logoBottomY,
        width: logoWidth,
        height: logoHeight,
      });
      currentY = Math.min(currentY, logoBottomY - 10);
    } catch (logoError) {
      console.error(
        `ERROR embedding logo: ${logoError.message}. Skipping logo.`
      );
      currentY = pageHeight - PDF_PAGE_MARGIN;
    }
    pdfContext.y = currentY;

    const titleText = `Vulnerability Report: ${cveId}`;
    const titleFont = pdfContext.fonts.bold;
    const titleFontSize = PDF_FONT_SIZE_TITLE;
    let titleWidth = 0;
    try {
      titleWidth = titleFont.widthOfTextAtSize(titleText, titleFontSize);
    } catch (e) {
      titleWidth = 300;
    }
    const titleLineHeight = titleFontSize * 1.2;
    const titleX = (pdfContext.page.getWidth() - titleWidth) / 2;
    if (pdfContext.y < PDF_PAGE_MARGIN + titleLineHeight) {
      addNewPage();
      pdfContext.y = pageHeight - PDF_PAGE_MARGIN;
    }
    pdfContext.page.drawText(titleText, {
      x: titleX,
      y: pdfContext.y,
      font: titleFont,
      size: titleFontSize,
      color: PDF_TEXT_COLOR_HEADER,
    });
    pdfContext.y -= titleLineHeight;
    const lineY = pdfContext.y + 2;
    if (lineY > PDF_PAGE_MARGIN) {
      pdfContext.page.drawLine({
        start: { x: PDF_PAGE_MARGIN, y: lineY },
        end: { x: pdfContext.page.getWidth() - PDF_PAGE_MARGIN, y: lineY },
        thickness: 0.75,
        color: BLACK_COLOR,
      });
      pdfContext.y -= SPACE_AFTER_MAIN_TITLE_LINE;
    }

    // --- Sections ---

    // Section 1: NVD Info (No changes needed here)
    const nvdInfoForPdf = {
      "CVE ID": relevantNvdData.id,
      Status: relevantNvdData.vulnStatus,
      Description: relevantNvdData.description,
      "Published Date": relevantNvdData.published,
      "Last Modified Date": relevantNvdData.lastModified,
      Source: relevantNvdData.sourceIdentifier,
      "Associated CWEs": relevantNvdData.cwe,
      ...(relevantNvdData.cisaKnownExploited && { "CISA KEV": "Yes" }),
      ...(relevantNvdData.cisaVulnerabilityName && {
        "CISA Name": relevantNvdData.cisaVulnerabilityName,
      }),
      ...(relevantNvdData.cisaRequiredAction && {
        "CISA Action": relevantNvdData.cisaRequiredAction,
      }),
      ...(relevantNvdData.cisaActionDue && {
        "CISA Due Date": relevantNvdData.cisaActionDue,
      }),
    };
    await drawSection(
      pdfContext,
      "Information from National Vulnerability Database",
      null,
      "keyValueList"
    );
    await drawKeyValueList(pdfContext, nvdInfoForPdf, {
      fontSize: PDF_FONT_SIZE_SMALL,
      valueColor: PDF_TEXT_COLOR_NORMAL,
    });

    // Section 2: CVSS v3.x Details ONLY
    const drawCvssV3Details = async (cvssV3Data) => {
      // Renamed function for clarity
      if (
        !cvssV3Data ||
        !cvssV3Data.version ||
        cvssV3Data.version === "N/A" ||
        !cvssV3Data.version.startsWith("3")
      ) {
        // console.log("Skipping CVSS v3.x section: No valid v3 data.");
        return false; // No valid V3 data
      }
      const version = cvssV3Data.version;
      const cvssDetails = {};
      // Use only V3 metric labels
      const metricsLabels = [
        "Score:",
        "Severity:",
        "Vector:",
        "Attack Vector:",
        "Attack Complexity:",
        "Privileges Required:",
        "User Interaction:",
        "Scope:",
        "Confidentiality:",
        "Integrity:",
        "Availability:",
      ];

      metricsLabels.forEach((label) => {
        const value = getCvssValue(cvssV3Data, label);
        cvssDetails[label.replace(":", "")] = value;
      });

      if (Object.keys(cvssDetails).length > 0) {
        const subTitle = `CVSS v3.x (v${version})`; // Title indicates it's V3
        const subTitleFontSize = PDF_FONT_SIZE_SMALL + 1;
        const subTitleLineHeight =
          subTitleFontSize * PDF_LINE_HEIGHT_MULTIPLIER;

        if (pdfContext.y - subTitleLineHeight < PDF_PAGE_MARGIN) {
          addNewPage();
          pdfContext.y = pageHeight - PDF_PAGE_MARGIN;
        }

        pdfContext.pdfPage.drawText(subTitle, {
          x: PDF_PAGE_MARGIN,
          y: pdfContext.y,
          font: pdfContext.fonts.bold,
          size: subTitleFontSize,
          color: PDF_TEXT_COLOR_HEADER,
        });
        pdfContext.y -= subTitleLineHeight * 1.2;

        await drawKeyValueList(pdfContext, cvssDetails, {
          fontSize: PDF_FONT_SIZE_SMALL,
          itemIndent: 10,
          valueColor: PDF_TEXT_COLOR_NORMAL,
        });
        return true;
      }
      return false;
    };

    // Draw CVSS section logic, simplified for V3 only
    if (relevantNvdData.cvssV3) {
      // Check if V3 data exists
      await drawSection(pdfContext, "CVSS Details", null, "keyValueList"); // Draw main title/line
      const v3Drawn = await drawCvssV3Details(relevantNvdData.cvssV3); // Attempt to draw V3 details

      if (!v3Drawn) {
        // If cvssV3 existed but drawing failed (e.g., no metrics found within it)
        const noDataMsg =
          "CVSS v3.x details recognized but could not be fully displayed.";
        const msgHeight = PDF_FONT_SIZE_SMALL * 1.2;
        if (pdfContext.y - msgHeight < PDF_PAGE_MARGIN) {
          addNewPage();
          pdfContext.y = pageHeight - PDF_PAGE_MARGIN;
        }
        pdfContext.pdfPage.drawText(noDataMsg, {
          x: PDF_PAGE_MARGIN + 10,
          y: pdfContext.y,
          font: pdfContext.fonts.regular,
          size: PDF_FONT_SIZE_SMALL,
          color: PDF_TEXT_COLOR_SECONDARY,
        });
        pdfContext.y -= msgHeight;
      }
    } else {
      // If relevantNvdData.cvssV3 was null from extraction
      await drawSection(
        pdfContext,
        "CVSS Details",
        "CVSS v3.x data not found in NVD record.",
        "paragraph"
      );
    }
    // CVSS V2 logic completely removed

    // Sections 3-7: Bedrock Analysis (No changes needed)
    await drawSection(
      pdfContext,
      "Vulnerability Analysis",
      bedrockAnalysisData.vulnerability_analysis,
      "paragraph"
    );
    await drawSection(
      pdfContext,
      "Vulnerability Exploitation",
      bedrockAnalysisData.vulnerability_exploitation,
      "paragraph"
    );
    await drawSection(
      pdfContext,
      "Vulnerability Mitigation",
      bedrockAnalysisData.vulnerability_mitigation,
      "paragraph"
    );
    await drawSection(
      pdfContext,
      "CWE Implications",
      bedrockAnalysisData.cwe_implications,
      "paragraph"
    );
    await drawSection(
      pdfContext,
      "Blind Spots & Additional Context",
      bedrockAnalysisData.blind_spots,
      "paragraph"
    );

    // --- Disclaimer (No changes needed) ---
    const disclaimerFontSize = PDF_FONT_SIZE_SMALL;
    const disclaimerFont = pdfContext.fonts.regular;
    const disclaimerLines = wrapText(
      DISCLAIMER_TEXT || "",
      disclaimerFont,
      disclaimerFontSize,
      contentWidth
    );
    const disclaimerLineHeight = disclaimerFontSize * 1.2;
    const disclaimerHeight =
      SPACE_BEFORE_DISCLAIMER + disclaimerLines.length * disclaimerLineHeight;
    if (pdfContext.y - disclaimerHeight < PDF_PAGE_MARGIN) {
      addNewPage();
      pdfContext.y = pageHeight - PDF_PAGE_MARGIN;
    }
    pdfContext.y -= SPACE_BEFORE_DISCLAIMER;
    for (const line of disclaimerLines) {
      if (pdfContext.y - disclaimerLineHeight < PDF_PAGE_MARGIN) {
        addNewPage();
        pdfContext.y = pageHeight - PDF_PAGE_MARGIN;
      }
      pdfContext.page.drawText(line, {
        x: PDF_PAGE_MARGIN,
        y: pdfContext.y,
        font: disclaimerFont,
        size: disclaimerFontSize,
        color: PDF_TEXT_COLOR_SECONDARY,
      });
      pdfContext.y -= disclaimerLineHeight;
    }

    // --- Footer (No changes needed) ---
    await addFooterToAllPages(
      pdfDoc,
      pdfContext.fonts.regular,
      FOOTER_TEXT,
      PDF_FONT_SIZE_SMALL
    );

    // --- Save ---
    const pdfBytes = await pdfDoc.save();
    console.log("PDF document generated successfully (CVSSv3 Focus).");
    return pdfBytes;
  } catch (error) {
    console.error("ERROR generating Professional PDF:", error);
    console.error(error.stack); // Log stack for debugging
    throw new Error(
      `Failed to generate professional PDF report: ${error.message}`
    );
  }
}

// --- DynamoDB & S3 Functions (No changes needed) ---

async function checkUserCredits(userId) {
  if (!USER_CREDITS_TABLE_NAME)
    throw new Error("USER_CREDITS_TABLE_NAME env var not set.");
  if (!userId) throw new Error("Cannot check credits for undefined userId.");
  const getParams = {
    TableName: USER_CREDITS_TABLE_NAME,
    Key: { UserID: userId },
    ProjectionExpression: "credit_balance",
  };
  try {
    const getData = await ddbDocClient.send(new GetCommand(getParams));
    const currentBalance = getData.Item?.credit_balance ?? 0;
    return currentBalance > 0;
  } catch (error) {
    console.error(`ERROR checking credits for user ${userId}:`, error);
    throw new Error("Failed to check user credit balance.");
  }
}

async function decrementUserCredits(userId) {
  console.log(`Attempting final credit decrement for user ${userId}`);
  if (!USER_CREDITS_TABLE_NAME)
    throw new Error("USER_CREDITS_TABLE_NAME env var not set.");
  if (!userId)
    throw new Error("Cannot decrement credits for undefined userId.");
  const updateParams = {
    TableName: USER_CREDITS_TABLE_NAME,
    Key: { UserID: userId },
    UpdateExpression: "SET credit_balance = credit_balance - :dec",
    ConditionExpression: "attribute_exists(UserID) AND credit_balance > :zero",
    ExpressionAttributeValues: { ":dec": 1, ":zero": 0 },
    ReturnValues: "UPDATED_NEW",
  };
  try {
    const updateData = await ddbDocClient.send(new UpdateCommand(updateParams));
    console.log(
      `Credits decremented successfully for ${userId}. New balance: ${updateData.Attributes?.credit_balance}`
    );
    return updateData.Attributes?.credit_balance;
  } catch (error) {
    if (error.name === "ConditionalCheckFailedException") {
      console.error(
        `Credit decrement failed conditionally for user ${userId}.`
      );
      throw {
        statusCode: 409,
        message:
          "Credit decrement failed: Insufficient credits or balance changed during processing. You were not charged.",
      };
    } else {
      console.error(`ERROR decrementing credits for user ${userId}:`, error);
      throw new Error(
        "Failed to update credit balance due to a database error."
      );
    }
  }
}

async function uploadReportToS3(pdfBytes, s3Key) {
  console.log(`Uploading PDF to S3 Bucket: ${S3_REPORT_BUCKET}, Key: ${s3Key}`);
  if (!S3_REPORT_BUCKET) throw new Error("S3_REPORT_BUCKET env var not set.");
  if (!s3Key) throw new Error("Cannot upload to S3 with undefined key.");
  const putCommand = new PutObjectCommand({
    Bucket: S3_REPORT_BUCKET,
    Key: s3Key,
    Body: pdfBytes,
    ContentType: "application/pdf",
  });
  try {
    await s3Client.send(putCommand);
    console.log("PDF successfully uploaded to S3.");
  } catch (error) {
    console.error(`ERROR uploading PDF to S3 (Key: ${s3Key}):`, error);
    throw new Error("Failed to upload generated report to storage.");
  }
}

// --- Response Formatting Functions (No changes needed) ---

function formatSuccessResponse(body, extraHeaders = {}) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers":
    "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "OPTIONS,POST,GET",
    
  };
  return {
    statusCode: 200,
    headers: { ...corsHeaders, ...extraHeaders },
    body: JSON.stringify(body),
    isBase64Encoded: false,
  };
}

function formatErrorResponse(error, extraHeaders = {}) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers":
      "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "OPTIONS,POST,GET",
  };
  const statusCode =
    typeof error.statusCode === "number" &&
    error.statusCode >= 400 &&
    error.statusCode < 600
      ? error.statusCode
      : 500;
  let message = error.message || "An unexpected error occurred.";
  if (statusCode === 500 && process.env.NODE_ENV === "production") {
    message = "Internal Server Error.";
  } else if (statusCode === 500) {
    message = `Internal Server Error: ${message}`;
  }
  console.log(
    `Formatting error response: Status ${statusCode}, Message: ${message}`
  );
  return {
    statusCode: statusCode,
    headers: { ...corsHeaders, ...extraHeaders },
    body: JSON.stringify({ message: message }),
    isBase64Encoded: false,
  };
}

// --- Main Lambda Handler (Simplified CVSS logic path) ---
export const handler = async (event, context) => {
  const requestId = context?.awsRequestId || "N/A";
  console.log(`--- Lambda Invocation Start (RequestId: ${requestId}) ---`);

  const corsHeaders = {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers":
      "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "OPTIONS,POST,GET",
  };

  if (event?.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders, body: "" };
  }

  let userId = null;
  try {
    validateEnvironmentVariables();

    userId = event?.requestContext?.authorizer?.claims?.sub || event?.requestContext?.authorizer?.jwt?.claims?.sub;
    const cveIdInput = event?.pathParameters?.id;

    if (!userId) {
      throw {
        statusCode: 403,
        message: "Forbidden: User identifier missing or invalid token.",
      };
    }
    if (!cveIdInput || !CVE_REGEX.test(cveIdInput)) {
      throw {
        statusCode: 400,
        message: `Bad Request: Valid CVE ID required (e.g., CVE-YYYY-NNNN). Received: ${
          cveIdInput || "nothing"
        }`,
      };
    }
    const cveId = cveIdInput.toUpperCase();
    console.log(
      `(RequestId: ${requestId}) Processing request for UserID: ${userId}, CVE ID: ${cveId}`
    );

    const hasCredits = await checkUserCredits(userId);
    if (!hasCredits) {
      throw {
        statusCode: 402,
        message: "Payment Required: Insufficient credits to generate report.",
      };
    }
    console.log(
      `(RequestId: ${requestId}) User ${userId} has sufficient credits.`
    );

    // Core Logic (CVSSv3 Focus)
    const nvdApiKey = await getNvdApiKey();
    const rawVulnerabilityData = await fetchNvdData(cveId, nvdApiKey);
    const relevantNvdData = extractRelevantNvdData(rawVulnerabilityData); // Now extracts only V3 or null
    const bedrockPrompt = prepareBedrockPrompt(relevantNvdData); // Uses only V3 summary
    const bedrockAnalysisData = await invokeBedrockAnalysis(bedrockPrompt);

    await decrementUserCredits(userId); // Charge user

    console.log(
      `(RequestId: ${requestId}) Starting PDF generation (CVSSv3 Focus)...`
    );
    const pdfBytes = await generatePdfReport(
      bedrockAnalysisData,
      cveId,
      relevantNvdData
    ); // PDF generator uses relevantNvdData (with only cvssV3)
    console.log(
      `(RequestId: ${requestId}) PDF generation completed. Size: ${
        pdfBytes?.length || 0
      } bytes`
    );

    const timestamp = Date.now();
    const s3Key = `${REPORT_S3_PREFIX}${cveId}-${userId}-${timestamp}.pdf`;
    await uploadReportToS3(pdfBytes, s3Key);

    const successBody = {
      message: "Report generated successfully.",
      reportKey: s3Key,
      cveId: cveId,
      timestamp: new Date(timestamp).toISOString(),
    };
    console.log(
      `(RequestId: ${requestId}) --- Lambda Invocation End (Success) ---`
    );
    return formatSuccessResponse(successBody, corsHeaders);
  } catch (error) {
    console.error(
      `(RequestId: ${requestId}) !!! OVERALL HANDLER ERROR:`,
      error
    );
    if (!error.statusCode || error.statusCode >= 500) {
      console.error(`(RequestId: ${requestId}) Stack Trace:`, error.stack);
    }
    console.log(
      `(RequestId: ${requestId}) --- Lambda Invocation End (Error) ---`
    );
    return formatErrorResponse(error, corsHeaders);
  }
};
