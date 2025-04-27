// Import AWS SDK v3 DynamoDB client and Document client libraries
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";

// Initialize DynamoDB Client for the AWS Region the Lambda is running in
const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);

// --- CONFIGURATION ---
// Retrieve table name from environment variable (Set this in Lambda config!)
const tableName =
  process.env.USER_CREDITS_TABLE_NAME || "UserCreditsVulnerametrics"; // Fallback only, use env var!
// Allowed origin for CORS - Hardcoded for production as per user decision
const allowedOrigin = "https://vulnerametrics.com";
// --- END CONFIGURATION ---

/**
 * Handles requests to check the user's credit balance.
 * Expects the UserID (Cognito sub) to be available in the authorizer claims context.
 */
export const handler = async (event) => {
  console.log("EVENT RECEIVED:", JSON.stringify(event));

  // Prepare CORS headers
  const headers = {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
  };

  let userId;
  try {
    // Extract UserID (Cognito 'sub') passed by the API Gateway Cognito Authorizer
    userId =
      event.requestContext?.authorizer?.jwt?.claims?.sub ||
      event.requestContext?.authorizer?.claims?.sub ||
      event.requestContext?.identity?.cognitoIdentityId;

    if (!userId) {
      console.error(
        "UserID ('sub' or identityId) not found in request context."
      );
      return {
        statusCode: 403, // Forbidden
        headers: headers,
        body: JSON.stringify({
          message: "Forbidden: User identifier not found.",
        }),
      };
    }

    console.log(`Checking credits for UserID: ${userId}`);

    // Prepare DynamoDB GetItem parameters
    const params = {
      TableName: tableName,
      Key: {
        UserID: userId, // Ensure 'UserID' matches your table's partition key name
      },
      ProjectionExpression: "credit_balance", // Only retrieve the credit_balance attribute
    };

    // Create and send the GetCommand
    const command = new GetCommand(params);
    const data = await docClient.send(command);

    let creditBalance = 0; // Default balance

    if (
      data.Item &&
      typeof data.Item.credit_balance === "number" &&
      !isNaN(data.Item.credit_balance)
    ) {
      creditBalance = data.Item.credit_balance;
      console.log(`UserID ${userId} found. Credit Balance: ${creditBalance}`);
    } else {
      console.log(
        `UserID ${userId} item or valid 'credit_balance' attribute not found. Defaulting to 0 credits.`
      );
    }

    // Return successful response
    return {
      statusCode: 200,
      headers: headers,
      body: JSON.stringify({
        creditBalance: creditBalance,
      }),
    };
  } catch (error) {
    console.error("ERROR accessing DynamoDB or processing request:", error);

    // Return generic server error response
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
