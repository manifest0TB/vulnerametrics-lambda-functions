// Import the DynamoDB client and commands
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb"; // Helper to convert JS objects to DynamoDB format

// Initialize the DynamoDB client
// Ensure your Lambda execution role has permissions for dynamodb:PutItem on the target table.
// The region should ideally be set via environment variables or dynamically,
// but we'll default to us-east-1 if not specified.
const region = process.env.AWS_REGION || "us-east-1";
const ddbClient = new DynamoDBClient({ region });

// Define the DynamoDB table name from an environment variable for flexibility
const tableName = process.env.DYNAMODB_TABLE_NAME; // We'll set this later in Lambda config

/**
 * Cognito Post Confirmation Trigger Handler
 *
 * This function is triggered after a user successfully confirms their registration.
 * It adds an entry to the UserCreditsVulnerametrics DynamoDB table, granting
 * the user 3 initial credits.
 */
export const handler = async (event, context) => {
  console.log(
    "Received Cognito Post Confirmation event:",
    JSON.stringify(event, null, 2)
  );

  // Ensure the table name environment variable is set
  if (!tableName) {
    console.error("Error: DYNAMODB_TABLE_NAME environment variable not set.");
    // Returning the event prevents Cognito from seeing this as a failure
    // that would block user login, but the credits won't be added.
    return event;
    // throw new Error("Configuration error: DynamoDB table name not set.");
  }

  // Extract the user sub (unique ID) from the event. This will be our UserID.
  // Check if userAttributes exists and has the sub property
  if (
    !event.request ||
    !event.request.userAttributes ||
    !event.request.userAttributes.sub
  ) {
    console.error(
      "Error: Could not extract user sub from event.request.userAttributes"
    );
    // Return the event to allow Cognito flow to continue, but log the error.
    return event;
  }
  const userId = event.request.userAttributes.sub;
  console.log(`Processing user confirmation for UserID: ${userId}`);

  // Prepare the item to be inserted/updated in DynamoDB
  const item = {
    UserID: userId, // Primary Key
    credit_balance: 3, // Grant 3 initial credits
    // You could add other initial attributes here if needed
  };

  // Construct the PutItem command parameters
  const params = {
    TableName: tableName,
    Item: marshall(item), // Convert the JS object to DynamoDB attribute value format
  };

  try {
    console.log(
      `Attempting to add/update credits for UserID: ${userId} in table ${tableName}`
    );
    const command = new PutItemCommand(params);
    const response = await ddbClient.send(command);
    console.log(
      `Successfully added/updated credits for UserID: ${userId}. Response:`,
      response
    );
    // Cognito requires the event object to be returned for the trigger to succeed
    return event;
  } catch (error) {
    console.error(
      `Error adding/updating credits for UserID: ${userId} in table ${tableName}:`,
      error
    );
    // Log the error but return the event to allow Cognito flow to complete.
    return event;
    // throw error; // Uncomment this if failure should prevent user login/confirmation completion
  }
};
