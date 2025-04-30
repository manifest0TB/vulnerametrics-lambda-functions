# vulnerametrics

The development of the released version started in 03/2025 only by [Miguel Cordero Pamphile](https://www.linkedin.com/in/miguelcorderopamphile/).

[frontend documentation](https://github.com/manifest0TB/vulnerametrics/blob/main/README.md)
[API documentation](https://github.com/manifest0TB/vulnerametrics/blob/main/vulnerametricsAPI.md)
## Main goal:

Release a Minimum Value Product with a search engine to find and select single vulnerabilities (CVE) from NVD and generate a Vulnerability Report through Claude 3.7 Sonnet inference in Amazon Bedrock.

## To future versions:

* Vector Indexing to compare similar CVE and reduce processing power.
* Range based on specific day, week, month or year and to be even more specific using keywords as addition to one of all the options.

## Data Source:

* National Vulnerability Database (NVD).

### NVD API Rate Limits:

* NIST firewall rules put in place to prevent denial of service attacks can thwart your application if it exceeds a predetermined rate limit.
* The public rate limit (without an API key) is 5 requests in a rolling 30 second window.
* The rate limit with an API key is 50 requests in a rolling 30 second window.
* Requesting an API key significantly raises the number of requests that can be made in a given time frame.
* However, it is still recommended that your application sleeps for several seconds between requests so that legitimate requests are not denied, and all requests are responded to in sequence.
[Source](https://nvd.nist.gov/developers/start-here).

## Description:

Vulnerametrics is a security SaaS tool that generates detailed reports on specific CVEs using Claude 3.7 Sonnet on AWS Bedrock. Users can search for vulnerabilities by their CVE ID, and the system fetches real-time data from the National Vulnerability Database (NVD), performs analysis using Claude, and generates downloadable PDF reports with comprehensive vulnerability assessments.

## Data to extract from NVD:

* **General Information**: CVE ID, Source Identifier, Published Date, Last Modified Date, Vulnerability Status.
* **Description**: Full text.
* **CVSS v3.1 Metrics**: Base Score, Vector String, Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality Impact, Integrity Impact, Availability Impact, Base Severity.
* **Weaknesses**: List of CWE IDs.
* **Configurations**: List of CPE strings.
* **Vendor Comments**: List of comments (if any).

## Implementation and process:

### Phase 1: Initial Setup & IAM Configuration

* **Create AWS Account**
    * Register with AWS and claim $300 credit.
    * Enable Multi-Factor Authentication on root account.
* **Create Administrative IAM User**
    * Log into AWS Management Console.
    * Navigate to IAM service.
    * Create an IAM user `iam-admin-user` with AdministratorAccess.
* **Configure MFA for Admin User**
    * Set up MFA for the `iam-admin-user` IAM user.
    * Log out of root, log in as `iam-admin-user`.

### Phase 2: Set Up Web Application Infrastructure

* **Register Domain and Configure DNS**
    * Create a public hosted zone in Route 53 for vulnerametrics.com.
    * Update Name Servers at the domain registrar (Namecheap) to Route 53 NS records.
* **Create S3 Bucket for PDF Reports**
    * Create an S3 bucket `s3-reports-bucket`.
    * Disable ACLS (Bucket owner enforced).
    * Block all public access.
    * Enable versioning.
    * Enable default server-side encryption (SSE-S3).
* **Set Up Web Hosting with Amplify**
    * Create a new Amplify app.
    * Connect to the GitHub repository (manifest0TB/vulnerametrics).
    * Configure build settings (amplify.yml) for Vue.js (baseDirectory: /dist).
    * (Defer environment variables for API endpoints).
    * Initiate the first build/deploy.
* **Configure SSL Certificate & Domain**
    * Request a public certificate in ACM (us-east-1) for vulnerametrics.com and *.vulnerametrics.com.
    * Use DNS validation (automatically creating CNAME records in Route 53).
    * Wait for certificate status "Issued".
    * Add custom domain vulnerametrics.com in Amplify, selecting the issued ACM certificate.
    * Configure redirects in Amplify (e.g., www to root).
    * Wait for DNS propagation and SSL activation.

### Phase 3: Authentication System & SES Integration

* **Configure Amazon SES for Email Sending**
    * Navigate to SES service (us-east-1 region).
    * Create and verify a Domain Identity for vulnerametrics.com.
    * Configure Easy DKIM (RSA 2048 bits).
    * Configure a Custom MAIL FROM domain (auth.vulnerametrics.com).
    * Publish required DNS records (TXT, CNAMES, MX) automatically via Route 53 integration.
    * Confirm domain identity status changes to "Verified".
* **Create Cognito User Pool**
    * Navigate to Cognito in AWS Console.
    * Create a user pool (`cognito-user-pool`) with appropriate settings:
        * Sign-in option: Email only.
        * Required user attributes: email, nickname.
        * Password policies: (Set as configured).
        * Configure email verification: Enabled.
        * Configure email sending method:
            * Initially set to "Send email with Cognito".
            * Modified to "Send email with Amazon SES".
            * Select the verified SES Identity: vulnerametrics.com.
            * Set the FROM email address: no-reply@vulnerametrics.com.
            * Allow Cognito to manage necessary IAM permissions (AWSServiceRoleForAmazonCognitoldpEmailService).
* **Configure Cognito App Client**
    * Create a new App Client `cognito-app-client`.
    * Configure OAuth 2.0 and OpenID Connect settings:
        * Allowed callback URLs: https://vulnerametrics.com/callback
        * Allowed sign-out URLs: https://vulnerametrics.com/
        * OAuth 2.0 grant types: Authorization code grant.
        * OpenID Connect scopes: openid, email, profile.
    * Configure Attribute read and write permissions:
        * Read enabled for: email, email_verified, nickname.
        * Write disabled for most attributes, including nickname after initial sign-up.
* **Set Up Identity Pool**
    * Navigate to Cognito Federated Identities (Identity pools).
    * Create an identity pool:
        * Name: `cognito-identity-pool`.
        * Enable access to: Authenticated identities only.
    * Configure Authentication providers:
        * Select Cognito User Pool tab.
        * Enter the User Pool ID.
        * Enter the App Client ID for `cognito-app-client`.
    * Configure IAM roles:
        * Create a new IAM role for authenticated users (`cognito-authenticated-iam-role`).
        * Accept default policy (to be modified later as needed).

### Phase 4: Credits System

* **Create DynamoDB Table for User Credits**
    * Create a table (`dynamodb-user-credits-table`) with 'UserID' (String) as primary key.
    * Define attributes conceptually (added via Lambda later): `credit_balance`, `free_trial_status`.
    * Configure Capacity Mode: On-demand.
    * Enable Point-in-Time Recovery (PITR).

### Phase 5: Backend Services

* **Create and Configure API Gateway**
    * Create REST API `api-gateway-rest-api` in API Gateway.
    * Configure CORS individually for `/credits/check`, `/cve/{id}`, `/report/{id}` resources:
        * Set `Access-Control-Allow-Origin` to https://vulnerametrics.com.
        * Set `Access-Control-Allow-Methods` to `GET`/`POST` as appropriate.
        * Include 'Authorization' in `Access-Control-Allow-Headers`.
        * Set `Access-Control-Allow-Credentials` to `true`.
    * Add `OPTIONS` methods automatically via 'Enable CORS' feature.
    * Set up and attach Cognito User Pool authorizer (`api-gateway-cognito-authorizer`) linked to `cognito-user-pool`.
    * Set up resources and methods:
        * `GET /credits/check`: Integrate with `lambda-check-credits-function` via Lambda Proxy, secure with Cognito Authorizer.
        * `GET /cve/{id}`: Integrate with `lambda-get-cve-function` via Lambda Proxy, secure with Cognito Authorizer.
        * `POST /report/{id}`: Integrate with `lambda-generate-report-function` via Lambda Proxy, secure with Cognito Authorizer.
* **Implement Lambda Functions (Node.js)**
    * Create Lambda function for CVE data retrieval (`lambda-get-cve-function` - Node.js):
        * Access NVD API using key from Secrets Manager (`secrets-manager-nvd-api-key-secret`).
        * Implement error handling and timeouts/retries.
    * Create Lambda function for report generation (`lambda-generate-report-function` - Node.js):
        * Configure Claude 3.7 Sonnet access via Bedrock Inference Profile.
        * Implement PDF generation logic (`pdf-lib`).
        * Set up S3 upload for generated reports to `s3-reports-bucket`.
        * Implement credit check and deduction logic (interfaces with DynamoDB `dynamodb-user-credits-table`).
    * Create Lambda function for user credits management (`lambda-check-credits-function` - Node.js):
        * Implement logic to read `credit_balance` from DynamoDB `dynamodb-user-credits-table`.
        * Implement logic via Cognito Post Confirmation trigger to grant 3 initial free credits upon user registration by writing/updating the user's record in `dynamodb-user-credits-table`.
* **Set Up IAM Roles for Lambda**
    * Create specific execution roles for each Lambda function with necessary permissions (DynamoDB R/W, Secrets Manager Read, Bedrock Invoke, S3 Write, CloudWatch Logs) following least privilege principle.
* **Deploy API Gateway (`api-gateway-rest-api`)**
    * Deploy API changes to the 'prod' stage.
    * Note the Invoke URL for frontend integration (`https://api-gateway-invoke-url/stage`).

### Phase 6: Monitoring & Security

* **Configure AWS WAF**
    * Create WebACL in us-east-1.
    * Associate with Amplify's CloudFront distribution.
    * Enable Managed Rule Sets (Common RuleSet, IpReputationList).
    * Configure Rate-based rules.
    * Set up WAF logging (CloudWatch Logs).
    * Configure basic CloudWatch Alarms based on WAF metrics.
* **Set up monitoring and log groups for Lambda functions.**
* **Configure alarms for Lambda errors/critical metrics.**
* **Enable CloudTrail for API activity logging.**
    * Configure log storage in a dedicated S3 bucket.
* **Set Up Security Hub & AWS Config**
    * Enable AWS Security Hub.
    * Enable foundational security best practice checks (AWS Foundational Security Best Practices v1.0.0 and CIS AWS Foundations Benchmark v1.2.0).
    * Enable AWS Config.
* **Reviewed AWS Foundational Security Best Practices v1.0.0 findings in Security Hub**
    * Addressed CRITICAL/HIGH findings: Suppressed `IAM.6` (Hardware MFA for root, as Virtual MFA is active), remediated `EC2.2` (hardened default Security Group rules), enabled `GuardDuty.1` (threat detection service), and enabled `Inspector.*` (vulnerability scanning service, including Lambda).
    * Addressed key MEDIUM findings: Added `Account.1` security contacts, enabled `DynamoDB.6` table deletion protection, strengthened `IAM.7` user password policy, enabled `S3.1` Block Public Access at the account level, enforced `S3.5` SSL via S3 bucket policies, enabled `APIGateway.1` stage execution logging, and reviewed `Cognito.1` Advanced Security (activation deferred).

### Phase 7: Frontend Development

* **Develop Web Application (Vue.js)**
    * NOTE: information only available in vmtrics-frontend-doc
* **Implement Authentication Flow**
    * NOTE: information only available in vmtrics-frontend-doc
* **Implement CVE Search Functionality**
    * NOTE: information only available in vmtrics-frontend-doc

### Phase 8: End-to-End Workflow Integration

* **End-to-End Process Implementation Review**
    1.  User registers and logs in via Cognito authentication.
    2.  Upon successful registration and confirmation, new users automatically receive 3 free credits (record created/updated in `dynamodb-user-credits-table` with `credit_balance = 3`).
    3.  User searches for a specific CVE by ID on the frontend.
    4.  System checks if the user has available credits (Lambda function `lambda-generate-report-function` reads `credit_balance` from DynamoDB).
    5.  If credits > 0, the system deducts one credit (Lambda function `lambda-generate-report-function` updates DynamoDB) and proceeds.
    6.  If credits = 0, the system prevents report generation (API returns error; UI should indicate no credits - requires frontend implementation).
    7.  After successful credit validation, Lambda retrieves data from NVD API.
    8.  Lambda sends data to Bedrock for Claude 3.7 Sonnet analysis.
    9.  Claude generates comprehensive report content.
    10. Lambda generates PDF and stores it in S3 reports bucket.
    11. Frontend receives S3 signed URL for PDF download.
    12. User downloads the report.
* **Testing & Debugging**
    * Test authentication flow (sign-up, sign-in, email verification, password reset).
    * Test free credits allocation for new users.
    * Test credits deduction logic.
    * Test CVE search functionality (valid and invalid IDs).
    * Test report generation process (API call, Lambda execution, Bedrock interaction, S3 upload).
    * Validate PDF content and format.
    * Test interaction when the user has no credits.
    * Test error handling scenarios (NVD API errors, Bedrock errors, etc.).
* **Deploy Production Frontend Version**
    * Push final code to the repository main branch.
    * Verify Amplify build and deployment succeeds.

### Phase 9: Finalization

* **Document Architecture**
    * Generate architecture diagrams with Workload Discovery.
    * Document API specifications (endpoints, request/response formats, auth).
* **Configure Cost Alerts**
    * Set up billing alerts in AWS Budgets.
    * Configure budget notifications.
* **Hardening Post-Release:**
    * Implement TTL (Time To Live) for free credits in DynamoDB `dynamodb-user-credits-table` table using an `expirationTimestamp` attribute, setting credits to expire 24 hours after being granted.
    * Review CIS AWS Foundations Benchmark v1.2.0.