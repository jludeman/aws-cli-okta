import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.*;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HTTP;
import org.apache.commons.codec.binary.Base64;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLResult;
import com.fasterxml.jackson.core.JsonFactory;
import com.amazonaws.auth.*;

public class AssumeRoleWithOktaSAML {
	
	//User specific variables
	private static String oktaOrg = "";
	private static Map<String, String> oktaAWSAppURLs = new HashMap<String, String>();
	
	/* creates required AWS credential file if necessary" */
	private static void awsSetup() throws FileNotFoundException, UnsupportedEncodingException{
		//check if credentials file has been created
		File f = new File (System.getProperty("user.home")+"/.aws/credentials");
		//creates credentials file
		if(!f.exists()){
			f.getParentFile().mkdirs();
			
			PrintWriter writer = new PrintWriter(f, "UTF-8");
			writer.println("[default]");
			writer.println("aws_access_key_id=");
			writer.println("aws_secret_access_key=");
			writer.close();
		}
	}
	
	/* Parses application's config file for app URL and Okta Org */
	private static void extractCredentials() throws IOException{
		BufferedReader oktaBr = new BufferedReader(new FileReader(new File (System.getProperty("user.dir")) +"/oktaAWSCLI.config"));
		
		//extract oktaOrg and oktaAWSAppURL from Okta settings file
		String line = oktaBr.readLine();
		while(line!=null){
			if(!line.startsWith("#") && line.contains("OKTA_ORG")){
				oktaOrg = line.substring(line.indexOf("=")+1).trim();
			}
			else if(!line.startsWith("#") && line.contains("OKTA_AWS_APP_URL")) {
				try {
					JSONArray json = new JSONArray(line.substring(line.indexOf("=")+1).trim());
					oktaAWSAppURLs.put(json.getString(0), json.getString(1));
				} catch (JSONException e) {
					throw new RuntimeException(e);
				}
			}
			line = oktaBr.readLine();
		}
		oktaBr.close();
	}
	
	/*Uses user's credentials to obtain Okta session Token */
	private static CloseableHttpResponse authenticateCredentials(String username, String password) throws JSONException, ClientProtocolException, IOException{
		HttpPost httpost = null;
		CloseableHttpClient httpClient = HttpClients.createDefault();
		
		
		//HTTP Post request to Okta API for session token
		httpost = new HttpPost("https://" + oktaOrg + "/api/v1/authn");
		httpost.addHeader("Accept", "application/json");
		httpost.addHeader("Content-Type", "application/json");
		httpost.addHeader("Cache-Control", "no-cache");
		
		//construction of request JSON 
		JSONObject jsonObjRequest = new JSONObject();
		jsonObjRequest.put("username", username);
		jsonObjRequest.put("password", password);
		
		StringEntity entity = new StringEntity(jsonObjRequest.toString(), HTTP.UTF_8);
		entity.setContentType("application/json");
		httpost.setEntity(entity);
		
		return httpClient.execute(httpost);
	}
	
	/*Handles possible authentication failures */
	private static void authnFailHandler(int requestStatus, CloseableHttpResponse response){
		//invalid creds
		if (requestStatus== 400 || requestStatus==401){
			System.out.println("Invalid Credentials, Please try again.");
		}
		else if(requestStatus == 500){
			//failed connection establishment
			System.out.println("\nUnable to establish connection with: " + 
					oktaOrg + " \nPlease verify that your Okta org url is corrct and try again" );
			System.exit(0);
		}
		else if(requestStatus!=200){
			//other
			throw new RuntimeException("Failed : HTTP error code : "
			+ response.getStatusLine().getStatusCode());
		}
	}
	
	/*Handles possible AWS assertion retrieval errors */ 
	private static void samlFailHandler(int requestStatus, CloseableHttpResponse responseSAML) throws UnknownHostException{
		if(responseSAML.getStatusLine().getStatusCode() == 500){
			//incorrectly formatted app url
			throw new UnknownHostException();
		}
		else if (responseSAML.getStatusLine().getStatusCode() != 200) {
			//other
			throw new RuntimeException("Failed : HTTP error code : "
					+ responseSAML.getStatusLine().getStatusCode());
		}
	}
	
	/* Handles user selection prompts */
	private static int numSelection(int max){
		Scanner scanner = new Scanner(System.in);
		
		int selection = -1;
		while (selection == -1) {
			//prompt user for selection
			System.out.print("Selection: ");
			String selectInput = scanner.nextLine();
			try{
				selection = Integer.parseInt(selectInput) - 1;
				if (selection >= max) {
					InputMismatchException e = new InputMismatchException();
					throw e;
				}
			}
			catch (InputMismatchException e ) {
				//raised by something other than a number entered
				System.out.println("Invalid input: Please enter a number corresponding to a choice \n");
				selection = -1;
			}
			catch (NumberFormatException e) {
				//raised by number too high or low selected
				System.out.println("Invalid input: Please enter in a number \n");
				selection = -1;
			}
		}
		return selection;
	}
	
	/*Handles question factor authentication,
	 * Precondition: question factor as JSONObject factor, current state token stateToken
	 * Postcondition: return session token as String sessionToken 
	 */
	private static String questionFactor(JSONObject factor, String stateToken) throws JSONException, ClientProtocolException, IOException{
		String question = factor.getJSONObject("profile").getString("questionText");
		Scanner scanner = new Scanner(System.in);
		String sessionToken = "";
		String answer = "";
		
		//prompt user for answer 
		System.out.println("\nSecurity Question Factor Authentication\nEnter 'change factor' to use a diffrent factor\n");
		while(sessionToken == ""){
			if( answer != ""){
				System.out.println("Incorrect answer, please try again");
			}
			System.out.println(question);
			System.out.print("Answer: ");
			answer = scanner.nextLine();
			//verify answer is correct
			if(answer.toLowerCase().equals("change factor")){
				return answer;
			}
			sessionToken = verifyAnswer(answer, factor, stateToken);
		}
		return sessionToken;
	}
	
	
	/*Handles sms factor authentication
	 * Precondition: question factor as JSONObject factor, current state token stateToken
	 * Postcondition: return session token as String sessionToken 
	 */
	private static String smsFactor(JSONObject factor, String stateToken) throws ClientProtocolException, JSONException, IOException{
		Scanner scanner = new Scanner(System.in);
		String answer = "";
		String sessionToken = "";
		
		//prompt for sms verification 
		System.out.println("\nSMS Factor Authenication \nEnter 'change factor' to use a diffrent factor");
		while(sessionToken == ""){
			if( answer != ""){
				System.out.println("Incorrect passcode, please try again or type 'new code' to be sent a new sms token");
			} else{
				//send initial code to user
				sessionToken = verifyAnswer("",factor,stateToken);
			}
			System.out.print("SMS Code: ");
			answer = scanner.nextLine();
			//resends code
			if(answer.equals("new code")){
				answer = "";
				System.out.println("New code sent! \n");
			}else if(answer.toLowerCase().equals("change factor")){
				return answer;
			}
			//verifies code
			sessionToken = verifyAnswer(answer, factor, stateToken);
		}
		return sessionToken;
	}
	
	
	/*Handles token factor authentication, i.e: Google Authenticator or Okta Verify
	 * Precondition: question factor as JSONObject factor, current state token stateToken
	 * Postcondition: return session token as String sessionToken 
	 */
	private static String totpFactor(JSONObject factor, String stateToken) throws ClientProtocolException, JSONException, IOException{
		Scanner scanner = new Scanner(System.in);
		String sessionToken = "";
		String answer = "";
		
		//prompt for token 
		System.out.println("\n" +factor.getString("provider") + " Token Factor Authentication\nEnter 'change factor' to use a diffrent factor");
		while(sessionToken == ""){
			if( answer != ""){
				System.out.println("Invalid token, please try again");
			}
			
			System.out.print("Token: ");
			answer = scanner.nextLine();
			//verify auth Token
			if(answer.toLowerCase().equals("change factor")){
				return answer;
			}
			sessionToken = verifyAnswer(answer, factor, stateToken);
		}
		return sessionToken;
	}
	
	
	/*Handles push factor authentication,
	 * 
	 * MIGHT NOT WORK CORRENTLY - NOT TESTED
	 * 
	 * Precondition: question factor as JSONObject factor, current state token stateToken
	 * Postcondition: return session token as String sessionToken 
	 */
	private static String pushFactor(JSONObject factor, String stateToken) throws ClientProtocolException, JSONException, IOException{
		Calendar newTime = null;
		Calendar time = Calendar.getInstance();
		String sessionToken = "";
		
		System.out.println("\nPush Factor Authentication");
		while( sessionToken == ""){
			System.out.print("Token: ");
			//prints waiting tick marks 
			if( time.compareTo(newTime) > 4000){
				System.out.println("...");
			}
			//Verify if Okta Push has been pushed
			sessionToken = verifyAnswer("", factor, stateToken);
			if(sessionToken.equals("Timeout")){
				System.out.println("Session has timed out");
				return "timeout";
			}
			time = newTime;
			newTime = Calendar.getInstance();
		}
		return sessionToken;
	}
	
	
	/*Handles verification for all Factor types
	 * Precondition: question factor as JSONObject factor, current state token stateToken
	 * Postcondition: return session token as String sessionToken 
	 */
	private static String verifyAnswer(String answer, JSONObject factor, String stateToken) throws JSONException, ClientProtocolException, IOException{
		JSONObject profile = new JSONObject();
		String verifyPoint = factor.getJSONObject("_links").getJSONObject("verify").getString("href");
		
		profile.put("stateToken", stateToken);
		
		if( answer != ""){
			profile.put("answer", answer);
		}
		
		//create post request 
		CloseableHttpResponse responseAuthenticate = null;
		CloseableHttpClient httpClient = HttpClients.createDefault();
		
		HttpPost httpost = new HttpPost(verifyPoint);
		httpost.addHeader("Accept", "application/json");
		httpost.addHeader("Content-Type", "application/json");
		httpost.addHeader("Cache-Control", "no-cache");
		
		StringEntity entity = new StringEntity(profile.toString(), HTTP.UTF_8);
		entity.setContentType("application/json");
		httpost.setEntity(entity);
		responseAuthenticate = httpClient.execute(httpost);
		
		BufferedReader br = new BufferedReader(new InputStreamReader(
		(responseAuthenticate.getEntity().getContent())));
		
		String outputAuthenticate = br.readLine();
		JSONObject jsonObjResponse = new JSONObject(outputAuthenticate);
		//Handles request response 
		if(jsonObjResponse.has("sessionToken")){
			//session token returned
			return jsonObjResponse.getString("sessionToken");
		} else if(jsonObjResponse.has("factorResult")){
			if(jsonObjResponse.getString("sessionToken").equals("TIMEOUT")){
				//push factor timeout
				return "timeout";
			}
			else{
				return "";
			}
		}
		else{
			//Unsuccessful verification 
			return "";
		}
	}
	
	
	/*Handles factor selection based on factors found in parameter authResponse, returns the selected factor
	 * Precondition: JSINObject authResponse
	 * Postcondition: return session token as String sessionToken 
	 */
	public static JSONObject selectFactor(JSONObject authResponse) throws JSONException{
		JSONArray factors = authResponse.getJSONObject("_embedded").getJSONArray("factors");
		JSONObject factor;
		String factorType;
		System.out.println("\nMulti-Factor authentication required. Please select a factor to use.");
		//list factor to select from to user
		System.out.println("Factors:");
		for(int i=0; i<factors.length(); i++){
			factor = factors.getJSONObject(i);
			factorType = factor.getString("factorType");
			if(factorType.equals("question")){
				factorType = "Security Question";
			}else if(factorType.equals("sms")){
				factorType = "SMS Authentication";
			}else if(factorType.equals("token:software:totp") ){
				String provider = factor.getString("provider");
				if(provider.equals("GOOGLE")){
					factorType = "Google Authenticator";
				} else{
					factorType = "Okta Verify";
				}
			}
			System.out.println("[ " + (i+1) + " ] :" + factorType );
		}
		
		//Handles user factor selection
		int selection = numSelection(factors.length());
		return factors.getJSONObject(selection);
	}
	
	
	/*Handles MFA for users, returns an Okta session token if user is authenticated 
	 * Precondition: question factor as JSONObject factor, current state token stateToken
	 * Postcondition: return session token as String sessionToken 
	 */
	private static String mfa(JSONObject authResponse){
		try {
			//User selects which factor to use
			JSONObject factor = selectFactor(authResponse);
			String factorType = factor.getString("factorType");
			String stateToken = authResponse.getString("stateToken");
			
			//factor selection handler
			switch(factorType){
				case ("question"):{
					//question factor handler
					String sessionToken = questionFactor(factor, stateToken);
					if(sessionToken.equals("change factor")){
						System.out.println("Factor Change Initiated");
						return mfa(authResponse);
					}
					return sessionToken;
				}
				case ("sms"):{
					//sms factor handler
					String sessionToken = smsFactor(factor,stateToken);
					if(sessionToken.equals("change factor")){
						System.out.println("Factor Change Initiated");
						return mfa(authResponse);
					}
					return sessionToken;
					
				}
				case ("token:software:totp"):{
					//token factor handler 
					String sessionToken = totpFactor(factor,stateToken);
					if(sessionToken.equals("change factor")){
						System.out.println("Factor Change Initiated");
						return mfa(authResponse);
					}
					return sessionToken;
				}
				case ("push"):{
					//push factor handles
					String result = pushFactor(factor,stateToken);
					if(result.equals("timeout")|| result.equals("change factor")){
						return mfa(authResponse);
					}
					return result;
				}
			}
		} catch (JSONException e) {
			e.printStackTrace();
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}
	
	
	/* prints final status message to user */
	private static void resultMessage(){
		Calendar date = Calendar.getInstance();
		SimpleDateFormat dateFormat = new SimpleDateFormat();
		date.add(Calendar.HOUR,1);
		
		//change with file customization
		System.out.println("\n----------------------------------------------------------------------------------------------------------------------");
		System.out.println("Your new access key pair has been stored in the aws configuration file "
				+ System.getProperty("user.home") + "/.aws/credentials under the saml profile.");
		System.out.println("Note that it will expire at " + dateFormat.format(date.getTime()));
		System.out.println("After this time you may safely rerun this script to refresh your access key pair.");
		System.out.println("To use this credential call the aws cli with the --profile option "
				+ "(e.g. aws --profile saml ec2 describe-instances)");
		System.out.println("----------------------------------------------------------------------------------------------------------------------");
	}
	
	
	/* Authenticates users credentials via Okta, return Okta session token
	 * Postcondition: returns String oktaSessionToken
	 * */
	private static String oktaAuthentication() throws ClientProtocolException, JSONException, IOException{
		CloseableHttpResponse responseAuthenticate = null;
		int requestStatus = 0;
		
		//Redo sequence if response from AWS doesn't return 200 Status
		while(requestStatus != 200){
			
			// Prompt for user credentials
			System.out.print("Username: ");
			Scanner scanner = new Scanner(System.in);
			
			String oktaUsername = scanner.next();
			
			Console console = System.console();
			String oktaPassword = new String(console.readPassword("Password: "));
			
			responseAuthenticate = authenticateCredentials(oktaUsername, oktaPassword);
			requestStatus = responseAuthenticate.getStatusLine().getStatusCode();
			authnFailHandler(requestStatus, responseAuthenticate);
		}
		
		//Retrieve and parse the Okta response for session token
		BufferedReader br = new BufferedReader(new InputStreamReader(
		(responseAuthenticate.getEntity().getContent())));
		
		String outputAuthenticate = br.readLine();
		JSONObject jsonObjResponse = new JSONObject(outputAuthenticate);
		
		responseAuthenticate.close();
		
		if(jsonObjResponse.getString("status").equals("MFA_REQUIRED")){
			return mfa(jsonObjResponse);
		} else{
			return jsonObjResponse.getString("sessionToken");
		}
	}
	
	
	/* Retrieves SAML assertion containing roles from AWS */
	private static String awsSamlHandler(String oktaSessionToken) throws ClientProtocolException, IOException{
		HttpGet httpget = null;
		CloseableHttpResponse responseSAML = null;
		CloseableHttpClient httpClient = HttpClients.createDefault();
		String resultSAML = "";
		String outputSAML = "";
		
		// Choose AWS Account
		String[] awsAccounts = Arrays.copyOf(oktaAWSAppURLs.keySet().toArray(), oktaAWSAppURLs.keySet().toArray().length, String[].class);
		Arrays.sort(awsAccounts);
		
		System.out.println("\nSelect an AWS Account to log in to\nNote that you may not have access to all listed");
		for (int i = 0; i < awsAccounts.length; i++) {
			System.out.println("[ " + (i+1) + " ]: " + awsAccounts[i]);
		}
		
		//Prompt user for accounts selection
		int selection = numSelection(awsAccounts.length);
		
		// Part 2: Get the Identity Provider and Role ARNs.
		// Request for AWS SAML response containing roles 
		httpget = new HttpGet(oktaAWSAppURLs.get(awsAccounts[selection]) + "?onetimetoken=" + oktaSessionToken);
		responseSAML = httpClient.execute(httpget);
		samlFailHandler(responseSAML.getStatusLine().getStatusCode(), responseSAML);
		
		//Parse SAML response
		BufferedReader brSAML = new BufferedReader(new InputStreamReader(
		(responseSAML.getEntity().getContent())));
		//responseSAML.close();
		
		while ((outputSAML = brSAML.readLine()) != null) {
			if (outputSAML.contains("SAMLResponse")) {
				resultSAML = outputSAML.substring(outputSAML.indexOf("value=") + 7, outputSAML.indexOf("/>") - 1);
			}
		}
		httpClient.close();
		return resultSAML;
	}
	
	
	/* Assumes SAML role selected by the user based on authorized Okta AWS roles given in SAML assertion result SAML
	 * Precondition: String resultSAML 
	 * Postcondition: returns type AssumeRoleWithSAMLResult
	 */
	private static AssumeRoleWithSAMLResult assumeAWSRole(String resultSAML){
		// Decode SAML response
		resultSAML = resultSAML.replace("&#x2b;", "+").replace("&#x3d;", "=");
		String resultSAMLDecoded = new String(Base64.decodeBase64(resultSAML));
		
		ArrayList<String> principalArns = new ArrayList<String>();
		ArrayList<String> roleArns = new ArrayList<String>();
		
		//When the app is not assigned to you no assertion is returned
		if(!resultSAMLDecoded.contains("arn:aws")){
			System.out.println(resultSAMLDecoded);
			System.out.println("\nYou do not have access to this AWS account through Okta. \nPlease contact your administrator if you require access.");
			return null;
		}
		
		System.out.println("\nPlease choose the role you would like to assume: ");
		
		//Gather list of applicable AWS roles
		int i = 0;
		while (resultSAMLDecoded.indexOf("arn:aws") != -1) {
			String resultSAMLRole = resultSAMLDecoded.substring(resultSAMLDecoded.indexOf("arn:aws"), resultSAMLDecoded.indexOf("</saml2:AttributeValue"));
			String[] parts = resultSAMLRole.split(",");
			principalArns.add(parts[0]);
			roleArns.add(parts[1]);
			System.out.println("[ " + (i+1) + " ]: " + roleArns.get(i));
			resultSAMLDecoded = (resultSAMLDecoded.substring(resultSAMLDecoded.indexOf("</saml2:AttributeValue") +1));
			i++;
		}
		
		//Prompt user for role selection
		int selection = numSelection(roleArns.size());
		
		String principalArn = principalArns.get(selection);
		String roleArn = roleArns.get(selection);
		
		//use user credentials to assume AWS role
		AWSSecurityTokenServiceClient stsClient = new AWSSecurityTokenServiceClient();
		AssumeRoleWithSAMLRequest assumeRequest = new AssumeRoleWithSAMLRequest() 
		.withPrincipalArn(principalArn) 
		.withRoleArn(roleArn) 
		.withSAMLAssertion(resultSAML);
		
		return stsClient.assumeRoleWithSAML(assumeRequest);
	}
	
	
	/* Retrieves AWS credentials from AWS's assumedRoleResult and write the to aws credential file
	 * Precondition : AssumeRoleWithSAMLResult assumeResult
	 */
	private static void setAWSCredentials(AssumeRoleWithSAMLResult assumeResult) throws FileNotFoundException, UnsupportedEncodingException{
		BasicSessionCredentials temporaryCredentials =
			new BasicSessionCredentials(
					assumeResult.getCredentials().getAccessKeyId(),
				assumeResult.getCredentials().getSecretAccessKey(),
				assumeResult.getCredentials().getSessionToken());
		
		String awsAccessKey = temporaryCredentials.getAWSAccessKeyId();
		String awsSecretKey = temporaryCredentials.getAWSSecretKey();
		String awsSessionToken = temporaryCredentials.getSessionToken();
		
		File file = new File (System.getProperty("user.home")+"/.aws/credentials");
		file.getParentFile().mkdirs();
		
		PrintWriter writer = new PrintWriter(file, "UTF-8");
		writer.println("[default]");
		writer.println("aws_access_key_id="+awsAccessKey);
		writer.println("aws_secret_access_key="+awsSecretKey);
		writer.println("aws_session_token="+awsSessionToken);
		writer.close();
	}
	
	
	public static void main(String[] args) throws Exception {
		awsSetup();
		extractCredentials();
		
		// Part 1: Initiate the authentication and capture the SAML assertion.
		CloseableHttpClient httpClient = null;
		String resultSAML = "";
//		String oktaSessionToken = "";
//		try {
//			oktaSessionToken = oktaAuthentication();
//		} catch (MalformedURLException e) {
//			e.printStackTrace();
//		} catch(UnknownHostException e){
//			System.out.println("\nUnable to establish connection with AWS. \nPlease verify that your AWS app url is corrct and try again" );
//			System.exit(0);
//		}
//		catch(ClientProtocolException e){
//			System.out.println("\nNo Org found, enter you org in you oktaCredentials file" );
//			System.exit(0);
//		}
//		catch (IOException e) {
//			e.printStackTrace();
//		}
		
		boolean validAccount = false;
		AssumeRoleWithSAMLResult assumeResult = null;
		while (!validAccount) {
			try {
				String oktaSessionToken = oktaAuthentication();
				//Part 2 get saml assertion
				resultSAML = awsSamlHandler(oktaSessionToken);
			} catch (MalformedURLException e) {
				e.printStackTrace();
			} catch(UnknownHostException e){
				System.out.println("\nUnable to establish connection with AWS. \nPlease verify that your AWS app url is corrct and try again" );
				System.exit(0);
			}
			catch(ClientProtocolException e){
				System.out.println("\nNo Org found, enter you org in you oktaCredentials file" );
				System.exit(0);
			}
			catch (IOException e) {
				e.printStackTrace();
			}
			
			// Part 3: Assume an AWS role using the SAML Assertion from Okta
			assumeResult = assumeAWSRole(resultSAML);
			if (assumeResult != null) validAccount = true;
		}
		// Part 4: Write the credentials to ~/.aws/credentials
		setAWSCredentials(assumeResult);
		
		// Print Final message
		resultMessage();
	}
}
