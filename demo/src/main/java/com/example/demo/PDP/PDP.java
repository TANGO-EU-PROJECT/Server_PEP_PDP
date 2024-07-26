package com.example.demo.PDP;

import static org.hamcrest.CoreMatchers.nullValue;

import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Array;
import java.security.PublicKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Base64;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import com.example.demo.PAP.PAPErat;
import com.example.demo.PAP.PAPInterface;
import com.example.demo.PAP.PAPTest;
import com.example.demo.PAP.PolicyStore;
import com.example.demo.PEP.PEP;
import com.example.demo.PIP.PIPErat;
import com.example.demo.PIP.PIPInterface;
import com.example.demo.PIP.PIPTest;
import com.example.demo.PIP.TrustScoreStore;
import com.example.demo.idAgent.IdentityAgent;
import com.example.demo.models.AuthRequest;
import com.example.demo.models.AuthRequestTango;
import com.example.demo.models.CapabilityToken;
import com.example.demo.models.Constraint;
import com.example.demo.models.CredentialSubject;
import com.example.demo.models.Degree;
import com.example.demo.models.Field;
import com.example.demo.models.Issuer;
import com.example.demo.models.Policy;
import com.example.demo.models.Proof;
import com.example.demo.models.VCredential;
import com.example.demo.models.VPresentation;
import com.fasterxml.jackson.annotation.JsonSubTypes.Type;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.fge.jackson.JsonLoader;
import com.github.fge.jsonschema.core.exceptions.ProcessingException;
import com.github.fge.jsonschema.main.JsonSchema;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;

import javax.json.*;

/*
import com.github.jsonldjava.core.JsonLdError;
import com.github.jsonldjava.core.JsonLdProcessor;
import com.github.jsonldjava.utils.JsonUtils;*/

import org.apache.commons.lang.StringEscapeUtils;
import org.mozilla.javascript.tools.shell.JSConsole;
import org.springframework.beans.factory.annotation.Value;

public class PDP implements PDPInterface {

	@Value("${app.VERIFIER_IP:localhost}")
	static String ipVerifier;

	@Value("${app.VERIFIER_PORT:8082}")
	static String portVerifier;
	
	@Value("${app.VERIFIER_ENDPOINT:\"/.well-known/jwks\"}")
	static String endpointVerifier;
	
	@Value("${app.PDP_KS: \"/app/crypto/serverErat.ks\"}")
	static String keystore;

	@Value("${app.PDP_PW:hola123}")
	static String keystorepwd;

	@Value("${app.PDP_ALIAS:MiAliasPriv}")
	static String alias;
	
	@Value("${app.CT_EXPIRATION:3600000}")
	static String expiration;
	long expirationInPolicy;

	PIPInterface pip;
	PAPInterface pap;

	String jwtString;

	public String getJwtString() {
		return jwtString;
	}

	public void setJwtString(String jwtString) {
		this.jwtString = jwtString;
	}
	
	JWTVerifier verifier = new JWTVerifier();
	IdentityAgent idAgent = new IdentityAgent();
	boolean createdWallet;
	Gson gson = new Gson();
	JsonNode schemaRequest;
	JsonNode schemaPolitica;
	JsonNode request;
	PublicKey pbk;

	/* CONSTRUCTOR */

	public PDP(PIPInterface pip, PAPInterface pap) {
		ipVerifier = System.getenv("VERIFIER_IP");
		if( System.getenv("VERIFIER_IP")==null) {
			ipVerifier="localhost";
		}
		
		portVerifier = System.getenv("VERIFIER_PORT");
		if( System.getenv("VERIFIER_PORT")==null) {
			portVerifier="8082";
		}

		endpointVerifier= System.getenv("VERIFIER_ENDPOINT");
		if( System.getenv("VERIFIER_ENDPOINT")==null) {
			endpointVerifier="/.well-known/jwks";
		}

		keystore = System.getenv("PDP_KS");
		if( System.getenv("PDP_KS")==null) {
			keystore="crypto/serverErat.ks";
		}
		
		keystorepwd = System.getenv("PDP_PW");
		if(System.getenv("PDP_PW")==null) {
			keystorepwd="hola123";
		}
		
		alias = System.getenv("PDP_ALIAS");
		if(System.getenv("PDP_ALIAS")==null) {
			alias="MiAliasPriv";
		}
		expiration = System.getenv("CT_EXPIRATION");
		if(System.getenv("CT_EXPIRATION")==null) {
			expiration="360000";
		}

		gson = new Gson();
		this.pip = pip;
		this.pap = pap;
		createdWallet = false;
	}

	/* METHODS */

	public CapabilityToken verifyIdErat(String authRequestJson) {

		CapabilityToken ct = null;
		AuthRequest ar = null;
		String goodJson = removeQuotesAndUnescape(authRequestJson);
		boolean allMatches = true;

		ar = gson.fromJson(goodJson, AuthRequest.class);

		// TRUST SCORE CHECKING

		// Get trust score associated to the requester
		double trustscore = pip.getTrustScore(ar.getDidRequester());

		// POLICY CHECKING

		// Get policies needed to do the requested action in that resource
		ArrayList<Policy> politicas = pap.getPolicies(ar.getDidSP(), ar.getSar().getResource(),
				ar.getSar().getAction());

		// Check if the requester's trust score is bigger than the one in the policy
		for (Policy p : politicas) {	
			expirationInPolicy=p.getAuthTime();
		System.out.println("expiration in the policy: "+expirationInPolicy);
			if (trustscore < p.getMinTrustScore()) {
				allMatches = false;
			}
		}

		// VERIFY THE REQUESTER'S VERIFIABLE PRESENTATION

		// Get the requester's VP
		String VP = ar.getVerifiablePresentation();
	
		// Call API for verifying the VPresentation
		if (!createdWallet) {
			idAgent.createWallet(ar.getDidRequester());
			createdWallet = true;
		}
		boolean response = idAgent.verifyPresentation(VP, ar.getDidRequester());
		if (!response) {
			allMatches = false;
		}

		// Prove matching policies with requester's VP

		// Deserialize JSON
		javax.json.JsonObject jsonObject;
		try (JsonReader reader = Json.createReader(new StringReader(VP))) {
			jsonObject = reader.readObject();
		}

		VPresentation presentationData = new VPresentation();
		List<JsonValue> contextList = jsonObject.getJsonArray("@context");
		ArrayList<String> stringList = new ArrayList<>();
		for (JsonValue jsonValue : contextList) {
			stringList.add(jsonValue.toString());
		}
		presentationData.setContext(stringList);

		presentationData.setHolder(jsonObject.getString("holder"));

		javax.json.JsonObject proofJsonObject = jsonObject.getJsonObject("proof");
		String jsonString = proofJsonObject.toString();
		Proof proof = gson.fromJson(jsonString, Proof.class);
		presentationData.setProof(proof);

		presentationData.setType(jsonObject.getString("type"));

		List<JsonValue> vcredential = jsonObject.getJsonArray("verifiableCredential");
		List<VCredential> stringCred = new ArrayList<>();

		List<javax.json.JsonObject> listajsn = new ArrayList<>();
		for (JsonValue jsonValue : vcredential) {

			javax.json.JsonObject jsonObject1;
			// Verifica si el JsonValue es un objeto JSON
			if (jsonValue.getValueType() == JsonValue.ValueType.OBJECT) {
				// Convierte el JsonValue a JsonObject
				jsonObject1 = jsonValue.asJsonObject();

				listajsn.add(jsonObject1);
			}

		}

		// POLICY MATCHING

		// Verify if every path's element match the object CredentialSubject's fields

		// True default, if there is a mismatch, finish the loop
		for (Policy p : politicas) {
			// Find out if the policy is correctly formed
			String politicaJSON = gson.toJson(p);

			// Matching

			Constraint constraints = p.getConstraints();
			List<Field> fields = constraints.getFields();

			System.out.println("Starting matching policies process...");
			for (Field f : fields) {

				List<String> path = f.getPath();
				// Look for hierarchy ( $.credentialSubject. )

				javax.json.JsonObject objGlobal = null;

				if (f.getFilter() == null) {
					for (String i : path) {
						String[] partes = i.split("\\.");

						// Hierarchy list
						for (String parte : partes) {
							String parte2 = new String(parte);

							// Proof that the policy's path is in the VP

							for (javax.json.JsonObject obj1 : listajsn) {
								javax.json.JsonObject credentialSubject = obj1.getJsonObject("credentialSubject");
								javax.json.JsonObject currentObj = obj1;
								// If the field is present, we take its value
								if (!parte.equals("$")) {

									if (credentialSubject.containsKey(parte)) {
										String parte1 = new String(parte);
										JsonValue e = credentialSubject.get(parte1);

										if (e.getValueType() == JsonValue.ValueType.OBJECT) {
											if (e.asJsonObject() != null) {
												objGlobal = e.asJsonObject();
											}
										}
									} else if (objGlobal != null && credentialSubject.containsKey(parte2)) {

										JsonValue valor = credentialSubject.get(parte2);
									} else {
										allMatches = false;
									}
								}

							}
						}
					}

				}
				if (f.getFilter() != null) {
					for (String i : path) {
						if (f.getFilter().getType().equals("string")) {
							String patron = f.getFilter().getPattern();
							String patron1 = "\"" + patron + "\"";
							for (String j : path) {

								String[] partes1 = i.split("\\.");

								// Hierarchy list
								for (String parte1 : partes1) {
									String parte2 = new String(parte1);
									for (javax.json.JsonObject obj1 : listajsn) {
										javax.json.JsonObject credentialSubject = obj1
												.getJsonObject("credentialSubject");
										javax.json.JsonObject currentObj = obj1;
										// If the field is present, we take its value
										if (!parte1.equals("$")) {
											if (credentialSubject.containsKey(parte1)) {
												String parte11 = new String(parte1);
												JsonValue e = credentialSubject.get(parte11);
												if (e.getValueType() == JsonValue.ValueType.OBJECT) {

													if (e.asJsonObject() != null) {
														objGlobal = e.asJsonObject();
													}
												}

											} else if (objGlobal != null && objGlobal.containsKey(parte2)) {

												JsonValue valor = objGlobal.get(parte2);
												String valorS = valor.toString();

												if (patron1.equals(valorS)) {

												} else {
													allMatches = false;
												}
											} else {
												allMatches = false;
											}
										}
									}
								}
							}
						} else if (f.getFilter().getType().equals("number")) {
							Number minimo = f.getFilter().getMin();
							Number maximo = f.getFilter().getMax();
							for (String j : path) {

								String[] partes1 = i.split("\\.");

								// Hierarchy list
								for (String parte1 : partes1) {
									String parte2 = new String(parte1);
									for (javax.json.JsonObject obj1 : listajsn) {
										javax.json.JsonObject credentialSubject = obj1
												.getJsonObject("credentialSubject");
										javax.json.JsonObject currentObj = obj1;
										// If the field is present, we take its value
										if (!parte1.equals("$")) {

											if (credentialSubject.containsKey(parte1)) {

												String parte11 = new String(parte1);
												JsonValue e = obj1.get(parte11);

												if (objGlobal != null && e.asJsonObject() != null) {
													objGlobal = e.asJsonObject();

												}
											} else if (objGlobal.containsKey(parte2)) {
												JsonValue valor = objGlobal.get(parte2);
												Number valorS = null;
												if (valor instanceof Number) {
													valorS = (Number) valor;
												}

												if ((valorS.intValue() < minimo.intValue())
														|| (valorS.intValue() > maximo.intValue())) {
													allMatches = false;
												}
											} else {
												allMatches = false;
											}
										}
									}
								}
							}
						}
					}
				}

			}
		}

		// If everything is OK, the Capability Token is issued

		if (allMatches == true) {
			System.out.println(
					"The matching process has been successfully finished. Issuing Capability Token for requester...\n");
			if(expirationInPolicy==0) { 
				//default value
			System.out.println("the capabilitytoken will be available for "+ expiration);
			ct = new CapabilityToken(keystore, keystorepwd.toCharArray(), alias, ar.getDidRequester(), ar.getDidSP(),
					ar.getSar(), expiration);
			pbk = ct.getPublicKey();
			}else {
				//value "authtime" in the policy
				String expstring=Long.toString(expirationInPolicy);
				System.out.println("the capabilitytoken will be available for "+ expstring);
				ct = new CapabilityToken(keystore, keystorepwd.toCharArray(), alias, ar.getDidRequester(), ar.getDidSP(),
						ar.getSar(), expstring);
				pbk = ct.getPublicKey();
			}
		} else {
			System.out.println("The matching process failed...\n");
		}
		return ct;
	}

	// Method for formatting JSON
	private String removeQuotesAndUnescape(String uncleanJson) {
		String noQuotes = uncleanJson.replaceAll("^\"|\"$", "");

		return StringEscapeUtils.unescapeJava(noQuotes);
	}

	// Method for verifying the connector token and issuing the Capability Token
	public CapabilityToken verifyConnectorToken(String authRequestJson) {
		System.out.println("PDP receives the information and starts the verifying process...\n");
		CapabilityToken ct = null;
		AuthRequestTango ar = null;
		boolean isVP = false;
		String goodJson = removeQuotesAndUnescape(authRequestJson);
		ar = gson.fromJson(goodJson, AuthRequestTango.class);

		boolean allMatches = true;

		// Get policies needed to do the requested action in that resource
		ArrayList<Policy> politicas = pap.getPolicies(ar.getDidSP(), ar.getSar().getResource(),
				ar.getSar().getAction());

		// Get trust score associated with the requester
		double trustScore = pip.getTrustScore(ar.getDidRequester());
		
		for (Policy p : politicas) {
			if (trustScore > p.getMinTrustScore()) {
				System.out.println("Trust Score successfully checked.\n");
			}else {allMatches=false;}
		}

		// Get the requester's VP
		String token = ar.getToken();

		// Deserialize JSON
		javax.json.JsonObject jsonObject;
		try (JsonReader reader = Json.createReader(new StringReader(token))) {
			jsonObject = reader.readObject();
		}

		List<JsonValue> vcredential = null;
		javax.json.JsonObject singleVcredential = null;
		JsonObject verifiableCredentialJsonObject = null;

		jsonObject.getString("iss");
		jsonObject.getString("client_id");
		jsonObject.getString("sub");
		jsonObject.getString("aud");

		// If there's more than 1 verifiable credential is a verifiable presentation
		if (jsonObject.getJsonArray("verifiablePresentation") != null) {
			isVP = true;
			jsonObject.getJsonArray("verifiablePresentation");
			vcredential = jsonObject.getJsonArray("verifiablePresentation");
			// Take the verifiable presentation values
			List<javax.json.JsonObject> listajsn = new ArrayList<>();
			for (JsonValue jsonValue : vcredential) {

				javax.json.JsonObject jsonObject1;
				// Verifies if JsonValue is a JSON object
				if (jsonValue.getValueType() == JsonValue.ValueType.OBJECT) {
					// turns JsonValue to a JsonObject
					jsonObject1 = jsonValue.asJsonObject();

					listajsn.add(jsonObject1);
				}

			}
		} else if (jsonObject.getString("verifiableCredential") != null) {

			String vc = jsonObject.getString("verifiableCredential");

			// Parse string JSON
			JsonParser jsonp = new JsonParser();
			verifiableCredentialJsonObject = jsonp.parse(vc).getAsJsonObject();

		}

	
		// Verify that the token is not expired
		long expTimestamp = jsonObject.getJsonNumber("exp").longValue();
		Instant expInstant = Instant.ofEpochSecond(expTimestamp);
		LocalDateTime expDateTime = LocalDateTime.ofInstant(expInstant, ZoneId.systemDefault());
		LocalDateTime now = LocalDateTime.now();
		if (expDateTime.isBefore(now)) {
			 allMatches=false;
			 System.out.println("The access token is expired.\n");
		}else {
			System.out.println("The access token is not expired.\n");
		}

		// Verify that the signing is correct
		String kid = jsonObject.getString("kid");
		
		//Make a request to the Verifier to get the JWKS
		String url = "http://"+ipVerifier+"/"+endpointVerifier;
					
		    boolean verificationResult = verifier.verifyJwt(jwtString, url);
		    if(verificationResult) {
		    	System.out.println("Access token signature has been successfully verified.\n");
		    }else {System.out.println("There was an error verifying Access token signature.\n"); allMatches=false;}
		 
		// POLICY MATCHING

		// Take the verifiable presentation or credential values

		List<javax.json.JsonObject> listajsn = new ArrayList<>();

		if (isVP) {
			for (JsonValue jsonValue : vcredential) {

				javax.json.JsonObject jsonObject1;
				// Verifica si el JsonValue es un objeto JSON
				if (jsonValue.getValueType() == JsonValue.ValueType.OBJECT) {
					// Convierte el JsonValue a JsonObject
					jsonObject1 = jsonValue.asJsonObject();

					listajsn.add(jsonObject1);
				}

			}

		} else {

			String jsonString = verifiableCredentialJsonObject.toString();
			JsonReader jsonReader = Json.createReader(new StringReader(jsonString));
			javax.json.JsonObject convertedJsonObject = jsonReader.readObject();
			listajsn.add(convertedJsonObject);
		}

		// True default, if there is a mismatch, finish the loop
		for (Policy p : politicas) {
			// Find out if the policy is correctly formed
			
			expirationInPolicy=p.getAuthTime();
			//System.out.println("expiration in the policy: "+expirationInPolicy);
			String politicaJSON = gson.toJson(p);

			// Matching

			Constraint constraints = p.getConstraints();
			List<Field> fields = constraints.getFields();

			System.out.println("Starting matching policies process...\n");
			for (Field f : fields) {
				List<String> path = f.getPath();
				// Look for hierarchy ( $.credentialSubject. )

				javax.json.JsonObject objGlobal = null;

				if (f.getFilter() == null) {
					for (String i : path) {
						String[] partes = i.split("\\.");

						// Hierarchy list
						for (String parte : partes) {
							String parte2 = new String(parte);

							for (javax.json.JsonObject obj1 : listajsn) {
								javax.json.JsonObject credentialSubject = obj1.getJsonObject("credentialSubject");
								javax.json.JsonObject currentObj = obj1;
								// If the field is present, we take its value
								if (!parte.equals("$")) {

									if (credentialSubject.containsKey(parte)) {
										String parte1 = new String(parte);
										JsonValue e = credentialSubject.get(parte1);

										if (e.getValueType() == JsonValue.ValueType.OBJECT) {
											if (e.asJsonObject() != null) {
												objGlobal = e.asJsonObject();
											}
										}
									} else if (objGlobal != null && credentialSubject.containsKey(parte2)) {

										JsonValue valor = credentialSubject.get(parte2);
									} else {
										allMatches = false;
									}
								}

							}
						}
					}

				}
				if (f.getFilter() != null) {
					for (String i : path) {
						if (f.getFilter().getType().equals("string")) {
							String patron = f.getFilter().getPattern();
							String patron1 = "\"" + patron + "\"";
							for (String j : path) {

								String[] partes1 = i.split("\\.");

								// Hierarchy list
								for (String parte1 : partes1) {
									String parte2 = new String(parte1);
									for (javax.json.JsonObject obj1 : listajsn) {
										javax.json.JsonObject credentialSubject = obj1
												.getJsonObject("credentialSubject");
										javax.json.JsonObject currentObj = obj1;
										// If the field is present, we take its value
										if (!parte1.equals("$")) {
											if (credentialSubject.containsKey(parte1)) {
												String parte11 = new String(parte1);
												JsonValue e = credentialSubject.get(parte11);
												if (e.getValueType() == JsonValue.ValueType.OBJECT) {

													if (e.asJsonObject() != null) {
														objGlobal = e.asJsonObject();
													}
												}

											} else if (objGlobal != null && objGlobal.containsKey(parte2)) {

												JsonValue valor = objGlobal.get(parte2);
												String valorS = valor.toString();

												if (patron1.equals(valorS)) {

												} else {
													allMatches = false;
												}
											} else {
												allMatches = false;
											}
										}
									}
								}
							}
						} else if (f.getFilter().getType().equals("number")) {
							Number minimo = f.getFilter().getMin();
							Number maximo = f.getFilter().getMax();
							for (String j : path) {

								String[] partes1 = i.split("\\.");

								// Hierarchy list
								for (String parte1 : partes1) {
									String parte2 = new String(parte1);
									for (javax.json.JsonObject obj1 : listajsn) {
										javax.json.JsonObject credentialSubject = obj1
												.getJsonObject("credentialSubject");
										javax.json.JsonObject currentObj = obj1;
										// If the field is present, we take its value
										if (!parte1.equals("$")) {

											if (credentialSubject.containsKey(parte1)) {

												String parte11 = new String(parte1);
												JsonValue e = obj1.get(parte11);

												if (objGlobal != null && e.asJsonObject() != null) {
													objGlobal = e.asJsonObject();

												}
											} else if (objGlobal.containsKey(parte2)) {
												JsonValue valor = objGlobal.get(parte2);
												Number valorS = null;
												if (valor instanceof Number) {
													valorS = (Number) valor;
												}

												if ((valorS.intValue() < minimo.intValue())
														|| (valorS.intValue() > maximo.intValue())) {
													allMatches = false;
												}
											} else {
												allMatches = false;
											}
										}
									}
								}
							}
						}
					}
				}

			}
		}

		// If everything is OK, the Capability Token is issued

		if (allMatches == true) {
			System.out.println(
					"The matching process has been successfully finished. Issuing Capability Token for requester...\n");
			if(expirationInPolicy==0) { 
				//default value
			System.out.println("the capabilitytoken will be available for "+ expiration);
			ct = new CapabilityToken(keystore, keystorepwd.toCharArray(), alias, ar.getDidRequester(), ar.getDidSP(),
					ar.getSar(), expiration);
			pbk = ct.getPublicKey();
			}else {
				//value "authtime" in the policy
				String expstring=Long.toString(expirationInPolicy);
				System.out.println("the capabilitytoken will be available for "+ expstring);
				ct = new CapabilityToken(keystore, keystorepwd.toCharArray(), alias, ar.getDidRequester(), ar.getDidSP(),
						ar.getSar(), expstring);
				pbk = ct.getPublicKey();
			}
		} else {
			System.out.println("The matching process failed...\n");
		}
		return ct;
	}

	public PublicKey getPbk() {
		return pbk;
	}

	
	
	@Override
	public CapabilityToken verifyId(String id) {
		// TODO Auto-generated method stub
		return null;
	}

}
