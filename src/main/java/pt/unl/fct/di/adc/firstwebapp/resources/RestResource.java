package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.Query;
import com.google.cloud.datastore.QueryResults;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.cloud.datastore.Transaction;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import pt.unl.fct.di.adc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.util.CreateAccountData;

@Path("/")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8") // TODO : needed?
@Consumes(MediaType.APPLICATION_JSON)
public class RestResource {

	//ERROR CODES
	private static final String INVALID_CREDENTIALS = "9900";
	private static final String USER_ALREADY_EXISTS = "9901";
	private static final String USER_NOT_FOUND = "9902";
	private static final String INVALID_TOKEN = "9903";
	private static final String TOKEN_EXPIRED = "9904";
	private static final String UNAUTHORIZED = "9905";
	private static final String INVALID_INPUT = "9906";
	private static final String FORBIDDEN = "9907";

	//ERROR MESSAGES
	private static final Map<String, String> ERROR_MESSAGES = new HashMap<>();
	static {
		ERROR_MESSAGES.put(INVALID_CREDENTIALS, "The username-password pair is not valid");
		ERROR_MESSAGES.put(USER_ALREADY_EXISTS, "Error in creating an account because the username already exists");
		ERROR_MESSAGES.put(USER_NOT_FOUND, "The username referred in the operation doesn't exist in registered accounts");
		ERROR_MESSAGES.put(INVALID_TOKEN, "The operation is called with an invalid token (wrong format for example)");
		ERROR_MESSAGES.put(TOKEN_EXPIRED, "The operation is called with a token that is expired");
		ERROR_MESSAGES.put(UNAUTHORIZED, "The operation is not allowed for the user role");
		ERROR_MESSAGES.put(INVALID_INPUT, "The call is using input data not following the correct specification");
		ERROR_MESSAGES.put(FORBIDDEN, "The operation generated a forbidden error by other reason");
	}

	// KINDS
	private static final String USER = "User";
	private static final String TOKEN = "Token";

	// USER ENTITIES
	private static final String PWD = "user_pwd";
	private static final String ROLE = "user_role";
	private static final String PHONE = "user_phone";
	private static final String ADDRESS = "user_address";
	private static final String CREATED = "user_creation_time";

	// TOKEN ENTITIES (some are used in repeated fields to avoid repetition)
	private static final String TOKEN_ID = "tokenId";
	private static final String USERNAME = "username";
	private static final String TK_ROLE = "role";
	private static final String ISSUED_AT = "issuedAt";
	private static final String EXPIRES_AT = "expiresAt";

	// ROLES
	private static final String BOFFICER = "BOFFICER";
	private static final String ADMIN = "ADMIN";

	// STRINGS TO AVOID REPETITION
	private static final String INPUT = "input";
	private static final String PASSWORD = "password";
	private static final String USERS = "users";
	private static final String MESSAGE = "message";

	private static final Logger LOG = Logger.getLogger(RestResource.class.getName());
	private static final Datastore DS = DatastoreOptions.getDefaultInstance().getService();
	private static final KeyFactory USER_KEY_FACTORY  = DS.newKeyFactory().setKind(USER);
	private static final KeyFactory TOKEN_KEY_FACTORY = DS.newKeyFactory().setKind(TOKEN);
	private final Gson gson = new Gson();

	@POST
	@Path("/createaccount")
	public Response createAccount(String body) {
		try {
			JsonObject req = gson.fromJson(body, JsonObject.class);
			JsonObject input = req.getAsJsonObject(INPUT);
			if (input == null) return error(INVALID_INPUT);
			CreateAccountData data = gson.fromJson(input, CreateAccountData.class);
			if (data == null || !data.isValid()) return error(INVALID_INPUT);
			Transaction t = DS.newTransaction();
			try {
				Key userKey = USER_KEY_FACTORY.newKey(data.username);
				Entity existing = t.get(userKey);
				if (existing != null) {
					t.rollback();
					return error(USER_ALREADY_EXISTS);
				}
				Entity user = Entity.newBuilder(userKey)
						.set(PWD, DigestUtils.sha512Hex(data.password)).set(ROLE, data.role)
						.set(PHONE, data.phone != null ? data.phone : "")
						.set(ADDRESS, data.address != null ? data.address : "")
						.set(CREATED, Timestamp.now()).build();
				t.put(user);
				t.commit();
				LOG.info("Account created: " + data.username);
				JsonObject dataOut = new JsonObject();
				dataOut.addProperty(USERNAME, data.username);
				dataOut.addProperty(TK_ROLE, data.role);
				return success(dataOut);
			} catch (Exception e) {
				if (t.isActive()) t.rollback();
				throw e;
			}
		} catch (Exception e) {
			LOG.severe("createAccount error: " + e.getMessage());
			return error(INVALID_INPUT);
		}
	}

	@POST
	@Path("/login")
	public Response login(String body) {
		try {
			JsonObject req = gson.fromJson(body, JsonObject.class);
			JsonObject input = req.getAsJsonObject(INPUT);
			if (input == null) return error(INVALID_INPUT);
			String username = getStr(input, USERNAME);
			String password = getStr(input, PASSWORD);
			if (username == null || password == null) return error(INVALID_INPUT);
			Key userKey = USER_KEY_FACTORY.newKey(username);
			Entity user = DS.get(userKey);
			if (user == null) return error(USER_NOT_FOUND);
			String stored = user.getString(PWD);
			if (!stored.equals(DigestUtils.sha512Hex(password)))
				return error(INVALID_CREDENTIALS);
			String role = user.getString(ROLE);
			AuthToken token = new AuthToken(username, role);
			Key tokenKey = TOKEN_KEY_FACTORY.newKey(token.tokenId);
			Entity tokenEntity = Entity.newBuilder(tokenKey)
					.set(TOKEN_ID, token.tokenId)
					.set(USERNAME, token.username)
					.set(TK_ROLE, token.role)
					.set(ISSUED_AT, token.issuedAt)
					.set(EXPIRES_AT, token.expiresAt)
					.build();
			DS.put(tokenEntity);
			LOG.info("Login successful: " + username);
			JsonObject dataOut = new JsonObject();
			dataOut.add("token", gson.toJsonTree(token));
			return success(dataOut);
		} catch (Exception e) {
			LOG.severe("login error: " + e.getMessage());
			return error(INVALID_INPUT);
		}
	}

	@POST
	@Path("/showusers")
	public Response showUsers(String body) {
		try {
			AuthToken token = extractAndValidateToken(body);
			if (token == null) return error(INVALID_TOKEN);
			if (token.hasExpired()) return error(TOKEN_EXPIRED);
			if (!hasRole(token, ADMIN, BOFFICER)) return error(UNAUTHORIZED);
			Query<Entity> q = Query.newEntityQueryBuilder().setKind(USER).build();
			QueryResults<Entity> results = DS.run(q);
			List<JsonObject> users = new ArrayList<>();
			results.forEachRemaining(u -> {
				JsonObject obj = new JsonObject();
				obj.addProperty(USERNAME, u.getKey().getName());
				obj.addProperty(TK_ROLE, u.getString(ROLE));
				users.add(obj);
			});
			JsonObject dataOut = new JsonObject();
			dataOut.add(USERS, gson.toJsonTree(users));
			return success(dataOut);
		} catch (Exception e) {
			LOG.severe("showUsers error: " + e.getMessage());
			return error(INVALID_TOKEN);
		}
	}

	@POST
	@Path("/deleteaccount")
	public Response deleteAccount(String body) {
		try {
			AuthToken token = extractAndValidateToken(body);
			if (token == null) return error(INVALID_TOKEN);
			if (token.hasExpired()) return error(TOKEN_EXPIRED);
			if (!hasRole(token, ADMIN)) return error(UNAUTHORIZED);
			JsonObject req = gson.fromJson(body, JsonObject.class);
			JsonObject input = req.getAsJsonObject(INPUT);
			String username = getStr(input, USERNAME);
			if (username == null) return error(INVALID_INPUT);
			Key userKey = USER_KEY_FACTORY.newKey(username);
			Entity user = DS.get(userKey);
			if (user == null) return error(USER_NOT_FOUND);
			Transaction txn = DS.newTransaction();
			try {
				txn.delete(userKey);
				Query<Entity> tq = Query.newEntityQueryBuilder()
						.setKind(TOKEN)
						.setFilter(PropertyFilter.eq(USERNAME, username))
						.build();
				DS.run(tq).forEachRemaining(t -> txn.delete(t.getKey()));
				txn.commit();
				LOG.info("Account deleted: " + username);
			} catch (Exception e) {
				if (txn.isActive()) txn.rollback();
				throw e;
			}
			JsonObject dataOut = new JsonObject();
			dataOut.addProperty(MESSAGE, "Account deleted successfully");
			return success(dataOut);
		} catch (Exception e) {
			LOG.severe("deleteAccount error: " + e.getMessage());
			return error(FORBIDDEN);
		}
	}

	@POST
	@Path("/modaccount")
	public Response modifyAccount(String body) {
		try {
			AuthToken token = extractAndValidateToken(body);
			if (token == null) return error(INVALID_TOKEN);
			if (token.hasExpired()) return error(TOKEN_EXPIRED);
			JsonObject req = gson.fromJson(body, JsonObject.class);
			JsonObject input = req.getAsJsonObject(INPUT);
			String target = getStr(input, USERNAME);
			JsonObject attributes = input != null ? input.getAsJsonObject("attributes") : null;
			if (target == null || attributes == null) return error(INVALID_INPUT);
			Key userKey = USER_KEY_FACTORY.newKey(target);
			Entity user = DS.get(userKey);
			if (user == null) return error(USER_NOT_FOUND);
			String callerRole = token.role;
			String targetRole = user.getString(ROLE);
			String callerName = token.username;
			boolean allowed = false;
			if (callerRole.equals(ADMIN)) allowed = true;
			else if (callerRole.equals(BOFFICER)) allowed = callerName.equals(target) || targetRole.equals("USER");
			else if (callerRole.equals("USER")) allowed = callerName.equals(target);
			if (!allowed) return error(FORBIDDEN);
			Entity.Builder builder = Entity.newBuilder(user);
			if (attributes.has("phone"))
				builder.set(PHONE, attributes.get("phone").getAsString());
			if (attributes.has("address"))
				builder.set(ADDRESS, attributes.get("address").getAsString());
			DS.update(builder.build());
			LOG.info("Account modified: " + target);
			JsonObject dataOut = new JsonObject();
			dataOut.addProperty(MESSAGE, "Updated successfully");
			return success(dataOut);
		} catch (Exception e) {
			LOG.severe("modifyAccount error: " + e.getMessage());
			return error(FORBIDDEN);
		}
	}

	@POST
	@Path("/showauthsessions")
	public Response showAuthSessions(String body) {
		try {
			AuthToken token = extractAndValidateToken(body);
			if (token == null) return error(INVALID_TOKEN);
			if (token.hasExpired()) return error(TOKEN_EXPIRED);
			if (!hasRole(token, ADMIN)) return error(UNAUTHORIZED);
			Query<Entity> q = Query.newEntityQueryBuilder().setKind(TOKEN).build();
			QueryResults<Entity> results = DS.run(q);
			List<JsonObject> sessions = new ArrayList<>();
			results.forEachRemaining(t -> {
				JsonObject s = new JsonObject();
				s.addProperty(TOKEN_ID, t.getString(TOKEN_ID));
				s.addProperty(USERNAME, t.getString(USERNAME));
				s.addProperty(TK_ROLE, t.getString(TK_ROLE));
				s.addProperty(EXPIRES_AT, t.getLong(EXPIRES_AT));
				sessions.add(s);
			});
			JsonObject dataOut = new JsonObject();
			dataOut.add("sessions", gson.toJsonTree(sessions));
			return success(dataOut);
		} catch (Exception e) {
			LOG.severe("showAuthSessions error: " + e.getMessage());
			return error(FORBIDDEN);
		}
	}

	@POST
	@Path("/showuserrole")
	public Response showUserRole(String body) {
		try {
			AuthToken token = extractAndValidateToken(body);
			if (token == null)    return error(INVALID_TOKEN);
			if (token.hasExpired()) return error(TOKEN_EXPIRED);
			if (!hasRole(token, ADMIN, BOFFICER)) return error(UNAUTHORIZED);
			JsonObject req = gson.fromJson(body, JsonObject.class);
			JsonObject input = req.getAsJsonObject(INPUT);
			String username = getStr(input, USERNAME);
			if (username == null) return error(INVALID_INPUT);
			Key userKey = USER_KEY_FACTORY.newKey(username);
			Entity user = DS.get(userKey);
			if (user == null) return error(USER_NOT_FOUND);
			JsonObject dataOut = new JsonObject();
			dataOut.addProperty(USERNAME, username);
			dataOut.addProperty(TK_ROLE, user.getString(ROLE));
			return success(dataOut);
		} catch (Exception e) {
			LOG.severe("showUserRole error: " + e.getMessage());
			return error(FORBIDDEN);
		}
	}

	@POST
	@Path("/changeuserrole")
	public Response changeUserRole(String body) {
		try {
			AuthToken token = extractAndValidateToken(body);
			if (token == null) return error(INVALID_TOKEN);
			if (token.hasExpired()) return error(TOKEN_EXPIRED);
			if (!hasRole(token, ADMIN)) return error(UNAUTHORIZED);
			JsonObject req = gson.fromJson(body, JsonObject.class);
			JsonObject input = req.getAsJsonObject(INPUT);
			String username = getStr(input, USERNAME);
			String newRole = getStr(input, "newRole");
			if (username == null || newRole == null) return error(INVALID_INPUT);
			if (!newRole.equals("USER") && !newRole.equals(BOFFICER) && !newRole.equals(ADMIN))
				return error(INVALID_INPUT);
			Key userKey = USER_KEY_FACTORY.newKey(username);
			Entity user = DS.get(userKey);
			if (user == null) return error(USER_NOT_FOUND);
			Entity updated = Entity.newBuilder(user).set(ROLE, newRole).build();
			DS.update(updated);
			LOG.info("Role of " + username + " changed to " + newRole);
			JsonObject dataOut = new JsonObject();
			dataOut.addProperty(MESSAGE, "Role updated successfully");
			return success(dataOut);
		} catch (Exception e) {
			LOG.severe("changeUserRole error: " + e.getMessage());
			return error(FORBIDDEN);
		}
	}

	@POST
	@Path("/changeuserpwd")
	public Response changeUserPassword(String body) {
		try {
			AuthToken token = extractAndValidateToken(body);
			if (token == null) return error(INVALID_TOKEN);
			if (token.hasExpired()) return error(TOKEN_EXPIRED);
			JsonObject req = gson.fromJson(body, JsonObject.class);
			JsonObject input = req.getAsJsonObject(INPUT);
			String username = getStr(input, USERNAME);
			String oldPassword = getStr(input, "oldPassword");
			String newPassword = getStr(input, "newPassword");
			if (username == null || oldPassword == null || newPassword == null)
				return error(INVALID_INPUT);
			if (!token.username.equals(username)) return error(FORBIDDEN);
			Key userKey = USER_KEY_FACTORY.newKey(username);
			Entity user = DS.get(userKey);
			if (user == null) return error(USER_NOT_FOUND);
			if (!user.getString(PWD).equals(DigestUtils.sha512Hex(oldPassword)))
				return error(INVALID_CREDENTIALS);
			Entity updated = Entity.newBuilder(user)
					.set(PWD, DigestUtils.sha512Hex(newPassword)).build();
			DS.update(updated);
			LOG.info("Password changed for: " + username);
			JsonObject dataOut = new JsonObject();
			dataOut.addProperty(MESSAGE, "Password changed successfully");
			return success(dataOut);
		} catch (Exception e) {
			LOG.severe("changeUserPassword error: " + e.getMessage());
			return error(FORBIDDEN);
		}
	}

	@POST
	@Path("/logout")
	public Response logout(String body) {
		try {
			AuthToken token = extractAndValidateToken(body);
			if (token == null) return error(INVALID_TOKEN);
			if (token.hasExpired()) return error(TOKEN_EXPIRED);
			JsonObject req = gson.fromJson(body, JsonObject.class);
			JsonObject input = req.getAsJsonObject(INPUT);
			String username = getStr(input, USERNAME);
			if (username == null) return error(INVALID_INPUT);
			if (!token.role.equals(ADMIN) && !token.username.equals(username))
				return error(FORBIDDEN);
			if (token.role.equals(ADMIN) && !token.username.equals(username)) {
				Query<Entity> tq = Query.newEntityQueryBuilder().setKind(TOKEN)
						.setFilter(PropertyFilter.eq(USERNAME, username)).build();
				DS.run(tq).forEachRemaining(t -> DS.delete(t.getKey()));
			} else {
				Key tokenKey = TOKEN_KEY_FACTORY.newKey(token.tokenId);
				DS.delete(tokenKey);
			}
			LOG.info("Logout successful for: " + username);
			JsonObject dataOut = new JsonObject();
			dataOut.addProperty(MESSAGE, "Logout successful");
			return success(dataOut);
		} catch (Exception e) {
			LOG.severe("logout error: " + e.getMessage());
			return error(FORBIDDEN);
		}
	}

	/**
	 * Creates success messages with the given data, varying on the type of operation.
	 * @param data given by the successful operation
	 * @return 200, operation succeeds
	 */
	private Response success(JsonObject data) {
		JsonObject out = new JsonObject();
		out.addProperty("status", "success");
		out.add("data", data);
		return Response.ok(out.toString()).build();
	}

	/**
	 * Creates error message according to the given code.
	 * @param code error message name
	 * @return 200, but operation does not succeed
	 */
	private Response error(String code) {
		JsonObject out = new JsonObject();
		out.addProperty("status", code);
		out.addProperty("data", ERROR_MESSAGES.getOrDefault(code, code));
		return Response.ok(out.toString()).build();
	}

	private AuthToken extractAndValidateToken(String body) {
		try {
			JsonObject req = gson.fromJson(body, JsonObject.class);
			JsonObject tokenObj = req.getAsJsonObject("token");
			if (tokenObj == null) return null;
			String tokenId = getStr(tokenObj, TOKEN_ID);
			if (tokenId == null || tokenId.isBlank()) return null;
			Key tokenKey = TOKEN_KEY_FACTORY.newKey(tokenId);
			Entity tokenEntity = DS.get(tokenKey);
			if (tokenEntity == null) return null;
			AuthToken at = new AuthToken();
			at.tokenId = tokenEntity.getString(TOKEN_ID);
			at.username = tokenEntity.getString(USERNAME);
			at.role = tokenEntity.getString(TK_ROLE);
			at.issuedAt = tokenEntity.getLong(ISSUED_AT);
			at.expiresAt = tokenEntity.getLong(EXPIRES_AT);
			return at;
		} catch (Exception e) {
			return null;
		}
	}

	private boolean hasRole(AuthToken token, String... allowedRoles) {
		for (String r : allowedRoles) {
			if (r.equals(token.role)) return true;
		}
		return false;
	}

	private String getStr(JsonObject obj, String key) {
		if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) return null;
		return obj.get(key).getAsString();
	}

}