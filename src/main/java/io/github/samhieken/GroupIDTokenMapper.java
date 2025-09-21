package io.github.samhieken;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

public class GroupIDTokenMapper extends AbstractOIDCProtocolMapper
		implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

	public static final String PROVIDER_ID = "group-id-token-mapper";
	private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

	static {
		OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
		OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, GroupIDTokenMapper.class);
	}

	public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo) {
		final ProtocolMapperModel mapper = new ProtocolMapperModel();
		mapper.setName(name);
		mapper.setProtocolMapper(PROVIDER_ID);
		mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
		
		final Map<String, String> config = new HashMap<>();
		config.put(ProtocolMapperUtils.MULTIVALUED, Boolean.TRUE.toString()); // Set the MULTIVALUED config
		
		if (accessToken) 
			config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
		
		if (idToken) 
			config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
		
		if (userInfo) 
			config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true");
		
		mapper.setConfig(config);
		return mapper;
	}

	@Override
	protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
			KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {

		boolean shouldUseLightweightToken = getShouldUseLightweightToken(keycloakSession);
		boolean includeInAccessToken = shouldUseLightweightToken
				? OIDCAttributeMapperHelper.includeInLightweightAccessToken(mappingModel)
				: includeInAccessToken(mappingModel);
		if (!includeInAccessToken) {
			return;
		}

		final UserModel user = userSession.getUser();
		final List<String> groupIds = user.getGroupsStream().map(group -> group.getId()).collect(Collectors.toList());

		if (groupIds != null) {
			OIDCAttributeMapperHelper.mapClaim(token, mappingModel, groupIds);
		}
	}

	private boolean includeInAccessToken(ProtocolMapperModel mappingModel) {
		final String includeInAccessToken = mappingModel.getConfig()
				.get(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN);

		// Backwards compatibility
		if (includeInAccessToken == null) {
			return true;
		}

		return "true".equals(includeInAccessToken);
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	public String getHelpText() {
		return "Adds the user's group IDs to the token.";
	}

	@Override
	public String getDisplayCategory() {
		return "Token mapper";
	}

	@Override
	public String getDisplayType() {
		return "Group IDs Token Mapper";
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}
}
