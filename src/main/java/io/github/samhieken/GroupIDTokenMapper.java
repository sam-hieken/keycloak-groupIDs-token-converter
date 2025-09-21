package io.github.samhieken;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
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

	@Override
	protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
			KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
		
		final UserModel user = userSession.getUser();
		final List<String> groupIds = user.getGroupsStream()
				.map(group -> group.getId())
				.collect(Collectors.toList());

		if (groupIds != null) {
			OIDCAttributeMapperHelper.mapClaim(token, mappingModel, groupIds);
		}
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	public String getHelpText() {
		return "Adds custom value to the token.";
	}

	@Override
	public String getDisplayCategory() {
		return "Token mapper";
	}

	@Override
	public String getDisplayType() {
		return "Custom Value Token Mapper";
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}
}
