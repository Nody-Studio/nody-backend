package org.nodystudio.nodybackend.service.auth;

import java.util.Collections;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.OAuthAttributes;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

  private final UserRepository userRepository;
  private final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate;

  @Autowired
  public CustomOAuth2UserService(UserRepository userRepository) {
    this(userRepository, new DefaultOAuth2UserService());
  }

  public CustomOAuth2UserService(UserRepository userRepository,
      OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate) {
    this.userRepository = userRepository;
    this.delegate = delegate;
  }

  @Override
  @Transactional
  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
    log.debug("UserRequest details: ClientRegistration={}, AccessToken(type)={}",
        userRequest.getClientRegistration(),
        userRequest.getAccessToken().getTokenType());

    OAuth2User oAuth2User = null;

    try {
      oAuth2User = delegate.loadUser(userRequest);
      log.debug("Successfully loaded user info from provider. Attributes: {}",
          oAuth2User.getAttributes());
    } catch (OAuth2AuthenticationException e) {
      log.error("OAuth2AuthenticationException occurred while loading user info for {}: {}",
          userRequest.getClientRegistration().getRegistrationId(), e.getMessage(), e);
      throw e;
    } catch (Exception e) {
      log.error("Unexpected exception occurred during user loading for {}: {}",
          userRequest.getClientRegistration().getRegistrationId(), e.getMessage(), e);
      OAuth2Error oauth2Error = new OAuth2Error("user_loading_failed",
          String.format("Failed to load user information for %s due to an unexpected error.",
              userRequest.getClientRegistration().getRegistrationId()),
          null);
      throw new OAuth2AuthenticationException(oauth2Error, e);
    }

    String registrationId = userRequest.getClientRegistration().getRegistrationId();
    String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
        .getUserInfoEndpoint()
        .getUserNameAttributeName();

    log.debug("OAuth2 Provider: {}, User Name Attribute: {}", registrationId,
        userNameAttributeName);

    OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName,
        oAuth2User.getAttributes());
    log.debug("Created OAuthAttributes for provider: {}", registrationId);

    User user = saveOrUpdate(attributes);

    log.debug("Returning DefaultOAuth2User for security context. User ID: {}", user.getId());
    return new DefaultOAuth2User(Collections.singleton(
        new SimpleGrantedAuthority("ROLE_USER")),
        attributes.getAttributes(),
        attributes.getNameAttributeKey());
  }

  /**
   * OAuthAttributes 정보를 바탕으로 사용자를 저장하거나 업데이트합니다.
   *
   * @param attributes OAuth 사용자 정보
   * @return 저장되거나 업데이트된 User 엔티티
   */
  User saveOrUpdate(OAuthAttributes attributes) {
    log.debug("Attempting to find user by provider [{}] and socialId [{}]",
        attributes.getProvider(),
        attributes.getProviderId());
    Optional<User> userOptional = userRepository.findByProviderAndSocialId(attributes.getProvider(),
        attributes.getProviderId());

    User user;
    if (userOptional.isPresent()) {
      user = userOptional.get();
      user.updateOAuthInfo(attributes.getName(), attributes.getEmail());
      log.info("Existing user found and updated: provider={}, socialId={}",
          attributes.getProvider(),
          attributes.getProviderId());
    } else {
      user = attributes.toEntity();
      user = userRepository.saveAndFlush(user);
      log.info("New user registered: provider={}, socialId={}", attributes.getProvider(),
          attributes.getProviderId());
    }
    return user;
  }
}