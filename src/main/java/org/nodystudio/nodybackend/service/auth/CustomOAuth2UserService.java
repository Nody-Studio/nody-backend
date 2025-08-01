package org.nodystudio.nodybackend.service.auth;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.OAuthAttributes;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.nodystudio.nodybackend.service.user.UserService;
import org.nodystudio.nodybackend.util.LoggingUtils;
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
  private final UserService userService;
  private final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate;

  @Autowired
  public CustomOAuth2UserService(UserRepository userRepository, UserService userService) {
    this(userRepository, userService, new DefaultOAuth2UserService());
  }

  public CustomOAuth2UserService(UserRepository userRepository, UserService userService,
      OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate) {
    this.userRepository = userRepository;
    this.userService = userService;
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

    log.debug("보안 컨텍스트용 DefaultOAuth2User 반환: userId={}", LoggingUtils.maskUserId(user.getId()));
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
   * @throws OAuth2AuthenticationException 재가입 제한 위반 시
   */
  User saveOrUpdate(OAuthAttributes attributes) {
    log.debug("OAuth 사용자 조회 시도: provider={}, socialId={}",
        attributes.getProvider(),
        LoggingUtils.maskIdentifier(attributes.getProviderId()));

    // 1. 활성 사용자 먼저 확인 (기존 로직)
    Optional<User> activeUserOptional = userRepository.findByProviderAndSocialIdAndIsActiveTrue(
        attributes.getProvider(), attributes.getProviderId());

    User user;
    if (activeUserOptional.isPresent()) {
      // 기존 활성 사용자 업데이트
      user = activeUserOptional.get();
      user.updateOAuthInfo(attributes.getName(), attributes.getEmail());
      log.info("기존 활성 사용자 업데이트: provider={}, socialId={}",
          attributes.getProvider(), LoggingUtils.maskIdentifier(attributes.getProviderId()));
      log.debug("사용자 정보 업데이트 상세: email={}, nickname={}",
          LoggingUtils.maskEmail(attributes.getEmail()),
          LoggingUtils.maskNickname(attributes.getName()));
    } else {
      // 2. 탈퇴한 사용자가 있는지 먼저 확인 (소셜 ID 기준)
      Optional<User> deactivatedUserOptional = userRepository.findByProviderAndSocialId(
          attributes.getProvider(), attributes.getProviderId());

      if (deactivatedUserOptional.isPresent()) {
        // 기존 탈퇴한 사용자 계정 재활성화 (제한 없음)
        user = deactivatedUserOptional.get();
        log.info("탈퇴한 계정 재활성화: provider={}, socialId={}, userId={}",
            attributes.getProvider(),
            LoggingUtils.maskIdentifier(attributes.getProviderId()),
            LoggingUtils.maskUserId(user.getId()));
        log.debug("계정 재활성화 상세: 기존닉네임={}, 새닉네임={}",
            LoggingUtils.maskNickname(user.getNickname()),
            LoggingUtils.maskNickname(attributes.getName()));
        user.reactivateAccount();

        // 사용자 생성 데이터도 재활성화 (UserService 참조)
        reactivateUserGeneratedData(user);
      } else {
        // 3. 완전히 새로운 사용자 등록 전에만 재가입 제한 검증
        validateReRegistration(attributes.getEmail());

        // 완전히 새로운 사용자 등록
        user = attributes.toEntity();
        user = userRepository.saveAndFlush(user);
        log.info("새 사용자 등록: provider={}, socialId={}",
            attributes.getProvider(), LoggingUtils.maskIdentifier(attributes.getProviderId()));
        log.debug("새 사용자 등록 상세: email={}, nickname={}",
            LoggingUtils.maskEmail(attributes.getEmail()),
            LoggingUtils.maskNickname(attributes.getName()));
      }
    }
    return user;
  }

  /**
   * 사용자 생성 데이터를 재활성화합니다.
   * 데이터 재활성화 실패 시 로그인도 실패합니다.
   *
   * @param user 재활성화할 사용자
   * @throws OAuth2AuthenticationException 데이터 재활성화 실패 시
   */
  private void reactivateUserGeneratedData(User user) {
    log.debug("사용자 생성 데이터 재활성화 시작: userId={}", LoggingUtils.maskUserId(user.getId()));

    try {
      userService.reactivateUserGeneratedData(user);
    } catch (Exception e) {
      log.error("사용자 데이터 재활성화 실패: userId={}, error={}", 
          LoggingUtils.maskUserId(user.getId()), e.getMessage(), e);
      
      // OAuth2AuthenticationException을 던져서 로그인 실패 처리
      OAuth2Error oauth2Error = new OAuth2Error("data_reactivation_failed",
          "탈퇴한 계정의 데이터를 복구하는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.",
          null);
      throw new OAuth2AuthenticationException(oauth2Error, e);
    }
  }

  /**
   * 재가입 제한을 검증합니다. 30일 이내에 탈퇴한 이메일로는 재가입할 수 없습니다.
   *
   * @param email 검증할 이메일
   * @throws OAuth2AuthenticationException 재가입 제한 위반 시
   */
  private void validateReRegistration(String email) {
    if (email == null || email.trim().isEmpty()) {
      return;
    }

    LocalDateTime thirtyDaysAgo = LocalDateTime.now().minusDays(30);
    Optional<User> recentlyDeactivatedUser = userRepository.findByEmailAndDeletedAtAfter(email,
        thirtyDaysAgo);

    if (recentlyDeactivatedUser.isPresent()) {
      log.warn("재가입 제한 위반: 30일 이내 탈퇴한 이메일로 가입 시도. email={}", LoggingUtils.maskEmail(email));
      OAuth2Error oauth2Error = new OAuth2Error("reregistration_restricted",
          "해당 이메일로는 탈퇴 후 30일 동안 재가입할 수 없습니다. " +
              "30일 후에 다시 시도해주세요.",
          null);
      throw new OAuth2AuthenticationException(oauth2Error);
    }
  }
}