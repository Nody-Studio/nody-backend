package org.nodystudio.nodybackend.dto;

import java.util.Map;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.domain.user.User;

/**
 * OAuth2 인증 과정에서 소셜 공급자로부터 받은 사용자 속성 정보를 담는 DTO 클래스
 */
@Slf4j
@Getter
public class OAuthAttributes {

  public static final String PROVIDER_GOOGLE = "google";
  public static final String PROVIDER_KAKAO = "kakao";

  private static final String FIELD_NAME = "name";
  private static final String FIELD_EMAIL = "email";

  private final Map<String, Object> attributes;
  private final String nameAttributeKey;
  private final String name;
  private final String email;
  private final String provider;
  private final String providerId;

  @Builder
  public OAuthAttributes(Map<String, Object> attributes, String nameAttributeKey, String name,
      String email, String provider, String providerId) {
    this.attributes = attributes;
    this.nameAttributeKey = nameAttributeKey;
    this.name = name;
    this.email = email;
    this.provider = provider;
    this.providerId = providerId;
  }

  /**
   * 소셜 로그인 제공자에 따라 적절한 속성값으로 변환하는 메서드
   *
   * @param registrationId        소셜 등록 ID (e.g., "google", "naver")
   * @param userNameAttributeName OAuth2 로그인 시 키가 되는 값 (application.yml 에서 설정)
   * @param attributes            OAuth2User의 attribute
   * @return OAuthAttributes 객체
   * @throws IllegalArgumentException 지원하지 않는 소셜 로그인 제공자이거나 필수 속성이 누락된 경우
   */
  public static OAuthAttributes of(String registrationId, String userNameAttributeName,
      Map<String, Object> attributes) {
    log.debug("OAuth 속성 변환 시작 - 제공자: {}", registrationId);

    if (PROVIDER_GOOGLE.equals(registrationId)) {
      return ofGoogle(userNameAttributeName, attributes);
    }
    // TODO: "naver", "kakao" 등 다른 소셜 로그인 제공자 구현 추가 필요

    log.warn("지원하지 않는 소셜 로그인 제공자: {}", registrationId);
    throw new IllegalArgumentException("지원하지 않는 소셜 로그인 제공자입니다: " + registrationId);
  }

  /**
   * Google OAuth 속성을 OAuthAttributes 객체로 변환
   *
   * @param userNameAttributeName OAuth2 로그인 시 키가 되는 값
   * @param attributes            Google OAuth 속성
   * @return 변환된 OAuthAttributes 객체
   */
  private static OAuthAttributes ofGoogle(String userNameAttributeName,
      Map<String, Object> attributes) {
    log.debug("Google OAuth 속성 변환 시작");

    String name = (String) attributes.get(FIELD_NAME);
    String email = (String) attributes.get(FIELD_EMAIL);
    String providerId = (String) attributes.get(userNameAttributeName);

    validateRequiredField(name, "Name cannot be null or empty.");
    validateRequiredField(email, "Email cannot be null or empty.");
    validateRequiredField(providerId,
        "Provider ID cannot be null or empty. UserNameAttributeName: " + userNameAttributeName);

    return buildOAuthAttributes(
        attributes,
        userNameAttributeName,
        name,
        email,
        PROVIDER_GOOGLE,
        providerId
    );
  }

  /**
   * OAuthAttributes 객체 생성을 위한 빌더 패턴 헬퍼 메서드
   */
  private static OAuthAttributes buildOAuthAttributes(
      Map<String, Object> attributes,
      String nameAttributeKey,
      String name,
      String email,
      String provider,
      String providerId) {

    return OAuthAttributes.builder()
        .attributes(attributes)
        .nameAttributeKey(nameAttributeKey)
        .name(name)
        .email(email)
        .provider(provider)
        .providerId(providerId)
        .build();
  }

  /**
   * 필수 필드 검증 헬퍼 메서드
   *
   * @param value   검사할 문자열 값
   * @param message 예외 발생 시 사용할 메시지
   * @throws IllegalArgumentException value가 null 또는 비어 있는 경우
   */
  private static void validateRequiredField(String value, String message) {
    if (value == null || value.isEmpty()) {
      log.warn("필수 OAuth 필드 누락: {}", message);
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * 처음 가입하는 사용자일 경우 User 엔티티 생성
   *
   * @return User 엔티티 객체
   */
  public User toEntity() {
    log.debug("OAuth 속성으로부터 User 엔티티 생성 - 이메일: {}, 제공자: {}", email, provider);

    return User.builder()
        .nickname(name)
        .email(email)
        .provider(provider)
        .socialId(providerId)
        .isActive(true)
        .build();
  }
}