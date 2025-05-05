package org.nodystudio.nodybackend.dto;

import lombok.Builder;
import lombok.Getter;
import org.nodystudio.nodybackend.domain.user.User;

import java.util.Map;

@Getter
public class OAuthAttributes {
  private Map<String, Object> attributes;
  private String nameAttributeKey;
  private String name;
  private String email;
  private String provider;
  private String providerId;

  @Builder
  public OAuthAttributes(Map<String, Object> attributes, String nameAttributeKey, String name, String email,
      String provider, String providerId) {
    this.attributes = attributes;
    this.nameAttributeKey = nameAttributeKey;
    this.name = name;
    this.email = email;
    this.provider = provider;
    this.providerId = providerId;
  }

  /**
   * 해당 소셜 로그인이 어떤 소셜인지 구분하여 속성값을 변환하는 메서드
   * 
   * @param registrationId        소셜 등록 ID (e.g., "google", "naver")
   * @param userNameAttributeName OAuth2 로그인 시 키가 되는 값 (application.yml 에서 설정)
   * @param attributes            OAuth2User의 attribute
   * @return OAuthAttributes 객체
   */
  public static OAuthAttributes of(String registrationId, String userNameAttributeName,
      Map<String, Object> attributes) {
    if ("google".equals(registrationId)) {
      return ofGoogle(userNameAttributeName, attributes);
    }
    // TODO: "naver", "kakao" 등 다른 소셜 로그인 제공자 구현 추가 필요

    throw new IllegalArgumentException("지원하지 않는 소셜 로그인 제공자입니다.");
  }

  private static OAuthAttributes ofGoogle(String userNameAttributeName, Map<String, Object> attributes) {
    String name = (String) attributes.get("name");
    String email = (String) attributes.get("email");
    String providerId = (String) attributes.get(userNameAttributeName);

    requireNonNullOrEmpty(name, "Name cannot be null or empty.");
    requireNonNullOrEmpty(email, "Email cannot be null or empty.");
    requireNonNullOrEmpty(providerId, "Provider ID cannot be null or empty. UserNameAttributeName: " + userNameAttributeName);

    return OAuthAttributes.builder()
        .name(name)
        .email(email)
        .provider("google")
        .providerId(providerId)
        .attributes(attributes)
        .nameAttributeKey(userNameAttributeName)
        .build();
  }

  /**
   * 문자열 값이 null 또는 비어 있는지 확인하고, 그렇지 않으면 예외를 발생시키는 헬퍼 메서드
   *
   * @param value   검사할 문자열 값
   * @param message 예외 발생 시 사용할 메시지
   * @throws IllegalArgumentException value가 null 또는 비어 있는 경우
   */
  private static void requireNonNullOrEmpty(String value, String message) {
    if (value == null || value.isEmpty()) {
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * 처음 가입하는 사용자일 경우 User 엔티티 생성
   * 
   * @return User 엔티티 객체
   */
  public User toEntity() {
    return User.builder()
        .nickname(name)
        .email(email)
        .provider(provider)
        .socialId(providerId)
        .isActive(true)
        .build();
  }
}