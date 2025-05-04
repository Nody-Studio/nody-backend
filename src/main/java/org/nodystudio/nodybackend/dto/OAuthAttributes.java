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

    return null; // TODO: 임시 반환, 실제로는 예외 처리 또는 기본값 설정 필요
  }

  private static OAuthAttributes ofGoogle(String userNameAttributeName, Map<String, Object> attributes) {
    return OAuthAttributes.builder()
        .name((String) attributes.get("name"))
        .email((String) attributes.get("email"))
        .provider("google")
        .providerId((String) attributes.get(userNameAttributeName))
        .attributes(attributes)
        .nameAttributeKey(userNameAttributeName)
        .build();
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