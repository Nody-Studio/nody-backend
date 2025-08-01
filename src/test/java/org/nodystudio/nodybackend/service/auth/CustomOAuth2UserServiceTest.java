package org.nodystudio.nodybackend.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.domain.enums.OAuthProvider;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.OAuthAttributes;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.nodystudio.nodybackend.service.user.UserService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails.UserInfoEndpoint;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;

@ExtendWith(MockitoExtension.class)
class CustomOAuth2UserServiceTest {

  private final String registrationId = OAuthProvider.GOOGLE.getValue();
  private final String userNameAttributeName = "sub";
  private final String socialId = "google_12345";
  @Mock
  private UserRepository userRepository;
  @Mock
  private UserService userService;
  @Mock
  private OAuth2UserService<OAuth2UserRequest, OAuth2User> mockDelegate;
  @Mock
  private OAuth2UserRequest userRequest;
  @Mock
  private ClientRegistration clientRegistration;
  @Mock
  private ProviderDetails providerDetails;
  @Mock
  private UserInfoEndpoint userInfoEndpoint;
  @Mock
  private OAuth2AccessToken accessToken;
  @Mock
  private OAuth2User mockOAuth2User;
  private CustomOAuth2UserService customOAuth2UserService;
  private Map<String, Object> googleAttributes;
  private User existingUser;
  private User newUser;

  @BeforeEach
  void setUp() {
    googleAttributes = new HashMap<>();
    googleAttributes.put("sub", "google_12345");
    googleAttributes.put("name", "Test User");
    googleAttributes.put("email", "test@example.com");
    googleAttributes.put("picture", "http://example.com/picture.jpg");

    existingUser = User.builder()
        .id(1L)
        .provider(OAuthProvider.GOOGLE)
        .socialId(socialId)
        .email("old@example.com")
        .nickname("Old Name")
        .isActive(true)
        .build();

    newUser = User.builder()
        .id(2L)
        .provider(OAuthProvider.GOOGLE)
        .socialId(socialId)
        .email("test@example.com")
        .nickname("Test User")
        .isActive(true)
        .build();

    given(userRequest.getClientRegistration()).willReturn(clientRegistration);
    given(clientRegistration.getRegistrationId()).willReturn(registrationId);
    given(userRequest.getAccessToken()).willReturn(accessToken);

    customOAuth2UserService = new CustomOAuth2UserService(userRepository, userService, mockDelegate);
  }

  @Test
  @DisplayName("신규 Google 사용자로 로그인 시 사용자 정보 저장")
  void loadUser_shouldSaveNewUser_whenUserIsNew() {
    // given
    given(clientRegistration.getProviderDetails()).willReturn(providerDetails);
    given(providerDetails.getUserInfoEndpoint()).willReturn(userInfoEndpoint);
    given(userInfoEndpoint.getUserNameAttributeName()).willReturn(userNameAttributeName);
    given(mockDelegate.loadUser(userRequest)).willReturn(mockOAuth2User);
    given(mockOAuth2User.getAttributes()).willReturn(googleAttributes);

    given(userRepository.findByProviderAndSocialIdAndIsActiveTrue(OAuthProvider.GOOGLE,
        "google_12345")).willReturn(
            Optional.empty());
    given(userRepository.findByEmailAndDeletedAtAfter(anyString(),
        any(LocalDateTime.class))).willReturn(
            Optional.empty());
    given(
        userRepository.findByProviderAndSocialId(OAuthProvider.GOOGLE, "google_12345")).willReturn(
            Optional.empty());
    given(userRepository.saveAndFlush(any(User.class))).willAnswer(invocation -> {
      User userToSave = invocation.getArgument(0);

      return User.builder()
          .id(newUser.getId())
          .provider(userToSave.getProvider())
          .socialId(userToSave.getSocialId())
          .email(userToSave.getEmail())
          .nickname(userToSave.getNickname())
          .isActive(userToSave.getIsActive())
          .build();
    });

    // when
    OAuth2User resultUser = customOAuth2UserService.loadUser(userRequest);

    // then
    then(mockDelegate).should(times(1)).loadUser(userRequest);
    then(userRepository).should(times(1))
        .findByProviderAndSocialIdAndIsActiveTrue(OAuthProvider.GOOGLE, socialId);
    then(userRepository).should(times(1)).saveAndFlush(any(User.class));
    then(userRepository).should(never()).save(any(User.class));

    assertThat(resultUser).isNotNull();
    assertThat(resultUser.getAuthorities())
        .extracting(GrantedAuthority::getAuthority)
        .contains("ROLE_USER");
    OAuthAttributes expectedAttributes = OAuthAttributes.of(registrationId, userNameAttributeName,
        googleAttributes);
    assertThat(resultUser.getAttributes()).isEqualTo(expectedAttributes.getAttributes());
  }

  @Test
  @DisplayName("기존 Google 사용자로 로그인 시 사용자 정보 업데이트")
  void loadUser_shouldUpdateExistingUser_whenUserExists() {
    // given
    given(clientRegistration.getProviderDetails()).willReturn(providerDetails);
    given(providerDetails.getUserInfoEndpoint()).willReturn(userInfoEndpoint);
    given(userInfoEndpoint.getUserNameAttributeName()).willReturn(userNameAttributeName);
    given(mockDelegate.loadUser(userRequest)).willReturn(mockOAuth2User);
    given(mockOAuth2User.getAttributes()).willReturn(googleAttributes);
    given(userRepository.findByProviderAndSocialIdAndIsActiveTrue(OAuthProvider.GOOGLE,
        "google_12345"))
        .willReturn(Optional.of(existingUser));

    // when
    OAuth2User resultUser = customOAuth2UserService.loadUser(userRequest);

    // then
    then(mockDelegate).should(times(1)).loadUser(userRequest);
    then(userRepository).should(times(1))
        .findByProviderAndSocialIdAndIsActiveTrue(OAuthProvider.GOOGLE, socialId);
    then(userRepository).should(never()).save(any(User.class));
    then(userRepository).should(never()).saveAndFlush(any(User.class));

    assertThat(resultUser).isNotNull();
    assertThat(resultUser.getName()).isEqualTo(socialId);
    assertThat(resultUser.getAuthorities()).extracting(GrantedAuthority::getAuthority)
        .containsExactly("ROLE_USER");

    OAuthAttributes expectedAttributes = OAuthAttributes.of(registrationId, userNameAttributeName,
        googleAttributes);
    assertThat(resultUser.getAttributes()).isEqualTo(expectedAttributes.getAttributes());
    assertThat(existingUser.getNickname()).isEqualTo(googleAttributes.get("name"));
  }

  @Test
  @DisplayName("Delegate에서 OAuth2AuthenticationException 발생 시 그대로 전파")
  void loadUser_shouldThrowException_whenDelegateThrowsOAuth2Exception() {
    // given
    OAuth2AuthenticationException expectedException = new OAuth2AuthenticationException(
        new OAuth2Error("test_error"),
        "Delegate Error");
    given(mockDelegate.loadUser(userRequest)).willThrow(expectedException);

    // when and then
    assertThatThrownBy(() -> customOAuth2UserService.loadUser(userRequest))
        .isInstanceOf(OAuth2AuthenticationException.class)
        .isSameAs(expectedException);
    then(userRepository).should(never())
        .findByProviderAndSocialId(any(OAuthProvider.class), anyString());
    then(userRepository).should(never()).saveAndFlush(any(User.class));
  }

  @Test
  @DisplayName("Delegate에서 일반 Exception 발생 시 OAuth2AuthenticationException으로 변환하여 전파")
  void loadUser_shouldThrowOAuth2Exception_whenDelegateThrowsGeneralException() {
    // given
    RuntimeException expectedCause = new RuntimeException("Unexpected Delegate Error");
    given(mockDelegate.loadUser(userRequest)).willThrow(expectedCause);

    // when and then
    assertThatThrownBy(() -> customOAuth2UserService.loadUser(userRequest))
        .isInstanceOf(OAuth2AuthenticationException.class)
        .satisfies(thrown -> {
          OAuth2AuthenticationException exception = (OAuth2AuthenticationException) thrown;
          assertThat(exception.getError().getErrorCode()).isEqualTo("user_loading_failed");
          assertThat(exception.getCause()).isEqualTo(expectedCause);
        });

    then(userRepository).should(never())
        .findByProviderAndSocialIdAndIsActiveTrue(any(OAuthProvider.class), anyString());
    then(userRepository).should(never()).saveAndFlush(any(User.class));
  }

  @Test
  @DisplayName("30일 이내 탈퇴한 이메일로 완전히 새로운 계정 재가입 시도 시 예외 발생")
  void loadUser_shouldThrowOAuth2Exception_whenNewAccountWithRecentlyDeactivatedEmail() {
    // given
    given(clientRegistration.getProviderDetails()).willReturn(providerDetails);
    given(providerDetails.getUserInfoEndpoint()).willReturn(userInfoEndpoint);
    given(userInfoEndpoint.getUserNameAttributeName()).willReturn(userNameAttributeName);
    given(mockDelegate.loadUser(userRequest)).willReturn(mockOAuth2User);
    given(mockOAuth2User.getAttributes()).willReturn(googleAttributes);

    // 활성 사용자 없음
    given(userRepository.findByProviderAndSocialIdAndIsActiveTrue(OAuthProvider.GOOGLE,
        "google_12345"))
        .willReturn(Optional.empty());

    // 기존 소셜 계정 없음 (완전히 새로운 사용자)
    given(userRepository.findByProviderAndSocialId(OAuthProvider.GOOGLE, "google_12345"))
        .willReturn(Optional.empty());

    // 30일 이내 탈퇴한 이메일 사용자 존재 (다른 소셜 ID)
    User recentlyDeactivatedUser = User.builder()
        .id(3L)
        .provider(OAuthProvider.GOOGLE)
        .socialId("different_social_id") // 다른 소셜 ID
        .email("test@example.com") // 동일한 이메일
        .nickname("Deactivated User")
        .isActive(false)
        .build();
    recentlyDeactivatedUser.deactivateAccount();

    given(userRepository.findByEmailAndDeletedAtAfter(eq("test@example.com"),
        any(LocalDateTime.class)))
        .willReturn(Optional.of(recentlyDeactivatedUser));

    // when & then
    assertThatThrownBy(() -> customOAuth2UserService.loadUser(userRequest))
        .isInstanceOf(OAuth2AuthenticationException.class)
        .hasMessageContaining("해당 이메일로는 탈퇴 후 30일 동안 재가입할 수 없습니다");

    // 새로운 로직 순서 확인: 탈퇴한 사용자 확인 > 재가입 제한 검증
    then(userRepository).should(times(1))
        .findByProviderAndSocialIdAndIsActiveTrue(OAuthProvider.GOOGLE, "google_12345");
    then(userRepository).should(times(1))
        .findByProviderAndSocialId(OAuthProvider.GOOGLE, "google_12345");
    then(userRepository).should(times(1))
        .findByEmailAndDeletedAtAfter(eq("test@example.com"), any(LocalDateTime.class));
    then(userRepository).should(never()).saveAndFlush(any(User.class));
  }

  @Test
  @DisplayName("탈퇴한 사용자가 재로그인 시 계정 및 데이터 재활성화")
  void loadUser_shouldReactivateAccountAndData_whenDeactivatedUserReturns() {
    // given
    given(clientRegistration.getProviderDetails()).willReturn(providerDetails);
    given(providerDetails.getUserInfoEndpoint()).willReturn(userInfoEndpoint);
    given(userInfoEndpoint.getUserNameAttributeName()).willReturn(userNameAttributeName);
    given(mockDelegate.loadUser(userRequest)).willReturn(mockOAuth2User);
    given(mockOAuth2User.getAttributes()).willReturn(googleAttributes);

    // 활성 사용자 없음
    given(userRepository.findByProviderAndSocialIdAndIsActiveTrue(OAuthProvider.GOOGLE,
        "google_12345"))
        .willReturn(Optional.empty());

    // 탈퇴한 사용자 존재
    User deactivatedUser = User.builder()
        .id(4L)
        .provider(OAuthProvider.GOOGLE)
        .socialId("google_12345")
        .email("old@example.com")
        .nickname("Old Name")
        .isActive(false)
        .build();
    deactivatedUser.deactivateAccount();

    given(userRepository.findByProviderAndSocialId(OAuthProvider.GOOGLE, "google_12345"))
        .willReturn(Optional.of(deactivatedUser));

    // when
    OAuth2User resultUser = customOAuth2UserService.loadUser(userRequest);

    // then
    // 계정이 재활성화되었는지 확인
    assertThat(deactivatedUser.getIsActive()).isTrue();
    assertThat(deactivatedUser.getDeletedAt()).isNull();
    assertThat(deactivatedUser.getNickname()).isEqualTo("Old Name"); // 기존 닉네임 유지
    assertThat(deactivatedUser.getEmail()).isEqualTo("old@example.com"); // 기존 이메일 유지

    // 사용자 생성 데이터 재활성화 확인 (UserService 통해)
    then(userService).should(times(1)).reactivateUserGeneratedData(deactivatedUser);

    // 기본 검증
    then(userRepository).should(times(1))
        .findByProviderAndSocialIdAndIsActiveTrue(OAuthProvider.GOOGLE, "google_12345");
    then(userRepository).should(times(1))
        .findByProviderAndSocialId(OAuthProvider.GOOGLE, "google_12345");
    then(userRepository).should(never()).saveAndFlush(any(User.class));

    assertThat(resultUser).isNotNull();
    assertThat(resultUser.getAuthorities()).extracting(GrantedAuthority::getAuthority)
        .containsExactly("ROLE_USER");
  }

  @Test
  @DisplayName("30일 이내 탈퇴한 이메일이지만 기존 소셜 계정으로 재로그인 시 재활성화 허용")
  void loadUser_shouldReactivateAccount_whenSameSocialAccountReturnsWithin30Days() {
    // given
    given(clientRegistration.getProviderDetails()).willReturn(providerDetails);
    given(providerDetails.getUserInfoEndpoint()).willReturn(userInfoEndpoint);
    given(userInfoEndpoint.getUserNameAttributeName()).willReturn(userNameAttributeName);
    given(mockDelegate.loadUser(userRequest)).willReturn(mockOAuth2User);
    given(mockOAuth2User.getAttributes()).willReturn(googleAttributes);

    // 활성 사용자 없음
    given(userRepository.findByProviderAndSocialIdAndIsActiveTrue(OAuthProvider.GOOGLE,
        "google_12345"))
        .willReturn(Optional.empty());

    // 탈퇴한 사용자 존재 (동일한 소셜 계정)
    User anotherDeactivatedUser = User.builder()
        .id(7L)
        .provider(OAuthProvider.GOOGLE)
        .socialId("google_12345") // 동일한 소셜 ID
        .email("test@example.com") // 동일한 이메일
        .nickname("Old Name")
        .isActive(false)
        .build();
    anotherDeactivatedUser.deactivateAccount();

    given(userRepository.findByProviderAndSocialId(OAuthProvider.GOOGLE, "google_12345"))
        .willReturn(Optional.of(anotherDeactivatedUser));

    // when
    OAuth2User resultUser = customOAuth2UserService.loadUser(userRequest);

    // then
    // 재가입 제한 검증은 호출되지 않음 (기존 소셜 계정이므로)
    then(userRepository).should(never())
        .findByEmailAndDeletedAtAfter(anyString(), any(LocalDateTime.class));

    // 계정이 재활성화되었는지 확인
    assertThat(anotherDeactivatedUser.getIsActive()).isTrue();
    assertThat(anotherDeactivatedUser.getDeletedAt()).isNull();
    assertThat(anotherDeactivatedUser.getNickname()).isEqualTo("Old Name"); // 기존 닉네임 유지
    assertThat(anotherDeactivatedUser.getEmail()).isEqualTo("test@example.com"); // 기존 이메일 유지

    // 데이터 재활성화 확인 (UserService 통해)
    then(userService).should(times(1)).reactivateUserGeneratedData(anotherDeactivatedUser);

    assertThat(resultUser).isNotNull();
    assertThat(resultUser.getAuthorities()).extracting(GrantedAuthority::getAuthority)
        .containsExactly("ROLE_USER");
  }

  @Test
  @DisplayName("데이터 재활성화 실패 시 로그인 실패")
  void loadUser_shouldFailLogin_whenDataReactivationFails() {
    // given
    given(clientRegistration.getProviderDetails()).willReturn(providerDetails);
    given(providerDetails.getUserInfoEndpoint()).willReturn(userInfoEndpoint);
    given(userInfoEndpoint.getUserNameAttributeName()).willReturn(userNameAttributeName);
    given(mockDelegate.loadUser(userRequest)).willReturn(mockOAuth2User);
    given(mockOAuth2User.getAttributes()).willReturn(googleAttributes);

    // 활성 사용자 없음
    given(userRepository.findByProviderAndSocialIdAndIsActiveTrue(OAuthProvider.GOOGLE,
        "google_12345"))
        .willReturn(Optional.empty());

    // 탈퇴한 사용자 존재
    User deactivatedUser = User.builder()
        .id(6L)
        .provider(OAuthProvider.GOOGLE)
        .socialId("google_12345")
        .email("test@example.com")
        .nickname("Test User")
        .isActive(false)
        .build();
    deactivatedUser.deactivateAccount();

    given(userRepository.findByProviderAndSocialId(OAuthProvider.GOOGLE, "google_12345"))
        .willReturn(Optional.of(deactivatedUser));

    // 데이터 재활성화 실패 설정
    doThrow(new RuntimeException("데이터베이스 연결 실패"))
        .when(userService).reactivateUserGeneratedData(deactivatedUser);

    // when & then
    assertThatThrownBy(() -> customOAuth2UserService.loadUser(userRequest))
        .isInstanceOf(OAuth2AuthenticationException.class)
        .satisfies(exception -> {
          OAuth2AuthenticationException oauthException = (OAuth2AuthenticationException) exception;
          assertThat(oauthException.getError().getErrorCode()).isEqualTo("data_reactivation_failed");
          assertThat(oauthException.getError().getDescription())
              .isEqualTo("탈퇴한 계정의 데이터를 복구하는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.");
          assertThat(oauthException.getCause()).isInstanceOf(RuntimeException.class);
          assertThat(oauthException.getCause().getMessage()).isEqualTo("데이터베이스 연결 실패");
        });
  }

}
