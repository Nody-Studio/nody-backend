package org.nodystudio.nodybackend.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.OAuthAttributes;
import org.nodystudio.nodybackend.repository.UserRepository;
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

  @Mock
  private UserRepository userRepository;
  @Mock
  private OAuth2UserService<OAuth2UserRequest, OAuth2User> delegateUserService;
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
  private final String registrationId = "google";
  private final String userNameAttributeName = "sub";
  private final String socialId = "google_12345";

  @BeforeEach
  void setUp() {
    googleAttributes = new HashMap<>();
    googleAttributes.put("sub", "google_12345");
    googleAttributes.put("name", "Test User");
    googleAttributes.put("email", "test@example.com");
    googleAttributes.put("picture", "http://example.com/picture.jpg");

    existingUser = User.builder()
        .id(1L)
        .provider("google")
        .socialId(socialId)
        .email("old@example.com")
        .nickname("Old Name")
        .isActive(true)
        .build();

    newUser = User.builder()
        .id(2L)
        .provider("google")
        .socialId(socialId)
        .email("test@example.com")
        .nickname("Test User")
        .isActive(true)
        .build();

    given(userRequest.getClientRegistration()).willReturn(clientRegistration);
    given(clientRegistration.getRegistrationId()).willReturn(registrationId);
    given(userRequest.getAccessToken()).willReturn(accessToken);

    customOAuth2UserService = new CustomOAuth2UserService(userRepository, delegateUserService);
  }

  @Test
  @DisplayName("신규 Google 사용자로 로그인 시 사용자 정보 저장")
  void loadUser_shouldSaveNewUser_whenUserIsNew() {
    // given
    given(clientRegistration.getProviderDetails()).willReturn(providerDetails);
    given(providerDetails.getUserInfoEndpoint()).willReturn(userInfoEndpoint);
    given(userInfoEndpoint.getUserNameAttributeName()).willReturn(userNameAttributeName);
    given(delegateUserService.loadUser(userRequest)).willReturn(mockOAuth2User);
    given(mockOAuth2User.getAttributes()).willReturn(googleAttributes);

    given(userRepository.findByProviderAndSocialId("google", "google_12345")).willReturn(
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
    then(delegateUserService).should(times(1)).loadUser(userRequest);
    then(userRepository).should(times(1)).findByProviderAndSocialId(registrationId, socialId);
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
    given(delegateUserService.loadUser(userRequest)).willReturn(mockOAuth2User);
    given(mockOAuth2User.getAttributes()).willReturn(googleAttributes);
    given(userRepository.findByProviderAndSocialId("google", "google_12345"))
        .willReturn(Optional.of(existingUser));

    // when
    OAuth2User resultUser = customOAuth2UserService.loadUser(userRequest);

    // then
    then(delegateUserService).should(times(1)).loadUser(userRequest);
    then(userRepository).should(times(1)).findByProviderAndSocialId(registrationId, socialId);
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
    given(delegateUserService.loadUser(userRequest)).willThrow(expectedException);

    // when and then
    OAuth2AuthenticationException actualException = assertThrows(
        OAuth2AuthenticationException.class, () -> {
          customOAuth2UserService.loadUser(userRequest);
        });

    assertThat(actualException).isSameAs(expectedException);
    then(userRepository).should(never()).findByProviderAndSocialId(anyString(), anyString());
    then(userRepository).should(never()).saveAndFlush(any(User.class));
  }

  @Test
  @DisplayName("Delegate에서 일반 Exception 발생 시 OAuth2AuthenticationException으로 변환하여 전파")
  void loadUser_shouldThrowOAuth2Exception_whenDelegateThrowsGeneralException() {
    // given
    RuntimeException expectedCause = new RuntimeException("Unexpected Delegate Error");
    given(delegateUserService.loadUser(userRequest)).willThrow(expectedCause);

    // when and then
    OAuth2AuthenticationException actualException = assertThrows(
        OAuth2AuthenticationException.class, () -> {
          customOAuth2UserService.loadUser(userRequest);
        });

    assertThat(actualException.getError().getErrorCode()).isEqualTo("user_loading_failed");
    assertThat(actualException.getCause()).isSameAs(expectedCause);
    then(userRepository).should(never()).findByProviderAndSocialId(anyString(), anyString());
    then(userRepository).should(never()).saveAndFlush(any(User.class));
  }
}