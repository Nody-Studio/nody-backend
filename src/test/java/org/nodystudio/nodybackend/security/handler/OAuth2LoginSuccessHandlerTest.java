package org.nodystudio.nodybackend.security.handler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.nodystudio.nodybackend.security.jwt.TokenProvider;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class OAuth2LoginSuccessHandlerTest {

  @Mock
  private TokenProvider tokenProvider;

  @Mock
  private UserRepository userRepository;

  @Mock
  private ClientRegistrationRepository clientRegistrationRepository;

  @InjectMocks
  private OAuth2LoginSuccessHandler successHandler;

  private MockHttpServletRequest request;
  private MockHttpServletResponse response;
  private Authentication authentication;
  private User testUser;
  private final String accessToken = "test-access-token";
  private final String refreshToken = "test-refresh-token-jwt";
  private final LocalDateTime refreshTokenExpiry = LocalDateTime.now().plusDays(7);
  private final String redirectUrl = "http://localhost:3000/oauth/callback";

  @BeforeEach
  void setUp() {
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();

    // 테스트용 사용자 설정
    testUser = User.builder()
        .id(1L)
        .provider("google")
        .socialId("google_12345")
        .email("test@example.com")
        .nickname("Test User")
        .build();

    // Mock Authentication (OAuth2AuthenticationToken)
    Map<String, Object> attributes = new HashMap<>();
    attributes.put("sub", "google_12345");
    attributes.put("name", "Test User");
    attributes.put("email", "test@example.com");

    OAuth2User oauth2User = new DefaultOAuth2User(
        Collections.singleton(new OAuth2UserAuthority(attributes)), attributes, "sub");

    ClientRegistration clientRegistration = ClientRegistration
        .withRegistrationId("google")
        .clientId("test-client-id")
        .clientSecret("test-client-secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .scope("profile", "email")
        .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
        .tokenUri("https://oauth2.googleapis.com/token")
        .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
        .userNameAttributeName("sub")
        .clientName("Google")
        .build();

    authentication = new OAuth2AuthenticationToken(oauth2User, Collections.emptyList(),
        clientRegistration.getRegistrationId());

    // Inject redirectUrl using ReflectionTestUtils as @Value won't work in unit
    // tests
    ReflectionTestUtils.setField(successHandler, "redirectUrl", redirectUrl);

    // Inject allowedDomains
    ReflectionTestUtils.setField(successHandler, "allowedDomains",
        "http://localhost:3000,https://localhost:3000");

    // Mock ClientRegistrationRepository 동작 설정
    given(clientRegistrationRepository.findByRegistrationId("google")).willReturn(
        clientRegistration);
  }

  @Test
  @DisplayName("OAuth2 로그인 성공 시 토큰 생성, DB 업데이트 및 리다이렉션 수행")
  void onAuthenticationSuccess_shouldGenerateTokensUpdateDbAndRedirect_whenLoginIsSuccessful()
      throws ServletException, IOException {
    // given
    given(userRepository.findByProviderAndSocialId("google", "google_12345"))
        .willReturn(Optional.of(testUser));
    given(tokenProvider.createAccessToken(testUser)).willReturn(accessToken);
    given(tokenProvider.createRefreshToken(testUser)).willReturn(refreshToken);
    given(tokenProvider.getRefreshTokenExpiry()).willReturn(refreshTokenExpiry);
    given(userRepository.saveAndFlush(any(User.class)))
        .willAnswer(invocation -> invocation.getArgument(0));

    // when
    successHandler.onAuthenticationSuccess(request, response, authentication);

    // then
    // 1. DB에 해싱된 리프레시 토큰과 만료 시간이 업데이트되었는지 검증
    ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
    then(userRepository).should(times(1)).saveAndFlush(userCaptor.capture());
    User savedUser = userCaptor.getValue();
    assertThat(savedUser.getRefreshToken()).isEqualTo(refreshToken);
    assertThat(savedUser.getRefreshTokenExpiry()).isEqualTo(refreshTokenExpiry);

    // 2. 리다이렉션 URL 검증
    String expectedRedirectUrl = redirectUrl + "?authSuccess=true&userId=" + testUser.getId();
    assertThat(response.getRedirectedUrl()).isEqualTo(expectedRedirectUrl);
    assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FOUND);

    // 3. TokenProvider 메서드 호출 검증
    then(tokenProvider).should(times(1)).createAccessToken(testUser);
    then(tokenProvider).should(times(1)).createRefreshToken(testUser);
    then(tokenProvider).should(times(1)).getRefreshTokenExpiry();
  }

  @Test
  @DisplayName("OAuth2 로그인 성공 후 사용자 조회 실패 시 에러 페이지로 리다이렉션")
  void onAuthenticationSuccess_shouldRedirectToErrorPage_whenUserNotFoundAfterLogin()
      throws ServletException, IOException {
    // given
    given(userRepository.findByProviderAndSocialId("google", "google_12345"))
        .willReturn(Optional.empty());

    // when
    successHandler.onAuthenticationSuccess(request, response, authentication);

    // then
    String expectedErrorUrl = "/login?error=true&message=oauth_login_failed";
    assertThat(response.getRedirectedUrl()).isEqualTo(expectedErrorUrl);
    assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FOUND);

    // verify: 토큰 생성 및 DB 저장이 호출되지 않았는지 확인
    then(tokenProvider).should(never()).createAccessToken(any());
    then(tokenProvider).should(never()).createRefreshToken(any());
    then(userRepository).should(never()).saveAndFlush(any());
  }

  @Test
  @DisplayName("유효하지 않은 리다이렉트 URL이 설정된 경우 에러 페이지로 리다이렉션")
  void onAuthenticationSuccess_shouldRedirectToErrorPage_whenInvalidRedirectUrl()
      throws IOException {
    // given
    given(userRepository.findByProviderAndSocialId("google", "google_12345")).willReturn(
        Optional.of(testUser));
    given(tokenProvider.createAccessToken(testUser)).willReturn(accessToken);
    given(tokenProvider.createRefreshToken(testUser)).willReturn(refreshToken);
    given(tokenProvider.getRefreshTokenExpiry()).willReturn(refreshTokenExpiry);
    given(userRepository.saveAndFlush(any(User.class))).willAnswer(
        invocation -> invocation.getArgument(0));

    // 유효하지 않은 리다이렉트 URL 설정
    ReflectionTestUtils.setField(successHandler, "redirectUrl",
        "http://malicious-site.com/callback");

    // when
    successHandler.onAuthenticationSuccess(request, response, authentication);

    // then: 에러 URL로 리다이렉션되었는지 검증
    String expectedErrorUrl = "/login?error=true&message=oauth_login_failed";
    assertThat(response.getRedirectedUrl()).isEqualTo(expectedErrorUrl);
    assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FOUND); // 302 Found
  }
}
