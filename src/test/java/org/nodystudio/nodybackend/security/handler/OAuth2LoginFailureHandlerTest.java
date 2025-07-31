package org.nodystudio.nodybackend.security.handler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
@DisplayName("OAuth2LoginFailureHandler 테스트")
class OAuth2LoginFailureHandlerTest {

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @Mock
  private RedirectStrategy redirectStrategy;

  private OAuth2LoginFailureHandler failureHandler;

  @BeforeEach
  void setUp() {
    failureHandler = new OAuth2LoginFailureHandler();
    ReflectionTestUtils.setField(failureHandler, "redirectUrl", "http://localhost:3000");
    failureHandler.setRedirectStrategy(redirectStrategy);
  }

  @Test
  @DisplayName("재가입 제한 예외 발생 시 적절한 에러 메시지로 리다이렉트")
  void onAuthenticationFailure_shouldRedirectWithReregistrationError() throws IOException {
    // given
    OAuth2Error oauth2Error = new OAuth2Error("reregistration_restricted",
        "해당 이메일로는 탈퇴 후 30일 동안 재가입할 수 없습니다.", null);
    OAuth2AuthenticationException exception = new OAuth2AuthenticationException(oauth2Error);

    // when
    failureHandler.onAuthenticationFailure(request, response, exception);

    // then
    ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
    verify(redirectStrategy).sendRedirect(any(), any(), urlCaptor.capture());

    String redirectUrl = urlCaptor.getValue();
    assertThat(redirectUrl).contains("error=true");
    assertThat(redirectUrl).contains("code=reregistration_restricted");
    assertThat(redirectUrl).contains("message=");
  }

  @Test
  @DisplayName("일반 OAuth2 예외 발생 시 기본 에러 메시지로 리다이렉트")
  void onAuthenticationFailure_shouldRedirectWithDefaultError() throws IOException {
    // given
    OAuth2Error oauth2Error = new OAuth2Error("invalid_request", "Invalid request", null);
    OAuth2AuthenticationException exception = new OAuth2AuthenticationException(oauth2Error);

    // when
    failureHandler.onAuthenticationFailure(request, response, exception);

    // then
    ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
    verify(redirectStrategy).sendRedirect(any(), any(), urlCaptor.capture());

    String redirectUrl = urlCaptor.getValue();
    assertThat(redirectUrl).contains("error=true");
    assertThat(redirectUrl).contains("code=oauth_login_failed");
    assertThat(redirectUrl).contains("message=");
  }
}
