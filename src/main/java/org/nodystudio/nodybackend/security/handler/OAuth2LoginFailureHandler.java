package org.nodystudio.nodybackend.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * OAuth2 로그인 실패 시 처리하는 핸들러
 * 재가입 제한 등의 비즈니스 예외를 프론트엔드에 전달
 */
@Slf4j
@Component
public class OAuth2LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

  @Value("${oauth2.redirect.url}")
  private String redirectUrl;

  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) throws IOException {

    log.warn("OAuth2 로그인 실패: {}", exception.getMessage());

    String errorCode = "oauth_login_failed";
    String errorMessage = "로그인 중 오류가 발생했습니다.";

    // OAuth2AuthenticationException인 경우 구체적인 에러 처리
    if (exception instanceof OAuth2AuthenticationException) {
      OAuth2AuthenticationException oauth2Exception = (OAuth2AuthenticationException) exception;
      String errorCodeFromException = oauth2Exception.getError().getErrorCode();

      if ("reregistration_restricted".equals(errorCodeFromException)) {
        errorCode = "reregistration_restricted";
        errorMessage = oauth2Exception.getError().getDescription();
        log.warn("재가입 제한 위반: {}", errorMessage);
      }
    }

    // 프론트엔드로 에러 정보와 함께 리다이렉트
    String targetUrl = UriComponentsBuilder
        .fromUriString(redirectUrl)
        .queryParam("error", "true")
        .queryParam("code", errorCode)
        .queryParam("message", URLEncoder.encode(errorMessage, StandardCharsets.UTF_8))
        .build()
        .toUriString();

    log.info("OAuth2 로그인 실패 - 리다이렉트: {}", targetUrl);
    getRedirectStrategy().sendRedirect(request, response, targetUrl);
  }
}
