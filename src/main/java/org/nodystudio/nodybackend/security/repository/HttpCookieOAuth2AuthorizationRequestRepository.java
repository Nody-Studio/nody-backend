package org.nodystudio.nodybackend.security.repository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.util.CookieUtils;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * OAuth2 인증 요청 정보를 쿠키에 저장하고 관리하는 리포지토리 구현체
 */
@Slf4j
@Component
public class HttpCookieOAuth2AuthorizationRequestRepository
    implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

  public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
  public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
  private static final int COOKIE_EXPIRE_SECONDS = 180;
  private static final boolean SECURE_COOKIE = true;
  private static final String SAME_SITE = "Lax";

  @Override
  public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
    log.debug("OAuth2 인증 요청 로드: {}", request.getRequestURI());

    return CookieUtils.getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
        .map(cookie -> {
          try {
            OAuth2AuthorizationRequest authRequest = CookieUtils.deserialize(cookie,
                OAuth2AuthorizationRequest.class);
            if (authRequest == null) {
              log.warn("인증 요청 쿠키 역직렬화 실패: null 반환");
            }
            return authRequest;
          } catch (Exception e) {
            log.error("인증 요청 쿠키 역직렬화 중 오류 발생", e);
            return null;
          }
        })
        .orElse(null);
  }

  @Override
  public void saveAuthorizationRequest(
      OAuth2AuthorizationRequest authorizationRequest,
      HttpServletRequest request,
      HttpServletResponse response) {

    if (authorizationRequest == null) {
      removeAuthorizationRequestCookies(request, response);
      return;
    }

    String serializedRequest = CookieUtils.serialize(authorizationRequest);
    log.debug("OAuth2 인증 요청 쿠키 저장: 상태={}", authorizationRequest.getState());

    CookieUtils.addSecureCookie(
        response,
        OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
        serializedRequest,
        COOKIE_EXPIRE_SECONDS,
        SECURE_COOKIE,
        SAME_SITE);

    String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
    if (StringUtils.hasText(redirectUriAfterLogin)) {
      CookieUtils.addSecureCookie(
          response,
          REDIRECT_URI_PARAM_COOKIE_NAME,
          redirectUriAfterLogin,
          COOKIE_EXPIRE_SECONDS,
          SECURE_COOKIE,
          SAME_SITE);
    }
  }

  @Override
  public OAuth2AuthorizationRequest removeAuthorizationRequest(
      HttpServletRequest request, HttpServletResponse response) {
    OAuth2AuthorizationRequest authRequest = this.loadAuthorizationRequest(request);
    if (authRequest != null) {
      removeAuthorizationRequestCookies(request, response);
    }
    return authRequest;
  }

  public void removeAuthorizationRequestCookies(
      HttpServletRequest request, HttpServletResponse response) {
    CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
    CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
    log.debug("OAuth2 인증 요청 쿠키 삭제 완료");
  }
}
