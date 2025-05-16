package org.nodystudio.nodybackend.security.repository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.util.CookieUtils;
import org.springframework.beans.factory.annotation.Value;
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
  private static final String SAME_SITE = "Lax";
  private static final int COOKIE_EXPIRE_SECONDS = 180;

  @Value("${oauth2.redirect.allowed-redirect-hosts}")
  private String allowedHosts;

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

    saveAuthorizationRequestCookie(authorizationRequest, request, response);
    processRedirectUri(request, response);
  }

  /**
   * OAuth2 인증 요청을 쿠키에 저장합니다.
   */
  private void saveAuthorizationRequestCookie(
      OAuth2AuthorizationRequest authorizationRequest,
      HttpServletRequest request,
      HttpServletResponse response) {

    String serializedRequest = CookieUtils.serialize(authorizationRequest);
    log.debug("OAuth2 인증 요청 쿠키 저장: 상태={}", authorizationRequest.getState());

    CookieUtils.addCookie(
        response,
        OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
        serializedRequest,
        COOKIE_EXPIRE_SECONDS,
        isSecureRequest(request),
        SAME_SITE);
  }

  /**
   * 리다이렉트 URI를 검증하고 유효한 경우 쿠키에 저장합니다.
   */
  private void processRedirectUri(HttpServletRequest request, HttpServletResponse response) {
    String redirectUri = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);

    if (!StringUtils.hasText(redirectUri)) {
      return;
    }

    if (isValidRedirectUri(redirectUri)) {
      CookieUtils.addCookie(
          response,
          REDIRECT_URI_PARAM_COOKIE_NAME,
          redirectUri,
          COOKIE_EXPIRE_SECONDS,
          isSecureRequest(request),
          SAME_SITE);
    } else {
      log.warn("유효하지 않은 리다이렉트 URI: {}", redirectUri);
    }
  }

  /**
   * 요청이 HTTPS인지 확인하여 쿠키의 보안 설정을 결정합니다.
   * 
   * @param request HTTP 요청
   * @return HTTPS 요청이면 true, 그렇지 않으면 false
   */
  private boolean isSecureRequest(HttpServletRequest request) {
    return request.isSecure() || "https".equalsIgnoreCase(request.getScheme());
  }

  private boolean isValidRedirectUri(String uri) {
    try {
      URI redirectUri = new URI(uri);

      boolean schemeAllowed = "https".equals(redirectUri.getScheme())
          || ("localhost".equals(redirectUri.getHost()) && "http".equals(redirectUri.getScheme()));

      boolean hostAllowed = Arrays.stream(allowedHosts.split(","))
          .anyMatch(host -> host.equals(redirectUri.getHost()));

      if (!schemeAllowed) {
        log.warn("허용되지 않은 스킴: {}", redirectUri.getScheme());
      }

      if (!hostAllowed) {
        log.warn("허용되지 않은 호스트: {}", redirectUri.getHost());
      }

      return schemeAllowed && hostAllowed;
    } catch (URISyntaxException e) {
      log.error("잘못된 리다이렉트 URI 형식: {}", uri, e);
      return false;
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