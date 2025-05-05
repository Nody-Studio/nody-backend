package org.nodystudio.nodybackend.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.OAuthAttributes;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.nodystudio.nodybackend.security.jwt.TokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

  private final TokenProvider tokenProvider;
  private final UserRepository userRepository;
  private final ClientRegistrationRepository clientRegistrationRepository;

  @Value("${oauth2.redirect.url}")
  private String redirectUrl;

  @Value("${oauth2.redirect.allowed-domains}")
  private String allowedDomains;

  private List<String> getAllowedDomainsList() {
    return Arrays.asList(allowedDomains.split(","));
  }

  /**
   * 리다이렉트 URL이 허용된 도메인인지 검증
   *
   * @param url 검증할 URL
   * @return 허용된 도메인이면 true, 아니면 false
   */
  private boolean isValidRedirectUrl(String url) {
    try {
      URI redirectUri = new URI(url);
      String redirectHost = redirectUri.getScheme() + "://" + redirectUri.getHost();
      if (redirectUri.getPort() != -1) {
        redirectHost += ":" + redirectUri.getPort();
      }

      for (String allowedDomain : getAllowedDomainsList()) {
        if (redirectHost.equals(allowedDomain.trim())) {
          return true;
        }
      }

      log.warn("Invalid redirect URL detected: {}", url);
      return false;
    } catch (URISyntaxException e) {
      log.error("Invalid redirect URL format: {}", url, e);
      return false;
    }
  }

  /**
   * OAuth2 로그인 성공 시 호출되는 메서드
   *
   * @param authentication OAuth2 인증 정보
   */
  @Override
  @Transactional
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException {
    log.info("OAuth2 Login successful! Starting handler logic.");

    try {
      OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
      OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

      String registrationId = oauthToken.getAuthorizedClientRegistrationId();
      ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(
          registrationId);
      String userNameAttributeName = clientRegistration.getProviderDetails().getUserInfoEndpoint()
          .getUserNameAttributeName();
      OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName,
          oAuth2User.getAttributes());

      log.debug("Extracted OAuthAttributes: provider={}, providerId={}",
          attributes.getProvider(), attributes.getProviderId());

      Optional<User> userOptional = userRepository
          .findByProviderAndSocialId(attributes.getProvider(), attributes.getProviderId());

      if (userOptional.isEmpty()) {
        log.error(
            "CRITICAL: User not found in DB after OAuth2 login success handling! Provider: {}, SocialId: {}",
            attributes.getProvider(), attributes.getProviderId());

        throw new IllegalStateException(
            "User not found in DB after OAuth2 login success handling! Provider: "
                + attributes.getProvider() + ", SocialId: " + attributes.getProviderId());
      }

      User user = userOptional.get();
      log.info("Found user in DB: {}", user.getId());

      String accessToken = tokenProvider.createAccessToken(user);
      String refreshToken = tokenProvider.createRefreshToken(user);
      LocalDateTime refreshTokenExpiry = tokenProvider.getRefreshTokenExpiry();

      user.updateRefreshToken(refreshToken, refreshTokenExpiry);
      userRepository.saveAndFlush(user);

      log.info("Updated refresh token for user: {}", user.getId());

      Cookie accessTokenCookie = new Cookie("access_token", accessToken);
      accessTokenCookie.setHttpOnly(false);
      accessTokenCookie.setSecure(true);
      accessTokenCookie.setPath("/");
      long accessTokenMaxAgeSeconds = tokenProvider.getAccessTokenExpirationMillis() / 1000;
      accessTokenCookie.setMaxAge((int) accessTokenMaxAgeSeconds);
      response.addCookie(accessTokenCookie);
      log.debug("Access token cookie set. Max-Age: {} seconds", accessTokenMaxAgeSeconds);

      Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
      refreshTokenCookie.setHttpOnly(true);
      refreshTokenCookie.setSecure(true);
      refreshTokenCookie.setPath("/");
      Duration duration = Duration.between(LocalDateTime.now(), refreshTokenExpiry);
      long refreshTokenMaxAgeSeconds = duration.getSeconds();
      refreshTokenCookie.setMaxAge((int) refreshTokenMaxAgeSeconds);
      response.addCookie(refreshTokenCookie);
      log.debug("Refresh token cookie set (HttpOnly). Max-Age: {} seconds",
          refreshTokenMaxAgeSeconds);

      if (!isValidRedirectUrl(redirectUrl)) {
        log.error("Invalid redirect URL: {}", redirectUrl);
        throw new IllegalArgumentException("Invalid redirect URL: " + redirectUrl);
      }

      String targetUrl = UriComponentsBuilder
          .fromUriString(redirectUrl)
          .queryParam("authSuccess", "true")
          .queryParam("userId", user.getId())
          .build()
          .toUriString();

      log.info("Redirecting to target URL with tokens: {}", targetUrl);

      getRedirectStrategy().sendRedirect(request, response, targetUrl);

    } catch (Exception e) {
      log.error("Error occurred during OAuth2 success handling: {}", e.getMessage(), e);

      Cookie removeAccessTokenCookie = new Cookie("access_token", null);
      removeAccessTokenCookie.setMaxAge(0);
      removeAccessTokenCookie.setPath("/");

      Cookie removeRefreshTokenCookie = new Cookie("refresh_token", null);
      removeRefreshTokenCookie.setMaxAge(0);
      removeRefreshTokenCookie.setPath("/");
      response.addCookie(removeAccessTokenCookie);
      response.addCookie(removeRefreshTokenCookie);

      String errorRedirectUrl = UriComponentsBuilder.fromUriString("/login")
          .queryParam("error", "true")
          .queryParam("message", "oauth_login_failed")
          .encode(StandardCharsets.UTF_8)
          .toUriString();
      getRedirectStrategy().sendRedirect(request, response, errorRedirectUrl);
    }
  }
}
