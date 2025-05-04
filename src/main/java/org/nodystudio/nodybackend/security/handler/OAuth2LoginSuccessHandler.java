package org.nodystudio.nodybackend.security.handler;

import jakarta.servlet.ServletException;
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
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
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

  /**
   * OAuth2 로그인 성공 시 호출되는 메서드
   * 
   * @param authentication OAuth2 인증 정보
   */
  @Override
  @Transactional
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    log.info("OAuth2 Login successful! Starting handler logic.");

    try {
      OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
      OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

      String registrationId = oauthToken.getAuthorizedClientRegistrationId();
      ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
      String userNameAttributeName = clientRegistration.getProviderDetails().getUserInfoEndpoint()
          .getUserNameAttributeName();
      OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName,
          oAuth2User.getAttributes());

      log.info("Extracted OAuthAttributes: {}", attributes);

      Optional<User> userOptional = userRepository
          .findByProviderAndSocialId(attributes.getProvider(), attributes.getProviderId());

      if (userOptional.isEmpty()) {
        log.error("CRITICAL: User not found in DB after OAuth2 login success handling! Provider: {}, SocialId: {}",
            attributes.getProvider(), attributes.getProviderId());

        throw new IllegalStateException("User not found in DB after OAuth2 login success handling! Provider: "
            + attributes.getProvider() + ", SocialId: " + attributes.getProviderId());
      }

      User user = userOptional.get();
      log.info("Found user in DB: {}", user.getId());

      String accessToken = tokenProvider.createAccessToken(user);
      String refreshToken = tokenProvider.createRefreshToken(user);
      LocalDateTime refreshTokenExpiry = tokenProvider.getRefreshTokenExpiry();

      log.debug("Generated Access Token: {}", accessToken);
      log.debug("Generated Refresh Token: {} (Expires: {})", refreshToken, refreshTokenExpiry);

      user.updateRefreshToken(refreshToken, refreshTokenExpiry);
      userRepository.saveAndFlush(user);

      log.info("Updated refresh token for user: {}", user.getId());

      String targetUrl = UriComponentsBuilder.fromUriString(redirectUrl)
          .queryParam("accessToken", accessToken)
          .queryParam("refreshToken", refreshToken).build()
          .encode(StandardCharsets.UTF_8).toUriString();

      log.info("Generated target URL: {}", targetUrl);

      getRedirectStrategy().sendRedirect(request, response, targetUrl);

    } catch (Exception e) {
      log.error("Error occurred during OAuth2 success handling: {}", e.getMessage(), e);

      String errorRedirectUrl = UriComponentsBuilder.fromUriString("/login")
          .queryParam("error", "true")
          .queryParam("message", "oauth_login_failed")
          .encode(StandardCharsets.UTF_8)
          .toUriString();
      getRedirectStrategy().sendRedirect(request, response, errorRedirectUrl);
    }
  }
}
