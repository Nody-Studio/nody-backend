package org.nodystudio.nodybackend.config;

import java.util.List;
import org.nodystudio.nodybackend.security.filter.JwtAuthenticationFilter;
import org.nodystudio.nodybackend.security.handler.CustomAccessDeniedHandler;
import org.nodystudio.nodybackend.security.handler.CustomAuthenticationEntryPoint;
import org.nodystudio.nodybackend.security.handler.OAuth2LoginFailureHandler;
import org.nodystudio.nodybackend.security.handler.OAuth2LoginSuccessHandler;
import org.nodystudio.nodybackend.service.auth.CustomOAuth2UserService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * 테스트 환경용 Security 설정 테스트에서만 필요한 설정들을 포함합니다.
 */
@Configuration
@EnableWebSecurity
@Profile("test")
public class TestSecurityConfig {

  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final CustomAccessDeniedHandler customAccessDeniedHandler;
  private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
  private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
  private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
  private final CustomOAuth2UserService customOAuth2UserService;

  @Value("${cors.allowed-origins}")
  private List<String> allowedOrigins;

  public TestSecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
      CustomAccessDeniedHandler customAccessDeniedHandler,
      CustomAuthenticationEntryPoint customAuthenticationEntryPoint,
      OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler,
      OAuth2LoginFailureHandler oAuth2LoginFailureHandler,
      CustomOAuth2UserService customOAuth2UserService) {
    this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    this.customAccessDeniedHandler = customAccessDeniedHandler;
    this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
    this.oAuth2LoginSuccessHandler = oAuth2LoginSuccessHandler;
    this.oAuth2LoginFailureHandler = oAuth2LoginFailureHandler;
    this.customOAuth2UserService = customOAuth2UserService;
  }

  /**
   * 테스트 환경용 Security 설정 테스트 전용 엔드포인트들을 포함합니다.
   */
  @Bean
  @Profile("test")
  public SecurityFilterChain testSecurityFilterChain(HttpSecurity http,
      @Qualifier("corsConfigurationSource") CorsConfigurationSource corsConfigurationSource)
      throws Exception {
    http
        .cors(cors -> cors.configurationSource(corsConfigurationSource))
        .csrf(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .oauth2Login(oauth2 -> oauth2
            .userInfoEndpoint(
                userInfo -> userInfo.userService(customOAuth2UserService))
            .successHandler(oAuth2LoginSuccessHandler)
            .failureHandler(oAuth2LoginFailureHandler))
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/api/auth/**", "/api/public/**", "/oauth2/**", "/login/oauth2/**")
            .permitAll()
            .requestMatchers("/swagger-ui/**", "/api-docs/**").permitAll()
            .requestMatchers("/openapi.json", "/favicon.ico").permitAll()
            .requestMatchers("/actuator/**").permitAll()
            .requestMatchers("/h2-console/**").permitAll()
            .requestMatchers("/api/test/exceptions/**").permitAll()
            .requestMatchers("/api/test/exceptions/security-access-test").hasRole("ADMIN")
            .requestMatchers("/api/test/exceptions/security-auth-test").authenticated()
            .requestMatchers(HttpMethod.GET, "/api/threads/*").permitAll()
            .anyRequest().authenticated())
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(customAuthenticationEntryPoint)
            .accessDeniedHandler(customAccessDeniedHandler))
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));

    return http.build();
  }
}
