package org.nodystudio.nodybackend.config;

import jakarta.annotation.PostConstruct;
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
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final CustomAccessDeniedHandler customAccessDeniedHandler;
  private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
  private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
  private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
  private final CustomOAuth2UserService customOAuth2UserService;

  @Value("${cors.allowed-origins}")
  private List<String> allowedOrigins;

  public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
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

  @PostConstruct
  public void validateConfiguration() {
    validateAllowedOrigins();
  }

  /**
   * CORS allowed-origins 설정값을 검증합니다.
   *
   * @throws IllegalStateException allowedOrigins가 null이거나 비어있거나 유효하지 않은 경우
   */
  private void validateAllowedOrigins() {
    if (allowedOrigins == null) {
      throw new IllegalStateException(
          "CORS allowed-origins 설정이 누락되었습니다. application.yaml에서 'cors.allowed-origins' 값을 설정해주세요.");
    }

    if (allowedOrigins.isEmpty()) {
      throw new IllegalStateException("CORS allowed-origins 설정이 비어있습니다. 최소 하나 이상의 origin을 설정해주세요.");
    }

    for (String origin : allowedOrigins) {
      if (origin == null || origin.trim().isEmpty()) {
        throw new IllegalStateException(
            "CORS allowed-origins에 유효하지 않은 값이 포함되어 있습니다. 빈 문자열이나 공백은 허용되지 않습니다.");
      }
    }
  }

  // --- 공통 빈 정의 ---
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  // --- 개발 환경(dev) 보안 설정 ---
  @Bean
  @Profile("dev")
  public SecurityFilterChain devSecurityFilterChain(HttpSecurity http,
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
            .requestMatchers("/api/auth/refresh", "/api/auth/login", "/api/auth/signup", "/api/public/**", "/oauth2/**",
                "/login/**")
            .permitAll()
            // 공개 조회 API 허용 (비로그인 사용자도 접근 가능)
            .requestMatchers(HttpMethod.GET, "/api/threads/**").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/logs/**").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/likes/status").permitAll()
            .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**").permitAll()
            .requestMatchers("/favicon.ico").permitAll()
            .requestMatchers("/actuator/**").permitAll()
            .anyRequest().authenticated())
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(customAuthenticationEntryPoint)
            .accessDeniedHandler(customAccessDeniedHandler))
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  // --- 프로덕션 환경(prod) 보안 설정 ---
  @Bean
  @Profile("prod")
  public SecurityFilterChain prodSecurityFilterChain(HttpSecurity http,
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
            .requestMatchers("/api/auth/refresh", "/api/auth/login", "/api/auth/signup", "/api/public/**", "/oauth2/**",
                "/login/**")
            .permitAll()
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            // 공개 조회 API 허용 (비로그인 사용자도 접근 가능)
            .requestMatchers(HttpMethod.GET, "/api/threads/**").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/logs/**").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/likes/status").permitAll()
            .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**").permitAll()
            .requestMatchers("/favicon.ico").permitAll()
            .requestMatchers("/actuator/**").permitAll()
            .anyRequest().authenticated())
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(customAuthenticationEntryPoint)
            .accessDeniedHandler(customAccessDeniedHandler))
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        // .requiresChannel(channel -> channel // HTTPS 강제 (프로덕션 환경에서 SSL 설정 후 활성화)
        // .anyRequest().requiresSecure()
        // )
        .headers(headers -> headers
            .frameOptions(FrameOptionsConfig::deny)
            .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
            .httpStrictTransportSecurity(
                hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000)));

    return http.build();
  }

  // --- 공통 CORS 설정 ---
  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    configuration.setAllowedOrigins(allowedOrigins);
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
    configuration.setExposedHeaders(List.of("Authorization"));
    configuration.setAllowCredentials(true);
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }
}
