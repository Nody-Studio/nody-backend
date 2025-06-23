package org.nodystudio.nodybackend.config;

import java.util.List;
import jakarta.annotation.PostConstruct;
import org.nodystudio.nodybackend.security.filter.JwtAuthenticationFilter;
import org.nodystudio.nodybackend.security.handler.CustomAccessDeniedHandler;
import org.nodystudio.nodybackend.security.handler.CustomAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
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

  @Value("${cors.allowed-origins}")
  private List<String> allowedOrigins;

  public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
      CustomAccessDeniedHandler customAccessDeniedHandler,
      CustomAuthenticationEntryPoint customAuthenticationEntryPoint) {
    this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    this.customAccessDeniedHandler = customAccessDeniedHandler;
    this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
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
        throw new IllegalStateException("CORS allowed-origins에 유효하지 않은 값이 포함되어 있습니다. 빈 문자열이나 공백은 허용되지 않습니다.");
      }
    }
  }

  // --- 공통 빈 정의 ---
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /**
   * Configures the security filter chain for the development environment.
   *
   * Enables CORS using the provided configuration, disables CSRF protection, form login, and HTTP Basic authentication, and sets session management to stateless. Defines authorization rules to permit public and documentation endpoints, restricts a test endpoint to users with the "ADMIN" role, and requires authentication for all other requests. Configures custom handlers for authentication and access denied exceptions, and adds the JWT authentication filter.
   *
   * @return the configured SecurityFilterChain for the development profile
   * @throws Exception if an error occurs during security configuration
   */
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
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/api/auth/**", "/api/public/**").permitAll()
            .requestMatchers("/swagger-ui/**", "/api-docs/**").permitAll()
            .requestMatchers("/openapi.json").permitAll()
            .requestMatchers("/api/test/exceptions/security-access-test").hasRole("ADMIN")
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
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/api/auth/**", "/api/public/**").permitAll()
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
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

  /**
   * Creates and configures a {@link CorsConfigurationSource} bean with allowed origins, methods, headers, and credentials for CORS requests.
   *
   * The configuration applies to all paths and exposes the Authorization header, allows credentials, and sets a max age for preflight requests.
   *
   * @return the configured {@link CorsConfigurationSource}
   */
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
