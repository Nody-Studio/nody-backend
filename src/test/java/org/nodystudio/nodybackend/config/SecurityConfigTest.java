package org.nodystudio.nodybackend.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.security.filter.JwtAuthenticationFilter;
import org.nodystudio.nodybackend.security.handler.CustomAccessDeniedHandler;
import org.nodystudio.nodybackend.security.handler.CustomAuthenticationEntryPoint;
import org.nodystudio.nodybackend.security.handler.OAuth2LoginFailureHandler;
import org.nodystudio.nodybackend.security.handler.OAuth2LoginSuccessHandler;
import org.nodystudio.nodybackend.service.auth.CustomOAuth2UserService;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
@DisplayName("SecurityConfig 테스트")
class SecurityConfigTest {

  private SecurityConfig securityConfig;
  private JwtAuthenticationFilter jwtAuthenticationFilter;
  private CustomAccessDeniedHandler customAccessDeniedHandler;
  private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
  private OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
  private OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
  private CustomOAuth2UserService customOAuth2UserService;

  @BeforeEach
  void setUp() {
    jwtAuthenticationFilter = mock(JwtAuthenticationFilter.class);
    customAccessDeniedHandler = mock(CustomAccessDeniedHandler.class);
    customAuthenticationEntryPoint = mock(CustomAuthenticationEntryPoint.class);
    oAuth2LoginSuccessHandler = mock(OAuth2LoginSuccessHandler.class);
    oAuth2LoginFailureHandler = mock(OAuth2LoginFailureHandler.class);
    customOAuth2UserService = mock(CustomOAuth2UserService.class);

    securityConfig = new SecurityConfig(
        jwtAuthenticationFilter,
        customAccessDeniedHandler,
        customAuthenticationEntryPoint,
        oAuth2LoginSuccessHandler,
        oAuth2LoginFailureHandler,
        customOAuth2UserService);
  }

  @Test
  @DisplayName("allowedOrigins가 null인 경우 IllegalStateException 발생")
  void validateAllowedOrigins_WhenNull_ShouldThrowException() {
    // given
    ReflectionTestUtils.setField(securityConfig, "allowedOrigins", null);

    // when & then
    assertThatThrownBy(() -> securityConfig.validateConfiguration())
        .isInstanceOf(IllegalStateException.class)
        .hasMessage(
            "CORS allowed-origins 설정이 누락되었습니다. application.yaml에서 'cors.allowed-origins' 값을 설정해주세요.");
  }

  @Test
  @DisplayName("allowedOrigins가 빈 리스트인 경우 IllegalStateException 발생")
  void validateAllowedOrigins_WhenEmpty_ShouldThrowException() {
    // given
    List<String> emptyList = new ArrayList<>();
    ReflectionTestUtils.setField(securityConfig, "allowedOrigins", emptyList);

    // when & then
    assertThatThrownBy(() -> securityConfig.validateConfiguration())
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("CORS allowed-origins 설정이 비어있습니다. 최소 하나 이상의 origin을 설정해주세요.");
  }

  @Test
  @DisplayName("allowedOrigins에 null 값이 포함된 경우 IllegalStateException 발생")
  void validateAllowedOrigins_WhenContainsNull_ShouldThrowException() {
    // given
    List<String> listWithNull = Arrays.asList("http://localhost:3000", null, "https://example.com");
    ReflectionTestUtils.setField(securityConfig, "allowedOrigins", listWithNull);

    // when & then
    assertThatThrownBy(() -> securityConfig.validateConfiguration())
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("CORS allowed-origins에 유효하지 않은 값이 포함되어 있습니다. 빈 문자열이나 공백은 허용되지 않습니다.");
  }

  @Test
  @DisplayName("allowedOrigins에 빈 문자열이 포함된 경우 IllegalStateException 발생")
  void validateAllowedOrigins_WhenContainsEmptyString_ShouldThrowException() {
    // given
    List<String> listWithEmpty = Arrays.asList("http://localhost:3000", "", "https://example.com");
    ReflectionTestUtils.setField(securityConfig, "allowedOrigins", listWithEmpty);

    // when & then
    assertThatThrownBy(() -> securityConfig.validateConfiguration())
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("CORS allowed-origins에 유효하지 않은 값이 포함되어 있습니다. 빈 문자열이나 공백은 허용되지 않습니다.");
  }

  @Test
  @DisplayName("allowedOrigins에 공백만 있는 문자열이 포함된 경우 IllegalStateException 발생")
  void validateAllowedOrigins_WhenContainsWhitespaceOnly_ShouldThrowException() {
    // given
    List<String> listWithWhitespace = Arrays.asList("http://localhost:3000", "   ",
        "https://example.com");
    ReflectionTestUtils.setField(securityConfig, "allowedOrigins", listWithWhitespace);

    // when & then
    assertThatThrownBy(() -> securityConfig.validateConfiguration())
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("CORS allowed-origins에 유효하지 않은 값이 포함되어 있습니다. 빈 문자열이나 공백은 허용되지 않습니다.");
  }

  @Test
  @DisplayName("유효한 allowedOrigins인 경우 예외가 발생하지 않음")
  void validateAllowedOrigins_WhenValid_ShouldNotThrowException() {
    // given
    List<String> validOrigins = Arrays.asList("http://localhost:3000", "https://example.com",
        "https://api.example.com");
    ReflectionTestUtils.setField(securityConfig, "allowedOrigins", validOrigins);

    // when & then - 예외가 발생하지 않아야 함
    securityConfig.validateConfiguration();
  }

  @Test
  @DisplayName("단일 유효한 origin인 경우 예외가 발생하지 않음")
  void validateAllowedOrigins_WhenSingleValidOrigin_ShouldNotThrowException() {
    // given
    List<String> singleOrigin = Collections.singletonList("http://localhost:3000");
    ReflectionTestUtils.setField(securityConfig, "allowedOrigins", singleOrigin);

    // when & then - 예외가 발생하지 않아야 함
    securityConfig.validateConfiguration();
  }
}
