package org.nodystudio.nodybackend.controller.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.times;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.TokenRefreshRequestDto;
import org.nodystudio.nodybackend.dto.TokenResponseDto;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.dto.code.SuccessCode;
import org.nodystudio.nodybackend.exception.GlobalExceptionHandler;
import org.nodystudio.nodybackend.exception.custom.InvalidRefreshTokenException;
import org.nodystudio.nodybackend.service.auth.AuthService;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthController 테스트")
class AuthControllerTest {

  private final ObjectMapper objectMapper = new ObjectMapper();
  private final String refreshToken = "test-refresh-token";
  private final String newAccessToken = "new-access-token";

  @Mock
  private AuthService authService;

  @InjectMocks
  private AuthController authController;

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc = MockMvcBuilders.standaloneSetup(authController)
        .setControllerAdvice(new GlobalExceptionHandler())
        .build();
  }

  @Nested
  @DisplayName("토큰 갱신 테스트")
  class TokenRefreshTests {

    @Test
    @DisplayName("유효한 리프레시 토큰으로 토큰을 성공적으로 갱신한다")
    void refreshAccessToken_WithValidToken_ShouldReturnOkAndNewTokens() throws Exception {
      // given
      TokenRefreshRequestDto requestDto = new TokenRefreshRequestDto(refreshToken);
      TokenResponseDto responseDto = TokenResponseDto.builder()
          .grantType("Bearer")
          .accessToken(newAccessToken)
          .refreshToken(refreshToken)
          .accessTokenExpiresIn(900000L)
          .build();

      given(authService.refreshAccessToken(any(TokenRefreshRequestDto.class)))
          .willReturn(responseDto);

      // when & then
      mockMvc
          .perform(post("/api/auth/refresh")
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(requestDto)))
          .andDo(print())
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON))
          .andExpect(jsonPath("$.status").value(SuccessCode.TOKEN_REFRESHED.getStatus().value()))
          .andExpect(jsonPath("$.code").value(SuccessCode.TOKEN_REFRESHED.getCode()))
          .andExpect(jsonPath("$.message").value(SuccessCode.TOKEN_REFRESHED.getMessage()))
          .andExpect(jsonPath("$.data.grantType").value("Bearer"))
          .andExpect(jsonPath("$.data.accessToken").value(newAccessToken))
          .andExpect(jsonPath("$.data.refreshToken").value(refreshToken));

      // then
      then(authService).should(times(1)).refreshAccessToken(any(TokenRefreshRequestDto.class));
    }

    @Test
    @DisplayName("유효하지 않은 리프레시 토큰일 때 401 Unauthorized를 반환한다")
    void refreshAccessToken_WithInvalidToken_ShouldReturnUnauthorized() throws Exception {
      // given
      TokenRefreshRequestDto requestDto = new TokenRefreshRequestDto("invalid-token");

      given(authService.refreshAccessToken(any(TokenRefreshRequestDto.class)))
          .willThrow(new InvalidRefreshTokenException(ErrorCode.INVALID_REFRESH_TOKEN));

      // when & then
      mockMvc.perform(post("/api/auth/refresh")
          .contentType(MediaType.APPLICATION_JSON)
          .content(objectMapper.writeValueAsString(requestDto)))
          .andDo(print())
          .andExpect(status().isUnauthorized())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON))
          .andExpect(jsonPath("$.status").value(ErrorCode.INVALID_REFRESH_TOKEN.getStatus().value()))
          .andExpect(jsonPath("$.code").value(ErrorCode.INVALID_REFRESH_TOKEN.getCode()))
          .andExpect(jsonPath("$.message").value(ErrorCode.INVALID_REFRESH_TOKEN.getMessage()));

      // then
      then(authService).should(times(1)).refreshAccessToken(any(TokenRefreshRequestDto.class));
    }
  }

  @Nested
  @DisplayName("로그아웃 테스트")
  class LogoutTests {

    // Note: 단위 테스트에서는 @AuthenticationPrincipal이 제대로 작동하지 않으므로
    // 실제 인증된 사용자의 로그아웃 성공 케이스는
    // FrontendAuthFlowTest.logout_shouldInvalidateRefreshTokenAndReturnSuccess()에서
    // 검증됨

    @Test
    @DisplayName("인증되지 않은 사용자일 때 401 Unauthorized를 반환한다")
    void logout_WithUnauthenticatedUser_ShouldReturnUnauthorized() throws Exception {
      // when & then
      mockMvc
          .perform(post("/api/auth/logout")
              .contentType(MediaType.APPLICATION_JSON))
          .andDo(print())
          .andExpect(status().isUnauthorized())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON))
          .andExpect(jsonPath("$.status").value(ErrorCode.USER_NOT_AUTHENTICATED.getStatus().value()))
          .andExpect(jsonPath("$.code").value(ErrorCode.USER_NOT_AUTHENTICATED.getCode()))
          .andExpect(jsonPath("$.message").value(ErrorCode.USER_NOT_AUTHENTICATED.getMessage()));

      // then
      then(authService).should(times(0)).logout(any(User.class));
    }

    @Test
    @DisplayName("CustomUserDetails가 null일 때 401 Unauthorized를 반환한다")
    void logout_WithNullUserDetails_ShouldReturnUnauthorized() throws Exception {
      // given
      UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
          null, null, null);

      // when & then
      mockMvc
          .perform(post("/api/auth/logout")
              .with(authentication(authentication))
              .contentType(MediaType.APPLICATION_JSON))
          .andDo(print())
          .andExpect(status().isUnauthorized())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON))
          .andExpect(jsonPath("$.status").value(ErrorCode.USER_NOT_AUTHENTICATED.getStatus().value()))
          .andExpect(jsonPath("$.code").value(ErrorCode.USER_NOT_AUTHENTICATED.getCode()))
          .andExpect(jsonPath("$.message").value(ErrorCode.USER_NOT_AUTHENTICATED.getMessage()));

      // then
      then(authService).should(times(0)).logout(any(User.class));
    }
  }
}
