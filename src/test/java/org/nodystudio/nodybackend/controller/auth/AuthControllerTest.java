package org.nodystudio.nodybackend.controller.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.times;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.dto.TokenRefreshRequestDto;
import org.nodystudio.nodybackend.dto.TokenResponseDto;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.dto.code.SuccessCode;
import org.nodystudio.nodybackend.exception.GlobalExceptionHandler;
import org.nodystudio.nodybackend.exception.custom.InvalidRefreshTokenException;
import org.nodystudio.nodybackend.service.auth.AuthService;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

  @Mock
  private AuthService authService;

  @InjectMocks
  private AuthController authController;

  private MockMvc mockMvc;
  private final ObjectMapper objectMapper = new ObjectMapper();

  private String refreshToken = "test-refresh-token";
  private String newAccessToken = "new-access-token";

  @BeforeEach
  void setUp() {
    mockMvc = MockMvcBuilders.standaloneSetup(authController)
        .setControllerAdvice(new GlobalExceptionHandler())
        .build();
  }

  @Test
  @DisplayName("POST /api/auth/refresh - 유효한 리프레시 토큰으로 성공 시 200 OK 및 새 토큰 반환")
  void refreshAccessToken_shouldReturnOkAndNewTokens_whenTokenIsValid() throws Exception {
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
        .andExpect(status().isOk()).andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.status").value(SuccessCode.TOKEN_REFRESHED.getStatus().value()))
        .andExpect(jsonPath("$.code").value(SuccessCode.TOKEN_REFRESHED.getCode()))
        .andExpect(jsonPath("$.message").value(SuccessCode.TOKEN_REFRESHED.getMessage()))
        .andExpect(jsonPath("$.data.grantType").value("Bearer"))
        .andExpect(jsonPath("$.data.accessToken").value(newAccessToken))
        .andExpect(jsonPath("$.data.refreshToken").value(refreshToken));

    // verify: authService.refreshAccessToken이 1번 호출되었는지 확인
    then(authService).should(times(1)).refreshAccessToken(any(TokenRefreshRequestDto.class));
  }

  @Test
  @DisplayName("POST /api/auth/refresh - 유효하지 않은 리프레시 토큰으로 실패 시 401 Unauthorized 반환")
  void refreshAccessToken_shouldReturnBadRequest_whenTokenIsInvalid() throws Exception {
    // given
    TokenRefreshRequestDto requestDto = new TokenRefreshRequestDto("invalid-token");

    given(authService.refreshAccessToken(any(TokenRefreshRequestDto.class)))
        .willThrow(new InvalidRefreshTokenException(ErrorCode.INVALID_REFRESH_TOKEN));

    // when & then
    mockMvc.perform(post("/api/auth/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto)))
        .andExpect(status().isUnauthorized())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.status").value(ErrorCode.INVALID_REFRESH_TOKEN.getStatus().value()))
        .andExpect(jsonPath("$.code").value(ErrorCode.INVALID_REFRESH_TOKEN.getCode()))
        .andExpect(jsonPath("$.message").value(ErrorCode.INVALID_REFRESH_TOKEN.getMessage()));

    // verify: authService.refreshAccessToken이 1번 호출되었는지 확인
    then(authService).should(times(1)).refreshAccessToken(any(TokenRefreshRequestDto.class));
  }
}