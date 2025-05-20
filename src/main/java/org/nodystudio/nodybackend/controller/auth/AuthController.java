package org.nodystudio.nodybackend.controller.auth;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.nodystudio.nodybackend.dto.ApiResponse;
import org.nodystudio.nodybackend.dto.TokenRefreshRequestDto;
import org.nodystudio.nodybackend.dto.TokenResponseDto;
import org.nodystudio.nodybackend.dto.code.SuccessCode;
import org.nodystudio.nodybackend.service.auth.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 인증 관련 API
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  /**
   * Access Token 재발급
   * 유효한 Refresh Token을 사용하여 새로운 Access Token을 발급받습니다.
   *
   * @param requestDto 토큰 재발급 요청 DTO
   * @return 토큰 재발급 응답
   */
  @PostMapping(value = "/refresh")
  public ResponseEntity<ApiResponse<TokenResponseDto>> refreshAccessToken(
      @Valid @RequestBody TokenRefreshRequestDto requestDto) {
    TokenResponseDto tokenData = authService.refreshAccessToken(requestDto);
    return ResponseEntity
        .status(SuccessCode.TOKEN_REFRESHED.getStatus())
        .body(ApiResponse.success(SuccessCode.TOKEN_REFRESHED, tokenData));
  }
}
