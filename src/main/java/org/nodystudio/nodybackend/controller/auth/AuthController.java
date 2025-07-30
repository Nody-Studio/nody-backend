package org.nodystudio.nodybackend.controller.auth;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.nodystudio.nodybackend.controller.auth.docs.AuthApiDocs;
import org.nodystudio.nodybackend.dto.ApiResponse;
import org.nodystudio.nodybackend.dto.TokenRefreshRequestDto;
import org.nodystudio.nodybackend.dto.TokenResponseDto;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.dto.code.SuccessCode;
import org.nodystudio.nodybackend.exception.custom.UnauthorizedException;
import org.nodystudio.nodybackend.security.userdetails.CustomUserDetails;
import org.nodystudio.nodybackend.service.auth.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
public class AuthController implements AuthApiDocs {

  private final AuthService authService;

  /**
   * Access Token 재발급 유효한 Refresh Token을 사용하여 새로운 Access Token을 발급받습니다.
   *
   * @param requestDto 토큰 재발급 요청 DTO
   * @return 토큰 재발급 응답
   */
  @Override
  @PostMapping(value = "/refresh")
  public ResponseEntity<ApiResponse<TokenResponseDto>> refreshAccessToken(
      @Valid @RequestBody TokenRefreshRequestDto requestDto) {
    TokenResponseDto tokenData = authService.refreshAccessToken(requestDto);
    return ResponseEntity
        .status(SuccessCode.TOKEN_REFRESHED.getStatus())
        .body(ApiResponse.success(SuccessCode.TOKEN_REFRESHED, tokenData));
  }

  /**
   * 로그아웃 현재 로그인한 사용자를 로그아웃하고 Refresh Token을 무효화합니다.
   *
   * @param userDetails 현재 인증된 사용자 정보
   * @param response    HTTP 응답 객체
   * @return 로그아웃 응답
   */
  @Override
  @PostMapping(value = "/logout")
  public ResponseEntity<ApiResponse<Void>> logout(
      @AuthenticationPrincipal CustomUserDetails userDetails,
      HttpServletResponse response) {
    if (userDetails == null || userDetails.getUser() == null) {
      throw new UnauthorizedException(ErrorCode.USER_NOT_AUTHENTICATED);
    }

    authService.logout(userDetails.getUser(), response);

    return ResponseEntity
        .status(SuccessCode.LOGOUT_SUCCESS.getStatus())
        .body(ApiResponse.success(SuccessCode.LOGOUT_SUCCESS, null));
  }
}
