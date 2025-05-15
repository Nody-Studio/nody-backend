package org.nodystudio.nodybackend.controller.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.nodystudio.nodybackend.dto.CommonResponseDto;
import org.nodystudio.nodybackend.dto.TokenRefreshRequestDto;
import org.nodystudio.nodybackend.dto.TokenResponseDto;
import org.nodystudio.nodybackend.service.auth.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Auth", description = "인증 관련 API")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  @Operation(summary = "Access Token 재발급", description = "유효한 Refresh Token을 사용하여 새로운 Access Token을 발급받습니다.")
  @ApiResponse(responseCode = "200", description = "토큰 재발급 성공", content = @Content(schema = @Schema(implementation = CommonResponseDto.class)))
  @ApiResponse(responseCode = "400", description = "유효하지 않거나 만료된 Refresh Token")
  @PostMapping("/refresh")
  public ResponseEntity<CommonResponseDto<TokenResponseDto>> refreshAccessToken(
      @RequestBody TokenRefreshRequestDto requestDto) {
    try {
      TokenResponseDto tokenData = authService.refreshAccessToken(requestDto);
      CommonResponseDto<TokenResponseDto> response = CommonResponseDto.success(
          "토큰이 성공적으로 재발급되었습니다.", tokenData);
      return ResponseEntity.ok(response);
    } catch (IllegalArgumentException e) {
      return ResponseEntity.badRequest().build();
    }
  }
}
