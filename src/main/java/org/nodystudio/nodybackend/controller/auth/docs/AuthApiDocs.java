package org.nodystudio.nodybackend.controller.auth.docs;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.nodystudio.nodybackend.dto.TokenRefreshRequestDto;
import org.nodystudio.nodybackend.dto.TokenResponseDto;
import org.nodystudio.nodybackend.security.userdetails.CustomUserDetails;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * 인증 관련 API 문서화 인터페이스
 */
@Tag(name = "인증", description = "JWT 토큰 기반 인증 관련 API")
public interface AuthApiDocs {

  @Operation(summary = "Access Token 재발급", description = "유효한 Refresh Token을 사용하여 새로운 Access Token을 발급받습니다.")
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "토큰 재발급 성공", useReturnTypeSchema = true),
      @ApiResponse(responseCode = "401", description = "유효하지 않은 Refresh Token", content = @Content(mediaType = "application/json", schema = @Schema(implementation = org.nodystudio.nodybackend.dto.ApiResponse.class))),
      @ApiResponse(responseCode = "400", description = "잘못된 요청 형식", content = @Content(mediaType = "application/json", schema = @Schema(implementation = org.nodystudio.nodybackend.dto.ApiResponse.class)))
  })
  ResponseEntity<org.nodystudio.nodybackend.dto.ApiResponse<TokenResponseDto>> refreshAccessToken(
      @Valid @RequestBody TokenRefreshRequestDto requestDto);

  @Operation(summary = "로그아웃", description = "현재 로그인한 사용자를 로그아웃하고 Refresh Token을 무효화합니다. 쿠키에서 토큰을 삭제합니다.")
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "로그아웃 성공", useReturnTypeSchema = true),
      @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자", content = @Content(mediaType = "application/json", schema = @Schema(implementation = org.nodystudio.nodybackend.dto.ApiResponse.class)))
  })
  ResponseEntity<org.nodystudio.nodybackend.dto.ApiResponse<Void>> logout(
      @AuthenticationPrincipal CustomUserDetails userDetails,
      HttpServletResponse response);
}