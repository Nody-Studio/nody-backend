package org.nodystudio.nodybackend.controller.user;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.ApiResponse;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.dto.code.SuccessCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "User", description = "사용자 관련 API")
@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

  @Operation(summary = "현재 사용자 정보 조회", description = "인증된 사용자의 기본 정보를 조회합니다.", security = @SecurityRequirement(name = "bearerAuth"))
  @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "사용자 정보 조회 성공", content = @Content(schema = @Schema(implementation = ApiResponse.class)))
  @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자")
  @GetMapping("/me")
  public ResponseEntity<ApiResponse<Map<String, Object>>> getCurrentUser(
      @AuthenticationPrincipal User user) {

    if (user == null) {
      return ResponseEntity
          .status(ErrorCode.USER_NOT_AUTHENTICATED.getStatus())
          .body(ApiResponse.error(ErrorCode.USER_NOT_AUTHENTICATED));
    }

    String email = user.getEmail();
    String nickname = user.getNickname();

    Map<String, Object> userData = Map.of(
        "email", email != null ? email : "N/A",
        "nickname", nickname != null ? nickname : "N/A");

    return ResponseEntity
        .status(SuccessCode.OK.getStatus())
        .body(ApiResponse.success(SuccessCode.OK, userData));
  }
}
