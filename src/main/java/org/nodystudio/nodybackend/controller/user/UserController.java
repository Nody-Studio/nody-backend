package org.nodystudio.nodybackend.controller.user;

import lombok.RequiredArgsConstructor;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.ApiResponse;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.dto.code.SuccessCode;
import org.nodystudio.nodybackend.dto.user.UserDetailResponseDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 사용자 관련 API
 */
@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

  /**
   * 인증된 사용자의 기본 정보를 조회
   *
   * @param user 인증된 사용자 정보 (@ignore)
   * @return UserDetailResponseDto 사용자 정보
   */
  @GetMapping(value = "/me")
  public ResponseEntity<ApiResponse<UserDetailResponseDto>> getCurrentUser(
      @AuthenticationPrincipal User user) {

    if (user == null) {
      return ResponseEntity
          .status(ErrorCode.USER_NOT_AUTHENTICATED.getStatus())
          .body(ApiResponse.error(ErrorCode.USER_NOT_AUTHENTICATED));
    }

    UserDetailResponseDto userDetail = UserDetailResponseDto.fromEntity(user);

    return ResponseEntity
        .status(SuccessCode.OK.getStatus())
        .body(ApiResponse.success(SuccessCode.OK, userDetail));
  }
}
