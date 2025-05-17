package org.nodystudio.nodybackend.controller.test;

import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.dto.ApiResponse;
import org.nodystudio.nodybackend.dto.code.SuccessCode;
import org.nodystudio.nodybackend.exception.custom.ForbiddenException;
import org.nodystudio.nodybackend.exception.custom.ResourceNotFoundException;
import org.nodystudio.nodybackend.exception.custom.UnauthorizedException;
import org.nodystudio.nodybackend.exception.custom.ValidationException;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.nodystudio.nodybackend.dto.code.ErrorCode.USER_NOT_AUTHENTICATED;

/**
 * 예외 처리 테스트를 위한 컨트롤러 개발 환경에서만 사용하고, 프로덕션 환경에서는 비활성화하는 것이 좋습니다.
 */
@Slf4j
@RestController
@Profile({ "dev", "test" })
@RequestMapping("/api/test/exceptions")
public class ExceptionTestController {

  /**
   * 정상 응답 테스트
   */
  @GetMapping("/ok")
  public ResponseEntity<ApiResponse<Map<String, Object>>> getOk() {
    Map<String, Object> data = new HashMap<>();
    data.put("description", "이것은 성공적인 응답의 데이터 부분입니다.");
    return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK, data));
  }

  /**
   * ResourceNotFoundException 테스트
   */
  @GetMapping("/not-found")
  public ResponseEntity<Void> getNotFound() {
    throw ResourceNotFoundException.of("User", "id", "12345");
  }

  @GetMapping("/unauthorized")
  public ResponseEntity<Void> getUnauthorized() {
    throw new UnauthorizedException("인증되지 않은 사용자입니다", USER_NOT_AUTHENTICATED);
  }

  /**
   * ForbiddenException 테스트
   */
  @GetMapping("/forbidden")
  public ResponseEntity<Void> getForbidden() {
    throw new ForbiddenException();
  }

  /**
   * ValidationException 테스트
   */
  @GetMapping("/validation")
  public ResponseEntity<Void> getValidationError() {
    Map<String, String> fieldErrors = new HashMap<>();
    fieldErrors.put("username", "사용자 이름은 4자에서 20자 사이여야 합니다");
    fieldErrors.put("email", "이메일 형식이 올바르지 않습니다");

    throw new ValidationException("요청 유효성 검사에 실패했습니다", fieldErrors);
  }

  /**
   * 일반 예외 테스트
   */
  @GetMapping("/error")
  public ResponseEntity<Void> getError() {
    throw new RuntimeException();
  }
}