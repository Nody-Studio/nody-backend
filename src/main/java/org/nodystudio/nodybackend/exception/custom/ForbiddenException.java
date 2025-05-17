package org.nodystudio.nodybackend.exception.custom;

import org.nodystudio.nodybackend.dto.code.ErrorCode;

/**
 * 인증된 사용자가 권한이 없는 리소스에 접근 시 발생하는 예외 (ErrorCode.ACCESS_DENIED 사용)
 */
public class ForbiddenException extends BusinessException {

  /**
   * 권한 없음 예외 생성자 (기본 메시지 사용)
   */
  public ForbiddenException() {
    super(ErrorCode.ACCESS_DENIED);
  }

  /**
   * 권한 없음 예외 생성자 (커스텀 메시지 사용)
   *
   * @param message 예외 메시지
   */
  public ForbiddenException(String message) {
    super(message, ErrorCode.ACCESS_DENIED);
  }

  /**
   * 권한 없음 예외 생성자 (커스텀 메시지 및 원인 포함)
   *
   * @param message 예외 메시지
   * @param cause   원인 예외
   */
  public ForbiddenException(String message, Throwable cause) {
    super(message, ErrorCode.ACCESS_DENIED, cause);
  }

  /**
   * 권한 없음 예외 생성자 (원인 포함, 기본 메시지 사용)
   *
   * @param cause 원인 예외
   */
  public ForbiddenException(Throwable cause) {
    super(ErrorCode.ACCESS_DENIED, cause);
  }
}