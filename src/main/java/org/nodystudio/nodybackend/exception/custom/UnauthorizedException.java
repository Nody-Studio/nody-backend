package org.nodystudio.nodybackend.exception.custom;

import org.nodystudio.nodybackend.exception.ErrorCode;

/**
 * 인증되지 않은 사용자가 접근 시 발생하는 예외 (ErrorCode.AUTHENTICATION_FAILED 또는 관련 코드 사용)
 */
public class UnauthorizedException extends BusinessException {

  /**
   * 인증 예외 생성자 (기본 메시지 사용, ErrorCode.AUTHENTICATION_FAILED)
   */
  public UnauthorizedException() {
    super(ErrorCode.AUTHENTICATION_FAILED);
  }

  /**
   * 인증 예외 생성자 (커스텀 메시지 사용, ErrorCode.AUTHENTICATION_FAILED)
   *
   * @param message 예외 메시지
   */
  public UnauthorizedException(String message) {
    super(message, ErrorCode.AUTHENTICATION_FAILED);
  }

  /**
   * 인증 예외 생성자 (커스텀 메시지 및 원인 포함, ErrorCode.AUTHENTICATION_FAILED)
   *
   * @param message 예외 메시지
   * @param cause   원인 예외
   */
  public UnauthorizedException(String message, Throwable cause) {
    super(message, ErrorCode.AUTHENTICATION_FAILED, cause);
  }

  /**
   * 인증 예외 생성자 (원인 포함, 기본 메시지 사용, ErrorCode.AUTHENTICATION_FAILED)
   *
   * @param cause 원인 예외
   */
  public UnauthorizedException(Throwable cause) {
    super(ErrorCode.AUTHENTICATION_FAILED, cause);
  }

  /**
   * 특정 ErrorCode를 사용하는 생성자 (예: INVALID_TOKEN, EXPIRED_TOKEN)
   *
   * @param errorCode 사용할 ErrorCode
   */
  public UnauthorizedException(ErrorCode errorCode) {
    super(errorCode);
  }

  /**
   * 특정 ErrorCode와 커스텀 메시지를 사용하는 생성자
   *
   * @param message   예외 메시지
   * @param errorCode 사용할 ErrorCode
   */
  public UnauthorizedException(String message, ErrorCode errorCode) {
    super(message, errorCode);
  }

  /**
   * 특정 ErrorCode, 커스텀 메시지, 원인을 사용하는 생성자
   *
   * @param message   예외 메시지
   * @param errorCode 사용할 ErrorCode
   * @param cause     원인 예외
   */
  public UnauthorizedException(String message, ErrorCode errorCode, Throwable cause) {
    super(message, errorCode, cause);
  }
}