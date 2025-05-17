package org.nodystudio.nodybackend.exception.custom;

import org.nodystudio.nodybackend.dto.code.ErrorCode;

/**
 * 유효하지 않은 토큰 관련 예외 (ErrorCode.INVALID_TOKEN 또는 EXPIRED_TOKEN 사용)
 */
public class InvalidTokenException extends BusinessException {

  /**
   * 유효하지 않은 토큰 예외 생성자 (기본 메시지 사용)
   */
  public InvalidTokenException() {
    super(ErrorCode.INVALID_TOKEN);
  }

  /**
   * 유효하지 않은 토큰 예외 생성자 (커스텀 메시지 사용)
   *
   * @param message 예외 메시지
   */
  public InvalidTokenException(String message) {
    super(message, ErrorCode.INVALID_TOKEN);
  }

  /**
   * 유효하지 않은 토큰 예외 생성자 (커스텀 메시지 및 원인 포함)
   *
   * @param message 예외 메시지
   * @param cause   원인 예외
   */
  public InvalidTokenException(String message, Throwable cause) {
    super(message, ErrorCode.INVALID_TOKEN, cause);
  }

  /**
   * 유효하지 않은 토큰 예외 생성자 (원인 포함, 기본 메시지 사용)
   *
   * @param cause 원인 예외
   */
  public InvalidTokenException(Throwable cause) {
    super(ErrorCode.INVALID_TOKEN, cause);
  }

  /**
   * 특정 ErrorCode를 사용하는 생성자 (예: EXPIRED_TOKEN)
   *
   * @param errorCode 사용할 ErrorCode
   */
  public InvalidTokenException(ErrorCode errorCode) {
    super(errorCode);
  }

  /**
   * 특정 ErrorCode와 커스텀 메시지를 사용하는 생성자
   *
   * @param message   예외 메시지
   * @param errorCode 사용할 ErrorCode
   */
  public InvalidTokenException(String message, ErrorCode errorCode) {
    super(message, errorCode);
  }

  /**
   * 특정 ErrorCode, 커스텀 메시지, 원인을 사용하는 생성자
   *
   * @param message   예외 메시지
   * @param errorCode 사용할 ErrorCode
   * @param cause     원인 예외
   */
  public InvalidTokenException(String message, ErrorCode errorCode, Throwable cause) {
    super(message, errorCode, cause);
  }
}
