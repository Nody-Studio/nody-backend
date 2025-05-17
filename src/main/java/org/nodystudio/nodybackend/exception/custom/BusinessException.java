package org.nodystudio.nodybackend.exception.custom;

import org.nodystudio.nodybackend.exception.ErrorCode;
import org.springframework.http.HttpStatus;

/**
 * 비즈니스 로직 관련 기본 예외 클래스 모든 커스텀 비즈니스 예외는 이 클래스를 상속받아야 함
 */
public abstract class BusinessException extends RuntimeException {

  private final ErrorCode errorCode;

  /**
   * 비즈니스 예외 생성자
   *
   * @param errorCode ErrorCode Enum 객체
   */
  public BusinessException(ErrorCode errorCode) {
    super(errorCode.getMessage());
    this.errorCode = errorCode;
  }

  /**
   * 비즈니스 예외 생성자 (커스텀 메시지 사용)
   *
   * @param message   커스텀 예외 메시지
   * @param errorCode ErrorCode Enum 객체
   */
  public BusinessException(String message, ErrorCode errorCode) {
    super(message);
    this.errorCode = errorCode;
  }

  /**
   * 비즈니스 예외 생성자 (원인 포함)
   *
   * @param errorCode ErrorCode Enum 객체
   * @param cause     원인 예외
   */
  public BusinessException(ErrorCode errorCode, Throwable cause) {
    super(errorCode.getMessage(), cause);
    this.errorCode = errorCode;
  }

  /**
   * 비즈니스 예외 생성자 (커스텀 메시지 및 원인 포함)
   *
   * @param message   커스텀 예외 메시지
   * @param errorCode ErrorCode Enum 객체
   * @param cause     원인 예외
   */
  public BusinessException(String message, ErrorCode errorCode, Throwable cause) {
    super(message, cause);
    this.errorCode = errorCode;
  }

  /**
   * ErrorCode Enum 객체 반환
   *
   * @return ErrorCode Enum 객체
   */
  public ErrorCode getErrorCode() {
    return errorCode;
  }

  /**
   * 에러 코드 문자열 반환
   *
   * @return 에러 코드 문자열 (예: "C001")
   */
  public String getErrorCodeString() {
    return errorCode.getCode();
  }

  /**
   * HTTP 상태 코드 반환
   *
   * @return HTTP 상태 코드
   */
  public HttpStatus getHttpStatus() {
    return errorCode.getStatus();
  }
}