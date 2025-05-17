package org.nodystudio.nodybackend.exception.custom;

import org.nodystudio.nodybackend.exception.ErrorCode;

/**
 * 요청한 리소스를 찾을 수 없을 때 발생하는 예외 (ErrorCode.RESOURCE_NOT_FOUND 사용)
 */
public class ResourceNotFoundException extends BusinessException {

  /**
   * 리소스를 찾을 수 없는 예외 생성자 (기본 메시지 사용)
   */
  public ResourceNotFoundException() {
    super(ErrorCode.RESOURCE_NOT_FOUND);
  }

  /**
   * 리소스를 찾을 수 없는 예외 생성자 (커스텀 메시지 사용)
   *
   * @param message 예외 메시지
   */
  public ResourceNotFoundException(String message) {
    super(message, ErrorCode.RESOURCE_NOT_FOUND);
  }

  /**
   * 리소스를 찾을 수 없는 예외 생성자 (커스텀 메시지 및 원인 포함)
   *
   * @param message 예외 메시지
   * @param cause   원인 예외
   */
  public ResourceNotFoundException(String message, Throwable cause) {
    super(message, ErrorCode.RESOURCE_NOT_FOUND, cause);
  }

  /**
   * 리소스를 찾을 수 없는 예외 생성자 (원인 포함, 기본 메시지 사용)
   *
   * @param cause 원인 예외
   */
  public ResourceNotFoundException(Throwable cause) {
    super(ErrorCode.RESOURCE_NOT_FOUND, cause);
  }

  /**
   * 특정 ID의 리소스를 찾을 수 없는 경우의 예외 생성 (커스텀 메시지 포맷 사용)
   *
   * @param resourceName 리소스 이름 (예: "User", "Thread", "Log")
   * @param fieldName    필드 이름 (예: "id", "email")
   * @param fieldValue   필드 값
   * @return ResourceNotFoundException 인스턴스
   */
  public static ResourceNotFoundException of(String resourceName, String fieldName,
      Object fieldValue) {
    String message = String.format("'%s'에서 '%s' 값이 '%s'인 리소스를 찾을 수 없습니다.", resourceName, fieldName,
        fieldValue);
    return new ResourceNotFoundException(message);
  }

  /**
   * 특정 ID의 리소스를 찾을 수 없는 경우의 예외 생성 (커스텀 메시지 포맷 및 원인 사용)
   *
   * @param resourceName 리소스 이름
   * @param fieldName    필드 이름
   * @param fieldValue   필드 값
   * @param cause        원인 예외
   * @return ResourceNotFoundException 인스턴스
   */
  public static ResourceNotFoundException of(String resourceName, String fieldName,
      Object fieldValue,
      Throwable cause) {
    String message = String.format("'%s'에서 '%s' 값이 '%s'인 리소스를 찾을 수 없습니다.", resourceName, fieldName,
        fieldValue);
    return new ResourceNotFoundException(message, cause);
  }
}