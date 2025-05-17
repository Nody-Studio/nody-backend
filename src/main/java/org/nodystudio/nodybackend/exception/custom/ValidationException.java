package org.nodystudio.nodybackend.exception.custom;

import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.exception.FieldErrorProvider;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

/**
 * 입력값 검증 실패 시 발생하는 예외 (ErrorCode.VALIDATION_ERROR 사용)
 */
public class ValidationException extends BusinessException implements FieldErrorProvider {

  private final Map<String, String> fieldErrors;

  /**
   * 검증 예외 생성자 (기본 메시지 사용)
   */
  public ValidationException() {
    super(ErrorCode.VALIDATION_ERROR);
    this.fieldErrors = Collections.emptyMap();
  }

  /**
   * 검증 예외 생성자 (커스텀 메시지 사용)
   *
   * @param message 예외 메시지
   */
  public ValidationException(String message) {
    super(message, ErrorCode.VALIDATION_ERROR);
    this.fieldErrors = Collections.emptyMap();
  }

  /**
   * 검증 예외 생성자 (커스텀 메시지 및 필드 에러 포함)
   *
   * @param message     예외 메시지
   * @param fieldErrors 필드별 에러 메시지 맵
   */
  public ValidationException(String message, Map<String, String> fieldErrors) {
    super(message, ErrorCode.VALIDATION_ERROR);
    this.fieldErrors =
        fieldErrors != null ? Collections.unmodifiableMap(fieldErrors) : Collections.emptyMap();
  }

  /**
   * 검증 예외 생성자 (커스텀 메시지, 필드 에러 및 원인 포함)
   *
   * @param message     예외 메시지
   * @param fieldErrors 필드별 에러 메시지 맵
   * @param cause       원인 예외
   */
  public ValidationException(String message, Map<String, String> fieldErrors, Throwable cause) {
    super(message, ErrorCode.VALIDATION_ERROR, cause);
    this.fieldErrors =
        fieldErrors != null ? Collections.unmodifiableMap(fieldErrors) : Collections.emptyMap();
  }

  /**
   * Spring의 BindingResult로부터 ValidationException 생성
   *
   * @param bindingResult Spring의 바인딩 결과
   * @return ValidationException 인스턴스
   */
  public static ValidationException from(BindingResult bindingResult) {
    Map<String, String> errors = bindingResult.getFieldErrors().stream()
        .collect(Collectors.toMap(
            FieldError::getField,
            error -> error.getDefaultMessage() != null ? error.getDefaultMessage()
                : "유효하지 않은 값입니다.",
            (existingValue, newValue) -> existingValue + ", " + newValue));
    return new ValidationException(ErrorCode.VALIDATION_ERROR.getMessage(), errors);
  }

  /**
   * 필드별 에러 메시지 맵 반환
   *
   * @return 필드별 에러 메시지 맵 (수정 불가)
   */
  public Map<String, String> getFieldErrors() {
    return fieldErrors;
  }
}