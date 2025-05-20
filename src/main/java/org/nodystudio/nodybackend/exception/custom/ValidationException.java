package org.nodystudio.nodybackend.exception.custom;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.nodystudio.nodybackend.dto.FieldErrorDto;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.exception.FieldErrorProvider;
import org.springframework.validation.BindingResult;

/**
 * 입력값 검증 실패 시 발생하는 예외 (ErrorCode.VALIDATION_ERROR 사용)
 */
public class ValidationException extends BusinessException implements FieldErrorProvider {

  private final List<FieldErrorDto> fieldErrorsList;

  /**
   * 검증 예외 생성자 (기본 메시지 사용)
   */
  public ValidationException() {
    super(ErrorCode.VALIDATION_ERROR);
    this.fieldErrorsList = Collections.emptyList();
  }

  /**
   * 검증 예외 생성자 (커스텀 메시지 사용)
   *
   * @param message 예외 메시지
   */
  public ValidationException(String message) {
    super(message, ErrorCode.VALIDATION_ERROR);
    this.fieldErrorsList = Collections.emptyList();
  }

  /**
   * 검증 예외 생성자 (커스텀 메시지 및 필드 에러 포함)
   *
   * @param message         예외 메시지
   * @param fieldErrorsList 필드별 에러 메시지 리스트
   */
  public ValidationException(String message, List<FieldErrorDto> fieldErrorsList) {
    super(message, ErrorCode.VALIDATION_ERROR);
    this.fieldErrorsList = fieldErrorsList != null ? Collections.unmodifiableList(fieldErrorsList)
        : Collections.emptyList();
  }

  /**
   * 검증 예외 생성자 (커스텀 메시지, 필드 에러 및 원인 포함)
   *
   * @param message         예외 메시지
   * @param fieldErrorsList 필드별 에러 메시지 리스트
   * @param cause           원인 예외
   */
  public ValidationException(String message, List<FieldErrorDto> fieldErrorsList, Throwable cause) {
    super(message, ErrorCode.VALIDATION_ERROR, cause);
    this.fieldErrorsList = fieldErrorsList != null ? Collections.unmodifiableList(fieldErrorsList)
        : Collections.emptyList();
  }

  /**
   * Spring의 BindingResult로부터 ValidationException 생성
   *
   * @param bindingResult Spring의 바인딩 결과
   * @return ValidationException 인스턴스
   */
  public static ValidationException from(BindingResult bindingResult) {
    List<FieldErrorDto> errors = bindingResult.getFieldErrors().stream()
        .map(error -> new FieldErrorDto(error.getField(),
            error.getDefaultMessage() != null ? error.getDefaultMessage() : "유효하지 않은 값입니다."))
        .collect(Collectors.toList());
    return new ValidationException(ErrorCode.VALIDATION_ERROR.getMessage(), errors);
  }

  /**
   * 필드별 에러 메시지 리스트 반환
   *
   * @return 필드별 에러 메시지 리스트 (수정 불가)
   */
  @Override
  public List<FieldErrorDto> getFieldErrorsList() {
    return fieldErrorsList;
  }
}