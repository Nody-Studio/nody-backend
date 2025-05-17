package org.nodystudio.nodybackend.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.LocalDateTime;
import java.util.Map;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.nodystudio.nodybackend.exception.ErrorCode;
import org.nodystudio.nodybackend.exception.FieldErrorProvider;

/**
 * API 에러 발생 시 응답을 위한 DTO 클래스입니다. 에러 상태, 메시지, 에러 코드, 필드 에러(선택적), 타임스탬프를 포함합니다.
 */
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponseDto {

  private int status;
  private String message;
  private String errorCode;
  private Map<String, String> errors;
  private final LocalDateTime timestamp = LocalDateTime.now();

  /**
   * 모든 필드를 초기화하는 private 생성자입니다.
   *
   * @param status    HTTP 상태 코드
   * @param message   에러 메시지
   * @param errorCode 커스텀 에러 코드
   * @param errors    필드 에러 맵 (선택적)
   */
  private ErrorResponseDto(int status, String message, String errorCode,
      Map<String, String> errors) {
    this.status = status;
    this.message = message;
    this.errorCode = errorCode;
    this.errors = errors;
  }

  /**
   * 필드 에러 없이 ErrorResponseDto 객체를 생성하는 private 생성자입니다.
   *
   * @param status    HTTP 상태 코드
   * @param message   에러 메시지
   * @param errorCode 커스텀 에러 코드
   */
  private ErrorResponseDto(int status, String message, String errorCode) {
    this(status, message, errorCode, null);
  }

  /**
   * {@link ErrorCode}를 기반으로 ErrorResponseDto 객체를 생성합니다.
   *
   * @param errorCode 에러 코드 열거형
   * @return 생성된 ErrorResponseDto 객체
   */
  public static ErrorResponseDto of(ErrorCode errorCode) {
    return new ErrorResponseDto(errorCode.getStatus().value(), errorCode.getMessage(),
        errorCode.getCode());
  }

  /**
   * {@link ErrorCode}와 커스텀 메시지를 기반으로 ErrorResponseDto 객체를 생성합니다. 커스텀 메시지가 null이거나 비어있으면
   * {@link ErrorCode}의 기본 메시지를 사용합니다.
   *
   * @param errorCode 에러 코드 열거형
   * @param message   커스텀 에러 메시지
   * @return 생성된 ErrorResponseDto 객체
   */
  public static ErrorResponseDto of(ErrorCode errorCode, String message) {
    if (message == null || message.trim().isEmpty()) {
      return of(errorCode);
    }
    return new ErrorResponseDto(errorCode.getStatus().value(), message, errorCode.getCode());
  }

  /**
   * {@link ErrorCode}와 발생한 예외 객체를 기반으로 ErrorResponseDto 객체를 생성합니다. 예외 객체에서 메시지를 추출하여 사용하며, 예외가
   * {@link FieldErrorProvider}를 구현한 경우 필드 에러 정보도 포함합니다.
   *
   * @param errorCode 에러 코드 열거형
   * @param exception 발생한 예외 객체
   * @return 생성된 ErrorResponseDto 객체
   */
  public static ErrorResponseDto of(ErrorCode errorCode, Exception exception) {
    String determinedMessage;
    if (exception != null && exception.getMessage() != null) {
      determinedMessage = exception.getMessage();
    } else {
      determinedMessage = errorCode.getMessage();
    }

    Map<String, String> fieldErrors = null;
    if (exception instanceof FieldErrorProvider) {
      fieldErrors = ((FieldErrorProvider) exception).getFieldErrors();
    }

    return new ErrorResponseDto(
        errorCode.getStatus().value(),
        determinedMessage,
        errorCode.getCode(),
        fieldErrors);
  }
}