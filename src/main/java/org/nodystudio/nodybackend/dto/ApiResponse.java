package org.nodystudio.nodybackend.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.LocalDateTime;
import java.util.List;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.dto.code.SuccessCode;
import org.nodystudio.nodybackend.exception.FieldErrorProvider;

/**
 * API 응답을 위한 범용 DTO 클래스입니다. 성공 시 데이터와 함께 상태, 코드, 메시지를 포함하며, 실패 시 에러 코드와 메시지,
 * 선택적으로 필드 에러 정보를
 * 포함합니다.
 *
 * @param <T> 응답 데이터의 타입
 */
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

  private int status;
  private String code;
  private String message;
  private T data;
  private List<FieldErrorDto> errors; // Map<String, String>에서 List<FieldErrorDto>로 변경
  private final LocalDateTime timestamp = LocalDateTime.now();

  /**
   * 성공 응답 생성자
   */
  private ApiResponse(int status, String code, String message, T data) {
    this.status = status;
    this.code = code;
    this.message = message;
    this.data = data;
  }

  /**
   * 실패 응답 생성자 (필드 에러 포함 가능)
   */
  private ApiResponse(int status, String code, String message, List<FieldErrorDto> errors) {
    this.status = status;
    this.code = code;
    this.message = message;
    this.errors = errors;
  }

  /**
   * 실패 응답 생성자 (필드 에러 없음)
   */
  private ApiResponse(int status, String code, String message) {
    this.status = status;
    this.code = code;
    this.message = message;
  }

  /**
   * 성공 응답을 생성합니다. (데이터만 포함)
   *
   * @param data 응답 데이터
   * @param <T>  데이터 타입
   * @return 성공 ApiResponse 객체
   */
  public static <T> ApiResponse<T> success(T data) {
    return new ApiResponse<>(SuccessCode.OK.getStatus().value(), SuccessCode.OK.getCode(),
        SuccessCode.OK.getMessage(),
        data);
  }

  /**
   * 성공 응답을 생성합니다. (메시지와 데이터 포함)
   *
   * @param message 성공 메시지
   * @param data    응답 데이터
   * @param <T>     데이터 타입
   * @return 성공 ApiResponse 객체
   */
  public static <T> ApiResponse<T> success(String message, T data) {
    return new ApiResponse<>(SuccessCode.OK.getStatus().value(), SuccessCode.OK.getCode(), message,
        data);
  }

  /**
   * 성공 응답을 생성합니다. (상태 코드, 커스텀 코드, 메시지, 데이터 포함)
   *
   * @param status  HTTP 상태 코드
   * @param code    커스텀 응답 코드
   * @param message 성공 메시지
   * @param data    응답 데이터
   * @param <T>     데이터 타입
   * @return 성공 ApiResponse 객체
   */
  public static <T> ApiResponse<T> success(int status, String code, String message, T data) {
    return new ApiResponse<>(status, code, message, data);
  }

  /**
   * {@link SuccessCode}를 기반으로 성공 응답을 생성합니다. (데이터 포함)
   *
   * @param successCode 성공 코드 열거형
   * @param data        응답 데이터
   * @param <T>         데이터 타입
   * @return 성공 ApiResponse 객체
   */
  public static <T> ApiResponse<T> success(SuccessCode successCode, T data) {
    return new ApiResponse<>(successCode.getStatus().value(), successCode.getCode(),
        successCode.getMessage(), data);
  }

  /**
   * {@link SuccessCode}와 커스텀 메시지를 기반으로 성공 응답을 생성합니다. (데이터 포함) 커스텀 메시지가 null이거나
   * 비어있으면
   * {@link SuccessCode}의 기본 메시지를 사용합니다.
   *
   * @param successCode 성공 코드 열거형
   * @param message     커스텀 성공 메시지
   * @param data        응답 데이터
   * @param <T>         데이터 타입
   * @return 성공 ApiResponse 객체
   */
  public static <T> ApiResponse<T> success(SuccessCode successCode, String message, T data) {
    String determinedMessage =
        (message == null || message.trim().isEmpty()) ? successCode.getMessage() : message;
    return new ApiResponse<>(successCode.getStatus().value(), successCode.getCode(),
        determinedMessage, data);
  }

  /**
   * {@link ErrorCode}를 기반으로 실패 응답을 생성합니다.
   *
   * @param errorCode 에러 코드 열거형
   * @param <T>       데이터 타입 (보통 Void 또는 Object)
   * @return 실패 ApiResponse 객체
   */
  public static <T> ApiResponse<T> error(ErrorCode errorCode) {
    return new ApiResponse<>(errorCode.getStatus().value(), errorCode.getCode(),
        errorCode.getMessage());
  }

  /**
   * {@link ErrorCode}와 커스텀 메시지를 기반으로 실패 응답을 생성합니다. 커스텀 메시지가 null이거나 비어있으면
   * {@link ErrorCode}의 기본
   * 메시지를 사용합니다.
   *
   * @param errorCode 에러 코드 열거형
   * @param message   커스텀 에러 메시지
   * @param <T>       데이터 타입
   * @return 실패 ApiResponse 객체
   */
  public static <T> ApiResponse<T> error(ErrorCode errorCode, String message) {
    String determinedMessage =
        (message == null || message.trim().isEmpty()) ? errorCode.getMessage() : message;
    return new ApiResponse<>(errorCode.getStatus().value(), errorCode.getCode(), determinedMessage);
  }

  /**
   * {@link ErrorCode}와 필드 에러 정보를 기반으로 실패 응답을 생성합니다.
   *
   * @param errorCode 에러 코드 열거형
   * @param errors    필드 에러 리스트
   * @param <T>       데이터 타입
   * @return 실패 ApiResponse 객체
   */
  public static <T> ApiResponse<T> error(ErrorCode errorCode,
      List<FieldErrorDto> errors) { // Map 대신
    // List<FieldErrorDto>
    return new ApiResponse<>(errorCode.getStatus().value(), errorCode.getCode(),
        errorCode.getMessage(), errors);
  }

  /**
   * {@link ErrorCode}와 발생한 예외 객체를 기반으로 실패 응답을 생성합니다. 예외 객체에서 메시지를 추출하여 사용하며, 예외가
   * {@link FieldErrorProvider}를 구현한 경우 필드 에러 정보도 포함합니다.
   *
   * @param errorCode 에러 코드 열거형
   * @param exception 발생한 예외 객체
   * @param <T>       데이터 타입
   * @return 실패 ApiResponse 객체
   */
  public static <T> ApiResponse<T> error(ErrorCode errorCode, Exception exception) {
    String determinedMessage;
    if (exception != null && exception.getMessage() != null && !exception.getMessage().trim()
        .isEmpty()) {
      determinedMessage = exception.getMessage();
    } else {
      determinedMessage = errorCode.getMessage();
    }

    List<FieldErrorDto> fieldErrorsList = null;
    if (exception instanceof FieldErrorProvider) {
      fieldErrorsList = ((FieldErrorProvider) exception).getFieldErrorsList();
    }

    if (fieldErrorsList != null && !fieldErrorsList.isEmpty()) {
      return new ApiResponse<>(errorCode.getStatus().value(), errorCode.getCode(),
          determinedMessage, fieldErrorsList);
    } else {
      return new ApiResponse<>(errorCode.getStatus().value(), errorCode.getCode(),
          determinedMessage);
    }
  }
}
