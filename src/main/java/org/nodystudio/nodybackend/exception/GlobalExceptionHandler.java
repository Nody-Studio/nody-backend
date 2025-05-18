package org.nodystudio.nodybackend.exception;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SecurityException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.dto.ApiResponse;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.exception.custom.BusinessException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

  /**
   * 표준화된 예외 처리 응답을 생성하는 템플릿 메소드
   *
   * @param ex        처리할 예외
   * @param errorCode 적용할 에러 코드
   * @param logLevel  로깅 레벨
   * @param details   추가 로깅 세부 정보 (선택적)
   * @return 표준화된 에러 응답
   */
  private ResponseEntity<ApiResponse<Object>> handleException(Exception ex, ErrorCode errorCode,
      LogLevel logLevel, String... details) {

    logException(ex, logLevel, details);

    if (ex instanceof FieldErrorProvider) {
      final ApiResponse<Object> response = ApiResponse.error(errorCode, ex);
      return ResponseEntity.status(errorCode.getStatus()).body(response);
    }

    final ApiResponse<Object> response = ApiResponse.error(errorCode, ex.getMessage());
    return ResponseEntity.status(errorCode.getStatus()).body(response);
  }

  /**
   * 로그 레벨 열거형
   */
  private enum LogLevel {
    WARN, ERROR;
  }

  /**
   * 예외 정보를 지정된 로그 레벨로 기록
   *
   * @param ex       기록할 예외
   * @param logLevel 로그 레벨
   * @param details  추가 세부 정보
   */
  private void logException(Exception ex, LogLevel logLevel, String... details) {
    String message = ex.getMessage();
    String exceptionType = ex.getClass().getSimpleName();
    String detailsStr = details.length > 0 ? " " + String.join(" ", details) : "";

    String logMessage = String.format("Handling %s: %s%s", exceptionType, message, detailsStr);

    if (logLevel == LogLevel.WARN) {
      log.warn(logMessage);
    } else {
      log.error(logMessage, ex);
    }
  }

  /**
   * {@link BusinessException} 및 하위 예외 처리
   */
  @ExceptionHandler(BusinessException.class)
  public ResponseEntity<ApiResponse<Object>> handleBusinessException(BusinessException ex) {
    final ErrorCode errorCode = ex.getErrorCode();
    String logMessage = String.format("Details: ErrorCode=%s, HttpStatus=%s", errorCode.getCode(),
        errorCode.getStatus());
    return handleException(ex, errorCode, LogLevel.WARN, logMessage);
  }

  /**
   * {@link MethodArgumentNotValidException} 처리 (주로 @Valid 어노테이션 실패 시)
   */
  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiResponse<Object>> handleMethodArgumentNotValidException(
      MethodArgumentNotValidException ex) {
    logException(ex, LogLevel.WARN);
    BindingResult bindingResult = ex.getBindingResult();
    Map<String, String> fieldErrors = bindingResult.getFieldErrors().stream()
        .filter(error -> error.getDefaultMessage() != null)
        .collect(java.util.stream.Collectors.toMap(
            FieldError::getField,
            FieldError::getDefaultMessage,
            (existingValue, newValue) -> existingValue));

    final ApiResponse<Object> response = ApiResponse.error(ErrorCode.INVALID_INPUT_VALUE,
        fieldErrors);
    return ResponseEntity.status(ErrorCode.INVALID_INPUT_VALUE.getStatus()).body(response);
  }

  /**
   * {@link BindException} 처리 (데이터 바인딩 실패 시)
   */
  @ExceptionHandler(BindException.class)
  public ResponseEntity<ApiResponse<Object>> handleBindException(BindException ex) {
    logException(ex, LogLevel.WARN);
    BindingResult bindingResult = ex.getBindingResult();
    Map<String, String> fieldErrors = bindingResult.getFieldErrors().stream()
        .filter(error -> error.getDefaultMessage() != null)
        .collect(java.util.stream.Collectors.toMap(
            FieldError::getField,
            FieldError::getDefaultMessage,
            (existingValue, newValue) -> existingValue));

    final ApiResponse<Object> response = ApiResponse.error(ErrorCode.INVALID_INPUT_VALUE,
        fieldErrors);
    return ResponseEntity.status(ErrorCode.INVALID_INPUT_VALUE.getStatus()).body(response);
  }

  /**
   * {@link MissingServletRequestParameterException} 처리 (필수 요청 파라미터 누락 시)
   */
  @ExceptionHandler(MissingServletRequestParameterException.class)
  public ResponseEntity<ApiResponse<Object>> handleMissingServletRequestParameterException(
      MissingServletRequestParameterException ex) {
    return handleException(ex, ErrorCode.REQUEST_PARAM_MISSING, LogLevel.WARN);
  }

  /**
   * {@link MethodArgumentTypeMismatchException} 처리 (요청 파라미터 타입 불일치 시)
   */
  @ExceptionHandler(MethodArgumentTypeMismatchException.class)
  public ResponseEntity<ApiResponse<Object>> handleMethodArgumentTypeMismatchException(
      MethodArgumentTypeMismatchException ex) {
    return handleException(ex, ErrorCode.INVALID_TYPE_VALUE, LogLevel.WARN);
  }

  /**
   * {@link HttpMessageNotReadableException} 처리 (잘못된 요청 본문 형식 등)
   */
  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<ApiResponse<Object>> handleHttpMessageNotReadableException(
      HttpMessageNotReadableException ex) {
    return handleException(ex, ErrorCode.INVALID_INPUT_VALUE, LogLevel.WARN);
  }

  /**
   * {@link HttpRequestMethodNotSupportedException} 처리 (지원하지 않는 HTTP 메서드 요청 시)
   */
  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  public ResponseEntity<ApiResponse<Object>> handleHttpRequestMethodNotSupportedException(
      HttpRequestMethodNotSupportedException ex, HttpServletRequest request) {
    String logMessage = String.format("Method %s not supported for %s. Supported methods are: %s",
        ex.getMethod(), request.getRequestURL().toString(), ex.getSupportedHttpMethods());
    return handleException(ex, ErrorCode.METHOD_NOT_ALLOWED, LogLevel.WARN, logMessage);
  }

  /**
   * {@link NoHandlerFoundException} 처리 (요청 URL에 해당하는 핸들러를 찾을 수 없을 때)
   */
  @ExceptionHandler(NoHandlerFoundException.class)
  public ResponseEntity<ApiResponse<Object>> handleNoHandlerFoundException(
      NoHandlerFoundException ex) {
    String logMessage = String.format("No handler found for %s %s", ex.getHttpMethod(),
        ex.getRequestURL());
    return handleException(ex, ErrorCode.RESOURCE_NOT_FOUND, LogLevel.WARN, logMessage);
  }

  /**
   * AccessDeniedException 처리 (파일 시스템 접근 거부)
   */
  @ExceptionHandler(java.nio.file.AccessDeniedException.class)
  public ResponseEntity<ApiResponse<Object>> handleNioAccessDeniedException(
      java.nio.file.AccessDeniedException ex) {
    return handleException(ex, ErrorCode.ACCESS_DENIED, LogLevel.WARN);
  }

  /**
   * AccessDeniedException 처리 (Spring Security 접근 거부)
   */
  @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
  public ResponseEntity<ApiResponse<Object>> handleSpringSecurityAccessDeniedException(
      org.springframework.security.access.AccessDeniedException ex) {
    return handleException(ex, ErrorCode.ACCESS_DENIED, LogLevel.WARN);
  }

  /**
   * JWT 예외 처리 그룹 - 토큰 만료
   */
  @ExceptionHandler(ExpiredJwtException.class)
  public ResponseEntity<ApiResponse<Object>> handleExpiredJwtException(ExpiredJwtException ex) {
    return handleException(ex, ErrorCode.EXPIRED_TOKEN, LogLevel.WARN);
  }

  /**
   * JWT 예외 처리 그룹 - 보안/서명 예외, 형식 오류, 미지원 토큰, 기타 JWT 예외
   */
  @ExceptionHandler({SecurityException.class, MalformedJwtException.class,
      UnsupportedJwtException.class, JwtException.class})
  public ResponseEntity<ApiResponse<Object>> handleJwtExceptions(JwtException ex) {
    return handleException(ex, ErrorCode.INVALID_TOKEN, LogLevel.WARN);
  }

  /**
   * 처리되지 않은 모든 {@link Exception} 처리
   */
  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiResponse<Object>> handleGlobalException(Exception ex) {
    return handleException(ex, ErrorCode.INTERNAL_SERVER_ERROR, LogLevel.ERROR);
  }
}