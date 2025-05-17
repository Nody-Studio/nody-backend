package org.nodystudio.nodybackend.dto.code;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

  // Common Errors
  INVALID_INPUT_VALUE(HttpStatus.BAD_REQUEST, "C001", "유효하지 않은 입력 값입니다."),
  METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "C002", "지원하지 않는 HTTP 메서드입니다."),
  INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "C003", "서버 내부 오류가 발생했습니다."),
  INVALID_TYPE_VALUE(HttpStatus.BAD_REQUEST, "C004", "유효하지 않은 타입 값입니다."),
  ACCESS_DENIED(HttpStatus.FORBIDDEN, "C005", "접근이 거부되었습니다."),
  REQUEST_PARAM_MISSING(HttpStatus.BAD_REQUEST, "C006", "필수 요청 파라미터가 누락되었습니다."),

  // Authentication & Authorization Errors
  AUTHENTICATION_FAILED(HttpStatus.UNAUTHORIZED, "A001", "인증에 실패했습니다."),
  INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "A002", "유효하지 않은 토큰입니다."),
  EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "A003", "만료된 토큰입니다."),
  TOKEN_NOT_FOUND(HttpStatus.UNAUTHORIZED, "A004", "토큰을 찾을 수 없습니다."),
  INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "A005", "유효하지 않은 리프레시 토큰입니다."),
  REFRESH_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "A006", "리프레시 토큰이 만료되었습니다."),
  USER_NOT_AUTHENTICATED(HttpStatus.UNAUTHORIZED, "A007", "인증되지 않은 사용자입니다."),
  OAUTH_AUTHENTICATION_FAILED(HttpStatus.UNAUTHORIZED, "A008", "OAuth2 인증에 실패했습니다."),

  // User Errors
  USER_NOT_FOUND(HttpStatus.NOT_FOUND, "U001", "사용자를 찾을 수 없습니다."),
  DUPLICATE_EMAIL(HttpStatus.CONFLICT, "U002", "이미 사용중인 이메일입니다."),
  DUPLICATE_NICKNAME(HttpStatus.CONFLICT, "U003", "이미 사용중인 닉네임입니다."),
  INVALID_PASSWORD(HttpStatus.BAD_REQUEST, "U004", "비밀번호가 일치하지 않습니다."),

  // Resource Errors
  RESOURCE_NOT_FOUND(HttpStatus.NOT_FOUND, "R001", "리소스를 찾을 수 없습니다."),

  // Validation Errors
  VALIDATION_ERROR(HttpStatus.BAD_REQUEST, "V001", "입력 값 유효성 검사에 실패했습니다.");

  private final HttpStatus status;
  private final String code;
  private final String message;
}