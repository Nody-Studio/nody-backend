package org.nodystudio.nodybackend.dto;

import lombok.Getter;

/**
 * API 응답 시 필드 에러 정보를 담는 DTO 클래스입니다.
 */
@Getter
public class FieldErrorDto {
  private final String field;
  private final String message;

  public FieldErrorDto(String field, String message) {
    this.field = field;
    this.message = message;
  }
}