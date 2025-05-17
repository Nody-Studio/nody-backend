package org.nodystudio.nodybackend.exception;

import java.util.Map;

/**
 * 필드별 오류 메시지를 제공하는 예외를 위한 인터페이스입니다.
 */
public interface FieldErrorProvider {

  /**
   * 필드별 오류 메시지 맵을 반환합니다.
   *
   * @return 필드명을 키로, 오류 메시지를 값으로 하는 맵 (수정 불가할 수 있음)
   */
  Map<String, String> getFieldErrors();
}