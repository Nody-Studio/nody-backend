package org.nodystudio.nodybackend.exception;

import java.util.List;
import org.nodystudio.nodybackend.dto.FieldErrorDto;

/**
 * 필드별 오류 메시지를 제공하는 예외를 위한 인터페이스입니다.
 */
public interface FieldErrorProvider {

  /**
   * 필드별 오류 메시지 리스트를 반환합니다.
   *
   * @return FieldErrorDto 객체의 리스트 (수정 불가할 수 있음)
   */
  List<FieldErrorDto> getFieldErrorsList();
}