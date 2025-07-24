package org.nodystudio.nodybackend.dto.code;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum SuccessCode {

  // 일반 성공
  OK(HttpStatus.OK, "SUCCESS_S001", "요청이 성공적으로 처리되었습니다."),
  CREATED(HttpStatus.CREATED, "SUCCESS_S002", "리소스가 성공적으로 생성되었습니다."),
  NO_CONTENT(HttpStatus.NO_CONTENT, "SUCCESS_S003", "요청이 성공적으로 처리되었지만 반환할 콘텐츠가 없습니다."),

  // 사용자 관련 성공
  USER_INFO_RETRIEVED(HttpStatus.OK, "USER_S001", "사용자 정보가 성공적으로 조회되었습니다."),
  USER_PROFILE_UPDATED(HttpStatus.OK, "USER_S002", "사용자 프로필이 성공적으로 업데이트되었습니다."),
  USER_DELETED(HttpStatus.OK, "USER_S003", "사용자 계정이 성공적으로 삭제되었습니다."),

  // 인증 관련 성공
  LOGIN_SUCCESS(HttpStatus.OK, "AUTH_S001", "로그인에 성공했습니다."),
  LOGOUT_SUCCESS(HttpStatus.OK, "AUTH_S002", "로그아웃에 성공했습니다."),
  TOKEN_REFRESHED(HttpStatus.OK, "AUTH_S003", "토큰이 성공적으로 재발급되었습니다."),

  // 좋아요 관련 성공
  LIKE_TOGGLE_SUCCESS(HttpStatus.OK, "LIKE_S001", "좋아요 토글이 성공적으로 처리되었습니다."),
  LIKE_STATUS_RETRIEVED(HttpStatus.OK, "LIKE_S002", "좋아요 상태가 성공적으로 조회되었습니다."),

  // 스레드 관련 성공
  THREAD_CREATED(HttpStatus.CREATED, "THREAD_S001", "스레드가 성공적으로 생성되었습니다."),
  THREAD_RETRIEVED(HttpStatus.OK, "THREAD_S002", "스레드 조회가 완료되었습니다."),
  THREAD_LIST_RETRIEVED(HttpStatus.OK, "THREAD_S003", "스레드 목록 조회가 완료되었습니다."),
  THREAD_UPDATED(HttpStatus.OK, "THREAD_S004", "스레드가 성공적으로 수정되었습니다."),
  THREAD_DELETED(HttpStatus.OK, "THREAD_S005", "스레드가 성공적으로 삭제되었습니다."),
  INDEPENDENT_THREAD_LIST_RETRIEVED(HttpStatus.OK, "THREAD_S006", "독립 스레드 목록 조회가 완료되었습니다."),
  LINKED_THREAD_LIST_RETRIEVED(HttpStatus.OK, "THREAD_S007", "로그 연결 스레드 목록 조회가 완료되었습니다.");

  private final HttpStatus status;
  private final String code;
  private final String message;
}