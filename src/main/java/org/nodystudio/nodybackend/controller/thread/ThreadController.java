package org.nodystudio.nodybackend.controller.thread;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.controller.thread.docs.ThreadApiDocs;
import org.nodystudio.nodybackend.domain.enums.SortDirection;
import org.nodystudio.nodybackend.domain.enums.ThreadSortField;
import org.nodystudio.nodybackend.domain.enums.ThreadType;
import org.nodystudio.nodybackend.dto.ApiResponse;
import org.nodystudio.nodybackend.dto.code.SuccessCode;
import org.nodystudio.nodybackend.dto.thread.ThreadCreateRequest;
import org.nodystudio.nodybackend.dto.thread.ThreadResponse;
import org.nodystudio.nodybackend.dto.thread.ThreadSearchRequest;
import org.nodystudio.nodybackend.dto.thread.ThreadUpdateRequest;
import org.nodystudio.nodybackend.security.userdetails.CustomUserDetails;
import org.nodystudio.nodybackend.service.thread.ThreadService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/threads")
@RequiredArgsConstructor
public class ThreadController implements ThreadApiDocs {

  private final ThreadService threadService;

  // === 공통 유틸리티 메소드 ===

  /**
   * 로그에 표시할 사용자 정보를 안전하게 가져옵니다. 인증되지 않은 사용자의 경우 "익명"을 반환합니다.
   */
  private String getUserDisplayName(CustomUserDetails userDetails) {
    return userDetails != null ? userDetails.getEmail() : "익명";
  }

  /**
   * Pageable을 ThreadSearchRequest로 변환합니다.
   *
   * @param pageable   페이지 정보
   * @param keyword    검색 키워드
   * @param threadType 스레드 타입
   * @return 변환된 ThreadSearchRequest
   */
  private ThreadSearchRequest createSearchRequestFromPageable(Pageable pageable, String keyword,
      ThreadType threadType) {
    return ThreadSearchRequest.builder()
        .page(pageable.getPageNumber())
        .size(pageable.getPageSize())
        .sortBy(pageable.getSort().iterator().hasNext() ?
            ThreadSortField.fromValueOrNull(pageable.getSort().iterator().next().getProperty()) :
            ThreadSortField.CREATED_AT)
        .sortDirection(
            pageable.getSort().iterator().hasNext() && pageable.getSort().iterator().next()
                .isDescending() ? SortDirection.DESC : SortDirection.ASC)
        .keyword(keyword)
        .threadType(threadType)
        .build();
  }

  /**
   * 스레드 생성 POST /api/threads
   */
  @Override
  @PostMapping
  public ResponseEntity<ApiResponse<ThreadResponse>> createThread(
      @AuthenticationPrincipal CustomUserDetails userDetails,
      @Valid @RequestBody ThreadCreateRequest request) {

    log.info("스레드 생성 요청 - 사용자: {}",
        getUserDisplayName(userDetails));

    ThreadResponse response = threadService.createThread(request, userDetails.getEmail());

    return ResponseEntity.status(HttpStatus.CREATED)
        .body(ApiResponse.success(SuccessCode.THREAD_CREATED, response));
  }

  /**
   * 스레드 단건 조회 GET /api/threads/{id}
   */
  @Override
  @GetMapping("/{id}")
  public ResponseEntity<ApiResponse<ThreadResponse>> getThread(
      @PathVariable Long id,
      @Nullable @AuthenticationPrincipal CustomUserDetails userDetails) {

    log.info("스레드 단건 조회 - ID: {}, 사용자: {}",
        id, getUserDisplayName(userDetails));

    ThreadResponse response = threadService.getThread(
        id, userDetails != null ? userDetails.getEmail() : null);

    return ResponseEntity.ok(ApiResponse.success(SuccessCode.THREAD_RETRIEVED, response));
  }

  /**
   * 스레드 목록 조회 (검색, 필터링, 페이징) GET /api/threads
   */
  @Override
  @GetMapping
  public ResponseEntity<ApiResponse<Page<ThreadResponse>>> getThreads(
      @Valid @ModelAttribute ThreadSearchRequest searchRequest,
      @PageableDefault(size = 20, sort = "createdAt") Pageable pageable,
      @Nullable @AuthenticationPrincipal CustomUserDetails userDetails) {

    log.info("스레드 목록 조회 - 키워드: {}, 타입: {}, 로그ID: {}, 사용자: {}",
        searchRequest.getKeyword(),
        searchRequest.getThreadType(),
        searchRequest.getLogId(),
        getUserDisplayName(userDetails));

    Page<ThreadResponse> response = threadService.searchThreads(searchRequest,
        userDetails != null ? userDetails.getEmail() : null);

    return ResponseEntity.ok(ApiResponse.success(SuccessCode.THREAD_LIST_RETRIEVED, response));
  }

  /**
   * 스레드 수정 PUT /api/threads/{id}
   */
  @Override
  @PutMapping("/{id}")
  public ResponseEntity<ApiResponse<ThreadResponse>> updateThread(
      @PathVariable Long id,
      @AuthenticationPrincipal CustomUserDetails userDetails,
      @Valid @RequestBody ThreadUpdateRequest request) {

    log.info("스레드 수정 요청 - ID: {}, 사용자: {}", id, getUserDisplayName(userDetails));

    ThreadResponse response = threadService.updateThread(id, request, userDetails.getEmail());

    return ResponseEntity.ok(ApiResponse.success(SuccessCode.THREAD_UPDATED, response));
  }

  /**
   * 스레드 삭제 DELETE /api/threads/{id}
   */
  @Override
  @DeleteMapping("/{id}")
  public ResponseEntity<ApiResponse<Void>> deleteThread(
      @PathVariable Long id,
      @AuthenticationPrincipal CustomUserDetails userDetails) {

    log.info("스레드 삭제 요청 - ID: {}, 사용자: {}", id, getUserDisplayName(userDetails));

    threadService.deleteThread(id, userDetails.getEmail());

    return ResponseEntity.ok(ApiResponse.success(SuccessCode.THREAD_DELETED, null));
  }


  /**
   * 독립 스레드 목록 조회 (로그에 연결되지 않은 스레드) GET /api/threads/independent
   */
  @Override
  @GetMapping("/independent")
  public ResponseEntity<ApiResponse<Page<ThreadResponse>>> getIndependentThreads(
      @PageableDefault(size = 20, sort = "createdAt") Pageable pageable,
      @Nullable @AuthenticationPrincipal CustomUserDetails userDetails) {
    String keyword = null;

    log.info("독립 스레드 목록 조회 - 키워드: {}, 사용자: {}", keyword,
        getUserDisplayName(userDetails));

    ThreadSearchRequest searchRequest = createSearchRequestFromPageable(pageable, keyword,
        ThreadType.INDEPENDENT);

    Page<ThreadResponse> response = threadService.searchThreads(searchRequest,
        userDetails != null ? userDetails.getEmail() : null);

    return ResponseEntity.ok(ApiResponse.success(SuccessCode.INDEPENDENT_THREAD_LIST_RETRIEVED, response));
  }

  /**
   * 로그 연결 스레드 목록 조회 (로그에 연결된 스레드) GET /api/threads/linked
   */
  @Override
  @GetMapping("/linked")
  public ResponseEntity<ApiResponse<Page<ThreadResponse>>> getLinkedThreads(
      @PageableDefault(size = 20, sort = "createdAt") Pageable pageable,
      @Nullable @AuthenticationPrincipal CustomUserDetails userDetails) {
    String keyword = null;

    log.info("로그 연결 스레드 목록 조회 - 키워드: {}, 사용자: {}", keyword,
        getUserDisplayName(userDetails));

    ThreadSearchRequest searchRequest = createSearchRequestFromPageable(pageable, keyword,
        ThreadType.LINKED);

    Page<ThreadResponse> response = threadService.searchThreads(searchRequest,
        userDetails != null ? userDetails.getEmail() : null);

    return ResponseEntity.ok(ApiResponse.success(SuccessCode.LINKED_THREAD_LIST_RETRIEVED, response));
  }
}