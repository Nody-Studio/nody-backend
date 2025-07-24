package org.nodystudio.nodybackend.controller.thread;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.dto.ApiResponse;
import org.nodystudio.nodybackend.dto.thread.ThreadResponse;
import org.nodystudio.nodybackend.dto.thread.ThreadSearchRequest;
import org.nodystudio.nodybackend.fixture.ThreadTestFixture;
import org.nodystudio.nodybackend.security.userdetails.CustomUserDetails;
import org.nodystudio.nodybackend.service.thread.ThreadService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;

/**
 * ThreadController의 스레드 검색 및 목록 조회 기능을 테스트합니다.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ThreadController 검색/목록 조회 테스트")
class ThreadControllerSearchTest {

    @Mock
    private ThreadService threadService;

    @InjectMocks
    private ThreadController threadController;

    @Nested
    @DisplayName("GET /api/threads - 스레드 목록 조회")
    class GetThreadsTests {

        @Test
        @DisplayName("검색 조건 없이 전체 목록 조회 시 성공한다")
        void getThreads_WithoutSearch_ShouldReturnAllThreads() {
            // given
            ThreadSearchRequest searchRequest = ThreadTestFixture.createDefaultThreadSearchRequest();
            Pageable pageable = PageRequest.of(0, 20);

            List<ThreadResponse> threadList = List.of(
                ThreadTestFixture.createThreadResponse(1L, "첫 번째 스레드", true),
                ThreadTestFixture.createThreadResponse(2L, "두 번째 스레드", true)
            );

            Page<ThreadResponse> threadPage = ThreadTestFixture.createThreadPage(threadList, pageable);

            given(threadService.searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL)))
                .willReturn(threadPage);

            // when
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            ResponseEntity<ApiResponse<Page<ThreadResponse>>> response = threadController.getThreads(
                searchRequest, pageable, userDetails);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<Page<ThreadResponse>> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getStatus()).isEqualTo(200);
            assertThat(body.getData().getContent()).hasSize(2);
            assertThat(body.getMessage()).isEqualTo("스레드 목록 조회가 완료되었습니다.");

            verify(threadService).searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("키워드 검색으로 스레드 목록 조회 시 성공한다")
        void getThreads_WithKeyword_ShouldReturnFilteredThreads() {
            // given
            ThreadSearchRequest searchRequest = ThreadTestFixture.createKeywordSearchRequest("테스트");
            Pageable pageable = PageRequest.of(0, 20);

            List<ThreadResponse> filteredList = List.of(
                ThreadTestFixture.createThreadResponse(1L, "테스트 키워드가 포함된 스레드", true)
            );

            Page<ThreadResponse> threadPage = ThreadTestFixture.createThreadPage(filteredList, pageable);

            given(threadService.searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL)))
                .willReturn(threadPage);

            // when
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            ResponseEntity<ApiResponse<Page<ThreadResponse>>> response = threadController.getThreads(
                searchRequest, pageable, userDetails);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<Page<ThreadResponse>> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getData().getContent()).hasSize(1);
            assertThat(body.getData().getContent().get(0).getContent()).contains("테스트");

            verify(threadService).searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("특정 로그의 스레드 목록 조회 시 성공한다")
        void getThreads_WithLogId_ShouldReturnLogThreads() {
            // given
            ThreadSearchRequest searchRequest = ThreadTestFixture.createLogSearchRequest(10L);
            Pageable pageable = PageRequest.of(0, 20);

            List<ThreadResponse> logThreadList = List.of(
                ThreadTestFixture.createLinkedThreadResponse(1L, "로그에 연결된 스레드")
            );

            Page<ThreadResponse> threadPage = ThreadTestFixture.createThreadPage(logThreadList, pageable);

            given(threadService.searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL)))
                .willReturn(threadPage);

            // when
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            ResponseEntity<ApiResponse<Page<ThreadResponse>>> response = threadController.getThreads(
                searchRequest, pageable, userDetails);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<Page<ThreadResponse>> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getData().getContent()).hasSize(1);
            assertThat(body.getData().getContent().get(0).getIsLinkedToLog()).isTrue();

            verify(threadService).searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("페이징 정보와 함께 목록 조회 시 성공한다")
        void getThreads_WithPagination_ShouldReturnPagedResults() {
            // given
            ThreadSearchRequest searchRequest = ThreadSearchRequest.builder()
                .page(1)
                .size(10)
                .build();
            Pageable pageable = PageRequest.of(1, 10);

            List<ThreadResponse> pagedList = List.of(
                ThreadTestFixture.createThreadResponse(11L, "두 번째 페이지의 첫 번째 스레드", true)
            );

            Page<ThreadResponse> threadPage = ThreadTestFixture.createThreadPage(pagedList, pageable, 25);

            given(threadService.searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL)))
                .willReturn(threadPage);

            // when
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            ResponseEntity<ApiResponse<Page<ThreadResponse>>> response = threadController.getThreads(
                searchRequest, pageable, userDetails);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<Page<ThreadResponse>> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getData().getNumber()).isEqualTo(1);
            assertThat(body.getData().getSize()).isEqualTo(10);
            assertThat(body.getData().getTotalElements()).isEqualTo(25);

            verify(threadService).searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("비로그인 사용자도 공개 스레드 목록을 조회할 수 있다")
        void getThreads_AnonymousUser_ShouldReturnPublicThreads() {
            // given
            ThreadSearchRequest searchRequest = ThreadTestFixture.createDefaultThreadSearchRequest();
            Pageable pageable = PageRequest.of(0, 20);

            List<ThreadResponse> publicThreadList = List.of(
                ThreadTestFixture.createThreadResponse(1L, "공개 스레드", true)
            );

            Page<ThreadResponse> threadPage = ThreadTestFixture.createThreadPage(publicThreadList, pageable);

            given(threadService.searchThreads(any(ThreadSearchRequest.class), eq(null)))
                .willReturn(threadPage);

            // when
            ResponseEntity<ApiResponse<Page<ThreadResponse>>> response = threadController.getThreads(
                searchRequest, pageable, null);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<Page<ThreadResponse>> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getData().getContent()).hasSize(1);
            assertThat(body.getData().getContent().get(0).getIsPublic()).isTrue();

            verify(threadService).searchThreads(any(ThreadSearchRequest.class), eq(null));
        }
    }

    @Nested
    @DisplayName("GET /api/threads/independent - 독립 스레드 목록 조회")
    class GetIndependentThreadsTests {

        @Test
        @DisplayName("독립 스레드 목록 조회 시 성공한다")
        void getIndependentThreads_ShouldReturnIndependentThreads() {
            // given
            Pageable pageable = PageRequest.of(0, 20);

            List<ThreadResponse> independentThreads = List.of(
                ThreadTestFixture.createIndependentThreadResponse(1L, "독립 스레드 1"),
                ThreadTestFixture.createIndependentThreadResponse(2L, "독립 스레드 2")
            );

            Page<ThreadResponse> threadPage = ThreadTestFixture.createThreadPage(independentThreads, pageable);

            given(threadService.searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL)))
                .willReturn(threadPage);

            // when
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            ResponseEntity<ApiResponse<Page<ThreadResponse>>> response = threadController.getIndependentThreads(
                pageable, userDetails);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<Page<ThreadResponse>> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getStatus()).isEqualTo(200);
            assertThat(body.getData().getContent()).hasSize(2);
            assertThat(body.getData().getContent().get(0).getIsIndependent()).isTrue();
            assertThat(body.getData().getContent().get(1).getIsIndependent()).isTrue();
            assertThat(body.getMessage()).isEqualTo("독립 스레드 목록 조회가 완료되었습니다.");

            verify(threadService).searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("비로그인 사용자도 공개 독립 스레드 목록을 조회할 수 있다")
        void getIndependentThreads_AnonymousUser_ShouldReturnPublicIndependentThreads() {
            // given
            Pageable pageable = PageRequest.of(0, 20);

            List<ThreadResponse> publicIndependentThreads = List.of(
                ThreadTestFixture.createIndependentThreadResponse(1L, "공개 독립 스레드")
            );

            Page<ThreadResponse> threadPage = ThreadTestFixture.createThreadPage(publicIndependentThreads, pageable);

            given(threadService.searchThreads(any(ThreadSearchRequest.class), eq(null)))
                .willReturn(threadPage);

            // when
            ResponseEntity<ApiResponse<Page<ThreadResponse>>> response = threadController.getIndependentThreads(
                pageable, null);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<Page<ThreadResponse>> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getData().getContent()).hasSize(1);
            assertThat(body.getData().getContent().get(0).getIsPublic()).isTrue();
            assertThat(body.getData().getContent().get(0).getIsIndependent()).isTrue();

            verify(threadService).searchThreads(any(ThreadSearchRequest.class), eq(null));
        }
    }

    @Nested
    @DisplayName("GET /api/threads/linked - 로그 연결 스레드 목록 조회")
    class GetLinkedThreadsTests {

        @Test
        @DisplayName("로그 연결 스레드 목록 조회 시 성공한다")
        void getLinkedThreads_ShouldReturnLinkedThreads() {
            // given
            Pageable pageable = PageRequest.of(0, 20);

            List<ThreadResponse> linkedThreads = List.of(
                ThreadTestFixture.createLinkedThreadResponse(1L, "로그 연결 스레드 1"),
                ThreadTestFixture.createLinkedThreadResponse(2L, "로그 연결 스레드 2")
            );

            Page<ThreadResponse> threadPage = ThreadTestFixture.createThreadPage(linkedThreads, pageable);

            given(threadService.searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL)))
                .willReturn(threadPage);

            // when
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            ResponseEntity<ApiResponse<Page<ThreadResponse>>> response = threadController.getLinkedThreads(
                pageable, userDetails);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<Page<ThreadResponse>> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getStatus()).isEqualTo(200);
            assertThat(body.getData().getContent()).hasSize(2);
            assertThat(body.getData().getContent().get(0).getIsLinkedToLog()).isTrue();
            assertThat(body.getData().getContent().get(1).getIsLinkedToLog()).isTrue();
            assertThat(body.getMessage()).isEqualTo("로그 연결 스레드 목록 조회가 완료되었습니다.");

            verify(threadService).searchThreads(any(ThreadSearchRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("비로그인 사용자도 공개 로그 연결 스레드 목록을 조회할 수 있다")
        void getLinkedThreads_AnonymousUser_ShouldReturnPublicLinkedThreads() {
            // given
            Pageable pageable = PageRequest.of(0, 20);

            List<ThreadResponse> publicLinkedThreads = List.of(
                ThreadTestFixture.createLinkedThreadResponse(1L, "공개 로그 연결 스레드")
            );

            Page<ThreadResponse> threadPage = ThreadTestFixture.createThreadPage(publicLinkedThreads, pageable);

            given(threadService.searchThreads(any(ThreadSearchRequest.class), eq(null)))
                .willReturn(threadPage);

            // when
            ResponseEntity<ApiResponse<Page<ThreadResponse>>> response = threadController.getLinkedThreads(
                pageable, null);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<Page<ThreadResponse>> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getData().getContent()).hasSize(1);
            assertThat(body.getData().getContent().get(0).getIsPublic()).isTrue();
            assertThat(body.getData().getContent().get(0).getIsLinkedToLog()).isTrue();

            verify(threadService).searchThreads(any(ThreadSearchRequest.class), eq(null));
        }
    }
}