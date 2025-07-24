package org.nodystudio.nodybackend.controller.thread;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willDoNothing;
import static org.mockito.Mockito.verify;

import java.util.Objects;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.dto.ApiResponse;
import org.nodystudio.nodybackend.dto.thread.ThreadCreateRequest;
import org.nodystudio.nodybackend.dto.thread.ThreadResponse;
import org.nodystudio.nodybackend.fixture.ThreadTestFixture;
import org.nodystudio.nodybackend.security.userdetails.CustomUserDetails;
import org.nodystudio.nodybackend.service.thread.ThreadService;
import org.springframework.http.ResponseEntity;

/**
 * ThreadController의 기본 CRUD 기능을 테스트합니다.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ThreadController 기본 CRUD 테스트")
class ThreadControllerBasicTest {

    @Mock
    private ThreadService threadService;

    @InjectMocks
    private ThreadController threadController;

    @Test
    @DisplayName("POST /api/threads - 스레드 생성 API 테스트")
    void createThread_Success() {
        // given
        ThreadCreateRequest request = ThreadTestFixture.createDefaultThreadCreateRequest();
        ThreadResponse expectedResponse = ThreadTestFixture.createThreadResponse(1L, "새 스레드 내용", true);

        given(threadService.createThread(any(ThreadCreateRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL)))
            .willReturn(expectedResponse);

        // when
        CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
        ResponseEntity<ApiResponse<ThreadResponse>> response = threadController.createThread(
            userDetails, request);

        // then
        assertThat(response.getStatusCode().value()).isEqualTo(201);
        assertThat(response.getBody()).isNotNull();
        ApiResponse<ThreadResponse> body = Objects.requireNonNull(response.getBody());
        assertThat(body.getStatus()).isEqualTo(201);
        assertThat(body.getData().getId()).isEqualTo(1L);
        assertThat(body.getData().getContent()).isEqualTo("새 스레드 내용");
        assertThat(body.getMessage()).isEqualTo("스레드가 성공적으로 생성되었습니다.");

        verify(threadService).createThread(any(ThreadCreateRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
    }

    @Test
    @DisplayName("GET /api/threads/{id} - 스레드 단건 조회 API 테스트")
    void getThread_Success() {
        // given
        ThreadResponse expectedResponse = ThreadTestFixture.createDefaultThreadResponse();
        given(threadService.getThread(ThreadTestFixture.DEFAULT_THREAD_ID, null))
            .willReturn(expectedResponse);

        // when
        ResponseEntity<ApiResponse<ThreadResponse>> response = threadController.getThread(
            ThreadTestFixture.DEFAULT_THREAD_ID, null);

        // then
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isNotNull();
        ApiResponse<ThreadResponse> body = Objects.requireNonNull(response.getBody());
        assertThat(body.getStatus()).isEqualTo(200);
        assertThat(body.getData().getId()).isEqualTo(ThreadTestFixture.DEFAULT_THREAD_ID);
        assertThat(body.getData().getContent()).isEqualTo(ThreadTestFixture.DEFAULT_THREAD_CONTENT);
        assertThat(body.getMessage()).isEqualTo("스레드 조회가 완료되었습니다.");

        verify(threadService).getThread(ThreadTestFixture.DEFAULT_THREAD_ID, null);
    }

    @Test
    @DisplayName("GET /api/threads/{id} - 비로그인 사용자 공개 스레드 조회 테스트")
    void getThread_AnonymousUser_PublicThread() {
        // given
        ThreadResponse expectedResponse = ThreadTestFixture.createDefaultThreadResponse();
        given(threadService.getThread(ThreadTestFixture.DEFAULT_THREAD_ID, null))
            .willReturn(expectedResponse);

        // when
        ResponseEntity<ApiResponse<ThreadResponse>> response = threadController.getThread(
            ThreadTestFixture.DEFAULT_THREAD_ID, null);

        // then
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isNotNull();
        ApiResponse<ThreadResponse> body = Objects.requireNonNull(response.getBody());
        assertThat(body.getStatus()).isEqualTo(200);
        assertThat(body.getData().getIsPublic()).isTrue();

        verify(threadService).getThread(ThreadTestFixture.DEFAULT_THREAD_ID, null);
    }

    @Test
    @DisplayName("DELETE /api/threads/{id} - 스레드 삭제 API 테스트")
    void deleteThread_Success() {
        // given
        willDoNothing().given(threadService)
            .deleteThread(ThreadTestFixture.DEFAULT_THREAD_ID, ThreadTestFixture.DEFAULT_USER_EMAIL);

        // when
        CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
        ResponseEntity<ApiResponse<Void>> response = threadController.deleteThread(
            ThreadTestFixture.DEFAULT_THREAD_ID, userDetails);

        // then
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isNotNull();
        ApiResponse<Void> body = Objects.requireNonNull(response.getBody());
        assertThat(body.getStatus()).isEqualTo(200);
        assertThat(body.getData()).isNull();
        assertThat(body.getMessage()).isEqualTo("스레드가 성공적으로 삭제되었습니다.");

        verify(threadService).deleteThread(ThreadTestFixture.DEFAULT_THREAD_ID, ThreadTestFixture.DEFAULT_USER_EMAIL);
    }
}