package org.nodystudio.nodybackend.controller.thread;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

import java.time.LocalDateTime;
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
import org.nodystudio.nodybackend.dto.thread.ThreadUpdateRequest;
import org.nodystudio.nodybackend.dto.user.UserSummaryResponse;
import org.nodystudio.nodybackend.fixture.ThreadTestFixture;
import org.nodystudio.nodybackend.security.userdetails.CustomUserDetails;
import org.nodystudio.nodybackend.service.thread.ThreadService;
import org.springframework.http.ResponseEntity;

/**
 * ThreadController의 스레드 수정 기능을 테스트합니다.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ThreadController 스레드 수정 테스트")
class ThreadControllerUpdateTest {

    @Mock
    private ThreadService threadService;

    @InjectMocks
    private ThreadController threadController;

    @Nested
    @DisplayName("PUT /api/threads/{id} - 스레드 수정")
    class UpdateThreadTests {

        @Test
        @DisplayName("유효한 요청으로 스레드 수정 시 성공한다")
        void updateThread_WithValidRequest_ShouldReturnUpdatedThread() {
            // given
            Long threadId = ThreadTestFixture.DEFAULT_THREAD_ID;
            ThreadUpdateRequest request = ThreadTestFixture.createDefaultThreadUpdateRequest();

            ThreadResponse updatedResponse = ThreadResponse.builder()
                .id(threadId)
                .content("수정된 스레드 내용")
                .isPublic(false)
                .viewCount(0L)
                .user(ThreadTestFixture.createDefaultUserSummaryResponse())
                .log(null)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .isLinkedToLog(false)
                .isIndependent(true)
                .build();

            given(threadService.updateThread(eq(threadId), any(ThreadUpdateRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL)))
                .willReturn(updatedResponse);

            // when
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            ResponseEntity<ApiResponse<ThreadResponse>> response = threadController.updateThread(
                threadId, userDetails, request);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<ThreadResponse> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getStatus()).isEqualTo(200);
            assertThat(body.getData().getId()).isEqualTo(threadId);
            assertThat(body.getData().getContent()).isEqualTo("수정된 스레드 내용");
            assertThat(body.getData().getIsPublic()).isFalse();
            assertThat(body.getMessage()).isEqualTo("스레드가 성공적으로 수정되었습니다.");

            verify(threadService).updateThread(eq(threadId), any(ThreadUpdateRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("내용만 수정하는 경우 성공한다")
        void updateThread_ContentOnly_ShouldUpdateContent() {
            // given
            Long threadId = ThreadTestFixture.DEFAULT_THREAD_ID;
            ThreadUpdateRequest request = ThreadTestFixture.createContentOnlyUpdateRequest("내용만 수정");

            ThreadResponse updatedResponse = ThreadResponse.builder()
                .id(threadId)
                .content("내용만 수정")
                .isPublic(true)
                .viewCount(0L)
                .user(ThreadTestFixture.createDefaultUserSummaryResponse())
                .log(null)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .isLinkedToLog(false)
                .isIndependent(true)
                .build();

            given(threadService.updateThread(eq(threadId), any(ThreadUpdateRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL)))
                .willReturn(updatedResponse);

            // when
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            ResponseEntity<ApiResponse<ThreadResponse>> response = threadController.updateThread(
                threadId, userDetails, request);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<ThreadResponse> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getData().getContent()).isEqualTo("내용만 수정");

            verify(threadService).updateThread(eq(threadId), any(ThreadUpdateRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("공개 설정만 수정하는 경우 성공한다")
        void updateThread_PublicSettingOnly_ShouldUpdatePublicSetting() {
            // given
            Long threadId = ThreadTestFixture.DEFAULT_THREAD_ID;
            ThreadUpdateRequest request = ThreadTestFixture.createPublicOnlyUpdateRequest(false);

            ThreadResponse updatedResponse = ThreadResponse.builder()
                .id(threadId)
                .content(ThreadTestFixture.DEFAULT_THREAD_CONTENT)
                .isPublic(false)
                .viewCount(0L)
                .user(ThreadTestFixture.createDefaultUserSummaryResponse())
                .log(null)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .isLinkedToLog(false)
                .isIndependent(true)
                .build();

            given(threadService.updateThread(eq(threadId), any(ThreadUpdateRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL)))
                .willReturn(updatedResponse);

            // when
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            ResponseEntity<ApiResponse<ThreadResponse>> response = threadController.updateThread(
                threadId, userDetails, request);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<ThreadResponse> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getData().getIsPublic()).isFalse();

            verify(threadService).updateThread(eq(threadId), any(ThreadUpdateRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("로그 연결을 해제하는 경우 성공한다")
        void updateThread_DisconnectLog_ShouldDisconnectFromLog() {
            // given
            Long threadId = ThreadTestFixture.DEFAULT_THREAD_ID;
            ThreadUpdateRequest request = ThreadTestFixture.createDisconnectLogRequest();

            ThreadResponse updatedResponse = ThreadResponse.builder()
                .id(threadId)
                .content(ThreadTestFixture.DEFAULT_THREAD_CONTENT)
                .isPublic(true)
                .viewCount(0L)
                .user(ThreadTestFixture.createDefaultUserSummaryResponse())
                .log(null)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .isLinkedToLog(false)
                .isIndependent(true)
                .build();

            given(threadService.updateThread(eq(threadId), any(ThreadUpdateRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL)))
                .willReturn(updatedResponse);

            // when
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            ResponseEntity<ApiResponse<ThreadResponse>> response = threadController.updateThread(
                threadId, userDetails, request);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isNotNull();
            ApiResponse<ThreadResponse> body = Objects.requireNonNull(response.getBody());
            assertThat(body.getData().getIsLinkedToLog()).isFalse();
            assertThat(body.getData().getIsIndependent()).isTrue();

            verify(threadService).updateThread(eq(threadId), any(ThreadUpdateRequest.class), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }
    }
}