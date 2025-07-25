package org.nodystudio.nodybackend.controller.thread;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.dto.thread.ThreadCreateRequest;
import org.nodystudio.nodybackend.dto.thread.ThreadUpdateRequest;
import org.nodystudio.nodybackend.exception.custom.ResourceNotFoundException;
import org.nodystudio.nodybackend.exception.custom.UnauthorizedException;
import org.nodystudio.nodybackend.exception.custom.UserNotFoundException;
import org.nodystudio.nodybackend.fixture.ThreadTestFixture;
import org.nodystudio.nodybackend.security.userdetails.CustomUserDetails;
import org.nodystudio.nodybackend.service.thread.ThreadService;

/**
 * ThreadController의 예외 처리 상황을 테스트합니다.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ThreadController 예외 처리 테스트")
class ThreadControllerExceptionTest {

    @Mock
    private ThreadService threadService;

    @InjectMocks
    private ThreadController threadController;

    @Nested
    @DisplayName("예외 처리 테스트")
    class ExceptionHandlingTests {

        @Test
        @DisplayName("존재하지 않는 스레드 조회 시 예외가 발생한다")
        void getThread_WithNonExistentId_ShouldThrowException() {
            // given
            Long nonExistentId = 999L;
            given(threadService.getThread(eq(nonExistentId), eq(null)))
                    .willThrow(new ResourceNotFoundException("스레드를 찾을 수 없습니다."));

            // when & then
            assertThatThrownBy(() -> threadController.getThread(nonExistentId, null))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessage("스레드를 찾을 수 없습니다.");

            verify(threadService).getThread(eq(nonExistentId), eq(null));
        }

        @Test
        @DisplayName("존재하지 않는 스레드 수정 시 예외가 발생한다")
        void updateThread_WithNonExistentThread_ShouldThrowException() {
            // given
            Long nonExistentId = 999L;
            ThreadUpdateRequest request = ThreadTestFixture.createContentOnlyUpdateRequest("수정 내용");

            willThrow(new ResourceNotFoundException("스레드를 찾을 수 없습니다."))
                    .given(threadService).updateThread(eq(nonExistentId), any(ThreadUpdateRequest.class),
                            eq(ThreadTestFixture.DEFAULT_USER_EMAIL));

            // when & then
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            assertThatThrownBy(() -> threadController.updateThread(nonExistentId, userDetails, request))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessage("스레드를 찾을 수 없습니다.");

            verify(threadService).updateThread(eq(nonExistentId), any(ThreadUpdateRequest.class),
                    eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("권한이 없는 사용자가 스레드 수정 시 예외가 발생한다")
        void updateThread_WithUnauthorizedUser_ShouldThrowException() {
            // given
            Long threadId = ThreadTestFixture.DEFAULT_THREAD_ID;
            ThreadUpdateRequest request = ThreadTestFixture.createContentOnlyUpdateRequest("수정 내용");

            willThrow(new UnauthorizedException("스레드 수정 권한이 없습니다."))
                    .given(threadService).updateThread(eq(threadId), any(ThreadUpdateRequest.class),
                            eq(ThreadTestFixture.DEFAULT_USER_EMAIL));

            // when & then
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            assertThatThrownBy(() -> threadController.updateThread(threadId, userDetails, request))
                    .isInstanceOf(UnauthorizedException.class)
                    .hasMessage("스레드 수정 권한이 없습니다.");

            verify(threadService).updateThread(eq(threadId), any(ThreadUpdateRequest.class),
                    eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("권한이 없는 사용자가 스레드 삭제 시 예외가 발생한다")
        void deleteThread_WithUnauthorizedUser_ShouldThrowException() {
            // given
            Long threadId = ThreadTestFixture.DEFAULT_THREAD_ID;

            willThrow(new UnauthorizedException("스레드 삭제 권한이 없습니다."))
                    .given(threadService).deleteThread(eq(threadId), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));

            // when & then
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            assertThatThrownBy(() -> threadController.deleteThread(threadId, userDetails))
                    .isInstanceOf(UnauthorizedException.class)
                    .hasMessage("스레드 삭제 권한이 없습니다.");

            verify(threadService).deleteThread(eq(threadId), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("존재하지 않는 스레드 삭제 시 예외가 발생한다")
        void deleteThread_WithNonExistentThread_ShouldThrowException() {
            // given
            Long nonExistentId = 999L;

            willThrow(new ResourceNotFoundException("스레드를 찾을 수 없습니다."))
                    .given(threadService).deleteThread(eq(nonExistentId), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));

            // when & then
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails();
            assertThatThrownBy(() -> threadController.deleteThread(nonExistentId, userDetails))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessage("스레드를 찾을 수 없습니다.");

            verify(threadService).deleteThread(eq(nonExistentId), eq(ThreadTestFixture.DEFAULT_USER_EMAIL));
        }

        @Test
        @DisplayName("스레드 생성 시 사용자를 찾을 수 없는 경우 예외가 발생한다")
        void createThread_WithNonExistentUser_ShouldThrowException() {
            // given
            ThreadCreateRequest request = ThreadTestFixture.createDefaultThreadCreateRequest();
            String nonExistentEmail = "nonexistent@example.com";

            given(threadService.createThread(any(ThreadCreateRequest.class), eq(nonExistentEmail)))
                    .willThrow(new UserNotFoundException("사용자를 찾을 수 없습니다."));

            // when & then
            CustomUserDetails userDetails = ThreadTestFixture.createMockUserDetails(999L, nonExistentEmail);

            assertThatThrownBy(() -> threadController.createThread(userDetails, request))
                    .isInstanceOf(UserNotFoundException.class)
                    .hasMessage("사용자를 찾을 수 없습니다.");

            verify(threadService).createThread(any(ThreadCreateRequest.class), eq(nonExistentEmail));
        }

        @Test
        @DisplayName("비공개 스레드를 권한 없는 사용자가 조회 시 예외가 발생한다")
        void getThread_PrivateThreadByUnauthorizedUser_ShouldThrowException() {
            // given
            Long privateThreadId = ThreadTestFixture.DEFAULT_THREAD_ID;
            String otherUserEmail = "other@example.com";

            given(threadService.getThread(eq(privateThreadId), eq(otherUserEmail)))
                    .willThrow(new UnauthorizedException("비공개 스레드에 접근할 권한이 없습니다."));

            // when & then
            CustomUserDetails otherUserDetails = ThreadTestFixture.createMockUserDetails(2L, otherUserEmail);

            assertThatThrownBy(() -> threadController.getThread(privateThreadId, otherUserDetails))
                    .isInstanceOf(UnauthorizedException.class)
                    .hasMessage("비공개 스레드에 접근할 권한이 없습니다.");

            verify(threadService).getThread(eq(privateThreadId), eq(otherUserEmail));
        }
    }
}