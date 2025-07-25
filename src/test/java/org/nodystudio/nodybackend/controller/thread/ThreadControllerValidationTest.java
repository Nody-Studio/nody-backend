package org.nodystudio.nodybackend.controller.thread;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.config.ThreadTestConfiguration;
import org.nodystudio.nodybackend.dto.ApiResponse;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.dto.thread.ThreadCreateRequest;
import org.nodystudio.nodybackend.dto.thread.ThreadSearchRequest;
import org.nodystudio.nodybackend.dto.thread.ThreadUpdateRequest;
import org.nodystudio.nodybackend.fixture.ThreadTestFixture;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * ThreadController의 유효성 검증 기능을 테스트합니다.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ThreadController 유효성 검증 테스트")
class ThreadControllerValidationTest {

    private final Validator validator = new ThreadTestConfiguration().validator();

    @Nested
    @DisplayName("ThreadSearchRequest 유효성 검증")
    class ThreadSearchRequestValidationTests {

        @Test
        @DisplayName("페이지 크기 최대값 초과 검증 테스트")
        void threadSearchRequest_PageSizeExceedsMax_ValidationError() {
            // given
            ThreadSearchRequest request = ThreadSearchRequest.builder()
                .page(0)
                .size(101)
                .build();

            // when
            Set<ConstraintViolation<ThreadSearchRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isNotEmpty();
            assertThat(violations).anyMatch(v -> v.getMessage().contains("100 이하여야 합니다"));
        }

        @ParameterizedTest
        @ValueSource(ints = {-10, -1, 0})
        @DisplayName("페이지 크기 최소값 미만 검증 테스트")
        void threadSearchRequest_PageSizeBelowMin_ValidationError(int invalidSize) {
            // given
            ThreadSearchRequest request = ThreadSearchRequest.builder()
                .page(0)
                .size(invalidSize)
                .build();

            // when
            Set<ConstraintViolation<ThreadSearchRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isNotEmpty();
            assertThat(violations).anyMatch(v -> v.getMessage().contains("1 이상이어야 합니다"));
        }

        @Test
        @DisplayName("페이지 크기 정상 범위 검증 테스트")
        void threadSearchRequest_PageSizeValid_NoViolation() {
            // given
            ThreadSearchRequest request = ThreadSearchRequest.builder()
                .page(0)
                .size(100)
                .build();

            // when
            Set<ConstraintViolation<ThreadSearchRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isEmpty();
        }
    }

    @Nested
    @DisplayName("ThreadCreateRequest 유효성 검증")
    class ThreadCreateRequestValidationTests {

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {" ", "\t", "\n", "   "})
        @DisplayName("빈 내용으로 스레드 생성 시 검증 오류 발생")
        void createThreadRequest_WithBlankContent_ValidationError(String blankContent) {
            // given
            ThreadCreateRequest request = ThreadCreateRequest.builder()
                .content(blankContent)
                .isPublic(true)
                .build();

            // when
            Set<ConstraintViolation<ThreadCreateRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isNotEmpty();
            assertThat(violations).anyMatch(v -> v.getMessage().contains("필수입니다") || v.getMessage().contains("공백일 수 없습니다"));
        }

        @Test
        @DisplayName("내용이 5000자를 초과할 때 검증 오류가 발생한다")
        void createThreadRequest_WithContentTooLong_ValidationError() {
            // given
            String longContent = "a".repeat(5001);
            ThreadCreateRequest request = ThreadCreateRequest.builder()
                .content(longContent)
                .isPublic(true)
                .build();

            // when
            Set<ConstraintViolation<ThreadCreateRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isNotEmpty();
            assertThat(violations).anyMatch(v -> v.getMessage().contains("5000자 이하여야 합니다"));
        }

        @Test
        @DisplayName("유효한 내용으로 스레드 생성 시 검증 오류가 발생하지 않는다")
        void createThreadRequest_WithValidContent_NoViolation() {
            // given
            ThreadCreateRequest request = ThreadTestFixture.createDefaultThreadCreateRequest();

            // when
            Set<ConstraintViolation<ThreadCreateRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isEmpty();
        }
    }

    @Nested
    @DisplayName("ThreadUpdateRequest 유효성 검증")
    class ThreadUpdateRequestValidationTests {

        @Test
        @DisplayName("빈 내용으로 수정 시 검증 오류가 발생한다")
        void updateThreadRequest_WithBlankContent_ValidationError() {
            // given
            ThreadUpdateRequest request = ThreadUpdateRequest.builder()
                .content("")
                .build();

            // when
            Set<ConstraintViolation<ThreadUpdateRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isNotEmpty();
            assertThat(violations).anyMatch(v -> v.getMessage().contains("공백일 수 없습니다"));
        }

        @Test
        @DisplayName("내용이 5000자를 초과할 때 검증 오류가 발생한다")
        void updateThreadRequest_WithContentTooLong_ValidationError() {
            // given
            String longContent = "a".repeat(5001);
            ThreadUpdateRequest request = ThreadUpdateRequest.builder()
                .content(longContent)
                .build();

            // when
            Set<ConstraintViolation<ThreadUpdateRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isNotEmpty();
            assertThat(violations).anyMatch(v -> v.getMessage().contains("5000자 이하여야 합니다"));
        }

        @Test
        @DisplayName("logId와 disconnectLog가 동시에 설정된 경우 검증 오류가 발생한다")
        void updateThreadRequest_WithBothLogIdAndDisconnectLog_ValidationError() {
            // given
            ThreadUpdateRequest request = ThreadUpdateRequest.builder()
                .logId(10L)
                .disconnectLog(true)
                .build();

            // when
            Set<ConstraintViolation<ThreadUpdateRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isNotEmpty();
            assertThat(violations).anyMatch(v -> v.getMessage().contains("동시에 요청할 수 없습니다"));
        }

        @Test
        @DisplayName("유효한 값들로 검증 시 오류가 발생하지 않는다")
        void updateThreadRequest_WithValidValues_NoViolation() {
            // given
            ThreadUpdateRequest request1 = ThreadUpdateRequest.builder()
                .content("유효한 내용")
                .isPublic(false)
                .logId(10L)
                .build();

            ThreadUpdateRequest request2 = ThreadUpdateRequest.builder()
                .content("다른 유효한 내용")
                .isPublic(true)
                .disconnectLog(true)
                .build();

            // when
            Set<ConstraintViolation<ThreadUpdateRequest>> violations1 = validator.validate(request1);
            Set<ConstraintViolation<ThreadUpdateRequest>> violations2 = validator.validate(request2);

            // then
            assertThat(violations1).isEmpty();
            assertThat(violations2).isEmpty();
        }

        @Test
        @DisplayName("내용만 수정하는 경우 검증 오류가 발생하지 않는다")
        void updateThreadRequest_ContentOnly_NoViolation() {
            // given
            ThreadUpdateRequest request = ThreadTestFixture.createContentOnlyUpdateRequest("유효한 내용");

            // when
            Set<ConstraintViolation<ThreadUpdateRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isEmpty();
        }

        @Test
        @DisplayName("공개 설정만 수정하는 경우 검증 오류가 발생하지 않는다")
        void updateThreadRequest_PublicSettingOnly_NoViolation() {
            // given
            ThreadUpdateRequest request = ThreadTestFixture.createPublicOnlyUpdateRequest(false);

            // when
            Set<ConstraintViolation<ThreadUpdateRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isEmpty();
        }

        @Test
        @DisplayName("로그 연결 해제만 하는 경우 검증 오류가 발생하지 않는다")
        void updateThreadRequest_DisconnectLogOnly_NoViolation() {
            // given
            ThreadUpdateRequest request = ThreadTestFixture.createDisconnectLogRequest();

            // when
            Set<ConstraintViolation<ThreadUpdateRequest>> violations = validator.validate(request);

            // then
            assertThat(violations).isEmpty();
        }
    }

    /**
     * 테스트용 유효성 검증 예외 핸들러입니다.
     */
    @RestControllerAdvice
    static class TestValidationExceptionHandler {

        @ExceptionHandler(MethodArgumentNotValidException.class)
        public ResponseEntity<ApiResponse<Object>> handleValidationException(
            MethodArgumentNotValidException ex) {
            String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(DefaultMessageSourceResolvable::getDefaultMessage)
                .collect(Collectors.joining(", "));

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(ErrorCode.VALIDATION_ERROR, errorMessage));
        }
    }
}