package org.nodystudio.nodybackend.fixture;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.time.LocalDateTime;
import java.util.List;
import org.nodystudio.nodybackend.domain.enums.ThreadType;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.thread.ThreadCreateRequest;
import org.nodystudio.nodybackend.dto.thread.ThreadResponse;
import org.nodystudio.nodybackend.dto.thread.ThreadSearchRequest;
import org.nodystudio.nodybackend.dto.thread.ThreadUpdateRequest;
import org.nodystudio.nodybackend.dto.user.UserSummaryResponse;
import org.nodystudio.nodybackend.security.userdetails.CustomUserDetails;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Thread 관련 테스트에서 사용할 공통 테스트 데이터 생성 유틸리티 클래스입니다.
 */
public class ThreadTestFixture {

    // 테스트 상수
    public static final String DEFAULT_USER_EMAIL = "test@example.com";
    public static final String DEFAULT_USER_NICKNAME = "testuser";
    public static final Long DEFAULT_USER_ID = 1L;
    public static final Long DEFAULT_THREAD_ID = 1L;
    public static final String DEFAULT_THREAD_CONTENT = "테스트 스레드 내용";

    /**
     * 기본 설정으로 ThreadResponse 객체를 생성합니다.
     *
     * @return 기본 ThreadResponse 객체
     */
    public static ThreadResponse createDefaultThreadResponse() {
        return createThreadResponse(DEFAULT_THREAD_ID, DEFAULT_THREAD_CONTENT, true);
    }

    /**
     * 커스텀 설정으로 ThreadResponse 객체를 생성합니다.
     *
     * @param id 스레드 ID
     * @param content 스레드 내용
     * @param isPublic 공개 여부
     * @return ThreadResponse 객체
     */
    public static ThreadResponse createThreadResponse(Long id, String content, Boolean isPublic) {
        return ThreadResponse.builder()
            .id(id)
            .content(content)
            .isPublic(isPublic)
            .viewCount(0L)
            .user(createDefaultUserSummaryResponse())
            .log(null)
            .createdAt(LocalDateTime.now())
            .updatedAt(LocalDateTime.now())
            .isLinkedToLog(false)
            .isIndependent(true)
            .build();
    }

    /**
     * 독립 스레드 ThreadResponse 객체를 생성합니다.
     *
     * @param id 스레드 ID
     * @param content 스레드 내용
     * @return 독립 스레드 ThreadResponse 객체
     */
    public static ThreadResponse createIndependentThreadResponse(Long id, String content) {
        return ThreadResponse.builder()
            .id(id)
            .content(content)
            .isPublic(true)
            .viewCount(5L)
            .user(createDefaultUserSummaryResponse())
            .log(null)
            .createdAt(LocalDateTime.now())
            .updatedAt(LocalDateTime.now())
            .isLinkedToLog(false)
            .isIndependent(true)
            .build();
    }

    /**
     * 로그 연결 스레드 ThreadResponse 객체를 생성합니다.
     *
     * @param id 스레드 ID
     * @param content 스레드 내용
     * @return 로그 연결 ThreadResponse 객체
     */
    public static ThreadResponse createLinkedThreadResponse(Long id, String content) {
        return ThreadResponse.builder()
            .id(id)
            .content(content)
            .isPublic(true)
            .viewCount(8L)
            .user(createDefaultUserSummaryResponse())
            .createdAt(LocalDateTime.now())
            .updatedAt(LocalDateTime.now())
            .isLinkedToLog(true)
            .isIndependent(false)
            .build();
    }

    /**
     * 기본 UserSummaryResponse 객체를 생성합니다.
     *
     * @return UserSummaryResponse 객체
     */
    public static UserSummaryResponse createDefaultUserSummaryResponse() {
        return createUserSummaryResponse(DEFAULT_USER_ID, DEFAULT_USER_NICKNAME);
    }

    /**
     * 커스텀 UserSummaryResponse 객체를 생성합니다.
     *
     * @param id 사용자 ID
     * @param nickname 사용자 닉네임
     * @return UserSummaryResponse 객체
     */
    public static UserSummaryResponse createUserSummaryResponse(Long id, String nickname) {
        return UserSummaryResponse.builder()
            .id(id)
            .nickname(nickname)
            .build();
    }

    /**
     * 기본 설정으로 Mock CustomUserDetails 객체를 생성합니다.
     *
     * @return Mock CustomUserDetails 객체
     */
    public static CustomUserDetails createMockUserDetails() {
        return createMockUserDetails(DEFAULT_USER_ID, DEFAULT_USER_EMAIL);
    }

    /**
     * 커스텀 설정으로 Mock CustomUserDetails 객체를 생성합니다.
     *
     * @param userId 사용자 ID
     * @param email 사용자 이메일
     * @return Mock CustomUserDetails 객체
     */
    public static CustomUserDetails createMockUserDetails(Long userId, String email) {
        User mockUser = mock(User.class);
        lenient().when(mockUser.getId()).thenReturn(userId);
        lenient().when(mockUser.getEmail()).thenReturn(email);
        lenient().when(mockUser.getRoles())
            .thenReturn(List.of(new SimpleGrantedAuthority("ROLE_USER")));
        lenient().when(mockUser.getIsActive()).thenReturn(true);

        return new CustomUserDetails(mockUser);
    }

    /**
     * 기본 ThreadCreateRequest 객체를 생성합니다.
     *
     * @return ThreadCreateRequest 객체
     */
    public static ThreadCreateRequest createDefaultThreadCreateRequest() {
        return createThreadCreateRequest("새 스레드 내용", true);
    }

    /**
     * 커스텀 ThreadCreateRequest 객체를 생성합니다.
     *
     * @param content 스레드 내용
     * @param isPublic 공개 여부
     * @return ThreadCreateRequest 객체
     */
    public static ThreadCreateRequest createThreadCreateRequest(String content, Boolean isPublic) {
        return ThreadCreateRequest.builder()
            .content(content)
            .isPublic(isPublic)
            .build();
    }

    /**
     * 기본 ThreadUpdateRequest 객체를 생성합니다.
     *
     * @return ThreadUpdateRequest 객체
     */
    public static ThreadUpdateRequest createDefaultThreadUpdateRequest() {
        return createThreadUpdateRequest("수정된 스레드 내용", false);
    }

    /**
     * 커스텀 ThreadUpdateRequest 객체를 생성합니다.
     *
     * @param content 수정할 내용
     * @param isPublic 공개 여부
     * @return ThreadUpdateRequest 객체
     */
    public static ThreadUpdateRequest createThreadUpdateRequest(String content, Boolean isPublic) {
        return ThreadUpdateRequest.builder()
            .content(content)
            .isPublic(isPublic)
            .build();
    }

    /**
     * 내용만 수정하는 ThreadUpdateRequest 객체를 생성합니다.
     *
     * @param content 수정할 내용
     * @return ThreadUpdateRequest 객체
     */
    public static ThreadUpdateRequest createContentOnlyUpdateRequest(String content) {
        return ThreadUpdateRequest.builder()
            .content(content)
            .build();
    }

    /**
     * 공개 설정만 수정하는 ThreadUpdateRequest 객체를 생성합니다.
     *
     * @param isPublic 공개 여부
     * @return ThreadUpdateRequest 객체
     */
    public static ThreadUpdateRequest createPublicOnlyUpdateRequest(Boolean isPublic) {
        return ThreadUpdateRequest.builder()
            .isPublic(isPublic)
            .build();
    }

    /**
     * 로그 연결 해제 ThreadUpdateRequest 객체를 생성합니다.
     *
     * @return ThreadUpdateRequest 객체
     */
    public static ThreadUpdateRequest createDisconnectLogRequest() {
        return ThreadUpdateRequest.builder()
            .disconnectLog(true)
            .build();
    }

    /**
     * 기본 ThreadSearchRequest 객체를 생성합니다.
     *
     * @return ThreadSearchRequest 객체
     */
    public static ThreadSearchRequest createDefaultThreadSearchRequest() {
        return ThreadSearchRequest.builder().build();
    }

    /**
     * 키워드 검색용 ThreadSearchRequest 객체를 생성합니다.
     *
     * @param keyword 검색 키워드
     * @return ThreadSearchRequest 객체
     */
    public static ThreadSearchRequest createKeywordSearchRequest(String keyword) {
        return ThreadSearchRequest.builder()
            .keyword(keyword)
            .build();
    }

    /**
     * 로그 ID로 검색하는 ThreadSearchRequest 객체를 생성합니다.
     *
     * @param logId 로그 ID
     * @return ThreadSearchRequest 객체
     */
    public static ThreadSearchRequest createLogSearchRequest(Long logId) {
        return ThreadSearchRequest.builder()
            .logId(logId)
            .build();
    }

    /**
     * 독립 스레드 검색용 ThreadSearchRequest 객체를 생성합니다.
     *
     * @return ThreadSearchRequest 객체
     */
    public static ThreadSearchRequest createIndependentSearchRequest() {
        return ThreadSearchRequest.builder()
            .threadType(ThreadType.INDEPENDENT)
            .build();
    }

    /**
     * 로그 연결 스레드 검색용 ThreadSearchRequest 객체를 생성합니다.
     *
     * @return ThreadSearchRequest 객체
     */
    public static ThreadSearchRequest createLinkedSearchRequest() {
        return ThreadSearchRequest.builder()
            .threadType(ThreadType.LINKED)
            .build();
    }

    /**
     * ThreadResponse 리스트로 Page 객체를 생성합니다.
     *
     * @param threads ThreadResponse 리스트
     * @param pageable Pageable 객체
     * @return Page<ThreadResponse> 객체
     */
    public static Page<ThreadResponse> createThreadPage(List<ThreadResponse> threads, Pageable pageable) {
        return new PageImpl<>(threads, pageable, threads.size());
    }

    /**
     * ThreadResponse 리스트로 총 개수를 지정한 Page 객체를 생성합니다.
     *
     * @param threads ThreadResponse 리스트
     * @param pageable Pageable 객체
     * @param totalElements 총 개수
     * @return Page<ThreadResponse> 객체
     */
    public static Page<ThreadResponse> createThreadPage(List<ThreadResponse> threads, Pageable pageable, long totalElements) {
        return new PageImpl<>(threads, pageable, totalElements);
    }

    /**
     * 여러 개의 ThreadResponse 리스트를 생성합니다.
     *
     * @param count 생성할 개수
     * @param contentPrefix 내용 접두사
     * @return ThreadResponse 리스트
     */
    public static List<ThreadResponse> createMultipleThreadResponses(int count, String contentPrefix) {
        return java.util.stream.IntStream.range(1, count + 1)
            .mapToObj(i -> createThreadResponse((long) i, contentPrefix + " " + i, true))
            .toList();
    }

    // ================================
    // Builder 패턴 확장
    // ================================

    /**
     * ThreadResponse Builder 패턴을 제공합니다.
     * 더 유연한 테스트 데이터 생성을 위한 빌더 패턴입니다.
     */
    public static class ThreadResponseBuilder {
        private Long id = DEFAULT_THREAD_ID;
        private String content = DEFAULT_THREAD_CONTENT;
        private boolean isPublic = true;
        private boolean isLinkedToLog = false;
        private Long logId = null;
        private String userEmail = DEFAULT_USER_EMAIL;
        private String userNickname = DEFAULT_USER_NICKNAME;
        private LocalDateTime createdAt = LocalDateTime.now();
        private LocalDateTime updatedAt = LocalDateTime.now();

        public static ThreadResponseBuilder create() {
            return new ThreadResponseBuilder();
        }

        public ThreadResponseBuilder withId(Long id) {
            this.id = id;
            return this;
        }

        public ThreadResponseBuilder withContent(String content) {
            this.content = content;
            return this;
        }

        public ThreadResponseBuilder withPublic(boolean isPublic) {
            this.isPublic = isPublic;
            return this;
        }

        public ThreadResponseBuilder withLinkedToLog(boolean isLinkedToLog) {
            this.isLinkedToLog = isLinkedToLog;
            return this;
        }

        public ThreadResponseBuilder withLogId(Long logId) {
            this.logId = logId;
            this.isLinkedToLog = (logId != null);
            return this;
        }

        public ThreadResponseBuilder withUserEmail(String userEmail) {
            this.userEmail = userEmail;
            return this;
        }

        public ThreadResponseBuilder withUserNickname(String userNickname) {
            this.userNickname = userNickname;
            return this;
        }

        public ThreadResponseBuilder withCreatedAt(LocalDateTime createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public ThreadResponseBuilder withUpdatedAt(LocalDateTime updatedAt) {
            this.updatedAt = updatedAt;
            return this;
        }

        public ThreadResponse build() {
            // 기존 정적 메서드를 활용하여 ThreadResponse 생성
            ThreadResponse baseResponse = createThreadResponse(id, content, isPublic);
            
            // 추가 필드 설정이 필요한 경우 여기서 처리
            return ThreadResponse.builder()
                .id(id)
                .content(content)
                .isPublic(isPublic)
                .isLinkedToLog(isLinkedToLog)
                .isIndependent(!isLinkedToLog)
                .user(baseResponse.getUser()) // 기존 메서드로 생성된 user 사용
                .log(null) // 필요시 설정
                .viewCount(0L)
                .likeCount(0L)
                .isLiked(false)
                .createdAt(createdAt)
                .updatedAt(updatedAt)
                .build();
        }
    }

    /**
     * ThreadCreateRequest Builder 패턴을 제공합니다.
     */
    public static class ThreadCreateRequestBuilder {
        private String content = "새 스레드 내용";
        private Boolean isPublic = true;
        private Long logId = null;

        public static ThreadCreateRequestBuilder create() {
            return new ThreadCreateRequestBuilder();
        }

        public ThreadCreateRequestBuilder withContent(String content) {
            this.content = content;
            return this;
        }

        public ThreadCreateRequestBuilder withPublic(Boolean isPublic) {
            this.isPublic = isPublic;
            return this;
        }

        public ThreadCreateRequestBuilder withLogId(Long logId) {
            this.logId = logId;
            return this;
        }

        public ThreadCreateRequest build() {
            return ThreadCreateRequest.builder()
                .content(content)
                .isPublic(isPublic)
                .logId(logId)
                .build();
        }
    }

    /**
     * ThreadUpdateRequest Builder 패턴을 제공합니다.
     */
    public static class ThreadUpdateRequestBuilder {
        private String content = null;
        private Boolean isPublic = null;
        private Long logId = null;
        private Boolean disconnectLog = null;

        public static ThreadUpdateRequestBuilder create() {
            return new ThreadUpdateRequestBuilder();
        }

        public ThreadUpdateRequestBuilder withContent(String content) {
            this.content = content;
            return this;
        }

        public ThreadUpdateRequestBuilder withPublic(Boolean isPublic) {
            this.isPublic = isPublic;
            return this;
        }

        public ThreadUpdateRequestBuilder withLogId(Long logId) {
            this.logId = logId;
            return this;
        }

        public ThreadUpdateRequestBuilder withDisconnectLog(Boolean disconnectLog) {
            this.disconnectLog = disconnectLog;
            return this;
        }

        public ThreadUpdateRequest build() {
            return ThreadUpdateRequest.builder()
                .content(content)
                .isPublic(isPublic)
                .logId(logId)
                .disconnectLog(disconnectLog)
                .build();
        }
    }
}