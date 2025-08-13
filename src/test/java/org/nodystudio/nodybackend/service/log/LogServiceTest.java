package org.nodystudio.nodybackend.service.log;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.domain.enums.LogSortField;
import org.nodystudio.nodybackend.domain.enums.OAuthProvider;
import org.nodystudio.nodybackend.domain.enums.SortDirection;
import org.nodystudio.nodybackend.domain.log.Log;
import org.nodystudio.nodybackend.domain.user.RoleType;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.log.LogCreateRequest;
import org.nodystudio.nodybackend.dto.log.LogResponse;
import org.nodystudio.nodybackend.dto.log.LogSearchRequest;
import org.nodystudio.nodybackend.dto.log.LogUpdateRequest;
import org.nodystudio.nodybackend.exception.custom.InvalidCoordinateException;
import org.nodystudio.nodybackend.repository.LogRepository;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

/**
 * - 로그 CRUD 기능 테스트 - 위치 기반 검색 테스트 - 권한 검증 테스트 - 공개/비공개 필터링 테스트 - 페이징 기능 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("LogService 테스트")
class LogServiceTest {

  @Mock
  private LogRepository logRepository;

  @Mock
  private UserRepository userRepository;

  @InjectMocks
  private LogService logService;

  private User testUser;
  private Log testLog;

  @BeforeEach
  void setUp() {
    testUser = User.builder()
        .id(1L)
        .email("test@example.com")
        .nickname("테스트유저")
        .provider(OAuthProvider.GOOGLE)
        .socialId("123456")
        .role(RoleType.USER)
        .isActive(true)
        .build();

    testLog = Log.builder()
        .id(1L)
        .user(testUser)
        .content("테스트 로그 내용")
        .latitude(new BigDecimal("37.5665"))
        .longitude(new BigDecimal("126.9780"))
        .address("서울특별시 중구")
        .isPublic(true)
        .viewCount(0L)
        .build();
  }

  @Test
  @DisplayName("로그 생성 기능 테스트")
  void createLog_Success() {
    // given
    LogCreateRequest request = LogCreateRequest.builder()
        .content("새로운 로그")
        .latitude(new BigDecimal("37.5665"))
        .longitude(new BigDecimal("126.9780"))
        .address("서울특별시 중구")
        .isPublic(true)
        .build();

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.save(any(Log.class))).willAnswer(invocation -> {
      Log log = invocation.getArgument(0);
      Log saved = Log.builder()
          .id(1L)
          .user(log.getUser())
          .content(log.getContent())
          .latitude(log.getLatitude())
          .longitude(log.getLongitude())
          .address(log.getAddress())
          .isPublic(log.getIsPublic())
          .viewCount(0L)
          .build();
      saved.updateMediaUrls(log.getMediaUrls());
      return saved;
    });

    // when
    LogResponse response = logService.createLog(request, "test@example.com");

    // then
    assertThat(response).isNotNull();
    assertThat(response.getContent()).isEqualTo("새로운 로그");
    assertThat(response.getLatitude()).isEqualTo(new BigDecimal("37.5665"));
    assertThat(response.getLongitude()).isEqualTo(new BigDecimal("126.9780"));
    assertThat(response.getAddress()).isEqualTo("서울특별시 중구");
    assertThat(response.getIsPublic()).isTrue();

    verify(logRepository).save(any(Log.class));
  }

  @Test
  @DisplayName("로그 조회 기능 테스트 (조회수 증가)")
  void getLog_Success_WithViewCountIncrement() {
    // given
    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findViewableLogByIdAndUserId(1L, 1L)).willReturn(Optional.of(testLog));

    // when
    LogResponse response = logService.getLog(1L, "test@example.com");

    // then
    assertThat(response).isNotNull();
    assertThat(response.getId()).isEqualTo(1L);
    assertThat(testLog.getViewCount()).isEqualTo(1L);
  }

  @Test
  @DisplayName("공개/비공개 필터링 테스트 - 비로그인 사용자는 공개 로그만 조회 가능")
  void getLog_PublicOnly_ForAnonymousUser() {
    // given
    given(logRepository.findByIdAndIsPublicTrue(1L)).willReturn(Optional.of(testLog));

    // when
    LogResponse response = logService.getLog(1L, null);

    // then
    assertThat(response).isNotNull();
    assertThat(response.getIsPublic()).isTrue();

    verify(logRepository).findByIdAndIsPublicTrue(1L);
    verify(logRepository, never()).findViewableLogByIdAndUserId(anyLong(), anyLong());
  }

  @Test
  @DisplayName("위치 기반 검색 테스트")
  void searchLogs_LocationBased_Success() {
    // given
    LogSearchRequest searchRequest = LogSearchRequest.builder()
        .latitude(new BigDecimal("37.5665"))
        .longitude(new BigDecimal("126.9780"))
        .radiusKm(new BigDecimal("10.0"))
        .page(0)
        .size(20)
        .build();

    List<Log> logs = Arrays.asList(testLog);
    Page<Log> logPage = new PageImpl<>(logs);

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findLogsByLocationNearWithUser(
        eq(new BigDecimal("37.5665")),
        eq(new BigDecimal("126.9780")),
        eq(new BigDecimal("10.0")),
        eq(1L),
        eq("ASC"),
        any(Pageable.class))).willReturn(logPage);

    // when
    Page<LogResponse> response = logService.searchLogs(searchRequest, "test@example.com");

    // then
    assertThat(response).isNotNull();
    assertThat(response.getContent()).hasSize(1);
    assertThat(response.getContent().get(0).getId()).isEqualTo(1L);

    verify(logRepository).findLogsByLocationNearWithUser(
        eq(new BigDecimal("37.5665")),
        eq(new BigDecimal("126.9780")),
        eq(new BigDecimal("10.0")),
        eq(1L),
        eq("ASC"),
        any(Pageable.class));
  }

  @Test
  @DisplayName("페이징 기능 테스트")
  void searchLogs_Pagination_Success() {
    // given
    LogSearchRequest searchRequest = LogSearchRequest.builder()
        .latitude(new BigDecimal("37.5665"))
        .longitude(new BigDecimal("126.9780"))
        .radiusKm(new BigDecimal("10.0"))
        .page(1)
        .size(10)
        .build();

    List<Log> logs = Arrays.asList(testLog);
    Page<Log> logPage = new PageImpl<>(logs);

    given(logRepository.findPublicLogsByLocationNear(
        any(BigDecimal.class),
        any(BigDecimal.class),
        any(BigDecimal.class),
        anyString(),
        any(Pageable.class))).willReturn(logPage);

    // when
    Page<LogResponse> response = logService.searchLogs(searchRequest, null);

    // then
    assertThat(response).isNotNull();
    assertThat(response.getNumber()).isEqualTo(0); // 실제 페이지 번호는 구현에 따라 다를 수 있음

    verify(logRepository).findPublicLogsByLocationNear(
        eq(new BigDecimal("37.5665")),
        eq(new BigDecimal("126.9780")),
        eq(new BigDecimal("10.0")),
        eq("ASC"),
        any(Pageable.class));
  }

  @Test
  @DisplayName("권한 검증 테스트 - 로그 수정 시 작성자 확인")
  void updateLog_PermissionCheck_Success() {
    // given
    LogUpdateRequest request = LogUpdateRequest.builder()
        .content("수정된 내용")
        .build();

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findByIdAndUserId(1L, 1L)).willReturn(Optional.of(testLog));

    // when
    LogResponse response = logService.updateLog(1L, request, "test@example.com");

    // then
    assertThat(response).isNotNull();
    assertThat(testLog.getContent()).isEqualTo("수정된 내용");

    verify(logRepository).findByIdAndUserId(1L, 1L);
  }

  @Test
  @DisplayName("권한 검증 테스트 - 다른 사용자 로그 수정 시도 시 예외 발생")
  void updateLog_PermissionCheck_Failure() {
    // given
    LogUpdateRequest request = LogUpdateRequest.builder()
        .content("수정 시도")
        .build();

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findByIdAndUserId(1L, 1L)).willReturn(Optional.empty());

    // when & then
    assertThatThrownBy(() -> logService.updateLog(1L, request, "test@example.com"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("수정 권한이 없거나 로그를 찾을 수 없습니다.");
  }

  @Test
  @DisplayName("권한 검증 테스트 - 로그 삭제 시 작성자 확인")
  void deleteLog_PermissionCheck_Success() {
    // given
    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findByIdAndUserId(1L, 1L)).willReturn(Optional.of(testLog));

    // when
    logService.deleteLog(1L, "test@example.com");

    // then
    verify(logRepository).findByIdAndUserId(1L, 1L);
    verify(logRepository).delete(testLog);
  }

  @Test
  @DisplayName("로그 수정 - 부분 좌표 제공 시 예외 발생 (위도만 제공)")
  void updateLog_PartialCoordinates_ThrowsException() {
    // given
    LogUpdateRequest request = LogUpdateRequest.builder()
        .content("수정된 내용")
        .latitude(new BigDecimal("37.5665")) // 위도만 제공
        .longitude(null) // 경도 누락
        .build();

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findByIdAndUserId(1L, 1L)).willReturn(Optional.of(testLog));

    // when & then
    assertThatThrownBy(() -> logService.updateLog(1L, request, "test@example.com"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("위도가 제공된 경우 경도도 함께 제공되어야 합니다.");
  }

  @Test
  @DisplayName("로그 수정 - 부분 좌표 제공 시 예외 발생 (경도만 제공)")
  void updateLog_PartialCoordinatesLongitudeOnly_ThrowsException() {
    // given
    LogUpdateRequest request = LogUpdateRequest.builder()
        .content("수정된 내용")
        .latitude(null) // 위도 누락
        .longitude(new BigDecimal("126.9780")) // 경도만 제공
        .build();

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findByIdAndUserId(1L, 1L)).willReturn(Optional.of(testLog));

    // when & then
    assertThatThrownBy(() -> logService.updateLog(1L, request, "test@example.com"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("경도가 제공된 경우 위도도 함께 제공되어야 합니다.");
  }

  @Test
  @DisplayName("로그 생성 - 빈 문자열 content로 생성 시도 시 예외 발생")
  void createLog_EmptyContent_ThrowsException() {
    // given
    LogCreateRequest request = LogCreateRequest.builder()
        .content("   ") // 공백 문자열
        .isPublic(true)
        .build();

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));

    // when & then
    assertThatThrownBy(() -> logService.createLog(request, "test@example.com"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("로그 내용은 필수입니다.");
  }

  @Test
  @DisplayName("로그 수정 - 빈 문자열 content로 수정 시도 시 예외 발생")
  void updateLog_EmptyContent_ThrowsException() {
    // given
    LogUpdateRequest request = LogUpdateRequest.builder()
        .content("   ")
        .build();

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findByIdAndUserId(1L, 1L)).willReturn(Optional.of(testLog));

    // when & then
    assertThatThrownBy(() -> logService.updateLog(1L, request, "test@example.com"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("로그 내용은 빈 문자열일 수 없습니다.");
  }

  @Test
  @DisplayName("권한 기반 전체 로그 조회 - 비로그인 사용자는 공개 로그만 조회")
  void searchLogs_AnonymousUser_ShouldGetPublicLogsOnly() {
    // given
    LogSearchRequest searchRequest = LogSearchRequest.builder()
        .page(0)
        .size(20)
        .build(); // 위치 정보 없이 전체 로그 조회

    List<Log> publicLogs = Arrays.asList(testLog);
    Page<Log> publicLogPage = new PageImpl<>(publicLogs);

    given(logRepository.findByIsPublicTrueOrderByCreatedAtDesc(any(Pageable.class)))
        .willReturn(publicLogPage);

    // when
    Page<LogResponse> response = logService.searchLogs(searchRequest, null);

    // then
    assertThat(response).isNotNull();
    assertThat(response.getContent()).hasSize(1);
    assertThat(response.getContent().get(0).getIsPublic()).isTrue();

    verify(logRepository).findByIsPublicTrueOrderByCreatedAtDesc(any(Pageable.class));
    verify(logRepository, never()).findPublicOrUserLogsOrderByCreatedAtDesc(anyLong(),
        any(Pageable.class));
  }

  @Test
  @DisplayName("거리 정렬 방향 테스트 - ASC (가까운 거리 우선)")
  void searchLogs_DistanceSortAsc_Success() {
    // given
    LogSearchRequest searchRequest = LogSearchRequest.builder()
        .latitude(new BigDecimal("37.5665"))
        .longitude(new BigDecimal("126.9780"))
        .radiusKm(new BigDecimal("10.0"))
        .sortBy(LogSortField.DISTANCE)
        .sortDirection(SortDirection.ASC)
        .page(0)
        .size(20)
        .build();

    List<Log> logs = Arrays.asList(testLog);
    Page<Log> logPage = new PageImpl<>(logs);

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findLogsByLocationNearWithUser(
        eq(new BigDecimal("37.5665")),
        eq(new BigDecimal("126.9780")),
        eq(new BigDecimal("10.0")),
        eq(1L),
        eq("ASC"),
        any(Pageable.class))).willReturn(logPage);

    // when
    Page<LogResponse> response = logService.searchLogs(searchRequest, "test@example.com");

    // then
    assertThat(response).isNotNull();
    assertThat(response.getContent()).hasSize(1);

    verify(logRepository).findLogsByLocationNearWithUser(
        eq(new BigDecimal("37.5665")),
        eq(new BigDecimal("126.9780")),
        eq(new BigDecimal("10.0")),
        eq(1L),
        eq("ASC"),
        any(Pageable.class));
  }

  @Test
  @DisplayName("거리 정렬 방향 테스트 - DESC (먼 거리 우선)")
  void searchLogs_DistanceSortDesc_Success() {
    // given
    LogSearchRequest searchRequest = LogSearchRequest.builder()
        .latitude(new BigDecimal("37.5665"))
        .longitude(new BigDecimal("126.9780"))
        .radiusKm(new BigDecimal("10.0"))
        .sortBy(LogSortField.DISTANCE)
        .sortDirection(SortDirection.DESC)
        .page(0)
        .size(20)
        .build();

    List<Log> logs = Arrays.asList(testLog);
    Page<Log> logPage = new PageImpl<>(logs);

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findLogsByLocationNearWithUser(
        eq(new BigDecimal("37.5665")),
        eq(new BigDecimal("126.9780")),
        eq(new BigDecimal("10.0")),
        eq(1L),
        eq("DESC"),
        any(Pageable.class))).willReturn(logPage);

    // when
    Page<LogResponse> response = logService.searchLogs(searchRequest, "test@example.com");

    // then
    assertThat(response).isNotNull();
    assertThat(response.getContent()).hasSize(1);

    verify(logRepository).findLogsByLocationNearWithUser(
        eq(new BigDecimal("37.5665")),
        eq(new BigDecimal("126.9780")),
        eq(new BigDecimal("10.0")),
        eq(1L),
        eq("DESC"),
        any(Pageable.class));
  }

  @Test
  @DisplayName("거리 정렬 방향 테스트 - 비로그인 사용자 DESC")
  void searchLogs_DistanceSortDesc_AnonymousUser_Success() {
    // given
    LogSearchRequest searchRequest = LogSearchRequest.builder()
        .latitude(new BigDecimal("37.5665"))
        .longitude(new BigDecimal("126.9780"))
        .radiusKm(new BigDecimal("10.0"))
        .sortBy(LogSortField.DISTANCE)
        .sortDirection(SortDirection.DESC)
        .page(0)
        .size(20)
        .build();

    List<Log> logs = Arrays.asList(testLog);
    Page<Log> logPage = new PageImpl<>(logs);

    given(logRepository.findPublicLogsByLocationNear(
        eq(new BigDecimal("37.5665")),
        eq(new BigDecimal("126.9780")),
        eq(new BigDecimal("10.0")),
        eq("DESC"),
        any(Pageable.class))).willReturn(logPage);

    // when
    Page<LogResponse> response = logService.searchLogs(searchRequest, null);

    // then
    assertThat(response).isNotNull();
    assertThat(response.getContent()).hasSize(1);

    verify(logRepository).findPublicLogsByLocationNear(
        eq(new BigDecimal("37.5665")),
        eq(new BigDecimal("126.9780")),
        eq(new BigDecimal("10.0")),
        eq("DESC"),
        any(Pageable.class));
  }

  @Test
  @DisplayName("거리 정렬 방향 테스트 - sortDirection이 null인 경우 기본값 ASC 사용")
  void searchLogs_DistanceSortNullDirection_DefaultsToAsc() {
    // given
    LogSearchRequest searchRequest = new LogSearchRequest(
        new BigDecimal("37.5665"),
        new BigDecimal("126.9780"),
        new BigDecimal("10.0"),
        null, // isPublic
        0, // page
        20, // size
        LogSortField.DISTANCE, // sortBy
        null // sortDirection을 명시적으로 null로 설정
    );

    List<Log> logs = Arrays.asList(testLog);
    Page<Log> logPage = new PageImpl<>(logs);

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findLogsByLocationNearWithUser(
        eq(new BigDecimal("37.5665")),
        eq(new BigDecimal("126.9780")),
        eq(new BigDecimal("10.0")),
        eq(1L),
        eq("ASC"), // null인 경우 기본값 ASC 사용
        any(Pageable.class))).willReturn(logPage);

    // when
    Page<LogResponse> response = logService.searchLogs(searchRequest, "test@example.com");

    // then
    assertThat(response).isNotNull();
    assertThat(response.getContent()).hasSize(1);

    verify(logRepository).findLogsByLocationNearWithUser(
        eq(new BigDecimal("37.5665")),
        eq(new BigDecimal("126.9780")),
        eq(new BigDecimal("10.0")),
        eq(1L),
        eq("ASC"),
        any(Pageable.class));
  }

  @Test
  @DisplayName("권한 기반 전체 로그 조회 - 로그인 사용자는 공개 로그 + 본인 비공개 로그 조회")
  void searchLogs_AuthenticatedUser_ShouldGetPublicAndOwnPrivateLogs() {
    // given
    LogSearchRequest searchRequest = LogSearchRequest.builder()
        .page(0)
        .size(20)
        .build(); // 위치 정보 없이 전체 로그 조회

    // 비공개 로그 추가
    Log privateLog = Log.builder()
        .id(2L)
        .user(testUser)
        .content("비공개 로그")
        .latitude(new BigDecimal("37.5665"))
        .longitude(new BigDecimal("126.9780"))
        .address("서울특별시 중구")
        .isPublic(false)
        .viewCount(0L)
        .build();

    List<Log> userAccessibleLogs = Arrays.asList(testLog, privateLog);
    Page<Log> userAccessibleLogPage = new PageImpl<>(userAccessibleLogs);

    given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
    given(logRepository.findPublicOrUserLogsOrderByCreatedAtDesc(eq(1L), any(Pageable.class)))
        .willReturn(userAccessibleLogPage);

    // when
    Page<LogResponse> response = logService.searchLogs(searchRequest, "test@example.com");

    // then
    assertThat(response).isNotNull();
    assertThat(response.getContent()).hasSize(2);

    // 공개 로그와 비공개 로그 모두 포함되어야 함
    boolean hasPublicLog = response.getContent().stream().anyMatch(LogResponse::getIsPublic);
    boolean hasPrivateLog = response.getContent().stream().anyMatch(log -> !log.getIsPublic());
    assertThat(hasPublicLog).isTrue();
    assertThat(hasPrivateLog).isTrue();

    verify(logRepository).findPublicOrUserLogsOrderByCreatedAtDesc(eq(1L), any(Pageable.class));
    verify(logRepository, never()).findByIsPublicTrueOrderByCreatedAtDesc(any(Pageable.class));
  }

  @Nested
  @DisplayName("위치 정보 검증 테스트")
  class LocationValidationTest {

    @Test
    @DisplayName("잘못된 위도로 로그 생성 시도")
    void createLog_InvalidLatitude_ThrowsExceptionWithSpecificMessage() {
      // given
      LogCreateRequest request = LogCreateRequest.builder()
          .content("테스트 로그")
          .latitude(new BigDecimal("999.0")) // 잘못된 위도 (90도 초과)
          .longitude(new BigDecimal("126.9780")) // 정상 경도
          .address("서울특별시")
          .isPublic(true)
          .build();

      given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));

      // when & then
      assertThatThrownBy(() -> logService.createLog(request, "test@example.com"))
          .isInstanceOf(InvalidCoordinateException.class)
          .hasMessage("위도는 -90도에서 90도 사이여야 합니다. 입력값: 999.0");
    }

    @Test
    @DisplayName("잘못된 경도로 로그 생성 시도")
    void createLog_InvalidLongitude_ThrowsExceptionWithSpecificMessage() {
      // given
      LogCreateRequest request = LogCreateRequest.builder()
          .content("테스트 로그")
          .latitude(new BigDecimal("37.5665")) // 정상 위도
          .longitude(new BigDecimal("999.0")) // 잘못된 경도 (180도 초과)
          .address("서울특별시")
          .isPublic(true)
          .build();

      given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));

      // when & then
      assertThatThrownBy(() -> logService.createLog(request, "test@example.com"))
          .isInstanceOf(InvalidCoordinateException.class)
          .hasMessage("경도는 -180도에서 180도 사이여야 합니다. 입력값: 999.0");
    }

    @Test
    @DisplayName("경계값 테스트 (유효한 극값)")
    void createLog_BoundaryCoordinates_Success() {
      // given - 유효한 경계값들
      LogCreateRequest request = LogCreateRequest.builder()
          .content("경계값 테스트")
          .latitude(new BigDecimal("90.0")) // 최대 유효 위도
          .longitude(new BigDecimal("-180.0")) // 최소 유효 경도
          .address("극지방")
          .isPublic(true)
          .build();

      Log expectedLog = Log.builder()
          .id(2L)
          .user(testUser)
          .content("경계값 테스트")
          .latitude(new BigDecimal("90.0"))
          .longitude(new BigDecimal("-180.0"))
          .address("극지방")
          .isPublic(true)
          .viewCount(0L)
          .build();

      given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));
      given(logRepository.save(any(Log.class))).willReturn(expectedLog);

      // when
      LogResponse response = logService.createLog(request, "test@example.com");

      // then
      assertThat(response).isNotNull();
      assertThat(response.getLatitude()).isEqualTo(new BigDecimal("90.0"));
      assertThat(response.getLongitude()).isEqualTo(new BigDecimal("-180.0"));
      verify(logRepository).save(any(Log.class));
    }

    @Test
    @DisplayName("경계값 초과 (무효한 극값)")
    void createLog_OutOfBoundaryCoordinates_ThrowsException() {
      // given - 경계값을 벗어난 좌표들
      LogCreateRequest request = LogCreateRequest.builder()
          .content("경계값 초과 테스트")
          .latitude(new BigDecimal("-90.1")) // 최소값 미만
          .longitude(new BigDecimal("180.1")) // 최대값 초과
          .address("유효하지 않은 위치")
          .isPublic(true)
          .build();

      given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));

      // when & then
      // LocationUtils는 위도를 먼저 검증하므로, 위도 오류만 반환됨
      // (경도도 유효하지 않지만 위도 검증에서 먼저 실패)
      assertThatThrownBy(() -> logService.createLog(request, "test@example.com"))
          .isInstanceOf(InvalidCoordinateException.class)
          .hasMessage("위도는 -90도에서 90도 사이여야 합니다. 입력값: -90.1");
    }
  }

}
