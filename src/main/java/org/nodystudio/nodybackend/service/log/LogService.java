package org.nodystudio.nodybackend.service.log;

import static java.util.stream.Collectors.toMap;

import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.domain.enums.LogSortField;
import org.nodystudio.nodybackend.domain.enums.SortDirection;
import org.nodystudio.nodybackend.domain.log.Log;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.log.LogCreateRequest;
import org.nodystudio.nodybackend.dto.log.LogResponse;
import org.nodystudio.nodybackend.dto.log.LogSearchRequest;
import org.nodystudio.nodybackend.dto.log.LogUpdateRequest;
import org.nodystudio.nodybackend.exception.custom.UserNotFoundException;
import org.nodystudio.nodybackend.repository.LogRepository;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.nodystudio.nodybackend.util.HtmlSanitizerUtil;
import org.nodystudio.nodybackend.util.LocationUtils;
import org.nodystudio.nodybackend.util.LoggingUtils;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 사용자의 위치 기반 로그 관리 서비스
 *
 * <p>
 * 지리적 위치 정보를 활용한 로그 생성, 조회, 검색 기능을 제공합니다. 사용자 권한에 따라 공개/비공개 로그에 대한 접근을 제어하며,
 * Haversine 공식을 사용한 반경
 * 기반 검색을 지원합니다.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class LogService {

  private final LogRepository logRepository;
  private final UserRepository userRepository;

  /**
   * 새로운 로그를 생성합니다.
   *
   * @param request   로그 생성 요청 정보
   * @param userEmail 로그 작성자의 이메일
   * @return 생성된 로그 정보
   * @throws IllegalArgumentException 위치 좌표가 유효하지 않은 경우
   * @throws UserNotFoundException    사용자를 찾을 수 없는 경우
   */
  @Transactional
  public LogResponse createLog(LogCreateRequest request, String userEmail) {
    log.info("로그 생성 요청 - 사용자: {}, 위치: ({}, {})",
        userEmail, request.getLatitude(), request.getLongitude());

    User user = findUserByEmail(userEmail);

    if (user == null) {
      throw new UserNotFoundException("사용자를 찾을 수 없습니다.");
    }

    if (request.getContent() != null && request.getContent().trim().isEmpty()) {
      throw new IllegalArgumentException("로그 내용은 필수입니다.");
    }

    // XSS 공격 방지를 위한 HTML sanitization
    String sanitizedContent = request.getContent() != null
        ? HtmlSanitizerUtil.sanitize(request.getContent())
        : null;

    LocationUtils.validateCoordinates(request.getLatitude(), request.getLongitude());

    Log logEntity = Log.builder()
        .user(user)
        .content(sanitizedContent)
        .latitude(request.getLatitude())
        .longitude(request.getLongitude())
        .address(request.getAddress())
        .mediaUrls(request.getMediaUrls())
        .isPublic(request.getIsPublic())
        .build();

    Log savedLog = logRepository.save(logEntity);
    log.info("로그 생성 완료 - ID: {}, HTML sanitization 적용됨", savedLog.getId());

    return LogResponse.from(savedLog);
  }

  /**
   * 로그를 조회하고 조회수를 증가시킵니다.
   *
   * <p>
   * 사용자 권한에 따라 접근 가능한 로그를 제한합니다:
   * <ul>
   * <li>로그인 사용자: 공개 로그 + 본인의 비공개 로그</li>
   * <li>비로그인 사용자: 공개 로그만</li>
   * </ul>
   *
   * @param logId     조회할 로그 ID
   * @param userEmail 조회 요청자의 이메일 (null 가능)
   * @return 로그 상세 정보
   * @throws IllegalArgumentException 로그를 찾을 수 없거나 접근 권한이 없는 경우
   */
  @Transactional
  public LogResponse getLog(Long logId, String userEmail) {
    log.info("로그 조회 요청 - ID: {}, 사용자: {}", logId, userEmail);

    User viewer = userEmail != null ? findUserByEmail(userEmail) : null;

    Log logEntity = findViewableLog(logId, viewer);
    logEntity.incrementViewCount();

    log.info("로그 조회 완료 - ID: {}, 조회수: {}", logEntity.getId(), logEntity.getViewCount());
    return LogResponse.from(logEntity);
  }

  /**
   * 위치 기반 로그를 검색합니다.
   *
   * <p>
   * 위치 정보가 제공된 경우 지정된 반경 내의 로그를 검색하고, 위치 정보가 없는 경우 전체 로그를 조회합니다. 사용자 권한에 따라
   * 공개/비공개 로그 접근을 제어합니다.
   * </p>
   *
   * @param searchRequest 검색 조건 (위치, 반경, 페이징 정보)
   * @param userEmail     검색 요청자의 이메일 (null 가능)
   * @return 검색된 로그 목록 (페이징 처리됨)
   * @throws IllegalArgumentException 위치 좌표가 유효하지 않은 경우
   */
  public Page<LogResponse> searchLogs(LogSearchRequest searchRequest, String userEmail) {
    log.info("로그 검색 요청 - 위치: ({}, {}), 반경: {}km, 사용자: {}",
        searchRequest.getLatitude(), searchRequest.getLongitude(),
        searchRequest.getRadiusKm(), userEmail);

    User viewer = userEmail != null ? findUserByEmail(userEmail) : null;

    // 위치 기반 검색 시 Native Query의 ORDER BY를 사용하므로 Pageable에서 정렬 제외
    Pageable pageable = createPageable(searchRequest, searchRequest.isLocationSearch());

    Page<Log> logs = executeLogSearch(searchRequest, viewer, pageable,
        searchRequest.isLocationSearch());

    log.info("로그 검색 완료 - 총 {}건", logs.getTotalElements());
    return logs.map(LogResponse::from);
  }

  /**
   * 로그를 수정합니다.
   *
   * <p>
   * 로그 작성자만 수정할 수 있으며, 제공된 필드만 업데이트됩니다. null이 아닌 필드만 변경되는 부분 업데이트 방식을 사용합니다.
   * </p>
   *
   * @param logId     수정할 로그 ID
   * @param request   수정할 정보
   * @param userEmail 수정 요청자의 이메일
   * @return 수정된 로그 정보
   * @throws IllegalArgumentException 권한이 없거나 로그를 찾을 수 없는 경우
   * @throws IllegalArgumentException 위치 좌표가 유효하지 않은 경우
   */
  @Transactional
  public LogResponse updateLog(Long logId, LogUpdateRequest request, String userEmail) {
    log.info("로그 수정 요청 - ID: {}, 사용자: {}", logId, userEmail);

    User user = findUserByEmail(userEmail);
    Log logEntity = findUserOwnedLog(logId, user.getId());

    validateLocationIfPresent(request);
    updateLogFields(logEntity, request);

    log.info("로그 수정 완료 - ID: {}", logEntity.getId());
    return LogResponse.from(logEntity);
  }

  /**
   * 로그를 삭제합니다.
   *
   * <p>
   * 로그 작성자만 삭제할 수 있습니다.
   * </p>
   *
   * @param logId     삭제할 로그 ID
   * @param userEmail 삭제 요청자의 이메일
   * @throws IllegalArgumentException 권한이 없거나 로그를 찾을 수 없는 경우
   */
  @Transactional
  public void deleteLog(Long logId, String userEmail) {
    log.info("로그 삭제 요청 - ID: {}, 사용자: {}", logId, userEmail);

    User user = findUserByEmail(userEmail);
    Log logEntity = findUserOwnedLog(logId, user.getId());

    logRepository.delete(logEntity);
    log.info("로그 삭제 완료 - ID: {}", logId);
  }

  /**
   * 검색 조건에 따라 페이징(Paging) 및 정렬(Sort) 설정을 담은 {@link Pageable} 객체를 생성합니다.
   *
   * <p>
   * 이 메서드는 위치 기반 검색 여부에 따라 정렬 객체의 포함 여부를 동적으로 결정합니다.
   * 위치 검색 시에는 거리순 정렬이 데이터베이스의 네이티브 쿼리에서 직접 처리되므로,
   * {@code Pageable} 객체에는 별도의 정렬 정보를 포함하지 않습니다.
   * 그 외의 경우에는 요청된 정렬 기준을 적용합니다.
   * </p>
   *
   * @param searchRequest    페이징 및 정렬 정보가 포함된 검색 요청 객체
   * @param isLocationSearch 위치 기반 검색 여부를 나타내는 플래그
   * @return 생성된 {@code Pageable} 객체
   */
  private Pageable createPageable(LogSearchRequest searchRequest, boolean isLocationSearch) {
    Sort sort = createSort(searchRequest.getSortBy(), searchRequest.getSortDirection());
    return isLocationSearch
        ? PageRequest.of(searchRequest.getPage(), searchRequest.getSize())
        : PageRequest.of(searchRequest.getPage(), searchRequest.getSize(), sort);
  }

  /**
   * 정렬 기준과 방향에 따라 Sort 객체를 생성합니다.
   *
   * @param sortBy        정렬 기준 (CREATED_AT, VIEW_COUNT, DISTANCE)
   * @param sortDirection 정렬 방향 (ASC, DESC)
   * @return Sort 객체 (distance의 경우 Repository 쿼리에서 거리 정렬이 이미 처리됨)
   */
  private Sort createSort(LogSortField sortBy, SortDirection sortDirection) {
    Sort.Direction direction = sortDirection == SortDirection.ASC
        ? Sort.Direction.ASC
        : Sort.Direction.DESC;

    return switch (sortBy) {
      case CREATED_AT -> Sort.by(direction, "createdAt");
      case VIEW_COUNT -> Sort.by(direction, "viewCount");
      case DISTANCE -> {
        // 거리 정렬은 Repository의 네이티브 쿼리에서 처리됨
        log.info("거리 정렬 요청됨 - Repository 쿼리에서 처리됩니다.");
        yield Sort.unsorted();
      }
      default -> Sort.by(Sort.Direction.DESC, "createdAt");
    };
  }

  /**
   * 이메일로 사용자를 조회합니다.
   *
   * @param email 조회할 사용자 이메일
   * @return 조회된 사용자
   * @throws UserNotFoundException 사용자를 찾을 수 없는 경우
   */
  private User findUserByEmail(String email) {
    return userRepository.findByEmail(email)
        .orElseThrow(() -> new UserNotFoundException("사용자를 찾을 수 없습니다: " + email));
  }

  /**
   * 사용자 권한에 따라 조회 가능한 로그를 찾습니다.
   */
  private Log findViewableLog(Long logId, User viewer) {
    if (viewer != null) {
      return logRepository.findViewableLogByIdAndUserId(logId, viewer.getId())
          .orElseThrow(() -> new IllegalArgumentException("로그를 찾을 수 없습니다."));
    } else {
      return logRepository.findByIdAndIsPublicTrue(logId)
          .orElseThrow(() -> new IllegalArgumentException("로그를 찾을 수 없습니다."));
    }
  }

  /**
   * 거리 정렬 방향을 결정합니다.
   */
  private String getDistanceSortDirection(LogSearchRequest searchRequest) {
    if (LogSortField.DISTANCE.equals(searchRequest.getSortBy())
        && searchRequest.getSortDirection() != null) {
      return searchRequest.getSortDirection().getValue().toUpperCase();
    }
    return SortDirection.ASC.getValue().toUpperCase(); // 기본값
  }

  /**
   * 위치 기반 로그 검색을 수행합니다.
   */
  private Page<Log> searchByLocation(LogSearchRequest searchRequest, User viewer,
      Pageable pageable) {
    LocationUtils.validateCoordinates(searchRequest.getLatitude(), searchRequest.getLongitude());

    // 거리 정렬 방향 결정
    String distanceSortDirection = getDistanceSortDirection(searchRequest);

    if (viewer != null) {
      return logRepository.findLogsByLocationNearWithUser(
          searchRequest.getLatitude(),
          searchRequest.getLongitude(),
          searchRequest.getRadiusKm(),
          viewer.getId(),
          distanceSortDirection,
          pageable);
    } else {
      return logRepository.findPublicLogsByLocationNear(
          searchRequest.getLatitude(),
          searchRequest.getLongitude(),
          searchRequest.getRadiusKm(),
          distanceSortDirection,
          pageable);
    }
  }

  /**
   * 검색 조건에 따라 로그를 조회하는 내부 헬퍼 메서드입니다.
   *
   * <p>
   * 위치 기반 검색과 전체 검색을 분기하여 처리합니다.
   * <ul>
   * <li><b>위치 기반 검색 (isLocationSearch = true):</b> {@link #searchByLocation} 메서드를
   * 호출하여 반경 내 로그를 검색합니다.</li>
   * <li><b>전체 검색 (isLocationSearch = false):</b>
   * <ul>
   * <li><b>로그인 사용자 (viewer != null):</b> 모든 공개 로그와 사용자 자신의 비공개 로그을 조회합니다.</li>
   * <li><b>비로그인 사용자 (viewer == null):</b> 모든 공개 로그만 조회합니다.</li>
   * </ul>
   * </li>
   * </ul>
   * </p>
   *
   * @param searchRequest    검색 조건이 담긴 요청 객체
   * @param viewer           조회하는 사용자 정보 (null일 경우 비로그인 사용자)
   * @param pageable         페이징 및 정렬 정보
   * @param isLocationSearch 위치 기반 검색 여부 플래그
   * @return 검색 조건에 맞는 페이징 처리된 로그 목록
   */
  private Page<Log> executeLogSearch(LogSearchRequest searchRequest, User viewer, Pageable pageable,
      boolean isLocationSearch) {

    if (isLocationSearch) {
      Page<Log> logsWithoutMedia = searchByLocation(searchRequest, viewer, pageable);
      if (logsWithoutMedia.hasContent()) {
        List<Long> logIds = logsWithoutMedia.getContent().stream()
            .map(Log::getId)
            .toList();
        List<Log> logsWithMedia = logRepository.findWithMediaUrlsByIdIn(logIds);
        Map<Long, Log> logMap = logsWithMedia.stream()
            .collect(toMap(Log::getId, l -> l));
        logsWithoutMedia.getContent().forEach(log -> {
          Log logWithMedia = logMap.get(log.getId());
          if (logWithMedia != null) {
            log.updateMediaUrls(logWithMedia.getMediaUrls());
          }
        });
      }
      return logsWithoutMedia;
    }

    // 전체 로그 검색
    if (viewer != null) {
      // 로그인 사용자: 공개 로그 + 본인 비공개 로그
      return logRepository.findPublicOrUserLogsOrderByCreatedAtDesc(viewer.getId(), pageable);
    } else {
      // 비로그인 사용자: 공개 로그만
      return logRepository.findByIsPublicTrueOrderByCreatedAtDesc(pageable);
    }
  }

  /**
   * 사용자가 소유한 로그를 찾습니다.
   */
  private Log findUserOwnedLog(Long logId, Long userId) {
    return logRepository.findByIdAndUserId(logId, userId)
        .orElseThrow(() -> new IllegalArgumentException("수정 권한이 없거나 로그를 찾을 수 없습니다."));
  }

  /**
   * 수정 요청에 위치 정보가 있는 경우 유효성을 검증합니다. 위도와 경도는 쌍으로 제공되어야 합니다.
   */
  private void validateLocationIfPresent(LogUpdateRequest request) {
    if (request.getLatitude() != null || request.getLongitude() != null) {
      if (request.getLatitude() == null) {
        throw new IllegalArgumentException("경도가 제공된 경우 위도도 함께 제공되어야 합니다.");
      }
      if (request.getLongitude() == null) {
        throw new IllegalArgumentException("위도가 제공된 경우 경도도 함께 제공되어야 합니다.");
      }
      LocationUtils.validateCoordinates(request.getLatitude(), request.getLongitude());
    }
  }

  /**
   * 로그 필드들을 업데이트합니다.
   */
  private void updateLogFields(Log logEntity, LogUpdateRequest request) {
    if (request.getContent() != null) {
      if (request.getContent().trim().isEmpty()) {
        throw new IllegalArgumentException("로그 내용은 빈 문자열일 수 없습니다.");
      }
      // XSS 공격 방지를 위한 HTML sanitization
      String sanitizedContent = HtmlSanitizerUtil.sanitize(request.getContent());
      logEntity.updateContent(sanitizedContent);
      log.debug("로그 내용 업데이트 - ID: {}, HTML sanitization 적용됨", logEntity.getId());
    }

    if (request.getLatitude() != null || request.getLongitude() != null
        || request.getAddress() != null) {
      logEntity.updateLocation(request.getLatitude(), request.getLongitude(), request.getAddress());
    }

    if (request.getIsPublic() != null) {
      logEntity.updatePublicSetting(request.getIsPublic());
    }

    if (request.getMediaUrls() != null) {
      logEntity.updateMediaUrls(request.getMediaUrls());
    }
  }

  /**
   * 특정 사용자의 모든 활성 로그를 비활성화합니다.
   * 계정 탈퇴 시 사용자 생성 데이터를 안전하게 보존하면서 조회에서 제외시킵니다.
   *
   * @param userId 비활성화할 사용자 ID
   * @return 비활성화된 로그의 개수
   */
  @Transactional
  public int deactivateLogsByUserId(Long userId) {
    log.debug("사용자 로그 비활성화 시작: userId={}", LoggingUtils.maskUserId(userId));

    List<Log> activeLogs = logRepository.findActiveLogsByUserId(userId);
    activeLogs.forEach(Log::deactivate);
    logRepository.saveAll(activeLogs);

    log.debug("사용자 로그 비활성화 완료: userId={}, count={}",
        LoggingUtils.maskUserId(userId), activeLogs.size());

    return activeLogs.size();
  }

  /**
   * 특정 사용자의 모든 비활성화된 로그를 재활성화합니다.
   * 계정 복구 시 원본 공개설정을 보존하면서 다시 조회 가능하도록 복원합니다.
   *
   * @param userId 재활성화할 사용자 ID
   * @return 재활성화된 로그의 개수
   */
  @Transactional
  public int reactivateLogsByUserId(Long userId) {
    log.debug("사용자 로그 재활성화 시작: userId={}", LoggingUtils.maskUserId(userId));

    int reactivatedCount = logRepository.reactivateByUserId(userId);

    log.debug("사용자 로그 재활성화 완료: userId={}, count={}",
        LoggingUtils.maskUserId(userId), reactivatedCount);

    return reactivatedCount;
  }
}
