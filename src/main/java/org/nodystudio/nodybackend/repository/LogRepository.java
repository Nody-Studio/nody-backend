package org.nodystudio.nodybackend.repository;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import org.nodystudio.nodybackend.domain.log.Log;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * - findByLocationNear: 특정 좌표 반경 내 로그 조회 (Haversine 공식) - findByUserIdOrderByCreatedAtDesc: 사용자별 로그
 * 조회 - @Query 어노테이션으로 네이티브 쿼리 작성
 */
@Repository
@Transactional(readOnly = true)
public interface LogRepository extends JpaRepository<Log, Long> {

  /**
   * 사용자별 로그 조회 (활성화된 로그만)
   */
  @Query("SELECT l FROM Log l WHERE l.user.id = :userId AND l.deactivatedAt IS NULL ORDER BY l.createdAt DESC")
  List<Log> findByUserIdOrderByCreatedAtDesc(@Param("userId") Long userId);

  /**
   * 사용자별 로그 조회 (페이징, 활성화된 로그만)
   */
  @Query("SELECT l FROM Log l WHERE l.user.id = :userId AND l.deactivatedAt IS NULL ORDER BY l.createdAt DESC")
  Page<Log> findByUserIdOrderByCreatedAtDesc(@Param("userId") Long userId, Pageable pageable);

  /**
   * 특정 좌표 반경 내 로그 조회 (Haversine 공식 사용)
   *
   * @param latitude  중심 위도
   * @param longitude 중심 경도
   * @param radiusKm  반경 (km)
   * @param pageable  페이징 정보
   * @return 반경 내 로그 목록
   */
  @Query(value = """
      SELECT l.*,
             (6371 * acos(cos(radians(:latitude)) * cos(radians(l.latitude)) *
             cos(radians(l.longitude) - radians(:longitude)) +
             sin(radians(:latitude)) * sin(radians(l.latitude)))) as distance
      FROM logs l
      WHERE l.latitude IS NOT NULL
        AND l.longitude IS NOT NULL
        AND l.deactivated_at IS NULL
        AND (6371 * acos(cos(radians(:latitude)) * cos(radians(l.latitude)) *
             cos(radians(l.longitude) - radians(:longitude)) +
             sin(radians(:latitude)) * sin(radians(l.latitude)))) <= :radiusKm
      ORDER BY distance ASC, l.created_at DESC
      """, countQuery = """
      SELECT COUNT(*)
      FROM logs l
      WHERE l.latitude IS NOT NULL
        AND l.longitude IS NOT NULL
        AND l.deactivated_at IS NULL
        AND (6371 * acos(cos(radians(:latitude)) * cos(radians(l.latitude)) *
             cos(radians(l.longitude) - radians(:longitude)) +
             sin(radians(:latitude)) * sin(radians(l.latitude)))) <= :radiusKm
      """, nativeQuery = true)
  Page<Log> findByLocationNear(@Param("latitude") BigDecimal latitude,
      @Param("longitude") BigDecimal longitude,
      @Param("radiusKm") BigDecimal radiusKm,
      Pageable pageable);

  /**
   * 공개 로그만 위치 기반으로 조회
   */
  @Query(value = """
      SELECT l.*,
             (6371 * acos(cos(radians(:latitude)) * cos(radians(l.latitude)) *
             cos(radians(l.longitude) - radians(:longitude)) +
             sin(radians(:latitude)) * sin(radians(l.latitude)))) as distance
      FROM logs l
      WHERE l.latitude IS NOT NULL
        AND l.longitude IS NOT NULL
        AND l.is_public = true
        AND l.deactivated_at IS NULL
        AND (6371 * acos(cos(radians(:latitude)) * cos(radians(l.latitude)) *
             cos(radians(l.longitude) - radians(:longitude)) +
             sin(radians(:latitude)) * sin(radians(l.latitude)))) <= :radiusKm
      ORDER BY 
        CASE WHEN :sortDirection = 'ASC' THEN distance END ASC,
        CASE WHEN :sortDirection = 'DESC' THEN distance END DESC,
        l.created_at DESC
      """, countQuery = """
      SELECT COUNT(*)
      FROM logs l
      WHERE l.latitude IS NOT NULL
        AND l.longitude IS NOT NULL
        AND l.is_public = true
        AND l.deactivated_at IS NULL
        AND (6371 * acos(cos(radians(:latitude)) * cos(radians(l.latitude)) *
             cos(radians(l.longitude) - radians(:longitude)) +
             sin(radians(:latitude)) * sin(radians(l.latitude)))) <= :radiusKm
      """, nativeQuery = true)
  Page<Log> findPublicLogsByLocationNear(@Param("latitude") BigDecimal latitude,
      @Param("longitude") BigDecimal longitude,
      @Param("radiusKm") BigDecimal radiusKm,
      @Param("sortDirection") String sortDirection,
      Pageable pageable);

  /**
   * 특정 사용자의 위치 기반 로그 조회 (본인 비공개 로그 포함)
   */
  @Query(value = """
      SELECT l.*,
             (6371 * acos(cos(radians(:latitude)) * cos(radians(l.latitude)) *
             cos(radians(l.longitude) - radians(:longitude)) +
             sin(radians(:latitude)) * sin(radians(l.latitude)))) as distance
      FROM logs l
      WHERE l.latitude IS NOT NULL
        AND l.longitude IS NOT NULL
        AND l.deactivated_at IS NULL
        AND (l.is_public = true OR l.user_id = :userId)
        AND (6371 * acos(cos(radians(:latitude)) * cos(radians(l.latitude)) *
             cos(radians(l.longitude) - radians(:longitude)) +
             sin(radians(:latitude)) * sin(radians(l.latitude)))) <= :radiusKm
      ORDER BY 
        CASE WHEN :sortDirection = 'ASC' THEN distance END ASC,
        CASE WHEN :sortDirection = 'DESC' THEN distance END DESC,
        l.created_at DESC
      """, countQuery = """
      SELECT COUNT(*)
      FROM logs l
      WHERE l.latitude IS NOT NULL
        AND l.longitude IS NOT NULL
        AND l.deactivated_at IS NULL
        AND (l.is_public = true OR l.user_id = :userId)
        AND (6371 * acos(cos(radians(:latitude)) * cos(radians(l.latitude)) *
             cos(radians(l.longitude) - radians(:longitude)) +
             sin(radians(:latitude)) * sin(radians(l.latitude)))) <= :radiusKm
      """, nativeQuery = true)
  Page<Log> findLogsByLocationNearWithUser(@Param("latitude") BigDecimal latitude,
      @Param("longitude") BigDecimal longitude,
      @Param("radiusKm") BigDecimal radiusKm,
      @Param("userId") Long userId,
      @Param("sortDirection") String sortDirection,
      Pageable pageable);

  /**
   * 로그 ID와 작성자 확인을 위한 조회 (활성화된 로그만)
   */
  @Query("SELECT l FROM Log l WHERE l.id = :id AND l.user.id = :userId AND l.deactivatedAt IS NULL")
  Optional<Log> findByIdAndUserId(@Param("id") Long id, @Param("userId") Long userId);

  /**
   * 공개 로그 또는 특정 사용자의 로그 조회 (활성화된 로그만)
   */
  @Query("SELECT l FROM Log l WHERE l.id = :id AND l.deactivatedAt IS NULL AND (l.isPublic = true OR l.user.id = :userId)")
  Optional<Log> findViewableLogByIdAndUserId(@Param("id") Long id, @Param("userId") Long userId);

  /**
   * 공개 로그만 조회 (활성화된 로그만)
   */
  @Query("SELECT l FROM Log l WHERE l.id = :id AND l.isPublic = true AND l.deactivatedAt IS NULL")
  Optional<Log> findByIdAndIsPublicTrue(@Param("id") Long id);

  /**
   * 공개 로그만 전체 조회 (비로그인 사용자용, 활성화된 로그만)
   */
  @Query("SELECT l FROM Log l WHERE l.isPublic = true AND l.deactivatedAt IS NULL ORDER BY l.createdAt DESC")
  Page<Log> findByIsPublicTrueOrderByCreatedAtDesc(Pageable pageable);

  /**
   * 공개 로그 + 특정 사용자의 비공개 로그 조회 (로그인 사용자용, 활성화된 로그만)
   */
  @Query("SELECT l FROM Log l WHERE l.deactivatedAt IS NULL AND (l.isPublic = true OR l.user.id = :userId) ORDER BY l.createdAt DESC")
  Page<Log> findPublicOrUserLogsOrderByCreatedAtDesc(@Param("userId") Long userId,
      Pageable pageable);

  /**
   * 활성화된 사용자 로그를 모두 조회합니다 (비활성화 작업용).
   */
  @Query("SELECT l FROM Log l WHERE l.user.id = :userId AND l.deactivatedAt IS NULL")
  List<Log> findActiveLogsByUserId(@Param("userId") Long userId);

  /**
   * 비활성화된 사용자 로그를 모두 조회합니다 (재활성화 작업용).
   */
  @Query("SELECT l FROM Log l WHERE l.user.id = :userId AND l.deactivatedAt IS NOT NULL")
  List<Log> findDeactivatedLogsByUserId(@Param("userId") Long userId);

  /**
   * 사용자별 로그를 재활성화합니다 (계정 복구 시).
   * Soft delete 상태를 해제하여 로그를 다시 공개합니다.
   */
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query("UPDATE Log l SET l.deactivatedAt = NULL WHERE l.user.id = :userId AND l.deactivatedAt IS NOT NULL")
  int reactivateByUserId(@Param("userId") Long userId);

  /**
   * 비활성화된 사용자 로그를 완전히 삭제합니다 (물리적 삭제).
   * 탈퇴 후 30일이 지난 사용자의 로그를 데이터베이스에서 완전히 제거합니다.
   *
   * @param userId 사용자 ID
   * @return 삭제된 로그 수
   */
  @Transactional
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query(value = "DELETE FROM logs WHERE user_id = :userId AND deactivated_at IS NOT NULL", nativeQuery = true)
  int deleteDeactivatedByUserId(@Param("userId") Long userId);

}