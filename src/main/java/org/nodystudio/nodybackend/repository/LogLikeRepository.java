package org.nodystudio.nodybackend.repository;

import java.util.Optional;

import org.nodystudio.nodybackend.domain.like.LogLike;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import jakarta.persistence.LockModeType;

/**
 * 로그 좋아요 데이터 접근을 위한 Repository
 */
@Repository
public interface LogLikeRepository extends JpaRepository<LogLike, Long> {

  /**
   * 원자적 로그 좋아요 토글 연산을 수행합니다.
   * <p>
   * 존재하지 않으면 새로운 활성 좋아요를 생성하고, 존재하면 상태를 토글합니다.
   * MySQL의 ON DUPLICATE KEY UPDATE 문법을 사용하여 동시성 안전성을 보장합니다.
   *
   * @param userId 사용자 ID
   * @param logId  로그 ID
   * @return 영향받은 행 수 (항상 1)
   */
  @Modifying
  @Query(value = """
      INSERT INTO log_likes (user_id, log_id, is_active, created_at, updated_at)
      VALUES (:userId, :logId, 1, NOW(), NOW())
      ON DUPLICATE KEY UPDATE
          is_active = IF(is_active = 1, 0, 1),
          updated_at = NOW()
      """, nativeQuery = true)
  int atomicToggleLike(@Param("userId") Long userId, @Param("logId") Long logId);

  /**
   * 특정 사용자가 특정 로그에 좋아요를 눌렀는지 확인합니다. (비관적 락 적용)
   *
   * @param userId 사용자 ID
   * @param logId  로그 ID
   * @return 좋아요 엔티티 (존재하지 않으면 empty)
   */
  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("SELECT ll FROM LogLike ll WHERE ll.user.id = :userId AND ll.log.id = :logId")
  Optional<LogLike> findByUserIdAndLogId(@Param("userId") Long userId,
      @Param("logId") Long logId);

  /**
   * 특정 로그의 활성 좋아요 개수를 조회합니다.
   *
   * @param logId 로그 ID
   * @return 활성 좋아요 개수
   */
  @Query("SELECT COUNT(ll) FROM LogLike ll WHERE ll.log.id = :logId AND ll.isActive = true")
  long countByLogIdAndIsActiveTrue(@Param("logId") Long logId);

  /**
   * 특정 사용자가 특정 로그에 활성 좋아요를 눌렀는지 확인합니다.
   *
   * @param userId 사용자 ID
   * @param logId  로그 ID
   * @return 활성 좋아요 존재 여부
   */
  @Query("SELECT COUNT(ll) > 0 FROM LogLike ll WHERE ll.user.id = :userId AND ll.log.id = :logId AND ll.isActive = true")
  boolean existsByUserIdAndLogIdAndIsActiveTrue(@Param("userId") Long userId,
      @Param("logId") Long logId);

  /**
   * 특정 사용자의 로그 좋아요를 삭제합니다. (물리적 삭제)
   * 테스트 용도로만 사용해야 합니다.
   *
   * @param userId 사용자 ID
   * @param logId  로그 ID
   */
  void deleteByUserIdAndLogId(Long userId, Long logId);

  /**
   * 사용자별 로그 좋아요를 비활성화합니다 (계정 탈퇴 시).
   * 물리적 삭제 대신 isActive = false로 설정합니다.
   */
  @Modifying
  @Query("UPDATE LogLike ll SET ll.isActive = false WHERE ll.user.id = :userId AND ll.isActive = true")
  int deactivateByUserId(@Param("userId") Long userId);

  /**
   * 사용자별 로그 좋아요를 재활성화합니다 (계정 복구 시).
   * 비활성화된 좋아요를 다시 활성화합니다.
   */
  @Modifying
  @Query("UPDATE LogLike ll SET ll.isActive = true WHERE ll.user.id = :userId AND ll.isActive = false")
  int reactivateByUserId(@Param("userId") Long userId);
}