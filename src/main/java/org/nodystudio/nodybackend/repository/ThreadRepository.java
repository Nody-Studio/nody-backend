package org.nodystudio.nodybackend.repository;

import java.util.List;
import java.util.Optional;
import org.nodystudio.nodybackend.domain.thread.Thread;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional(readOnly = true)
public interface ThreadRepository extends JpaRepository<Thread, Long> {

  /**
   * 사용자가 소유한 스레드를 조회합니다 (활성화된 스레드만).
   */
  @Query("SELECT t FROM Thread t WHERE t.id = :id AND t.user.id = :userId AND t.deactivatedAt IS NULL")
  Optional<Thread> findByIdAndUserId(@Param("id") Long id, @Param("userId") Long userId);

  /**
   * 공개 스레드를 ID로 조회합니다 (활성화된 스레드만).
   */
  @Query("SELECT t FROM Thread t WHERE t.id = :id AND t.isPublic = true AND t.deactivatedAt IS NULL")
  Optional<Thread> findByIdAndIsPublicTrue(@Param("id") Long id);

  /**
   * 사용자가 볼 수 있는 스레드를 조회합니다 (공개 스레드 + 본인 스레드, 활성화된 스레드만).
   */
  @Query("""
          SELECT t FROM Thread t
          WHERE t.id = :threadId
            AND t.deactivatedAt IS NULL
            AND (t.isPublic = true OR t.user.id = :userId)
      """)
  Optional<Thread> findViewableThreadByIdAndUserId(@Param("threadId") Long threadId,
      @Param("userId") Long userId);

  /**
   * 공개 스레드 목록을 최신순으로 조회합니다 (활성화된 스레드만).
   */
  @Query("SELECT t FROM Thread t WHERE t.isPublic = true AND t.deactivatedAt IS NULL ORDER BY t.createdAt DESC")
  Page<Thread> findByIsPublicTrueOrderByCreatedAtDesc(Pageable pageable);

  /**
   * 사용자가 볼 수 있는 스레드 목록을 조회합니다 (공개 스레드 + 본인 스레드, 활성화된 스레드만).
   */
  @Query("""
          SELECT t FROM Thread t
          WHERE t.deactivatedAt IS NULL
            AND (t.isPublic = true OR t.user.id = :userId)
          ORDER BY t.createdAt DESC
      """)
  Page<Thread> findPublicOrUserThreadsOrderByCreatedAtDesc(@Param("userId") Long userId,
      Pageable pageable);

  /**
   * 특정 로그에 연결된 스레드 목록을 조회합니다 (공개 스레드만, 활성화된 스레드만).
   */
  @Query("""
          SELECT t FROM Thread t
          WHERE t.log.id = :logId 
            AND t.isPublic = true 
            AND t.deactivatedAt IS NULL
          ORDER BY t.createdAt DESC
      """)
  Page<Thread> findPublicThreadsByLogIdOrderByCreatedAtDesc(@Param("logId") Long logId,
      Pageable pageable);

  /**
   * 특정 로그에 연결된 스레드 목록을 조회합니다 (사용자별 권한 고려, 활성화된 스레드만).
   */
  @Query("""
          SELECT t FROM Thread t
          WHERE t.log.id = :logId 
            AND t.deactivatedAt IS NULL
            AND (t.isPublic = true OR t.user.id = :userId)
          ORDER BY t.createdAt DESC
      """)
  Page<Thread> findThreadsByLogIdWithUser(@Param("logId") Long logId,
      @Param("userId") Long userId,
      Pageable pageable);

  /**
   * 특정 사용자가 작성한 스레드 목록을 조회합니다 (활성화된 스레드만).
   */
  @Query("SELECT t FROM Thread t WHERE t.user.id = :userId AND t.deactivatedAt IS NULL ORDER BY t.createdAt DESC")
  Page<Thread> findByUserIdOrderByCreatedAtDesc(@Param("userId") Long userId, Pageable pageable);

  /**
   * 독립 스레드 목록을 조회합니다 (로그에 연결되지 않은 스레드, 공개만, 활성화된 스레드만).
   */
  @Query("""
          SELECT t FROM Thread t
          WHERE t.log IS NULL 
            AND t.isPublic = true 
            AND t.deactivatedAt IS NULL
          ORDER BY t.createdAt DESC
      """)
  Page<Thread> findIndependentPublicThreadsOrderByCreatedAtDesc(Pageable pageable);

  /**
   * 독립 스레드 목록을 조회합니다 (사용자별 권한 고려, 활성화된 스레드만).
   */
  @Query("""
          SELECT t FROM Thread t
          WHERE t.log IS NULL 
            AND t.deactivatedAt IS NULL
            AND (t.isPublic = true OR t.user.id = :userId)
          ORDER BY t.createdAt DESC
      """)
  Page<Thread> findIndependentThreadsWithUser(@Param("userId") Long userId,
      Pageable pageable);

  /**
   * 로그 연결 스레드 목록을 조회합니다 (로그에 연결된 스레드, 공개만, 활성화된 스레드만).
   */
  @Query("""
          SELECT t FROM Thread t
          WHERE t.log IS NOT NULL 
            AND t.isPublic = true 
            AND t.deactivatedAt IS NULL
          ORDER BY t.createdAt DESC
      """)
  Page<Thread> findLinkedPublicThreadsOrderByCreatedAtDesc(Pageable pageable);

  /**
   * 로그 연결 스레드 목록을 조회합니다 (사용자별 권한 고려, 활성화된 스레드만).
   */
  @Query("""
          SELECT t FROM Thread t
          WHERE t.log IS NOT NULL 
            AND t.deactivatedAt IS NULL
            AND (t.isPublic = true OR t.user.id = :userId)
          ORDER BY t.createdAt DESC
      """)
  Page<Thread> findLinkedThreadsWithUser(@Param("userId") Long userId,
      Pageable pageable);

  /**
   * 내용으로 공개 스레드를 검색합니다 (활성화된 스레드만).
   */
  @Query("""
          SELECT t FROM Thread t
          WHERE t.isPublic = true 
            AND t.deactivatedAt IS NULL
            AND LOWER(t.content) LIKE LOWER(CONCAT('%', :keyword, '%'))
          ORDER BY t.createdAt DESC
      """)
  Page<Thread> searchPublicThreadsByContent(@Param("keyword") String keyword,
      Pageable pageable);

  /**
   * 내용으로 스레드를 검색합니다 (사용자별 권한 고려, 활성화된 스레드만).
   */
  @Query("""
          SELECT t FROM Thread t
          WHERE t.deactivatedAt IS NULL
            AND (t.isPublic = true OR t.user.id = :userId) 
            AND LOWER(t.content) LIKE LOWER(CONCAT('%', :keyword, '%'))
          ORDER BY t.createdAt DESC
      """)
  Page<Thread> searchThreadsByContentWithUser(@Param("keyword") String keyword,
      @Param("userId") Long userId,
      Pageable pageable);

  /**
   * 특정 로그에 연결된 스레드 개수를 조회합니다 (활성화된 스레드만).
   * Derived Query Method를 활용합니다.
   */
  long countByLogIdAndDeactivatedAtIsNull(Long logId);

  /**
   * 특정 사용자가 작성한 스레드 개수를 조회합니다 (활성화된 스레드만).
   * Derived Query Method를 활용합니다.
   */
  long countByUserIdAndDeactivatedAtIsNull(Long userId);

  /**
   * 스레드의 조회수를 원자적으로 증가시킵니다. 동시성 이슈를 해결하기 위해 데이터베이스 레벨에서 원자적 증가를 수행합니다.
   */
  @Transactional
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query("UPDATE Thread t SET t.viewCount = t.viewCount + 1 WHERE t.id = :threadId")
  int incrementViewCount(@Param("threadId") Long threadId);

  /**
   * 활성화된 사용자 스레드를 모두 조회합니다 (비활성화 작업용).
   */
  @Query("SELECT t FROM Thread t WHERE t.user.id = :userId AND t.deactivatedAt IS NULL")
  List<Thread> findActiveThreadsByUserId(@Param("userId") Long userId);

  /**
   * 비활성화된 사용자 스레드를 모두 조회합니다 (재활성화 작업용).
   */
  @Query("SELECT t FROM Thread t WHERE t.user.id = :userId AND t.deactivatedAt IS NOT NULL")
  List<Thread> findDeactivatedThreadsByUserId(@Param("userId") Long userId);

  /**
   * 사용자별 스레드를 재활성화합니다 (계정 복구 시).
   * Soft delete 상태를 해제하여 스레드를 다시 공개합니다.
   */
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query("UPDATE Thread t SET t.deactivatedAt = NULL WHERE t.user.id = :userId AND t.deactivatedAt IS NOT NULL")
  int reactivateByUserId(@Param("userId") Long userId);

  /**
   * 비활성화된 사용자 스레드를 완전히 삭제합니다 (물리적 삭제).
   * 탈퇴 후 30일이 지난 사용자의 스레드를 데이터베이스에서 완전히 제거합니다.
   * CASCADE 설정에 의해 관련된 댓글, 좋아요 등도 함께 삭제됩니다.
   *
   * @param userId 사용자 ID
   * @return 삭제된 스레드 수
   */
  @Transactional
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query(value = "DELETE FROM threads WHERE user_id = :userId AND deactivated_at IS NOT NULL", nativeQuery = true)
  int deleteDeactivatedByUserId(@Param("userId") Long userId);

}