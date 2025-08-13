package org.nodystudio.nodybackend.repository;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.nodystudio.nodybackend.domain.enums.OAuthProvider;
import org.nodystudio.nodybackend.domain.enums.TargetType;
import org.nodystudio.nodybackend.domain.user.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * MySQL ON DUPLICATE KEY UPDATE 개선된 쿼리 통합 테스트
 *
 * <p>
 * 개선된 IF 함수 기반 토글 쿼리의 동작을 실제 MySQL 환경에서 검증합니다.
 * TestContainers를 사용하여 격리된 MySQL 환경에서 테스트합니다.
 * </p>
 */
@DataJpaTest
@Testcontainers
@ActiveProfiles("mysql")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@DisplayName("MySQL 개선된 Boolean 토글 통합 테스트")
class LikeRepositoryMySQLIntegrationTest {

  @Container
  @SuppressWarnings("resource")
  static final MySQLContainer<?> mysql = new MySQLContainer<>("mysql:8.0")
      .withDatabaseName("testdb")
      .withUsername("test")
      .withPassword("test");
  @Autowired
  private LikeRepository likeRepository;
  @Autowired
  private UserRepository userRepository;
  private User testUser;
  private Long targetId;
  private TargetType targetType;

  @DynamicPropertySource
  static void configureProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", mysql::getJdbcUrl);
    registry.add("spring.datasource.username", mysql::getUsername);
    registry.add("spring.datasource.password", mysql::getPassword);
  }

  @BeforeEach
  void setUp() {
    // 테스트 사용자 생성
    testUser = User.builder()
        .email("test@example.com")
        .nickname("testuser")
        .socialId("123456789")
        .provider(OAuthProvider.GOOGLE)
        .build();
    testUser = userRepository.save(testUser);

    targetId = 1L;
    targetType = TargetType.THREAD;
  }

  @Nested
  @DisplayName("개선된 MySQL 쿼리 시뮬레이션 테스트")
  class ImprovedQuerySimulationTest {

    @Test
    @DisplayName("MySQL에서 실제 atomicToggleLike 쿼리 실행 검증")
    void atomicToggleLike_WithMySQL_ShouldWork() {
      // Given
      Long userId = testUser.getId();
      String targetTypeStr = targetType.name();

      // When
      int result = likeRepository.atomicToggleLike(userId, targetTypeStr, targetId);

      // Then
      // MySQL에서는 정상적으로 실행되어야 함
      assertThat(result).isEqualTo(1);

      // 좋아요가 생성되었는지 확인
      boolean exists = likeRepository.existsByUserIdAndTargetTypeAndTargetIdAndIsActiveTrue(
          userId, targetType, targetId);
      assertThat(exists).isTrue();
    }
  }

  @Nested
  @DisplayName("IF 함수 로직 정확성 테스트")
  class IFFunctionLogicTest {

    @Test
    @DisplayName("IF(is_active = 1, 0, 1) 로직 검증 - 모든 경우")
    void testIFLogic_AllCases() {
      // Given & When & Then
      // TRUE인 경우: IF(is_active = 1, 0, 1) → 0 (false)
      assertThat(simulateIFLogic(true)).isFalse();

      // FALSE인 경우: IF(is_active = 1, 0, 1) → 1 (true)
      assertThat(simulateIFLogic(false)).isTrue();

      // NULL인 경우: IF(is_active = 1, 0, 1) → 1 (true)
      assertThat(simulateIFLogic(null)).isTrue();
    }

    private Boolean simulateIFLogic(Boolean currentActive) {
      return (currentActive != null && currentActive) ? false : true;
    }
  }

  @Nested
  @DisplayName("연속 토글 동작 테스트")
  class ContinuousToggleTest {

    @Test
    @DisplayName("연속 토글 동작 실제 MySQL 환경 테스트")
    void testContinuousToggle() {
      // Given
      Long userId = testUser.getId();
      String targetTypeStr = targetType.name();

      // 첫 번째 토글 (생성)
      likeRepository.atomicToggleLike(userId, targetTypeStr, targetId);
      boolean isActive = likeRepository.existsByUserIdAndTargetTypeAndTargetIdAndIsActiveTrue(
          userId, targetType, targetId);
      assertThat(isActive).isTrue();

      // 두 번째 토글 (비활성화)
      likeRepository.atomicToggleLike(userId, targetTypeStr, targetId);
      isActive = likeRepository.existsByUserIdAndTargetTypeAndTargetIdAndIsActiveTrue(
          userId, targetType, targetId);
      assertThat(isActive).isFalse();

      // 세 번째 토글 (재활성화)
      likeRepository.atomicToggleLike(userId, targetTypeStr, targetId);
      isActive = likeRepository.existsByUserIdAndTargetTypeAndTargetIdAndIsActiveTrue(
          userId, targetType, targetId);
      assertThat(isActive).isTrue();

      // 네 번째 토글 (비활성화)
      likeRepository.atomicToggleLike(userId, targetTypeStr, targetId);
      isActive = likeRepository.existsByUserIdAndTargetTypeAndTargetIdAndIsActiveTrue(
          userId, targetType, targetId);
      assertThat(isActive).isFalse();
    }
  }
}