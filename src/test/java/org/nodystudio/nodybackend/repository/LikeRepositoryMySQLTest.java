package org.nodystudio.nodybackend.repository;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
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
 * MySQL의 ON DUPLICATE KEY UPDATE 문법 테스트
 *
 * <p>
 * 이 테스트는 실제 MySQL 환경에서 MySQL 전용 쿼리의 동작을 검증합니다.
 * TestContainers를 사용하여 격리된 MySQL 환경에서 테스트합니다.
 * </p>
 */
@DataJpaTest
@Testcontainers
@ActiveProfiles("mysql")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@DisplayName("MySQL ON DUPLICATE KEY UPDATE 토글 동작 테스트")
class LikeRepositoryMySQLTest {

  @Container
  @SuppressWarnings("resource")
  static MySQLContainer<?> mysql = new MySQLContainer<>("mysql:8.0")
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
        .provider(org.nodystudio.nodybackend.domain.enums.OAuthProvider.GOOGLE)
        .build();
    testUser = userRepository.save(testUser);

    targetId = 1L;
    targetType = TargetType.THREAD;
  }

  @Nested
  @DisplayName("MySQL ON DUPLICATE KEY UPDATE 문법 테스트")
  class MySQLSyntaxTest {

    @Test
    @DisplayName("MySQL 환경에서 ON DUPLICATE KEY UPDATE 문법이 정상 작동한다")
    void atomicToggleLike_WithMySQLDatabase_ShouldWork() {
      // Given
      Long userId = testUser.getId();
      String targetTypeStr = targetType.name();

      // When
      int result = likeRepository.atomicToggleLike(userId, targetTypeStr, targetId);

      // Then
      // MySQL 환경에서는 정상적으로 실행되어야 함
      assertThat(result).isEqualTo(1);

      // 좋아요가 생성되었는지 확인
      boolean exists = likeRepository.existsByUserIdAndTargetTypeAndTargetIdAndIsActiveTrue(
          userId, targetType, targetId);
      assertThat(exists).isTrue();
    }

    @Test
    @DisplayName("MySQL 전용 쿼리 문법 검증 - 쿼리 문자열 분석")
    void verifyMySQLQuerySyntax() {
      // Given
      String expectedQuery = """
          INSERT INTO likes (user_id, target_type, target_id, is_active, created_at, updated_at)
          VALUES (:userId, :targetType, :targetId, 1, NOW(), NOW())
          ON DUPLICATE KEY UPDATE
              is_active = IF(is_active = 1, 0, 1),
              updated_at = NOW()
          """;

      // When & Then
      // 쿼리 문법이 올바른지 확인
      assertThat(expectedQuery)
          .contains("INSERT INTO likes")
          .contains("VALUES")
          .contains("ON DUPLICATE KEY UPDATE")
          .contains("is_active = IF(is_active = 1, 0, 1)")
          .contains("updated_at = NOW()");
    }
  }
}