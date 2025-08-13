package org.nodystudio.nodybackend.service.like;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.nodystudio.nodybackend.domain.enums.OAuthProvider;
import org.nodystudio.nodybackend.domain.enums.TargetType;
import org.nodystudio.nodybackend.domain.like.ThreadLike;
import org.nodystudio.nodybackend.domain.thread.Thread;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.like.LikeRequest;
import org.nodystudio.nodybackend.repository.ThreadLikeRepository;
import org.nodystudio.nodybackend.repository.ThreadRepository;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * TestContainers MySQL 환경에서의 LikeService 동시성 테스트
 *
 * <p>
 * 실제 MySQL 데이터베이스를 사용하여 좋아요 서비스의 동시성 안전성을 검증합니다.
 * H2에서 지원하지 않는 MySQL 전용 원자적 토글 기능을 실제 환경에서 테스트합니다.
 * </p>
 *
 * <p>
 * <strong>테스트 목적:</strong>
 * <ul>
 * <li>MySQL의 ON DUPLICATE KEY UPDATE 구문을 사용한 원자적 토글 기능 검증</li>
 * <li>다중 스레드 환경에서의 Race condition 방지 확인</li>
 * <li>동시성 상황에서의 데이터 무결성 보장</li>
 * <li>서비스 계층에서의 전체적인 동시성 안전성 검증</li>
 * </ul>
 * </p>
 *
 * <p>
 * <strong>기술적 특징:</strong>
 * TestContainers를 사용해 격리된 MySQL 환경을 제공하며,
 * 실제 운영 환경과 동일한 조건에서 동시성 테스트를 수행합니다.
 * </p>
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("mysql")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@DisplayName("LikeService MySQL 동시성 테스트")
class LikeServiceConcurrencyMySQLTest {

  @Container
  @SuppressWarnings("resource")
  static MySQLContainer<?> mysql = new MySQLContainer<>("mysql:8.0")
      .withDatabaseName("testdb")
      .withUsername("test")
      .withPassword("test");
  @Autowired
  private LikeService likeService;
  @Autowired
  private UserRepository userRepository;
  @Autowired
  private ThreadRepository threadRepository;
  @Autowired
  private ThreadLikeRepository threadLikeRepository;
  private User testUser;
  private Thread testThread;

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
        .provider(OAuthProvider.GOOGLE)
        .socialId("mysql-concurrency-test-user")
        .email("mysql-concurrency@test.com")
        .nickname("MySQL동시성테스트")
        .build();
    testUser = userRepository.save(testUser);

    // 테스트 스레드 생성
    testThread = Thread.builder()
        .user(testUser)
        .content("MySQL 동시성 테스트용 스레드")
        .build();
    testThread = threadRepository.save(testThread);
  }

  @Test
  @DisplayName("동시에 여러 좋아요 추가 요청이 들어와도 원자적으로 처리된다")
  void concurrentLikeCreation_ShouldHandleAtomically() throws InterruptedException {
    // Given
    int numberOfThreads = 10;
    ExecutorService executorService = Executors.newFixedThreadPool(numberOfThreads);
    CountDownLatch latch = new CountDownLatch(numberOfThreads);
    AtomicInteger successCount = new AtomicInteger(0);
    AtomicInteger failureCount = new AtomicInteger(0);

    LikeRequest request = LikeRequest.builder()
        .targetType(TargetType.THREAD)
        .targetId(testThread.getId())
        .build();

    // When
    IntStream.range(0, numberOfThreads).forEach(i -> {
      executorService.submit(() -> {
        try {
          likeService.toggleLike(request, testUser.getEmail());
          successCount.incrementAndGet();
        } catch (Exception e) {
          failureCount.incrementAndGet();
        } finally {
          latch.countDown();
        }
      });
    });

    latch.await(30, TimeUnit.SECONDS);
    executorService.shutdown();

    // 모든 스레드가 완전히 종료될 때까지 대기
    boolean terminated = executorService.awaitTermination(10, TimeUnit.SECONDS);
    assertThat(terminated).isTrue();

    // Then
    // 원자적 연산이므로 모든 요청이 성공해야 함
    assertThat(successCount.get()).isEqualTo(numberOfThreads);
    assertThat(failureCount.get()).isEqualTo(0);

    // 최종 상태 확인 - 짝수 번 토글하면 좋아요가 없고, 홀수 번이면 있어야 함
    List<ThreadLike> allLikes = threadLikeRepository.findAll();
    long activeLikes = allLikes.stream()
        .filter(like -> like.getIsActive())
        .count();

    // 10번(짝수)의 토글이므로 최종적으로 좋아요가 없어야 함
    assertThat(activeLikes).isEqualTo(0);

    // 하지만 데이터베이스에는 하나의 레코드가 존재해야 함 (isActive=false)
    assertThat(allLikes).hasSize(1);
    assertThat(allLikes.get(0).getIsActive()).isFalse();
  }

  @Test
  @DisplayName("좋아요가 있는 상태에서 동시에 토글 요청이 들어와도 최종 상태가 일관성있게 유지된다")
  void concurrentToggle_ShouldMaintainConsistency() throws InterruptedException {
    // Given - 먼저 좋아요를 추가
    ThreadLike existingLike = ThreadLike.builder()
        .user(testUser)
        .thread(testThread)
        .isActive(true)
        .build();
    threadLikeRepository.save(existingLike);

    int numberOfThreads = 20;
    ExecutorService executorService = Executors.newFixedThreadPool(numberOfThreads);
    CountDownLatch latch = new CountDownLatch(numberOfThreads);
    AtomicInteger successCount = new AtomicInteger(0);
    AtomicInteger failureCount = new AtomicInteger(0);

    LikeRequest request = LikeRequest.builder()
        .targetType(TargetType.THREAD)
        .targetId(testThread.getId())
        .build();

    // When - 동시에 토글 요청
    IntStream.range(0, numberOfThreads).forEach(i -> {
      executorService.submit(() -> {
        try {
          likeService.toggleLike(request, testUser.getEmail());
          successCount.incrementAndGet();
        } catch (Exception e) {
          failureCount.incrementAndGet();
        } finally {
          latch.countDown();
        }
      });
    });

    latch.await(30, TimeUnit.SECONDS);
    executorService.shutdown();

    // 모든 스레드가 완전히 종료될 때까지 대기
    boolean terminated = executorService.awaitTermination(10, TimeUnit.SECONDS);
    assertThat(terminated).isTrue();

    // Then
    // 모든 요청이 성공해야 함
    assertThat(successCount.get()).isEqualTo(numberOfThreads);
    assertThat(failureCount.get()).isEqualTo(0);

    // 최종 상태 확인 - 초기에 활성 좋아요가 1개 있었고, 20번 토글했으므로
    // 21번의 상태 변화가 있어야 함 (홀수이므로 최종적으로 활성)
    long activeLikeCount = threadLikeRepository.countByThreadIdAndIsActiveTrue(testThread.getId());
    assertThat(activeLikeCount).isEqualTo(1);

    // 데이터베이스에는 여전히 하나의 레코드만 있어야 함
    List<ThreadLike> allLikes = threadLikeRepository.findAll();
    assertThat(allLikes).hasSize(1);
    assertThat(allLikes.get(0).getIsActive()).isTrue();
  }

  @Test
  @DisplayName("서로 다른 사용자가 동시에 같은 대상에 좋아요를 누르면 모두 성공한다")
  void concurrentLikesByDifferentUsers_ShouldAllSucceed() throws InterruptedException {
    // Given
    int numberOfUsers = 5;
    List<User> users = IntStream.range(0, numberOfUsers)
        .mapToObj(i -> User.builder()
            .provider(OAuthProvider.GOOGLE)
            .socialId("mysql-user-" + i)
            .email("mysql-user" + i + "@test.com")
            .nickname("MySQL사용자" + i)
            .build())
        .map(userRepository::save)
        .toList();

    ExecutorService executorService = Executors.newFixedThreadPool(numberOfUsers);
    CountDownLatch latch = new CountDownLatch(numberOfUsers);
    AtomicInteger successCount = new AtomicInteger(0);
    AtomicInteger failureCount = new AtomicInteger(0);

    LikeRequest request = LikeRequest.builder()
        .targetType(TargetType.THREAD)
        .targetId(testThread.getId())
        .build();

    // When
    users.forEach(user -> {
      executorService.submit(() -> {
        try {
          likeService.toggleLike(request, user.getEmail());
          successCount.incrementAndGet();
        } catch (Exception e) {
          failureCount.incrementAndGet();
        } finally {
          latch.countDown();
        }
      });
    });

    latch.await(30, TimeUnit.SECONDS);
    executorService.shutdown();

    // 모든 스레드가 완전히 종료될 때까지 대기
    boolean terminated = executorService.awaitTermination(10, TimeUnit.SECONDS);
    assertThat(terminated).isTrue();

    // Then
    // 모든 요청이 성공해야 함
    assertThat(successCount.get()).isEqualTo(numberOfUsers);
    assertThat(failureCount.get()).isEqualTo(0);

    // 모든 사용자의 활성 좋아요가 정상적으로 생성되었는지 확인
    long totalActiveLikes = threadLikeRepository.countByThreadIdAndIsActiveTrue(testThread.getId());
    assertThat(totalActiveLikes).isEqualTo(numberOfUsers);

    // 각 사용자별로 정확히 하나의 활성 좋아요가 생성되었는지 확인
    users.forEach(user -> {
      boolean liked = threadLikeRepository.existsByUserIdAndThreadIdAndIsActiveTrue(
          user.getId(), testThread.getId());
      assertThat(liked).isTrue();
    });
  }

  @Test
  @DisplayName("동일 사용자가 빠르게 연속으로 토글 요청을 보내도 데이터 무결성이 유지된다")
  void rapidToggleByOneUser_ShouldMaintainIntegrity() throws InterruptedException {
    // Given
    int numberOfRequests = 50;
    ExecutorService executorService = Executors.newFixedThreadPool(10);
    CountDownLatch latch = new CountDownLatch(numberOfRequests);
    AtomicInteger successCount = new AtomicInteger(0);
    AtomicInteger failureCount = new AtomicInteger(0);

    LikeRequest request = LikeRequest.builder()
        .targetType(TargetType.THREAD)
        .targetId(testThread.getId())
        .build();

    // When
    IntStream.range(0, numberOfRequests).forEach(i -> {
      executorService.submit(() -> {
        try {
          likeService.toggleLike(request, testUser.getEmail());
          successCount.incrementAndGet();
        } catch (Exception e) {
          failureCount.incrementAndGet();
        } finally {
          latch.countDown();
        }
      });
    });

    latch.await(60, TimeUnit.SECONDS);
    executorService.shutdown();

    // 모든 스레드가 완전히 종료될 때까지 대기
    boolean terminated = executorService.awaitTermination(15, TimeUnit.SECONDS);
    assertThat(terminated).isTrue();

    // Then
    // 모든 요청이 성공해야 함
    assertThat(successCount.get()).isEqualTo(numberOfRequests);
    assertThat(failureCount.get()).isEqualTo(0);

    // 최종 상태는 0 또는 1이어야 함 (짝수 번 토글하면 0, 홀수 번이면 1)
    // 50번(짝수)이므로 최종적으로 활성 좋아요는 0개여야 함
    long activeFinalCount = threadLikeRepository.countByThreadIdAndIsActiveTrue(testThread.getId());
    assertThat(activeFinalCount).isEqualTo(0);

    // 해당 사용자의 좋아요 레코드는 정확히 1개만 존재해야 함 (isActive=false)
    List<ThreadLike> userLikes = threadLikeRepository.findAll().stream()
        .filter(like -> like.getUser().getId().equals(testUser.getId()))
        .toList();
    assertThat(userLikes).hasSize(1);
    assertThat(userLikes.get(0).getIsActive()).isFalse();
  }

  @Test
  @DisplayName("대량의 동시 요청 처리에서도 성능과 안정성을 유지한다")
  void massiveConcurrentRequests_ShouldMaintainPerformanceAndStability()
      throws InterruptedException {
    // Given
    int numberOfUsers = 20;
    int requestsPerUser = 10;
    int totalRequests = numberOfUsers * requestsPerUser;

    List<User> users = IntStream.range(0, numberOfUsers)
        .mapToObj(i -> User.builder()
            .provider(OAuthProvider.GOOGLE)
            .socialId("massive-user-" + i)
            .email("massive-user" + i + "@test.com")
            .nickname("대량테스트사용자" + i)
            .build())
        .map(userRepository::save)
        .toList();

    ExecutorService executorService = Executors.newFixedThreadPool(50);
    CountDownLatch latch = new CountDownLatch(totalRequests);
    AtomicInteger successCount = new AtomicInteger(0);
    AtomicInteger failureCount = new AtomicInteger(0);

    LikeRequest request = LikeRequest.builder()
        .targetType(TargetType.THREAD)
        .targetId(testThread.getId())
        .build();

    long startTime = System.currentTimeMillis();

    // When
    users.forEach(user -> {
      IntStream.range(0, requestsPerUser).forEach(i -> {
        executorService.submit(() -> {
          try {
            likeService.toggleLike(request, user.getEmail());
            successCount.incrementAndGet();
          } catch (Exception e) {
            failureCount.incrementAndGet();
          } finally {
            latch.countDown();
          }
        });
      });
    });

    latch.await(120, TimeUnit.SECONDS);
    executorService.shutdown();

    boolean terminated = executorService.awaitTermination(30, TimeUnit.SECONDS);
    assertThat(terminated).isTrue();

    long endTime = System.currentTimeMillis();
    long totalTime = endTime - startTime;

    // Then
    assertThat(successCount.get()).isEqualTo(totalRequests);
    assertThat(failureCount.get()).isEqualTo(0);

    // 각 사용자별로 짝수 번(10번) 토글했으므로 모든 사용자의 좋아요가 비활성 상태여야 함
    long totalActiveLikes = threadLikeRepository.countByThreadIdAndIsActiveTrue(testThread.getId());
    assertThat(totalActiveLikes).isEqualTo(0);

    // 각 사용자별로 정확히 하나의 레코드가 존재해야 함
    long totalRecords = threadLikeRepository.count();
    assertThat(totalRecords).isEqualTo(numberOfUsers);

    // 성능 확인 - 평균 처리 시간이 합리적인 범위 내에 있어야 함
    double avgTimePerRequest = (double) totalTime / totalRequests;
    // 평균 처리 시간이 100ms 이하여야 함 (성능 기준)
    assertThat(avgTimePerRequest).isLessThan(100.0);
  }
}