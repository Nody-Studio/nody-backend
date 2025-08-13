package org.nodystudio.nodybackend.domain.log;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.nodystudio.nodybackend.domain.enums.OAuthProvider;
import org.nodystudio.nodybackend.domain.user.RoleType;
import org.nodystudio.nodybackend.domain.user.User;

@DisplayName("Log 도메인 엔티티 테스트")
class LogTest {

  private User testUser;
  private User otherUser;
  private Log log;

  @BeforeEach
  void setUp() {
    testUser = User.builder()
        .id(1L)
        .email("test@example.com")
        .nickname("testuser")
        .provider(OAuthProvider.GOOGLE)
        .socialId("12345")
        .role(RoleType.USER)
        .build();

    otherUser = User.builder()
        .id(2L)
        .email("other@example.com")
        .nickname("otheruser")
        .provider(OAuthProvider.GOOGLE)
        .socialId("67890")
        .role(RoleType.USER)
        .build();

    log = Log.builder()
        .id(1L)
        .user(testUser)
        .content("테스트 로그 내용")
        .latitude(new BigDecimal("37.5665"))
        .longitude(new BigDecimal("126.9780"))
        .address("서울특별시 중구 세종대로 110")
        .isPublic(true)
        .viewCount(0L)
        .build();
  }

  @Test
  @DisplayName("내용 업데이트 성공")
  void updateContent_Success() {
    // given
    String newContent = "새로운 로그 내용";

    // when
    log.updateContent(newContent);

    // then
    assertThat(log.getContent()).isEqualTo(newContent);
  }

  @Test
  @DisplayName("위치 정보 업데이트 성공")
  void updateLocation_Success() {
    // given
    BigDecimal newLatitude = new BigDecimal("35.1796");
    BigDecimal newLongitude = new BigDecimal("129.0756");
    String newAddress = "부산광역시 해운대구";

    // when
    log.updateLocation(newLatitude, newLongitude, newAddress);

    // then
    assertThat(log.getLatitude()).isEqualTo(newLatitude);
    assertThat(log.getLongitude()).isEqualTo(newLongitude);
    assertThat(log.getAddress()).isEqualTo(newAddress);
  }

  @Test
  @DisplayName("공개 설정 업데이트 성공")
  void updatePublicSetting_Success() {
    // given
    assertThat(log.getIsPublic()).isTrue();

    // when
    log.updatePublicSetting(false);

    // then
    assertThat(log.getIsPublic()).isFalse();
  }

  @Test
  @DisplayName("미디어 URL 목록 업데이트 성공")
  void updateMediaUrls_Success() {
    // given
    List<String> newMediaUrls = List.of(
        "https://example.com/image1.jpg",
        "https://example.com/image2.jpg");

    // when
    log.updateMediaUrls(newMediaUrls);

    // then
    assertThat(log.getMediaUrls()).hasSize(2);
    assertThat(log.getMediaUrls()).containsExactly(
        "https://example.com/image1.jpg",
        "https://example.com/image2.jpg");
  }

  @Test
  @DisplayName("미디어 URL null로 업데이트 시 빈 리스트로 설정")
  void updateMediaUrls_NullList_ClearsUrls() {
    // given
    log.updateMediaUrls(List.of("https://example.com/image.jpg"));
    assertThat(log.getMediaUrls()).hasSize(1);

    // when
    log.updateMediaUrls(null);

    // then
    assertThat(log.getMediaUrls()).isEmpty();
  }

  @Test
  @DisplayName("조회수 증가 성공")
  void incrementViewCount_Success() {
    // given
    long initialViewCount = log.getViewCount();

    // when
    log.incrementViewCount();

    // then
    assertThat(log.getViewCount()).isEqualTo(initialViewCount + 1);
  }

  @Test
  @DisplayName("조회수 여러 번 증가")
  void incrementViewCount_Multiple_Success() {
    // given
    long initialViewCount = log.getViewCount();

    // when
    log.incrementViewCount();
    log.incrementViewCount();
    log.incrementViewCount();

    // then
    assertThat(log.getViewCount()).isEqualTo(initialViewCount + 3);
  }

  @Test
  @DisplayName("로그 소유자 확인 - 본인인 경우")
  void isOwnedBy_OwnLog_ReturnsTrue() {
    // when & then
    assertThat(log.isOwnedBy(testUser)).isTrue();
  }

  @Test
  @DisplayName("로그 소유자 확인 - 다른 사용자인 경우")
  void isOwnedBy_OtherUser_ReturnsFalse() {
    // when & then
    assertThat(log.isOwnedBy(otherUser)).isFalse();
  }

  @Test
  @DisplayName("로그 소유자 확인 - null 사용자인 경우")
  void isOwnedBy_NullUser_ReturnsFalse() {
    // when & then
    assertThat(log.isOwnedBy(null)).isFalse();
  }

  @Test
  @DisplayName("로그 소유자 확인 - 로그 사용자가 null인 경우")
  void isOwnedBy_LogUserIsNull_ReturnsFalse() {
    // given
    Log logWithNullUser = Log.builder()
        .id(2L)
        .user(null)
        .content("내용")
        .build();

    // when & then
    assertThat(logWithNullUser.isOwnedBy(testUser)).isFalse();
  }

  @Test
  @DisplayName("공개 로그 조회 권한 확인 - 익명 사용자")
  void isViewableBy_PublicLog_AnonymousUser_ReturnsTrue() {
    // given
    assertThat(log.getIsPublic()).isTrue();

    // when & then
    assertThat(log.isViewableBy(null)).isTrue();
  }

  @Test
  @DisplayName("공개 로그 조회 권한 확인 - 다른 사용자")
  void isViewableBy_PublicLog_OtherUser_ReturnsTrue() {
    // given
    assertThat(log.getIsPublic()).isTrue();

    // when & then
    assertThat(log.isViewableBy(otherUser)).isTrue();
  }

  @Test
  @DisplayName("비공개 로그 조회 권한 확인 - 작성자")
  void isViewableBy_PrivateLog_Owner_ReturnsTrue() {
    // given
    log.updatePublicSetting(false);

    // when & then
    assertThat(log.isViewableBy(testUser)).isTrue();
  }

  @Test
  @DisplayName("비공개 로그 조회 권한 확인 - 다른 사용자")
  void isViewableBy_PrivateLog_OtherUser_ReturnsFalse() {
    // given
    log.updatePublicSetting(false);

    // when & then
    assertThat(log.isViewableBy(otherUser)).isFalse();
  }

  @Test
  @DisplayName("비공개 로그 조회 권한 확인 - 익명 사용자")
  void isViewableBy_PrivateLog_AnonymousUser_ReturnsFalse() {
    // given
    log.updatePublicSetting(false);

    // when & then
    assertThat(log.isViewableBy(null)).isFalse();
  }

  @Test
  @DisplayName("빌더 패턴으로 로그 생성 - 기본값 확인")
  void builder_DefaultValues_Success() {
    // when
    Log logWithDefaults = Log.builder()
        .user(testUser)
        .content("기본값 테스트")
        .build();

    // then
    assertThat(logWithDefaults.getIsPublic()).isTrue();
    assertThat(logWithDefaults.getViewCount()).isZero();
    assertThat(logWithDefaults.getMediaUrls()).isEmpty();
  }

  @Test
  @DisplayName("로그 비활성화 - 성공")
  void deactivate_Success() {
    // given
    assertThat(log.isActive()).isTrue();
    assertThat(log.isDeactivated()).isFalse();

    // when
    log.deactivate();

    // then
    assertThat(log.isActive()).isFalse();
    assertThat(log.isDeactivated()).isTrue();
    assertThat(log.getDeactivatedAt()).isNotNull();
  }

  @Test
  @DisplayName("로그 재활성화 - 성공")
  void reactivate_Success() {
    // given
    log.deactivate();
    assertThat(log.isDeactivated()).isTrue();

    // when
    log.reactivate();

    // then
    assertThat(log.isActive()).isTrue();
    assertThat(log.isDeactivated()).isFalse();
    assertThat(log.getDeactivatedAt()).isNull();
  }

  @Test
  @DisplayName("활성 로그 상태 확인")
  void isActive_ActiveLog_ReturnsTrue() {
    // given & when & then
    assertThat(log.isActive()).isTrue();
    assertThat(log.isDeactivated()).isFalse();
  }

  @Test
  @DisplayName("비활성 로그 상태 확인")
  void isDeactivated_DeactivatedLog_ReturnsTrue() {
    // given
    log.deactivate();

    // when & then
    assertThat(log.isDeactivated()).isTrue();
    assertThat(log.isActive()).isFalse();
  }

  @Test
  @DisplayName("비활성화된 로그의 원본 공개설정 보존 확인")
  void deactivate_PreservesOriginalPublicSetting() {
    // given
    log.updatePublicSetting(false); // 비공개로 설정
    assertThat(log.getIsPublic()).isFalse();

    // when
    log.deactivate();

    // then
    assertThat(log.getIsPublic()).isFalse(); // 원본 설정 보존
    assertThat(log.isDeactivated()).isTrue();
  }

  @Test
  @DisplayName("재활성화된 로그의 원본 공개설정 보존 확인")
  void reactivate_PreservesOriginalPublicSetting() {
    // given
    log.updatePublicSetting(false); // 비공개로 설정
    log.deactivate();

    // when
    log.reactivate();

    // then
    assertThat(log.getIsPublic()).isFalse(); // 원본 설정 보존
    assertThat(log.isActive()).isTrue();
  }
}