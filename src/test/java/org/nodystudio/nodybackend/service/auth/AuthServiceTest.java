package org.nodystudio.nodybackend.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.anyLong;
import static org.mockito.BDDMockito.argThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.never;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.times;

import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.TokenRefreshRequestDto;
import org.nodystudio.nodybackend.dto.TokenResponseDto;
import org.nodystudio.nodybackend.exception.custom.InvalidRefreshTokenException;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.nodystudio.nodybackend.security.jwt.TokenProvider;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

  @Mock
  private UserRepository userRepository;

  @Mock
  private TokenProvider tokenProvider;

  @InjectMocks
  private AuthService authService;
  private User testUser;
  private String validRefreshToken;
  private String newAccessToken;
  private String newRefreshToken;
  private LocalDateTime validExpiry;
  private LocalDateTime expiredExpiry;

  @BeforeEach
  void setUp() {
    validRefreshToken = "valid-refresh-token-jwt";
    newAccessToken = "new-access-token";
    newRefreshToken = "new-refresh-token-jwt";
    validExpiry = LocalDateTime.now().plusDays(1);
    expiredExpiry = LocalDateTime.now().minusDays(1);

    testUser = User.builder()
        .id(1L)
        .email("test@example.com")
        .nickname("testuser")
        .provider("google")
        .socialId("google_12345")
        .refreshToken(validRefreshToken)
        .refreshTokenExpiry(validExpiry)
        .build();
  }

  @Test
  @DisplayName("유효한 리프레시 토큰으로 액세스 토큰 재발급 성공 (Rotation 적용)")
  void refreshAccessToken_shouldReturnNewTokens_whenRefreshTokenIsValidAndRotationEnabled() {
    // given
    TokenRefreshRequestDto requestDto = new TokenRefreshRequestDto(validRefreshToken);

    given(tokenProvider.validateToken(validRefreshToken)).willReturn(true);
    given(tokenProvider.getUserIdFromToken(validRefreshToken)).willReturn(testUser.getId());
    given(userRepository.findById(testUser.getId())).willReturn(Optional.of(testUser));
    given(tokenProvider.createAccessToken(testUser)).willReturn(newAccessToken);
    given(tokenProvider.createRefreshToken(testUser)).willReturn(newRefreshToken);
    given(tokenProvider.getRefreshTokenExpiry()).willReturn(validExpiry);

    // when
    TokenResponseDto responseDto = authService.refreshAccessToken(requestDto);

    // then
    assertThat(responseDto).isNotNull();
    assertThat(responseDto.getGrantType()).isEqualTo("Bearer");
    assertThat(responseDto.getAccessToken()).isEqualTo(newAccessToken);
    assertThat(responseDto.getRefreshToken()).isEqualTo(newRefreshToken);

    // verify
    then(userRepository).should(times(1))
        .save(argThat(savedUser ->
            savedUser.getId().equals(testUser.getId()) &&
                savedUser.getRefreshToken().equals(newRefreshToken) &&
                savedUser.getRefreshTokenExpiry().equals(validExpiry)));
  }

  @Test
  @DisplayName("유효하지 않은 형식의 리프레시 토큰으로 재발급 시 예외 발생")
  void refreshAccessToken_shouldThrowException_whenTokenIsInvalidFormat() {
    // given
    String invalidFormatToken = "invalid-token-format";
    TokenRefreshRequestDto requestDto = new TokenRefreshRequestDto(invalidFormatToken);

    given(tokenProvider.validateToken(invalidFormatToken))
        .willThrow(
            new InvalidRefreshTokenException("유효하지 않은 형식의 토큰입니다."));

    // when and then
    assertThatThrownBy(() -> authService.refreshAccessToken(requestDto))
        .isInstanceOf(InvalidRefreshTokenException.class)
        .hasMessageContaining(
            "리프레시 토큰 처리 중 오류가 발생했습니다.");

    // verify: DB 조회나 다른 로직이 호출되지 않았는지 확인
    then(userRepository).should(never()).findById(anyLong());
  }

  @Test
  @DisplayName("토큰에서 사용자 ID 추출 실패 시 예외 발생")
  void refreshAccessToken_shouldThrowException_whenUserIdExtractionFails() {
    // given
    TokenRefreshRequestDto requestDto = new TokenRefreshRequestDto(validRefreshToken);

    given(tokenProvider.validateToken(validRefreshToken)).willReturn(true);
    given(tokenProvider.getUserIdFromToken(validRefreshToken))
        .willThrow(new RuntimeException("Extraction failed"));

    // when and then
    assertThatThrownBy(() -> authService.refreshAccessToken(requestDto))
        .isInstanceOf(InvalidRefreshTokenException.class)
        .hasMessageContaining("리프레시 토큰 처리 중 오류가 발생했습니다.");
  }

  @Test
  @DisplayName("DB에 해당 사용자가 없을 경우 예외 발생")
  void refreshAccessToken_shouldThrowException_whenUserNotFound() {
    // given
    TokenRefreshRequestDto requestDto = new TokenRefreshRequestDto(validRefreshToken);

    given(tokenProvider.validateToken(validRefreshToken)).willReturn(true);
    given(tokenProvider.getUserIdFromToken(validRefreshToken)).willReturn(testUser.getId());
    given(userRepository.findById(testUser.getId())).willReturn(Optional.empty());

    // when and then
    assertThatThrownBy(() -> authService.refreshAccessToken(requestDto))
        .isInstanceOf(InvalidRefreshTokenException.class)
        .hasMessageContaining("리프레시 토큰과 연결된 사용자가 존재하지 않습니다.");
  }

  @Test
  @DisplayName("DB에 저장된 토큰과 불일치 시 예외 발생 및 DB 토큰 무효화")
  void refreshAccessToken_shouldThrowExceptionAndClearToken_whenTokenMismatch() {
    // given
    final String mismatchedToken = "mismatched-refresh-token";
    final TokenRefreshRequestDto requestDto = new TokenRefreshRequestDto(mismatchedToken);

    given(userRepository.findById(testUser.getId())).willReturn(Optional.of(testUser));
    given(tokenProvider.validateToken(mismatchedToken)).willReturn(true);
    given(tokenProvider.getUserIdFromToken(mismatchedToken)).willReturn(testUser.getId());

    // when and then
    assertThatThrownBy(() -> authService.refreshAccessToken(requestDto))
        .isInstanceOf(InvalidRefreshTokenException.class)
        .hasMessageContaining("제공된 리프레시 토큰이 저장된 토큰과 일치하지 않습니다.");

    // verify
    then(userRepository).should(times(1))
        .save(argThat(user ->
            user.getId().equals(testUser.getId()) &&
                user.getRefreshToken() == null &&
                user.getRefreshTokenExpiry() == null
        ));
  }

  @Test
  @DisplayName("DB에 저장된 토큰이 만료되었을 경우 예외 발생 및 DB 토큰 무효화")
  void refreshAccessToken_shouldThrowExceptionAndClearToken_whenTokenExpiredInDb() {
    // given
    testUser.updateRefreshToken(validRefreshToken, expiredExpiry);
    TokenRefreshRequestDto requestDto = new TokenRefreshRequestDto(validRefreshToken);

    given(tokenProvider.validateToken(validRefreshToken)).willReturn(true);
    given(tokenProvider.getUserIdFromToken(validRefreshToken)).willReturn(testUser.getId());
    given(userRepository.findById(testUser.getId())).willReturn(Optional.of(testUser));

    // when and then
    assertThatThrownBy(() -> authService.refreshAccessToken(requestDto))
        .isInstanceOf(InvalidRefreshTokenException.class)
        .hasMessageContaining("리프레시 토큰이 만료되었습니다.");

    // verify: DB 토큰이 null로 업데이트되었는지 확인
    then(userRepository).should(times(1))
        .save(argThat(savedUser ->
            savedUser.getId().equals(testUser.getId()) &&
                savedUser.getRefreshToken() == null &&
                savedUser.getRefreshTokenExpiry() == null));
  }
}