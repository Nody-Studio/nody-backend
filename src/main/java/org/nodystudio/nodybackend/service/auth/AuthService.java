package org.nodystudio.nodybackend.service.auth;

import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.TokenRefreshRequestDto;
import org.nodystudio.nodybackend.dto.TokenResponseDto;
import org.nodystudio.nodybackend.exception.custom.InvalidRefreshTokenException;
import org.nodystudio.nodybackend.exception.custom.InvalidTokenException;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.nodystudio.nodybackend.security.jwt.TokenProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserRepository userRepository;
  private final TokenProvider tokenProvider;

  private static final String BEARER_TYPE = "Bearer";

  /**
   * Refresh Token을 사용하여 새로운 Access Token과 Refresh Token을 발급합니다. (Rotation 적용)
   *
   * @param requestDto Refresh Token을 포함한 DTO
   * @return 새로운 Access Token과 Refresh Token 정보를 담은 DTO
   * @throws InvalidRefreshTokenException 유효하지 않은 Refresh Token일 경우
   */
  @Transactional
  public TokenResponseDto refreshAccessToken(TokenRefreshRequestDto requestDto) {
    String providedRefreshToken = requestDto.getRefreshToken();

    if (providedRefreshToken == null || providedRefreshToken.isBlank()) {
      throw new InvalidRefreshTokenException("리프레시 토큰를 찾을 수 없습니다.");
    }
    log.debug("토큰 리프레시 요청 처리 시작");

    User user = validateRefreshTokenAndGetUser(providedRefreshToken);
    TokenPair newTokens = rotateTokens(user);
    TokenResponseDto response = buildTokenResponse(newTokens);
    log.info("사용자 ID: {}의 토큰 리프레시 완료", user.getId());

    return response;
  }

  /**
   * Refresh Token을 검증하고 해당 토큰의 소유자인 사용자를 반환합니다.
   *
   * @param refreshToken 검증할 Refresh Token
   * @return 검증된 사용자
   * @throws InvalidRefreshTokenException 토큰 검증 실패 시
   */
  private User validateRefreshTokenAndGetUser(String refreshToken) {

    Long userId = validateTokenSignatureAndExtractUserId(refreshToken);
    User user = findUserById(userId);

    validateStoredToken(user, refreshToken);
    validateTokenExpiration(user);

    return user;
  }

  /**
   * 토큰의 서명을 검증하고 사용자 ID를 추출합니다.
   */
  private Long validateTokenSignatureAndExtractUserId(String token) {
    try {
      tokenProvider.validateToken(token);
      return tokenProvider.getUserIdFromToken(token);
    } catch (InvalidTokenException e) {
      log.warn("리프레시 토큰 유효성 검증 실패 (InvalidTokenException): {}", e.getMessage());
      throw new InvalidRefreshTokenException("제공된 리프레시 토큰이 유효하지 않습니다.", e);
    } catch (Exception e) {
      log.warn("토큰 검증 또는 사용자 ID 추출 중 예기치 않은 오류 발생: {}", e.getMessage());
      throw new InvalidRefreshTokenException("리프레시 토큰 처리 중 오류가 발생했습니다.", e);
    }
  }

  /**
   * 사용자 ID로 사용자를 조회합니다.
   */
  private User findUserById(Long userId) {
    return userRepository.findById(userId)
        .orElseThrow(() -> {
          log.warn("리프레시 토큰에서 추출한 사용자 ID가 존재하지 않음: {}", userId);
          return new InvalidRefreshTokenException("리프레시 토큰과 연결된 사용자가 존재하지 않습니다.");
        });
  }

  /**
   * 제공된 토큰이 DB에 저장된 토큰과 일치하는지 검증합니다.
   */
  private void validateStoredToken(User user, String providedToken) {
    if (user.getRefreshToken() == null || !providedToken.equals(user.getRefreshToken())) {
      log.warn("제공된 리프레시 토큰이 DB에 저장된 토큰과 일치하지 않음. 사용자 ID: {}", user.getId());
      invalidateUserToken(user);
      throw new InvalidRefreshTokenException("제공된 리프레시 토큰이 저장된 토큰과 일치하지 않습니다.");
    }
  }

  /**
   * 토큰 만료 시간을 검증합니다.
   */
  private void validateTokenExpiration(User user) {
    if (user.getRefreshTokenExpiry() == null ||
        user.getRefreshTokenExpiry().isBefore(LocalDateTime.now())) {
      log.warn("리프레시 토큰 만료됨. 사용자 ID: {}", user.getId());
      invalidateUserToken(user);
      throw new InvalidRefreshTokenException("리프레시 토큰이 만료되었습니다.");
    }
  }

  /**
   * 보안 위반 가능성이 있는 경우 사용자의 토큰을 무효화합니다.
   */
  private void invalidateUserToken(User user) {
    user.clearRefreshToken();
    userRepository.save(user);
    log.info("사용자 ID: {}의 리프레시 토큰 무효화 완료", user.getId());
  }

  /**
   * 새로운 Access Token과 Refresh Token을 생성하고 사용자 정보를 업데이트합니다.
   */
  private TokenPair rotateTokens(User user) {
    String newAccessToken = tokenProvider.createAccessToken(user);
    String newRefreshToken = tokenProvider.createRefreshToken(user);
    LocalDateTime newRefreshTokenExpiry = tokenProvider.getRefreshTokenExpiry();

    user.updateRefreshToken(newRefreshToken, newRefreshTokenExpiry);
    userRepository.save(user);

    log.debug("사용자 ID: {}의 새로운 토큰 발급 완료", user.getId());
    return new TokenPair(newAccessToken, newRefreshToken);
  }

  /**
   * 토큰 응답 DTO를 생성합니다.
   */
  private TokenResponseDto buildTokenResponse(TokenPair tokens) {
    return TokenResponseDto.builder()
        .grantType(BEARER_TYPE)
        .accessToken(tokens.accessToken)
        .refreshToken(tokens.refreshToken)
        .accessTokenExpiresIn(tokenProvider.getAccessTokenExpirationMillis())
        .build();
  }

  /**
   * Access Token과 Refresh Token 쌍을 담는 내부 클래스
   */
  private record TokenPair(String accessToken, String refreshToken) {

  }
}
