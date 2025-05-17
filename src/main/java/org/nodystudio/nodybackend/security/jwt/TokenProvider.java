package org.nodystudio.nodybackend.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.SecurityException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.exception.custom.InvalidTokenException;
import org.nodystudio.nodybackend.exception.custom.UnauthorizedException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class TokenProvider {

  private static final String CLAIM_USER_ID = "userId";
  private static final String CLAIM_EMAIL = "email";
  private static final String CLAIM_PROVIDER = "provider";

  private static final int MINIMUM_KEY_LENGTH_BYTES = 64;
  private static final SecureDigestAlgorithm<SecretKey, SecretKey> SIGNATURE_ALGORITHM = Jwts.SIG.HS512;

  private final SecretKey secretKey;
  private final long accessTokenExpirationMillis;
  private final long refreshTokenExpirationMillis;

  public TokenProvider(
      @Value("${jwt.secret-key}") String secretString,
      @Value("${jwt.access-token-expiration-minutes}") long accessTokenExpirationMinutes,
      @Value("${jwt.refresh-token-expiration-days}") long refreshTokenExpirationDays) {
    byte[] keyBytes = Decoders.BASE64.decode(secretString);

    if (keyBytes.length < MINIMUM_KEY_LENGTH_BYTES) {
      String errorMsg = String.format(
          "보안 키 길이가 부족합니다. 현재 길이: %d 바이트, 필요한 최소 길이: %d 바이트 (512 비트)",
          keyBytes.length, MINIMUM_KEY_LENGTH_BYTES);
      log.error(errorMsg);
      throw new IllegalArgumentException(errorMsg);
    }

    this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    this.accessTokenExpirationMillis = TimeUnit.MINUTES.toMillis(accessTokenExpirationMinutes);
    this.refreshTokenExpirationMillis = TimeUnit.DAYS.toMillis(refreshTokenExpirationDays);
    log.info("TokenProvider 초기화 완료. 비밀 키 길이: {} 바이트. Access Token 만료: {}ms, Refresh Token 만료: {}ms",
        keyBytes.length, this.accessTokenExpirationMillis, this.refreshTokenExpirationMillis);
  }

  /**
   * Access Token 생성
   *
   * @param user 사용자 정보
   * @return 생성된 Access Token
   */
  public String createAccessToken(User user) {
    log.debug("Attempting to create access token for user ID: {}", user.getId());
    try {
      Instant now = Instant.now();
      Instant expirationInstant = now.plusMillis(accessTokenExpirationMillis);
      Date expirationDate = Date.from(expirationInstant);

      return Jwts.builder()
          .subject(user.getSocialId())
          .claim(CLAIM_USER_ID, user.getId())
          .claim(CLAIM_EMAIL, user.getEmail())
          .claim(CLAIM_PROVIDER, user.getProvider())
          .issuedAt(Date.from(now))
          .expiration(expirationDate)
          .signWith(secretKey, SIGNATURE_ALGORITHM)
          .compact();
    } catch (Exception e) {
      log.error("Error creating access token for user ID: {}", user.getId(), e);
      throw new UnauthorizedException("토큰 생성 중 오류가 발생했습니다.", ErrorCode.AUTHENTICATION_FAILED, e);
    }
  }

  /**
   * Refresh Token 생성
   *
   * @param user 사용자 정보 (Subject 및 userId Claim 설정용)
   * @return 생성된 Refresh Token
   */
  public String createRefreshToken(User user) {
    log.debug("Attempting to create refresh token for user ID: {}", user.getId());
    try {
      Instant now = Instant.now();
      Instant expirationInstant = now.plusMillis(refreshTokenExpirationMillis);
      Date expirationDate = Date.from(expirationInstant);

      String jti = UUID.randomUUID().toString();

      return Jwts.builder()
          .subject(user.getSocialId())
          .claim(CLAIM_USER_ID, user.getId())
          .id(jti)
          .issuedAt(Date.from(now))
          .expiration(expirationDate)
          .signWith(secretKey, SIGNATURE_ALGORITHM)
          .compact();
    } catch (Exception e) {
      log.error("Error creating refresh token for user ID: {}", user.getId(), e);
      throw new UnauthorizedException("리프레시 토큰 생성 중 오류가 발생했습니다.", ErrorCode.AUTHENTICATION_FAILED, e);
    }
  }

  /**
   * 토큰에서 Claims 추출
   *
   * @param token JWT 토큰
   * @return Claims 객체
   * @throws ExpiredJwtException 만료된 토큰일 경우
   * @throws SecurityException   유효하지 않은 토큰일 경우
   */
  private Claims getClaims(String token) {
    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }

  /**
   * 토큰에서 사용자 ID 추출
   *
   * @param token JWT 토큰 (Access Token 또는 Refresh Token)
   * @return 사용자 ID (Long)
   */
  public Long getUserIdFromToken(String token) {
    return getClaims(token).get(CLAIM_USER_ID, Long.class);
  }

  /**
   * 토큰에서 이메일 추출
   *
   * @param token JWT 토큰
   * @return 이메일 (String)
   */
  public String getEmailFromToken(String token) {
    return getClaims(token).get(CLAIM_EMAIL, String.class);
  }

  /**
   * 토큰에서 소셜 플랫폼 정보 추출
   *
   * @param token JWT 토큰
   * @return 소셜 플랫폼 (String)
   */
  public String getProviderFromToken(String token) {
    return getClaims(token).get(CLAIM_PROVIDER, String.class);
  }

  /**
   * 토큰 유효성 검증
   *
   * @param token JWT 토큰
   * @return 유효하면 true, 아니면 false
   */
  public boolean validateToken(String token) {
    try {
      Jwts.parser()
          .verifyWith(secretKey)
          .build()
          .parseSignedClaims(token);
      return true;
    } catch (SecurityException | MalformedJwtException e) {
      log.warn("Invalid JWT signature: {}", e.getMessage());
      throw new InvalidTokenException("유효하지 않은 토큰 서명입니다.", e);
    } catch (ExpiredJwtException e) {
      log.warn("Expired JWT token: {}", e.getMessage());
      throw new InvalidTokenException("만료된 토큰입니다.", ErrorCode.EXPIRED_TOKEN, e);
    } catch (UnsupportedJwtException e) {
      log.warn("Unsupported JWT token: {}", e.getMessage());
      throw new InvalidTokenException("지원하지 않는 형식의 토큰입니다.", e);
    } catch (IllegalArgumentException e) {
      log.warn("JWT claims string is empty: {}", e.getMessage());
      throw new InvalidTokenException("JWT claims가 비어있습니다.", e);
    } catch (JwtException e) {
      log.warn("JWT validation error: {}", e.getMessage());
      throw new InvalidTokenException("토큰 검증 중 오류가 발생했습니다.", e);
    }
  }

  /**
   * 현재 시간을 기준으로 새로 생성될 Refresh Token의 예상 만료 시간을 LocalDateTime으로 반환합니다.
   * 이 메서드는 특정 토큰의 실제 만료 시간을 분석하지 않고, 시스템 설정에 따른 리프레시 토큰의 유효 기간을 알려줍니다.
   *
   * @return 새로 생성될 Refresh Token의 예상 만료 시간 (LocalDateTime)
   */
  public LocalDateTime getRefreshTokenExpiry() {
    Instant now = Instant.now();
    Instant expirationInstant = now.plusMillis(refreshTokenExpirationMillis);
    return LocalDateTime.ofInstant(expirationInstant, ZoneId.systemDefault());
  }

  /**
   * Access Token의 만료 시간(밀리초)을 반환합니다.
   *
   * @return Access Token 만료 시간 (long)
   */
  public long getAccessTokenExpirationMillis() {
    return accessTokenExpirationMillis;
  }
}