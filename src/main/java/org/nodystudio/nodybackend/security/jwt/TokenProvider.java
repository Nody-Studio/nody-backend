package org.nodystudio.nodybackend.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Slf4j
@Component
public class TokenProvider {

  private static final String CLAIM_USER_ID = "userId";
  private static final String CLAIM_EMAIL = "email";
  private static final String CLAIM_PROVIDER = "provider";

  private final SecretKey secretKey;
  private final long accessTokenExpirationMillis;
  private final long refreshTokenExpirationMillis;

  public TokenProvider(
      @Value("${jwt.secret-key}") String secretString,
      @Value("${jwt.access-token-expiration-minutes}") long accessTokenExpirationMinutes,
      @Value("${jwt.refresh-token-expiration-days}") long refreshTokenExpirationDays) {
    byte[] keyBytes = Decoders.BASE64.decode(secretString);
    this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    this.accessTokenExpirationMillis = accessTokenExpirationMinutes * 60 * 1000; // 분 -> 밀리초
    this.refreshTokenExpirationMillis = refreshTokenExpirationDays * 24 * 60 * 60 * 1000; // 일 -> 밀리초
  }

  /**
   * Access Token 생성
   *
   * @param user 사용자 정보
   * @return 생성된 Access Token
   */
  public String createAccessToken(User user) {
    Instant now = Instant.now();
    Instant expirationInstant = now.plusMillis(accessTokenExpirationMillis);
    Date expirationDate = Date.from(expirationInstant);

    return Jwts.builder()
        .subject(user.getSocialId()) // 토큰 제목 (일반적으로 사용자 식별자)
        .claim(CLAIM_USER_ID, user.getId())
        .claim(CLAIM_EMAIL, user.getEmail())
        .claim(CLAIM_PROVIDER, user.getProvider())
        .issuedAt(Date.from(now)) // 발급 시간
        .expiration(expirationDate) // 만료 시간
        .signWith(secretKey, Jwts.SIG.HS512) // 서명 알고리즘 및 키
        .compact();
  }

  /**
   * Refresh Token 생성 (별도 Claim 없이 만료 시간만 길게 설정)
   *
   * @param user 사용자 정보 (Subject 설정용)
   * @return 생성된 Refresh Token
   */
  public String createRefreshToken(User user) {
    Instant now = Instant.now();
    Instant expirationInstant = now.plusMillis(refreshTokenExpirationMillis);
    Date expirationDate = Date.from(expirationInstant);

    return Jwts.builder()
        .subject(user.getSocialId()) // Refresh Token에도 Subject 설정 (선택적)
        .issuedAt(Date.from(now))
        .expiration(expirationDate)
        .signWith(secretKey, Jwts.SIG.HS512)
        .compact();
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
   * @param token JWT 토큰
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
      Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
      return true;
    } catch (SecurityException | MalformedJwtException e) {
      log.warn("Invalid JWT signature: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      log.warn("Expired JWT token: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      log.warn("Unsupported JWT token: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      log.warn("JWT claims string is empty: {}", e.getMessage());
    } catch (JwtException e) {
      log.warn("JWT validation error: {}", e.getMessage());
    }
    return false;
  }

  /**
   * Refresh Token의 만료 시간을 LocalDateTime으로 반환
   *
   * @return Refresh Token 만료 시간
   */
  public LocalDateTime getRefreshTokenExpiry() {
    Instant now = Instant.now();
    Instant expirationInstant = now.plusMillis(refreshTokenExpirationMillis);
    return LocalDateTime.ofInstant(expirationInstant, ZoneId.systemDefault());
  }
}