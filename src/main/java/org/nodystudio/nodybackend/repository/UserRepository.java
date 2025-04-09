package org.nodystudio.nodybackend.repository;

import org.nodystudio.nodybackend.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

  /**
   * 소셜 로그인 제공자와 소셜 ID로 사용자를 찾습니다.
   *
   * @param provider 소셜 로그인 제공자 (e.g., "google")
   * @param socialId 소셜 ID
   * @return Optional<User>
   */
  Optional<User> findByProviderAndSocialId(String provider, String socialId);

  /**
   * Refresh Token으로 사용자를 찾습니다.
   * Refresh Token은 고유하거나, 특정 사용자와 1:1 매핑된다고 가정합니다.
   * (만약 한 사용자가 여러 기기에서 로그인하여 여러 Refresh Token을 가질 수 있다면 로직 수정 필요)
   *
   * @param refreshToken Refresh Token
   * @return Optional<User>
   */
  Optional<User> findByRefreshToken(String refreshToken);

  /**
   * 이메일로 사용자를 찾습니다. (선택적: 필요시 사용)
   *
   * @param email 사용자 이메일
   * @return Optional<User>
   */
  Optional<User> findByEmail(String email);
}