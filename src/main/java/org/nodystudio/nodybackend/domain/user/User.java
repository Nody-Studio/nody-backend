package org.nodystudio.nodybackend.domain.user;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;
import org.nodystudio.nodybackend.domain.BaseTimeEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = "user", uniqueConstraints = {
    @UniqueConstraint(columnNames = { "provider", "social_id" }),
    @UniqueConstraint(columnNames = "email")
})
public class User extends BaseTimeEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "user_id")
  private Long id;

  @Column(name = "provider", nullable = false, length = 50)
  private String provider;

  @Column(name = "social_id", nullable = false)
  private String socialId;

  @Column(name = "email", length = 255)
  @Email(message = "유효한 이메일 형식이 아닙니다.")
  private String email;

  @Column(name = "nickname", nullable = false, length = 50)
  private String nickname;

  @Column(name = "is_active", nullable = false)
  @ColumnDefault("true")
  @Builder.Default
  private Boolean isActive = true;

  @Column(name = "refresh_token", length = 500)
  private String refreshToken;

  @Column(name = "refresh_token_expiry")
  private LocalDateTime refreshTokenExpiry;

  @Enumerated(EnumType.STRING)
  @Column(name = "role", nullable = false, length = 20)
  @Builder.Default
  private RoleType role = RoleType.USER;

  public void updateRefreshToken(String refreshToken, LocalDateTime refreshTokenExpiry) {
    this.refreshToken = refreshToken;
    this.refreshTokenExpiry = refreshTokenExpiry;
  }

  public User updateOAuthInfo(String nickname, String email) {
    if (nickname != null && !nickname.isBlank()) {
      this.nickname = nickname;
    }
    return this;
  }

  public void clearRefreshToken() {
    this.refreshToken = null;
    this.refreshTokenExpiry = null;
  }

  public List<GrantedAuthority> getRoles() {
    return Collections.singletonList(new SimpleGrantedAuthority(this.role.getKey()));
  }
}
