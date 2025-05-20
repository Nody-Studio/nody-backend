package org.nodystudio.nodybackend.dto.user;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.nodystudio.nodybackend.domain.user.User;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserDetailResponseDto {

  /**
   * 사용자 이메일 주소
   */
  private String email;

  /**
   * 사용자 닉네임
   */
  private String nickname;

  @Builder
  private UserDetailResponseDto(String email, String nickname) {
    this.email = email;
    this.nickname = nickname;
  }

  public static UserDetailResponseDto fromEntity(User user) {
    String email = user.getEmail();
    String nickname = user.getNickname();

    return UserDetailResponseDto.builder()
        .email(email)
        .nickname(nickname)
        .build();
  }
}