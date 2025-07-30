package org.nodystudio.nodybackend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDateTime;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.nodystudio.nodybackend.base.BaseIntegrationTest;
import org.nodystudio.nodybackend.domain.enums.OAuthProvider;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.TokenRefreshRequestDto;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.nodystudio.nodybackend.security.jwt.TokenProvider;
import org.nodystudio.nodybackend.security.userdetails.CustomUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * 프론트엔드 관점에서 검증하는 인증 플로우 통합 테스트
 * <p>
 * 이 테스트는 프론트엔드 개발자가 백엔드 인증 API를 어떻게 사용해야 하는지 명확하게 보여주는 실용적인 예제들을 포함합니다.
 */
@DisplayName("프론트엔드 인증 플로우 통합 테스트")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
class FrontendAuthFlowTest extends BaseIntegrationTest {

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private TokenProvider tokenProvider;

  @Autowired
  private ObjectMapper objectMapper;

  private User testUser;

  @BeforeEach
  void setUp() {
    userRepository.deleteAll();

    testUser = User.builder()
        .provider(OAuthProvider.GOOGLE)
        .socialId("google_12345")
        .email("user@example.com")
        .nickname("Test User")
        .isActive(true)
        .build();
  }

  @AfterEach
  void tearDown() {
    userRepository.deleteAll();
  }

  /**
   * 시나리오 1: 프론트엔드에서 "구글로 로그인" 버튼 클릭
   * <p>
   * 프론트엔드에서는 사용자를 '/oauth2/authorization/google'로 리다이렉트시켜야 합니다. 이는 OAuth2 인증 과정을
   * 시작하는 표준적인 방법입니다.
   */
  @Test
  @DisplayName("1. 구글 로그인 시작 - OAuth2 인증 서버로 리다이렉트")
  void startGoogleLogin_shouldRedirectToOAuth2Provider() throws Exception {
    // when: 프론트엔드에서 구글 로그인 URL 요청
    MvcResult result = mockMvc.perform(get("/oauth2/authorization/google"))
        .andDo(print())
        .andExpect(status().is3xxRedirection())
        .andExpect(header().exists("Location"))
        .andReturn();

    // then: 구글 OAuth2 서버로 리다이렉트
    String redirectUrl = result.getResponse().getHeader("Location");
    assertThat(redirectUrl)
        .contains("accounts.google.com")
        .contains("oauth2")
        .contains("client_id");
  }

  /**
   * 시나리오 2: 토큰 갱신하기
   * <p>
   * 프론트엔드에서 Access Token이 만료되었을 때 Refresh Token을 사용해 새로운 토큰을 발급받는 방법입니다.
   */
  @Test
  @DisplayName("2. 토큰 갱신 - Refresh Token으로 새 Access Token 발급")
  void refreshToken_shouldReturnNewTokens() throws Exception {
    // given: 로그인된 사용자와 유효한 refresh token
    User savedUser = userRepository.saveAndFlush(testUser);
    String refreshToken = tokenProvider.createRefreshToken(savedUser);
    LocalDateTime expiry = tokenProvider.getRefreshTokenExpiry();

    savedUser.updateRefreshToken(refreshToken, expiry);
    userRepository.saveAndFlush(savedUser);

    TokenRefreshRequestDto request = new TokenRefreshRequestDto(refreshToken);

    // when: 프론트엔드에서 토큰 갱신 요청
    MvcResult result = mockMvc.perform(post("/api/auth/refresh")
        .contentType("application/json")
        .content(objectMapper.writeValueAsString(request)))
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status").value(200))
        .andExpect(jsonPath("$.code").value("AUTH_S003"))
        .andExpect(jsonPath("$.data.accessToken").exists())
        .andExpect(jsonPath("$.data.refreshToken").exists())
        .andExpect(jsonPath("$.data.grantType").value("Bearer"))
        .andReturn();

    // then: 새로운 토큰들 반환
    String responseBody = result.getResponse().getContentAsString();
    @SuppressWarnings("unchecked")
    Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
    @SuppressWarnings("unchecked")
    Map<String, Object> data = (Map<String, Object>) response.get("data");

    String newAccessToken = (String) data.get("accessToken");
    String newRefreshToken = (String) data.get("refreshToken");

    assertThat(newAccessToken).isNotNull().isNotEmpty();
    assertThat(newRefreshToken).isNotNull().isNotEmpty();
    assertThat(newRefreshToken).isNotEqualTo(refreshToken);
  }

  /**
   * 시나리오 3: 잘못된 토큰 처리
   * <p>
   * 프론트엔드에서 잘못된 refresh token을 보냈을 때의 에러 처리입니다. 이런 경우 사용자를 다시 로그인 페이지로 리다이렉트해야
   * 합니다.
   */
  @Test
  @DisplayName("3. 잘못된 토큰 - 적절한 에러 응답으로 재로그인 유도")
  void invalidToken_shouldReturnErrorAndRequireRelogin() throws Exception {
    // given: 잘못된 토큰
    TokenRefreshRequestDto request = new TokenRefreshRequestDto("invalid.token.here");

    // when: 잘못된 토큰으로 갱신 시도
    MvcResult result = mockMvc.perform(post("/api/auth/refresh")
        .contentType("application/json")
        .content(objectMapper.writeValueAsString(request)))
        .andDo(print())
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.status").value(401))
        .andExpect(jsonPath("$.code").value("A005"))
        .andExpect(jsonPath("$.message").exists())
        .andReturn();

    // then: 에러 응답 확인
    String responseBody = result.getResponse().getContentAsString();
    @SuppressWarnings("unchecked")
    Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);

    assertThat(response.get("status")).isEqualTo(401);
    assertThat(response.get("code")).isEqualTo("A005");
    assertThat(response.get("message")).isNotNull();
  }

  /**
   * 시나리오 4: 토큰 재사용 방지
   * <p>
   * 보안을 위해 한 번 사용된 refresh token은 더 이상 사용할 수 없습니다. 프론트엔드는 항상 최신 토큰을 사용해야 합니다.
   */
  @Test
  @DisplayName("4. 보안 - 사용된 토큰 재사용 방지")
  void usedToken_shouldBeInvalidatedAndPreventReuse() throws Exception {
    // given: 유효한 refresh token
    User savedUser = userRepository.saveAndFlush(testUser);
    String refreshToken = tokenProvider.createRefreshToken(savedUser);
    LocalDateTime expiry = tokenProvider.getRefreshTokenExpiry();

    savedUser.updateRefreshToken(refreshToken, expiry);
    userRepository.saveAndFlush(savedUser);

    TokenRefreshRequestDto request = new TokenRefreshRequestDto(refreshToken);

    // when: 첫 번째 갱신 성공
    mockMvc.perform(post("/api/auth/refresh")
        .contentType("application/json")
        .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isOk());

    // then: 같은 토큰으로 두 번째 시도 시 차단
    mockMvc.perform(post("/api/auth/refresh")
        .contentType("application/json")
        .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("A005"));
  }

  /**
   * 시나리오 5: 연속 토큰 갱신
   * <p>
   * 장시간 사용하는 SPA에서 여러 번 토큰을 갱신하는 시나리오입니다. 각 갱신마다 새로운 토큰이 발급되어야 합니다.
   */
  @Test
  @DisplayName("5. 장시간 사용 - 연속 토큰 갱신")
  void multipleTokenRefresh_shouldWorkSequentially() throws Exception {
    // given: 초기 토큰
    User savedUser = userRepository.saveAndFlush(testUser);
    String currentRefreshToken = tokenProvider.createRefreshToken(savedUser);
    LocalDateTime expiry = tokenProvider.getRefreshTokenExpiry();

    savedUser.updateRefreshToken(currentRefreshToken, expiry);
    userRepository.saveAndFlush(savedUser);

    // when & then: 3번 연속 갱신
    for (int i = 1; i <= 3; i++) {
      TokenRefreshRequestDto request = new TokenRefreshRequestDto(currentRefreshToken);

      MvcResult result = mockMvc.perform(post("/api/auth/refresh")
          .contentType("application/json")
          .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isOk())
          .andReturn();

      String responseBody = result.getResponse().getContentAsString();
      @SuppressWarnings("unchecked")
      Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
      @SuppressWarnings("unchecked")
      Map<String, Object> data = (Map<String, Object>) response.get("data");

      String newRefreshToken = (String) data.get("refreshToken");
      assertThat(newRefreshToken).isNotEqualTo(currentRefreshToken);

      currentRefreshToken = newRefreshToken;
    }
  }

  /**
   * 시나리오 5: 로그아웃
   * <p>
   * 프론트엔드에서 사용자가 로그아웃할 때 서버에서 refresh token을 무효화하는 과정입니다.
   */
  @Test
  @DisplayName("5. 로그아웃 - Refresh Token 무효화 및 성공 응답")
  void logout_shouldInvalidateRefreshTokenAndReturnSuccess() throws Exception {
    // given: 로그인된 사용자와 유효한 refresh token
    User savedUser = userRepository.saveAndFlush(testUser);
    String refreshToken = tokenProvider.createRefreshToken(savedUser);
    LocalDateTime expiry = tokenProvider.getRefreshTokenExpiry();

    savedUser.updateRefreshToken(refreshToken, expiry);
    userRepository.saveAndFlush(savedUser);

    // 인증 정보 생성
    CustomUserDetails userDetails = new CustomUserDetails(savedUser);
    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
        userDetails, null, userDetails.getAuthorities());

    // when: 프론트엔드에서 로그아웃 요청
    mockMvc.perform(post("/api/auth/logout")
        .with(authentication(authentication))
        .contentType("application/json"))
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status").value(200))
        .andExpect(jsonPath("$.code").value("AUTH_S002"))
        .andExpect(jsonPath("$.message").value("로그아웃에 성공했습니다."))
        .andExpect(jsonPath("$.data").doesNotExist());

    // then: 사용자의 refresh token이 무효화되었는지 확인
    User updatedUser = userRepository.findById(savedUser.getId()).orElseThrow();
    assertThat(updatedUser.getRefreshToken()).isNull();
    assertThat(updatedUser.getRefreshTokenExpiry()).isNull();

    // 무효화된 토큰으로 갱신 시도 시 실패하는지 확인
    TokenRefreshRequestDto request = new TokenRefreshRequestDto(refreshToken);
    mockMvc.perform(post("/api/auth/refresh")
        .contentType("application/json")
        .content(objectMapper.writeValueAsString(request)))
        .andDo(print())
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("A005"));
  }

  @Test
  @DisplayName("6. 인증되지 않은 사용자 로그아웃 시도 - 401 Unauthorized")
  void logout_shouldReturnUnauthorized_whenNotAuthenticated() throws Exception {
    // when: 인증되지 않은 상태에서 로그아웃 시도
    mockMvc.perform(post("/api/auth/logout")
        .contentType("application/json"))
        .andDo(print())
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("A007"));
  }
}
