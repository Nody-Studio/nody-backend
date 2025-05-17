package org.nodystudio.nodybackend.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.anyLong;
import static org.mockito.BDDMockito.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.never;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.times;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.Collections;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.nodystudio.nodybackend.domain.user.RoleType;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.nodystudio.nodybackend.security.jwt.TokenProvider;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

  @Mock
  private TokenProvider tokenProvider;

  @Mock
  private UserRepository userRepository;

  @Mock
  private FilterChain filterChain;

  @InjectMocks
  private JwtAuthenticationFilter jwtAuthenticationFilter;

  private MockHttpServletRequest request;
  private MockHttpServletResponse response;
  private final String validToken = "valid-jwt-token";
  private final Long userId = 1L;

  @BeforeEach
  void setUp() {
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
    SecurityContextHolder.clearContext();
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  @DisplayName("제외된 경로에 대해서는 필터가 적용되지 않음")
  void shouldNotFilter_returnsTrue_forExcludedPaths() {
    // given
    String[] excludedPaths = {
        "/api/auth/refresh",
        "/api/auth/login",
        "/api/auth/signup",
        "/api/public/test",
        "/swagger-ui/index.html",
        "/v3/api-docs/swagger-config"
    };

    for (String path : excludedPaths) {
      // when
      request.setRequestURI(path);
      boolean shouldNotFilter = jwtAuthenticationFilter.shouldNotFilter(request);

      // then
      assertThat(shouldNotFilter).as("경로 %s는 필터링에서 제외되어야 함", path).isTrue();
    }
  }

  @Test
  @DisplayName("보호된 경로에 대해서는 필터가 적용됨")
  void shouldNotFilter_returnsFalse_forProtectedPaths() {
    // given
    String[] protectedPaths = {
        "/api/user/profile",
        "/api/posts",
        "/api/comments/1"
    };

    for (String path : protectedPaths) {
      // when
      request.setRequestURI(path);
      boolean shouldNotFilter = jwtAuthenticationFilter.shouldNotFilter(request);

      // then
      assertThat(shouldNotFilter).as("경로 %s는 필터링되어야 함", path).isFalse();
    }
  }

  @Test
  @DisplayName("유효한 JWT 토큰이 헤더에 있을 경우 SecurityContext에 Authentication 설정")
  void doFilterInternal_shouldSetAuthentication_whenTokenIsValid()
      throws ServletException, IOException {
    // given
    User mockUser = mock(User.class);
    request.addHeader("Authorization", "Bearer " + validToken);
    given(tokenProvider.validateToken(validToken)).willReturn(true);
    given(tokenProvider.getUserIdFromToken(validToken)).willReturn(userId);
    given(userRepository.findById(userId)).willReturn(Optional.of(mockUser));
    given(mockUser.getRoles())
        .willReturn(Collections.singletonList(new SimpleGrantedAuthority(RoleType.USER.getKey())));
    given(mockUser.getIsActive()).willReturn(true);

    // when
    jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

    // then
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    assertThat(authentication).isNotNull();
    assertThat(authentication.isAuthenticated()).isTrue();
    assertThat(authentication.getPrincipal()).isEqualTo(mockUser);
    assertThat(authentication.getAuthorities()).extracting("authority")
        .containsExactly("ROLE_USER");

    // verify
    then(filterChain).should(times(1)).doFilter(request, response);
    then(tokenProvider).should(times(1)).validateToken(validToken);
    then(tokenProvider).should(times(1)).getUserIdFromToken(validToken);
    then(userRepository).should(times(1)).findById(userId);
  }

  @Test
  @DisplayName("헤더에 토큰이 없거나 Bearer 타입이 아닐 경우 Authentication 설정 안 함")
  void doFilterInternal_shouldNotSetAuthentication_whenTokenIsMissingOrNotBearer()
      throws ServletException, IOException {
    // given
    request.addHeader("Authorization", "Basic somecredentials");

    // when
    jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

    // then
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    assertThat(authentication).isNull();

    // verify
    then(filterChain).should(times(1)).doFilter(request, response);
    then(tokenProvider).should(never()).validateToken(anyString());
    then(tokenProvider).should(never()).getUserIdFromToken(anyString());
  }

  @Test
  @DisplayName("토큰 유효성 검증 실패 시 Authentication 설정 안 함")
  void doFilterInternal_shouldNotSetAuthentication_whenTokenIsInvalid()
      throws ServletException, IOException {
    // given
    String invalidToken = "invalid-jwt-token";
    request.addHeader("Authorization", "Bearer " + invalidToken);
    given(tokenProvider.validateToken(invalidToken)).willReturn(false);

    // when
    jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

    // then
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    assertThat(authentication).isNull();

    // verify
    then(filterChain).should(times(1)).doFilter(request, response);
    then(tokenProvider).should(times(1)).validateToken(invalidToken);
    then(tokenProvider).should(never()).getUserIdFromToken(anyString());
    then(userRepository).should(never()).findById(anyLong());
  }

  @Test
  @DisplayName("사용자를 찾을 수 없는 경우 Authentication 설정 안 함")
  void doFilterInternal_shouldNotSetAuthentication_whenUserNotFound()
      throws ServletException, IOException {
    // given
    request.addHeader("Authorization", "Bearer " + validToken);
    given(tokenProvider.validateToken(validToken)).willReturn(true);
    given(tokenProvider.getUserIdFromToken(validToken)).willReturn(userId);
    given(userRepository.findById(userId)).willReturn(Optional.empty());

    // when
    jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

    // then
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    assertThat(authentication).isNull();

    // verify
    then(filterChain).should(times(1)).doFilter(request, response);
    then(tokenProvider).should(times(1)).validateToken(validToken);
    then(tokenProvider).should(times(1)).getUserIdFromToken(validToken);
    then(userRepository).should(times(1)).findById(userId);
  }

  @Test
  @DisplayName("예외 발생 시 SecurityContext가 클리어되고 필터체인은 계속 진행")
  void doFilterInternal_shouldClearSecurityContext_whenExceptionThrown()
      throws ServletException, IOException {
    // given
    request.addHeader("Authorization", "Bearer " + validToken);
    given(tokenProvider.validateToken(validToken)).willReturn(true);
    given(tokenProvider.getUserIdFromToken(validToken)).willThrow(
        new RuntimeException("처리 중 오류 발생"));

    // when
    jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

    // then
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    assertThat(authentication).isNull();

    // verify
    then(filterChain).should(times(1)).doFilter(request, response);
  }
}