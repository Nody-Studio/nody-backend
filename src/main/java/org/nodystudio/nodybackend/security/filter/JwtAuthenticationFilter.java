package org.nodystudio.nodybackend.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.nodystudio.nodybackend.security.jwt.TokenProvider;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * JWT 토큰 기반 인증 필터입니다.
 * <p>
 * HTTP 요청의 {@code Authorization} 헤더에서 JWT 토큰을 추출하고, 토큰의 유효성을 검증하여
 * Spring Security 컨텍스트에 인증 정보를 설정합니다.
 * 특정 경로 (예: 로그인, 회원가입, 공개 API)는 이 필터의 처리를 받지 않습니다.
 * </p>
 *
 * @see OncePerRequestFilter
 * @see TokenProvider
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String BEARER_PREFIX = "Bearer ";

  /**
   * JWT 인증 필터가 적용되지 않아야 하는 경로 목록입니다.
   * AntPathMatcher 패턴을 사용하여 요청 경로와 비교합니다.
   */
  private static final List<String> EXCLUDED_PATHS = List.of(
      "/api/auth/refresh",
      "/api/auth/login",
      "/api/auth/signup",
      "/api/public/**",
      "/swagger-ui/**",
      "/swagger-ui.html",
      "/h2-console/**",
      "/v3/api-docs/**");

  private final AntPathMatcher pathMatcher = new AntPathMatcher();
  private final TokenProvider tokenProvider;
  private final UserRepository userRepository;

  /**
   * 현재 요청이 JWT 인증 필터를 거치지 않아야 하는지 여부를 결정합니다.
   * {@link #EXCLUDED_PATHS} 목록에 포함된 경로는 필터링하지 않습니다.
   *
   * @param request 현재 HTTP 요청
   * @return 필터링하지 않아야 하면 {@code true}, 그렇지 않으면 {@code false}
   */
  @Override
  protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
    String requestPath = request.getRequestURI();
    return EXCLUDED_PATHS.stream()
        .anyMatch(pattern -> pathMatcher.match(pattern, requestPath));
  }

  /**
   * 실제 필터링 로직을 수행합니다.
   * <p>
   * 요청에서 JWT 토큰을 추출하고 유효성을 검증한 후, 성공하면 {@link SecurityContextHolder}에 인증 정보를
   * 설정합니다.
   * 인증 과정에서 예외 발생 시 로그를 남기고 컨텍스트를 정리합니다.
   * </p>
   *
   * @param request     현재 HTTP 요청
   * @param response    현재 HTTP 응답
   * @param filterChain 필터 체인
   * @throws ServletException 서블릿 처리 중 예외 발생 시
   * @throws IOException      입출력 예외 발생 시
   */
  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain) throws ServletException, IOException {
    try {
      String jwt = resolveToken(request);

      if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
        Authentication authentication = getAuthentication(jwt);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.debug("사용자 인증 성공: {}", request.getRequestURI());
      }
    } catch (AuthenticationException e) {
      log.warn("인증 실패: {}, URI: {}", e.getMessage(), request.getRequestURI());
      SecurityContextHolder.clearContext();
    } catch (Exception e) {
      log.error("보안 컨텍스트에 사용자 인증 정보를 설정할 수 없습니다: {}", request.getRequestURI(), e);
      SecurityContextHolder.clearContext();
    }

    filterChain.doFilter(request, response);
  }

  /**
   * Request Header에서 Bearer 토큰 정보를 추출합니다.
   *
   * @param request HttpServletRequest
   * @return 추출된 토큰 문자열 (Bearer 제외) or null (토큰이 없거나 형식이 잘못된 경우)
   */
  private String resolveToken(HttpServletRequest request) {
    String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
      return bearerToken.substring(BEARER_PREFIX.length());
    }
    return null;
  }

  /**
   * JWT 토큰을 기반으로 Authentication 객체를 생성하고 반환합니다. 이 메서드는 토큰 유효성 검증 이후에 호출되어야 합니다.
   *
   * @param jwt 유효성이 검증된 JWT 토큰
   * @return 생성된 Authentication 객체
   * @throws AuthenticationException 인증 실패 시 발생 (e.g., 사용자 없음, 토큰 파싱 오류)
   */
  private Authentication getAuthentication(String jwt) throws AuthenticationException {
    try {
      Long userId = tokenProvider.getUserIdFromToken(jwt);
      User user = userRepository.findById(userId)
          .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + userId));

      if (!user.getIsActive()) {
        throw new DisabledException("비활성화된 사용자 계정입니다: " + userId);
      }

      List<GrantedAuthority> authorities = user.getRoles();

      return new UsernamePasswordAuthenticationToken(user, null, authorities);
    } catch (UsernameNotFoundException e) {
      throw e;
    } catch (DisabledException e) {
      throw e;
    } catch (Exception e) {
      throw new BadCredentialsException("JWT 토큰 처리 중 오류가 발생했습니다", e);
    }
  }
}
