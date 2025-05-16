package org.nodystudio.nodybackend.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseCookie;

public class CookieUtils {

  private static final ObjectMapper objectMapper = new ObjectMapper();
  private static final Logger logger = LoggerFactory.getLogger(CookieUtils.class);

  public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
    Cookie[] cookies = request.getCookies();

    if (cookies != null && cookies.length > 0) {
      for (Cookie cookie : cookies) {
        if (cookie.getName().equals(name)) {
          return Optional.of(cookie);
        }
      }
    }

    return Optional.empty();
  }

  public static void addCookie(
      HttpServletResponse response, String name, String value, int maxAge) {
    Cookie cookie = new Cookie(name, value);
    cookie.setPath("/");
    cookie.setHttpOnly(true);
    cookie.setMaxAge(maxAge);
    response.addCookie(cookie);
  }

  /**
   * 보안 속성이 적용된 쿠키를 생성하고 응답에 추가합니다.
   *
   * @param response 응답 객체
   * @param name     쿠키 이름
   * @param value    쿠키 값
   * @param maxAge   쿠키 유효 시간(초)
   * @param secure   HTTPS에서만 쿠키를 전송할지 여부
   * @param sameSite 쿠키의 SameSite 속성 (Strict, Lax, None)
   */
  public static void addSecureCookie(
      HttpServletResponse response, String name, String value, int maxAge,
      boolean secure, String sameSite) {
    ResponseCookie responseCookie = ResponseCookie.from(name, value)
        .path("/")
        .httpOnly(true)
        .maxAge(maxAge)
        .secure(secure)
        .sameSite(sameSite)
        .build();

    response.addHeader("Set-Cookie", responseCookie.toString());
  }

  public static void deleteCookie(
      HttpServletRequest request, HttpServletResponse response, String name) {
    Cookie[] cookies = request.getCookies();
    if (cookies != null && cookies.length > 0) {
      for (Cookie cookie : cookies) {
        if (cookie.getName().equals(name)) {
          ResponseCookie responseCookie = ResponseCookie.from(name, "")
              .path("/")
              .httpOnly(true)
              .maxAge(0)
              .secure(true)
              .sameSite("Lax")
              .build();
          response.addHeader("Set-Cookie", responseCookie.toString());
        }
      }
    }
  }

  public static String serialize(Object object) {
    try {
      return Base64.getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(object));
    } catch (JsonProcessingException e) {
      logger.error("객체 직렬화 중 오류 발생: {}", object, e);
      throw new RuntimeException("객체 직렬화에 실패했습니다.", e);
    }
  }

  public static <T> T deserialize(Cookie cookie, Class<T> cls) {
    try {
      byte[] decodedBytes = Base64.getUrlDecoder().decode(cookie.getValue());
      return objectMapper.readValue(decodedBytes, cls);
    } catch (IOException e) {
      logger.error("쿠키 역직렬화 중 오류 발생: {}", cookie.getValue(), e);
      throw new RuntimeException("쿠키 역직렬화에 실패했습니다.", e);
    }
  }
}
