package org.nodystudio.nodybackend.exception;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.nodystudio.nodybackend.controller.test.ExceptionTestController;
import org.nodystudio.nodybackend.dto.code.ErrorCode;
import org.nodystudio.nodybackend.dto.code.SuccessCode;
import org.springframework.test.web.servlet.MockMvc;

class GlobalExceptionHandlerTest {

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    ExceptionTestController controller = new ExceptionTestController();
    GlobalExceptionHandler exceptionHandler = new GlobalExceptionHandler();
    mockMvc = standaloneSetup(controller)
        .setControllerAdvice(exceptionHandler)
        .build();
  }

  @Test
  @DisplayName("정상 응답 테스트")
  void getOk_shouldReturnSuccessResponse() throws Exception {
    mockMvc.perform(get("/api/test/exceptions/ok"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status").value(SuccessCode.OK.getStatus().value()))
        .andExpect(jsonPath("$.code").value(SuccessCode.OK.getCode()))
        .andExpect(jsonPath("$.message").value(SuccessCode.OK.getMessage()))
        .andExpect(jsonPath("$.data.description").value("이것은 성공적인 응답의 데이터 부분입니다."));
  }

  @Test
  @DisplayName("ResourceNotFoundException 발생 시 404 NOT_FOUND 와 ErrorCode.RESOURCE_NOT_FOUND 응답")
  void handleBusinessException_whenResourceNotFound_shouldReturnNotFound() throws Exception {
    mockMvc.perform(get("/api/test/exceptions/not-found"))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.status").value(404))
        .andExpect(jsonPath("$.code").value(ErrorCode.RESOURCE_NOT_FOUND.getCode()))
        .andExpect(jsonPath("$.message").value("'User'에서 'id' 값이 '12345'인 리소스를 찾을 수 없습니다."));
  }

  @Test
  @DisplayName("UnauthorizedException 발생 시 401 UNAUTHORIZED 와 ErrorCode.USER_NOT_AUTHENTICATED 응답")
  void handleBusinessException_whenUnauthorized_shouldReturnUnauthorized() throws Exception {
    mockMvc.perform(get("/api/test/exceptions/unauthorized"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.status").value(401))
        .andExpect(jsonPath("$.code").value(ErrorCode.USER_NOT_AUTHENTICATED.getCode()))
        .andExpect(jsonPath("$.message").value("인증되지 않은 사용자입니다"));
  }

  @Test
  @DisplayName("ForbiddenException 발생 시 403 FORBIDDEN 과 ErrorCode.ACCESS_DENIED 응답")
  void handleBusinessException_whenForbidden_shouldReturnForbidden() throws Exception {
    mockMvc.perform(get("/api/test/exceptions/forbidden"))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.status").value(403))
        .andExpect(jsonPath("$.code").value(ErrorCode.ACCESS_DENIED.getCode()))
        .andExpect(jsonPath("$.message").value("접근이 거부되었습니다."));
  }

  @Test
  @DisplayName("ValidationException 발생 시 400 BAD_REQUEST 와 ErrorCode.VALIDATION_ERROR 응답")
  void handleBusinessException_whenValidationException_shouldReturnBadRequest() throws Exception {
    mockMvc.perform(get("/api/test/exceptions/validation"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.status").value(400))
        .andExpect(jsonPath("$.code").value(ErrorCode.VALIDATION_ERROR.getCode()))
        .andExpect(jsonPath("$.message").value("요청 유효성 검사에 실패했습니다"))
        .andExpect(jsonPath("$.errors[?(@.field == 'username')].message")
            .value("사용자 이름은 4자에서 20자 사이여야 합니다"))
        .andExpect(jsonPath("$.errors[?(@.field == 'email')].message")
            .value("이메일 형식이 올바르지 않습니다"));
  }

  @Test
  @DisplayName("RuntimeException 발생 시 500 INTERNAL_SERVER_ERROR 와 ErrorCode.INTERNAL_SERVER_ERROR 응답")
  void handleGlobalException_whenRuntimeException_shouldReturnInternalServerError()
      throws Exception {
    mockMvc.perform(get("/api/test/exceptions/error"))
        .andExpect(status().isInternalServerError())
        .andExpect(jsonPath("$.status").value(500))
        .andExpect(jsonPath("$.code").value(ErrorCode.INTERNAL_SERVER_ERROR.getCode()))
        .andExpect(jsonPath("$.message").value("서버 내부 오류가 발생했습니다."));
  }
}
