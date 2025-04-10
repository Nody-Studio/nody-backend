package org.nodystudio.nodybackend.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Springdoc OpenAPI 설정 클래스
 */
@Configuration
public class OpenApiConfig {

  @Bean
  public OpenAPI openAPI() {
    Info info = new Info()
        .title("Nody API")
        .version("v0.0.1")
        .description("Nody 프로젝트 API 명세서")
        .contact(new io.swagger.v3.oas.models.info.Contact().email("an622911@gmail.com"));

    return new OpenAPI()
        .info(info);
  }
}