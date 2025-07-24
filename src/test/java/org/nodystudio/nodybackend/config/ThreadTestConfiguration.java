package org.nodystudio.nodybackend.config;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * Thread 컨트롤러 테스트에서 사용할 공통 설정을 제공하는 테스트 구성 클래스입니다.
 */
@TestConfiguration
public class ThreadTestConfiguration {

    /**
     * 테스트에서 사용할 Validator Bean을 생성합니다.
     * 
     * @return Validator 인스턴스
     */
    @Bean
    public Validator validator() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            return factory.getValidator();
        }
    }
}