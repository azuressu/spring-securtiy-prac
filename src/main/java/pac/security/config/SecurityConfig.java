package pac.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /* SecurityConfig
    * 스프링 시큐리티의 인가 및 설정을 담당하는 클래스
    * SecurityConfig 구현은 Spring Security 세부 버전별로 많이 상이 */

    /**
     * 비밀번호 인코딩
     * BCrypt 해싱 알고리즘을 사용해 비밀번호를 안전하게 해싱
     * 이렇게 해서 사용자의 비밀번호가 안전하게 저장되고, 보안을 향상시킴
     * BCryptPasswordEncoder를 사용하면 보안적으로 안전한 방식으로 비밀번호 저장 가능
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        // CSRF Disable
        httpSecurity.csrf((auth) -> auth.disable());

        // Form 로그인 방식 Disable
        httpSecurity.formLogin((auth) -> auth.disable());

        // Http Basic 인증 방식 Disable
        httpSecurity.httpBasic((auth) -> auth.disable());

        // 경로별로 인가 작업하기
        httpSecurity
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        /* 세션 설정
        * JWT를 통한 인증/인가를 위해서 세션을 STATELESS 상태로 설정하는 것이 중요
        * 이유는 ?
            * 확장성: 서버의 부하를 줄이고 확장성을 향상시킴
            * 분산 환경에서의 유용성: 분산 시스템에서 세션 동기화 문제를 해결
            * 클라이언트 측 저장소 활용: 클라이언트 측에서도 상태를 유지할 수 있어 효율적
            * 보안: 세션 데이터를 서버에 저장하지 않고도 보안을 유지할 수 있음 */
        httpSecurity
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return httpSecurity.build();
    }


}
