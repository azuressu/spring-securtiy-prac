package pac.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import pac.security.config.JWTUtil;
import pac.security.userdetails.CustomUserDetails;

import java.util.Collection;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;  // JWTUtil 주입

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        // 클라이언트 요청에서 username, password 추출하기
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        // Spring Security에서 username과 password를 검증하기 위해서는 token에 담아주어야 함
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(username, password, null);

        // token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(authenticationToken);
    }

    // 로그인 성공 시 실행하는 메소드 (여기서 JWT 발급)
    /* 로그인 성공 시 successfulAuthentication() 메소드를 통해 JWT를 응답해야 함.
    *  따라서 JWT 응답 구문 작성이 필요한데, JWT 발급 클래스를 아직 생성하지 않았으므로
    *  다음 시간에 DB 기반 회원 검증 구현 후, JWT 발급 및 검증을 진행하는 클래스 생성 예정*/
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain filterChain, Authentication authentication) {
        // UserDetails
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        // 예시 : Authorization: Bearer 인증토큰String
        response.addHeader("Authorization", "Bearer " + token);
    }

    // 로그인 실패 시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) {
        // 로그인 실패 시 401 응답 코드 반환
        response.setStatus(401);
    }



}
