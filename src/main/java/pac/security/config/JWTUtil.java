package pac.security.config;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    /* Jwt는 Header.Payload.Signature 구조로 이루어짐
        * Header
        * JWT 명시
        * 사용된 암호화 알고리즘
        *
        * Payload
        * 정보
        *
        * Signature
        * 암호화 알고리즘 ((Base64(Header) + (Base64(Payload)) + 암호화 키

    * Jwt의 특징은 내부 정보를 단순 Base64 방식으로 인코딩하므로 외부에서 쉽게 디코딩할 수 있음
    * 외부에서 열람해도 되는 정보를 담아야 하며, 토큰 자체의 발급처를 확인하기 위해서 사용
    * (지폐와 같이 외부에서 그 금액을 확인하고, 금방 외형을 따라서 만들 수 있지만, 발급처에 대한 보장 및 검증은
    * 확실하게 해야 하는 경우에 사용. 따라서 토큰 내부에는 비밀번호 같은 값이 금지)*/

    /* 토큰 Payload에 저장될 정보
        * username
        * role
        * 생성일
        * 만료일
    * JWTUtil 구현 메소드
        * JWTUtil 생성자
        * username 확인 메소드
        * role 확인 메소드
        * 만료일 확인 메소드 */

    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createJwt(String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }

}
