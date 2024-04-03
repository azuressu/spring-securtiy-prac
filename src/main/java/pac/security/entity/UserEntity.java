package pac.security.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class UserEntity {

    /* ddl-auto=create 설정 후 실행
     * 데이터베이스에서 회원 정보를 저장할 테이블을 생성해야 하지만
     * ddl-auto 설정을 통해 스프링 부트 Entity 클래스 기반으로 테이블을 생성할 수 있다.*/

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String username;
    private String password;

    private String role;
}
