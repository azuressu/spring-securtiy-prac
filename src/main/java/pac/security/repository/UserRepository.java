package pac.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pac.security.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Boolean existsByUsername(String username);

}
