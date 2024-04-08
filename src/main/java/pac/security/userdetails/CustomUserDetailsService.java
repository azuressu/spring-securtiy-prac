package pac.security.userdetails;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import pac.security.entity.UserEntity;
import pac.security.repository.UserRepository;

public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // DB에서 조회
        UserEntity userData = userRepository.findByUsername(username);

        // userData가 없는 경우
        if (userData != null) {
            // UserDetails에 담아서 return 하면 AuthenticationManager가 검증 함
            return new CustomUserDetails(userData);
        }

        return null;
    }
}
