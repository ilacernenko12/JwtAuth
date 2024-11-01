package by.che.authorization.service;

import by.che.authorization.model.UserEntity;
import by.che.authorization.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.stream.Collectors;

/*
Этот класс служит для связи Spring Security и базы данных: он позволяет Spring
загружать пользователя и его роли для проверки подлинности и авторизации в приложении.
*/

@Service
public class CustomUserDetailService implements UserDetailsService {

    @Autowired // что-то вроде @inject из даггера
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByLogin(username).orElseThrow(() ->
                new UsernameNotFoundException("loadUserByUsername -> Пользователь не найден"));

        return new User(
                userEntity.getLogin(),
                userEntity.getPassword(),
                Arrays.stream(userEntity.getRole().name().split("\\|"))
                        .map(SimpleGrantedAuthority::new) // оборачивает каждую роль в объект, который Spring использует для проверки прав
                        .collect(Collectors.toList())
        );
    }
}
