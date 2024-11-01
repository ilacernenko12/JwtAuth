package by.che.authorization.service;

import by.che.authorization.model.UserEntity;
import by.che.authorization.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service public class ServiceImpl {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtEncoder jwtEncoder;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final Logger logger = LoggerFactory.getLogger(ServiceImpl.class);

    /*
    Регистрирует нового пользователя.
    Проверяет, существует ли уже пользователь с таким именем.
    Если имя занято, возвращает соответствующее сообщение.
    Если имя свободно, кодирует пароль и сохраняет нового пользователя в базе данных.
*/
    public String registerUser(UserEntity user){
        Optional<UserEntity> userEntity = userRepository.findByLogin(user.getLogin());
        if (userEntity.isPresent()){
            return "Имя пользователя занято";
        }

        // Проверка: соответствие пароля требованиям (заглавная, строчная буквы и спец. символ)
        String passwordPattern = "(?=.*[a-z])(?=.*[A-Z])(?=.*\\W).*";
        if (!user.getPassword().matches(passwordPattern)) {
            return "Неверный формат пароля";
        }

        // Проверка: обязательные поля не пусты
        if (user.getLogin() == null || user.getLogin().isEmpty() ||
                user.getOrganization() == null || user.getOrganization().isEmpty() ||
                user.getMerchantName() == null || user.getMerchantName().isEmpty() ||
                user.getEmail() == null || user.getEmail().isEmpty()) {
            return "Поля не могут быть пустыми";
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(user.getRole());
        userRepository.save(user);

        return "Пользователь успешно зарегистрирован";
    }

/*
    Обрабатывает процесс аутентификации пользователя.
    Проверяет учетные данные и, если они верны, генерирует JWT токен для успешных входов.
    Возвращает mao с токеном и временем его действия
*/
    public Map<String, Object> login(String login, String password) {
        Optional<UserEntity> userEntity = userRepository.findByLogin(login);
        Map<String, Object> response = new HashMap<>();

        // аутентификация пользователя с помощью введенных учетных данных
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(login, password));

        // проверка наличия пользователя перед выдачей токена
        if (!userEntity.isPresent()){ // содержит ли объект Optional значение
            response.put("status", "login() -> Пользователь не найден");
            return response;
        }

        // генерация JWT токена на основе сущности пользователя и аутентификации
        String accessToken = generateToken(userEntity.get(), authentication, 3600);
        response.put("access_token", accessToken);
        response.put("expires_in", 3600); // время действия токена в секундах (1ч)
        return response;
    }

/*
    Создает JWT токен с утверждениями (claims), такими как роли и идентификатор пользователя.
    Указывает издателя, время выпуска и истечения токена, а также другую пользовательскую информацию.
*/
    private String generateToken(UserEntity userEntity, Authentication authentication, long expiryDuration){
        Instant now = Instant.now(); // получает текущее время

        Set<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        // Выводим роли в лог
        logger.info("Пользователь {} имеет роли: {}", userEntity.getLogin(), roles);

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("auth-server") // кто выдал токен
                .issuedAt(now) // время выпуска токена
                .expiresAt(now.plusSeconds(expiryDuration)) // время истечения токена
                .subject(authentication.getName())
                .claim("role", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet())) // собирает роли пользователя
                .claim("login", userEntity.getLogin())
                .claim("password", userEntity.getPassword())
                .claim("userId", userEntity.getId()) // уникальный идентификатор пользователя
                .build();

        // генерирует и возвращает JWT токен на основе созданного набора утверждений
        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }

    public List<UserEntity> getAll() {
        return userRepository.findAll();
    }
}
